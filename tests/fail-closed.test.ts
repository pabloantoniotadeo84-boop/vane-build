import { describe, it, expect, vi, afterEach } from 'vitest';
import { Hono } from 'hono';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { signPayload, verifyPayload } from '../src/crypto/signer.js';
import { AttestationChain } from '../src/crypto/chain.js';
import { verifyProof } from '../src/crypto/merkle.js';
import { agentSpiffeId, companySpiffeId } from '../src/crypto/spiffe.js';
import { issueJwtSvid, verifyJwtSvid } from '../src/crypto/svid.js';
import { issuePassport, PASSPORT_AUDIENCE } from '../src/passport/credential.js';
import { verifyPassport } from '../src/passport/verify.js';
import { issueCrossOrgToken, verifyCrossOrgToken } from '../src/crypto/cross-org.js';
import {
  verifyPassport as mwVerifyPassport,
  verifyCrossOrgToken as mwVerifyCrossOrg,
} from '../packages/mcp-middleware/src/verify.js';
import { createVaneMiddleware } from '../packages/mcp-middleware/src/middleware.js';
import type { AttestationRecord } from '../src/crypto/types.js';

// These tests assert the single property the task targets: every verification
// and authorization path FAILS CLOSED. Any error, ambiguity, or unexpected
// state must produce a deny (a structured `{ valid: false }` result, a thrown
// error for the throws-to-deny verifier, or a non-2xx response for middleware)
// — never `undefined`, never a thrown error escaping a result-returning
// verifier, and never a fall-through that reaches the protected handler.

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ORG_ID = companySpiffeId('acme');
const AGENT_ID = agentSpiffeId('acme', 'agent-1');

function makePassport(
  kp: { publicKey: string; privateKey: string },
  scopes: string[] = ['tool:*'],
): string {
  return issuePassport({
    agentId: 'agent-1',
    agentSpiffeId: AGENT_ID,
    org: 'acme',
    orgSpiffeId: ORG_ID,
    scopes,
    delegationChain: [ORG_ID, AGENT_ID],
    privateKeyPem: kp.privateKey,
    publicKeyPem: kp.publicKey,
  });
}

function makeXorgToken(
  kp: { publicKey: string; privateKey: string },
  scopes: string[] = ['tool:search'],
): string {
  return issueCrossOrgToken({
    agentId: 'agent-1',
    agentSpiffeId: AGENT_ID,
    originOrg: 'acme',
    originOrgSpiffeId: ORG_ID,
    targetOrg: 'exa',
    targetOrgSpiffeId: companySpiffeId('exa'),
    scopes,
    delegationChain: [ORG_ID, AGENT_ID],
    privateKeyPem: kp.privateKey,
    publicKeyPem: kp.publicKey,
  });
}

// ── Injected throw: signature check ───────────────────────────────────────────

describe('fail-closed: thrown error inside the signature check', () => {
  it('verifyPassport returns false (not undefined) when the key makes signature verification throw', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);

    // A malformed CA public key makes createPublicKey throw *inside* the
    // signature-check step. The result must be a defined deny, never undefined.
    const result = verifyPassport(token, { caPublicKey: 'not-a-real-pem-key' });

    expect(result).toBeDefined();
    expect(typeof result.valid).toBe('boolean');
    expect(result.valid).toBe(false);
    expect(result.valid).not.toBe(undefined);
    if (!result.valid) expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('verifyCrossOrgToken returns false when the key makes signature verification throw', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    const result = verifyCrossOrgToken(token, 'not-a-real-pem-key');

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    expect(result.valid).not.toBe(undefined);
  });

  it('mcp-middleware verifyPassport returns false when signature verification throws', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    const result = mwVerifyPassport(token, 'not-a-real-pem-key');

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
  });
});

// ── Injected throw: delegation chain check ────────────────────────────────────

describe('fail-closed: thrown error inside the delegation chain check', () => {
  it('verifyPassport returns false when the chain check throws', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);

    // Surgically force the delegation-chain validation step (Array.isArray on
    // the delegationChain) to throw, leaving every other step untouched.
    const realIsArray = Array.isArray;
    vi.spyOn(Array, 'isArray').mockImplementation((arg: unknown): arg is unknown[] => {
      if (
        realIsArray(arg) &&
        arg.length === 2 &&
        arg[0] === ORG_ID &&
        arg[1] === AGENT_ID
      ) {
        throw new Error('injected: delegation chain check failure');
      }
      return realIsArray(arg);
    });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    expect(result.valid).not.toBe(undefined);
    if (!result.valid) expect(result.code).toBe('VERIFICATION_ERROR');
  });
});

// ── Injected throw: expiry check ──────────────────────────────────────────────

describe('fail-closed: thrown error inside the expiry check', () => {
  it('verifyPassport returns false when the expiry time source throws', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp); // issued before the clock is sabotaged

    // The expiry step compares exp against `now`; force the time source to throw.
    vi.spyOn(Date, 'now').mockImplementation(() => {
      throw new Error('injected: clock failure during expiry check');
    });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    expect(result.valid).not.toBe(undefined);
    if (!result.valid) expect(result.code).toBe('VERIFICATION_ERROR');
  });
});

// ── Injected throw: audience check ────────────────────────────────────────────

describe('fail-closed: thrown error inside the audience check', () => {
  it('verifyPassport returns false when the audience membership check throws', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);

    // Surgically force only the audience membership test (aud.includes on the
    // passport audience) to throw.
    const realIncludes = Array.prototype.includes;
    vi.spyOn(Array.prototype, 'includes').mockImplementation(function (
      this: unknown[],
      ...args: unknown[]
    ): boolean {
      if (args[0] === PASSPORT_AUDIENCE) {
        throw new Error('injected: audience check failure');
      }
      return (realIncludes as (...a: unknown[]) => boolean).apply(this, args);
    });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    expect(result.valid).not.toBe(undefined);
    if (!result.valid) expect(result.code).toBe('VERIFICATION_ERROR');
  });
});

// ── Pure-input outer-catch proof (no mocks) ───────────────────────────────────
//
// A non-string scope makes the scope-matching step throw via String.prototype
// methods. With no mocking involved, this proves the fail-closed wrapper
// actually catches real exceptions raised deep in the verifier.

describe('fail-closed: real exception in scope matching (no mocks)', () => {
  it('verifyPassport denies a passport whose scopes contain a non-string', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp, [123 as unknown as string]);
    const result = verifyPassport(token, { caPublicKey: kp.publicKey, tool: 'search' });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('VERIFICATION_ERROR');
  });

  it('verifyCrossOrgToken denies a token whose scopes contain a non-string', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp, [123 as unknown as string]);
    const result = verifyCrossOrgToken(token, kp.publicKey, { tool: 'search' });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('VERIFICATION_ERROR');
  });

  it('mcp-middleware verifyPassport denies a passport whose scopes contain a non-string', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp, [123 as unknown as string]);
    const result = mwVerifyPassport(token, kp.publicKey, { tool: 'search' });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
  });

  it('mcp-middleware verifyCrossOrgToken denies a token whose scopes contain a non-string', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp, [123 as unknown as string]);
    const result = mwVerifyCrossOrg(token, kp.publicKey, { tool: 'search' });

    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
  });
});

// ── No verifier ever returns undefined ────────────────────────────────────────

describe('fail-closed: no verification function ever returns undefined', () => {
  const kp = generateKeyPair();
  const malformedTokens = [
    '',
    'only-one-part',
    'two.parts',
    'a.b.c',
    'not.valid.token',
    `${Buffer.from('{}').toString('base64url')}.${Buffer.from('{}').toString('base64url')}.sig`,
    '....',
  ];

  it('verifyPassport returns a defined boolean result for every malformed input', () => {
    for (const t of malformedTokens) {
      const r = verifyPassport(t, { caPublicKey: kp.publicKey });
      expect(r).toBeDefined();
      expect(typeof r.valid).toBe('boolean');
      expect(r.valid).toBe(false);
    }
  });

  it('verifyCrossOrgToken returns a defined boolean result for every malformed input', () => {
    for (const t of malformedTokens) {
      const r = verifyCrossOrgToken(t, kp.publicKey);
      expect(r).toBeDefined();
      expect(typeof r.valid).toBe('boolean');
      expect(r.valid).toBe(false);
    }
  });

  it('mcp-middleware verifyPassport / verifyCrossOrgToken return defined boolean results', () => {
    for (const t of malformedTokens) {
      const rp = mwVerifyPassport(t, kp.publicKey);
      expect(rp).toBeDefined();
      expect(rp.valid).toBe(false);

      const rx = mwVerifyCrossOrg(t, kp.publicKey);
      expect(rx).toBeDefined();
      expect(rx.valid).toBe(false);
    }
  });

  it('verifyPayload returns a defined { valid: false } for malformed key/signature', () => {
    const r = verifyPayload({ a: 1 }, 'not-a-sig', 'not-a-key');
    expect(r).toBeDefined();
    expect(typeof r.valid).toBe('boolean');
    expect(r.valid).toBe(false);
  });

  it('verifyJwtSvid (throws-to-deny) never returns undefined — it throws on bad input', () => {
    const kp2 = generateKeyPair();
    const good = issueJwtSvid(companySpiffeId('acme'), kp2.privateKey, kp2.publicKey);
    // Valid token + bad key → throws (deny), never returns undefined.
    expect(() => verifyJwtSvid(good, 'not-a-key')).toThrow();
    // Malformed token → throws (deny).
    expect(() => verifyJwtSvid('a.b.c', kp2.publicKey)).toThrow();
  });
});

// ── Chain + Merkle verifiers fail closed ──────────────────────────────────────

describe('fail-closed: AttestationChain.verify and verifyProof', () => {
  it('AttestationChain.verify marks a record invalid (not throw) when its payload cannot be hashed', () => {
    const kp = generateKeyPair();
    // A BigInt payload is un-serializable by canonicalize → hashing throws.
    const poisoned: AttestationRecord = {
      index: 0,
      timestamp: new Date().toISOString(),
      payload: 10n as unknown,
      hash: 'a'.repeat(64),
      signature: 'sig',
    };
    const chain = new AttestationChain();
    chain.hydrate([poisoned]);

    const result = chain.verify(kp.publicKey);
    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    expect(result.failedAtIndex).toBe(0);
  });

  it('verifyProof returns false (not throw) for a malformed proof', () => {
    // Passing a non-iterable proof would throw inside the loop; must yield false.
    const result = verifyProof('a'.repeat(64), null as never, 'b'.repeat(64));
    expect(result).toBe(false);
  });
});

// ── Middleware chain fails closed ─────────────────────────────────────────────

describe('fail-closed: middleware chain denies on a post-authentication exception', () => {
  it('an error after auth passes but before the handler is denied, not passed through', async () => {
    const app = new Hono<{ Variables: { companyId: string } }>();
    let handlerReached = false;

    // 1. Auth middleware — succeeds and resolves a tenant.
    app.use('/protected', async (c, next) => {
      c.set('companyId', 'acme');
      return next();
    });

    // 2. A middleware that runs AFTER auth but BEFORE the handler, and throws.
    app.use('/protected', async () => {
      throw new Error('injected: failure after authentication, before handler');
    });

    // 3. The protected handler — must never run.
    app.get('/protected', (c) => {
      handlerReached = true;
      return c.json({ secret: 'leaked' });
    });

    app.onError((_err, c) => c.json({ error: 'Internal Server Error' }, 500));

    const res = await app.request('/protected');

    expect(handlerReached).toBe(false);
    expect(res.status).toBe(500);
    expect(res.status).not.toBe(200);
    const body = (await res.json()) as { secret?: string };
    expect(body.secret).toBeUndefined();
  });

  it('fetchMiddleware denies (401, no next) when the revocation fetch throws', async () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);

    const vane = createVaneMiddleware({
      vanePublicKey: kp.publicKey,
      fetchRevocationList: async () => {
        throw new Error('injected: revocation backend unavailable');
      },
    });

    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/call', params: { name: 'search' } }),
    });

    let nextCalled = false;
    const response = await middleware(req, async () => {
      nextCalled = true;
      return new Response('ok');
    });

    expect(nextCalled).toBe(false);
    expect(response.status).toBe(401);
    const body = (await response.json()) as { code?: string };
    expect(body.code).toBe('VERIFICATION_ERROR');
  });

  it('fetchMiddleware denies (401, no next) when cross-org key resolution throws', async () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);

    const vane = createVaneMiddleware({
      vanePublicKey: kp.publicKey,
      expectedTargetOrg: 'exa',
      resolveCrossOrgPublicKey: async () => {
        throw new Error('injected: origin-org key lookup failed');
      },
    });

    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/call', params: { name: 'search' } }),
    });

    let nextCalled = false;
    const response = await middleware(req, async () => {
      nextCalled = true;
      return new Response('ok');
    });

    expect(nextCalled).toBe(false);
    expect(response.status).toBe(401);
  });
});
