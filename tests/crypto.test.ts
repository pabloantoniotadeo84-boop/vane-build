import { describe, it, expect } from 'vitest';
import { sign as cryptoSign, createPrivateKey, generateKeyPairSync, randomUUID } from 'node:crypto';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { signPayload, verifyPayload } from '../src/crypto/signer.js';
import { AttestationChain } from '../src/crypto/chain.js';
import { deriveKeyId } from '../src/crypto/svid.js';
import { agentSpiffeId, companySpiffeId } from '../src/crypto/spiffe.js';
import { issueJwtSvid, verifyJwtSvid } from '../src/crypto/svid.js';
import { exchangeToken, extractDelegationChain } from '../src/crypto/token-exchange.js';
import { issuePassport, PASSPORT_AUDIENCE, PASSPORT_TTL_MIN, PASSPORT_TTL_MAX } from '../src/passport/credential.js';
import { verifyPassport } from '../src/passport/verify.js';
import {
  issueCrossOrgToken,
  verifyCrossOrgToken,
  CROSS_ORG_MAX_TTL,
} from '../src/crypto/cross-org.js';
import { createVaneMiddleware } from '../packages/mcp-middleware/src/middleware.js';
import { verifyCrossOrgToken as middlewareVerifyCrossOrg } from '../packages/mcp-middleware/src/verify.js';
import type { AttestationRecord } from '../src/crypto/types.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Builds a signed CAP+JWT passport without enforcing the chain-tail === sub
 * invariant. Used to produce intentionally incoherent tokens for negative tests.
 */
function craftPassportRaw(opts: {
  sub: string;
  orgSpiffeId: string;
  delegationChain: string[];
  privateKeyPem: string;
  publicKeyPem: string;
}): string {
  const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
  const kid = deriveKeyId(opts.publicKeyPem);
  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'CAP+JWT', kid }));
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: 'spiffe://vane.local/ca',
    sub: opts.sub,
    aud: [PASSPORT_AUDIENCE],
    jti: randomUUID(),
    iat: now,
    exp: now + 3600,
    nbf: now,
    vane: {
      v: 1,
      agentId: 'agent-1',
      org: 'acme',
      orgSpiffeId: opts.orgSpiffeId,
      scopes: ['tool:*'],
      delegationChain: opts.delegationChain,
    },
  };
  const payload = b64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(signingInput), createPrivateKey(opts.privateKeyPem))
    .toString('base64url');
  return `${signingInput}.${sig}`;
}

// ── Test 1: Sign and verify golden vector ────────────────────────────────────

describe('Ed25519 signPayload / verifyPayload', () => {
  it('signs a known payload and verifies the signature', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const payload = {
      action: 'data-query',
      agentId: 'agent-golden',
      timestamp: '2026-01-01T00:00:00.000Z',
    };

    const signature = signPayload(payload, privateKey);

    expect(typeof signature).toBe('string');
    expect(signature.length).toBeGreaterThan(0);

    const result = verifyPayload(payload, signature, publicKey);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  // ── Test 2: Tampered payload rejection ──────────────────────────────────────

  it('rejects verification when the payload has been tampered', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const original = { action: 'read', resource: '/secrets/prod' };
    const tampered = { action: 'write', resource: '/secrets/prod' };

    const signature = signPayload(original, privateKey);

    // Tampered object must fail even though it shares all keys with original
    const result = verifyPayload(tampered, signature, publicKey);
    expect(result.valid).toBe(false);
  });

  it('rejects verification when a single field value is changed', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const original = { agentId: 'agent-1', companyId: 'acme' };

    const signature = signPayload(original, privateKey);

    // Only companyId changed
    const result = verifyPayload({ agentId: 'agent-1', companyId: 'evil-corp' }, signature, publicKey);
    expect(result.valid).toBe(false);
  });

  it('rejects verification when a wrong key is used', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const payload = { msg: 'hello' };

    const signature = signPayload(payload, kp1.privateKey);

    // Verify with a different keypair's public key
    const result = verifyPayload(payload, signature, kp2.publicKey);
    expect(result.valid).toBe(false);
  });
});

// ── Test 3: Expired passport rejection ──────────────────────────────────────

describe('Passport expiry', () => {
  it('rejects a passport whose exp is in the past', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    // Issue a passport with the minimum allowed TTL
    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      ttl: PASSPORT_TTL_MIN,
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    // Advance the clock past the TTL — the passport is now expired
    const futureNow = Math.floor(Date.now() / 1000) + PASSPORT_TTL_MIN + 1;
    const result = verifyPassport(token, { caPublicKey: publicKey, now: futureNow });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.code).toBe('TOKEN_EXPIRED');
    }
  });

  it('accepts a passport that is still within its TTL', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:read'],
      delegationChain: [orgId, agentId],
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const result = verifyPassport(token, { caPublicKey: publicKey });
    expect(result.valid).toBe(true);
  });
});

// ── Test 4: Delegation chain validation ─────────────────────────────────────

describe('Passport delegation chain coherence', () => {
  it('accepts a passport where delegation chain tail matches sub', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    // chain = [org, agent]; tail = agent = sub ✓
    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:search'],
      delegationChain: [orgId, agentId],
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const result = verifyPassport(token, { caPublicKey: publicKey });
    expect(result.valid).toBe(true);
  });

  it('rejects a passport where delegation chain tail does not match sub', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');
    const wrongId = agentSpiffeId('acme', 'evil-agent'); // will be placed at chain tail

    // chain tail = wrongId, but sub = agentId → incoherent ✗
    const token = craftPassportRaw({
      sub: agentId,
      orgSpiffeId: orgId,
      delegationChain: [orgId, wrongId],
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const result = verifyPassport(token, { caPublicKey: publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.code).toBe('CHAIN_INCOHERENT');
    }
  });

  it('issuePassport throws when chain tail does not match agentSpiffeId', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');
    const otherId = agentSpiffeId('acme', 'other-agent');

    expect(() =>
      issuePassport({
        agentId: 'agent-1',
        agentSpiffeId: agentId,
        org: 'acme',
        orgSpiffeId: orgId,
        scopes: ['tool:*'],
        delegationChain: [orgId, otherId], // tail ≠ agentSpiffeId
        privateKeyPem: privateKey,
        publicKeyPem: publicKey,
      }),
    ).toThrow(/delegationChain tail/);
  });
});

// ── Test 5: Append-only Merkle insert ───────────────────────────────────────

describe('AttestationChain integrity', () => {
  it('verifies a clean chain successfully', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const chain = new AttestationChain();

    chain.append({ action: 'login', user: 'alice' }, privateKey);
    chain.append({ action: 'query', table: 'users' }, privateKey);
    chain.append({ action: 'logout' }, privateKey);

    const result = chain.verify(publicKey);
    expect(result.valid).toBe(true);
    expect(typeof result.merkleRoot).toBe('string');
    expect((result.merkleRoot ?? '').length).toBe(64); // 32-byte SHA-256 hex
  });

  it('detects payload tampering via hash mismatch', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const chain = new AttestationChain();

    chain.append({ action: 'login', user: 'alice' }, privateKey);
    chain.append({ action: 'query', table: 'users' }, privateKey);
    chain.append({ action: 'logout' }, privateKey);

    // Build a tampered record list — modify the payload of record at index 1
    const original = chain.getRecords();
    const tampered: AttestationRecord[] = original.map((r, i) =>
      i === 1
        ? { ...r, payload: { action: 'DROP TABLE users', table: 'users' } }
        : { ...r },
    );

    const tamperedChain = new AttestationChain();
    tamperedChain.hydrate(tampered);

    const result = tamperedChain.verify(publicKey);
    expect(result.valid).toBe(false);
    expect(result.failedAtIndex).toBe(1);
  });

  it('detects hash field tampering via signature mismatch', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const chain = new AttestationChain();

    chain.append({ action: 'transfer', amount: 100 }, privateKey);
    chain.append({ action: 'transfer', amount: 200 }, privateKey);

    // Replace the stored hash of record 0 with a different value
    // (simulates an attacker who edits the DB hash column directly)
    const original = chain.getRecords();
    const tampered: AttestationRecord[] = original.map((r, i) =>
      i === 0
        ? { ...r, hash: 'a'.repeat(64) } // arbitrary fake hash
        : { ...r },
    );

    const tamperedChain = new AttestationChain();
    tamperedChain.hydrate(tampered);

    const result = tamperedChain.verify(publicKey);
    expect(result.valid).toBe(false);
    expect(result.failedAtIndex).toBe(0);
  });

  it('produces a valid Merkle inclusion proof that verifies against the root', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const chain = new AttestationChain();

    chain.append({ seq: 0 }, privateKey);
    chain.append({ seq: 1 }, privateKey);
    chain.append({ seq: 2 }, privateKey);
    chain.append({ seq: 3 }, privateKey);

    const { record, proof, root } = chain.getProof(2);

    const valid = AttestationChain.verifyProof(record.hash, proof, root);
    expect(valid).toBe(true);

    // Tampered leaf hash should NOT verify
    const fakeHash = 'b'.repeat(64);
    expect(AttestationChain.verifyProof(fakeHash, proof, root)).toBe(false);
  });
});

// ── Bonus: JWT-SVID and delegation token exchange ────────────────────────────

describe('JWT-SVID issuance and exchange', () => {
  it('issues and verifies a SPIFFE JWT-SVID', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const spiffeId = companySpiffeId('acme');

    const token = issueJwtSvid(spiffeId, privateKey, publicKey);
    const claims = verifyJwtSvid(token, publicKey);

    expect(claims.sub).toBe(spiffeId);
    expect(claims.aud).toContain('vane');
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('rejects an expired JWT-SVID', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const spiffeId = companySpiffeId('acme');

    // TTL = -100 → exp is 100 seconds in the past
    const token = issueJwtSvid(spiffeId, privateKey, publicKey, -100);

    expect(() => verifyJwtSvid(token, publicKey)).toThrow(/expired/);
  });

  it('produces a delegation token that encodes the full act chain', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const companyId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'worker-1');

    const companyToken = issueJwtSvid(companyId, privateKey, publicKey);
    const agentToken = issueJwtSvid(agentId, privateKey, publicKey);

    const { access_token } = exchangeToken(companyToken, agentToken, privateKey, publicKey);

    const claims = verifyJwtSvid(access_token, publicKey);
    expect(claims.sub).toBe(companyId);
    expect(claims.act?.sub).toBe(agentId);

    const chain = extractDelegationChain(claims);
    expect(chain[0]).toBe(companyId);  // subject at index 0
    expect(chain[1]).toBe(agentId);    // proximate actor at index 1
  });
});

// ── Passport TTL enforcement ─────────────────────────────────────────────────

describe('Passport TTL bounds', () => {
  it('rejects TTL below the minimum (< 5 minutes)', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    expect(() =>
      issuePassport({
        agentId: 'agent-1',
        agentSpiffeId: agentId,
        org: 'acme',
        orgSpiffeId: orgId,
        scopes: ['tool:*'],
        delegationChain: [orgId, agentId],
        ttl: PASSPORT_TTL_MIN - 1, // 299 s — below floor
        privateKeyPem: privateKey,
        publicKeyPem: publicKey,
      }),
    ).toThrow(/out of bounds/);
  });

  it('rejects TTL above the maximum (> 1 hour)', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    expect(() =>
      issuePassport({
        agentId: 'agent-1',
        agentSpiffeId: agentId,
        org: 'acme',
        orgSpiffeId: orgId,
        scopes: ['tool:*'],
        delegationChain: [orgId, agentId],
        ttl: PASSPORT_TTL_MAX + 1, // 3601 s — above cap
        privateKeyPem: privateKey,
        publicKeyPem: publicKey,
      }),
    ).toThrow(/out of bounds/);
  });

  it('accepts TTL at the minimum boundary (5 minutes)', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      ttl: PASSPORT_TTL_MIN,
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const result = verifyPassport(token, { caPublicKey: publicKey });
    expect(result.valid).toBe(true);
  });

  it('accepts TTL at the maximum boundary (1 hour)', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');

    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      ttl: PASSPORT_TTL_MAX,
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const result = verifyPassport(token, { caPublicKey: publicKey });
    expect(result.valid).toBe(true);
  });

});

// ── Revocation rejection ─────────────────────────────────────────────────────

describe('Revocation rejection', () => {
  function makePassport(kp: { publicKey: string; privateKey: string }) {
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-revoke');
    const token = issuePassport({
      agentId: 'agent-revoke',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
    // Decode JTI from the token without verifying (for test setup)
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as { jti: string };
    return { token, jti: payload.jti };
  }

  it('rejects a passport whose JTI is in the revocation list', async () => {
    const kp = generateKeyPair();
    const { token, jti } = makePassport(kp);

    const vane = createVaneMiddleware({
      vanePublicKey: kp.publicKey,
      fetchRevocationList: async () => [jti],
    });

    // Use the standalone verify helper which should accept the signature
    // but we must also simulate the middleware flow for revocation.
    // Test via fetchMiddleware directly.
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
    const body = await response.json() as { code?: string };
    expect(body.code).toBe('PASSPORT_REVOKED');
  });

  it('accepts a passport whose JTI is NOT in the revocation list', async () => {
    const kp = generateKeyPair();
    const { token } = makePassport(kp);

    const vane = createVaneMiddleware({
      vanePublicKey: kp.publicKey,
      fetchRevocationList: async () => ['some-other-jti'],
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

    expect(nextCalled).toBe(true);
    expect(response.status).toBe(200);
  });

  it('skips revocation check when fetchRevocationList is not provided', async () => {
    const kp = generateKeyPair();
    const { token } = makePassport(kp);

    const vane = createVaneMiddleware({ vanePublicKey: kp.publicKey }); // no fetchRevocationList
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

    expect(nextCalled).toBe(true);
    expect(response.status).toBe(200);
  });
});

// ── OCSP response signing ────────────────────────────────────────────────────

describe('OCSP signed response', () => {
  // The OCSP endpoint signs the status payload with the company key.
  // Verify that a signed OCSP body can be independently re-verified by any
  // holder of the CA public key using the same signPayload / verifyPayload
  // primitive used by the server.
  it('produces a verifiable signed status for a non-revoked JTI', () => {
    const kp = generateKeyPair();
    const jti = randomUUID();
    const checkedAt = new Date().toISOString();
    const responseData = { jti, status: 'valid', checkedAt };

    const signature = signPayload(responseData, kp.privateKey);
    const result = verifyPayload(responseData, signature, kp.publicKey);

    expect(result.valid).toBe(true);
  });

  it('produces a verifiable signed status for a revoked JTI', () => {
    const kp = generateKeyPair();
    const jti = randomUUID();
    const checkedAt = new Date().toISOString();
    const revokedAt = new Date().toISOString();
    const responseData = { jti, status: 'revoked', checkedAt, revokedAt, reason: 'rotated' };

    const signature = signPayload(responseData, kp.privateKey);
    const result = verifyPayload(responseData, signature, kp.publicKey);

    expect(result.valid).toBe(true);
  });

  it('rejects a tampered OCSP status payload', () => {
    const kp = generateKeyPair();
    const jti = randomUUID();
    const checkedAt = new Date().toISOString();
    const original = { jti, status: 'revoked', checkedAt };
    const tampered = { jti, status: 'valid', checkedAt }; // attacker flips status

    const signature = signPayload(original, kp.privateKey);
    const result = verifyPayload(tampered, signature, kp.publicKey);

    expect(result.valid).toBe(false);
  });
});

// ── Key rotation ─────────────────────────────────────────────────────────────

describe('Key rotation', () => {
  it('new key signs correctly and old key cannot verify the new passport', () => {
    const kp1 = generateKeyPair(); // key before rotation
    const kp2 = generateKeyPair(); // key after rotation

    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-rotation');

    const passport = issuePassport({
      agentId: 'agent-rotation',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      privateKeyPem: kp2.privateKey,
      publicKeyPem: kp2.publicKey,
    });

    const newKeyResult = verifyPassport(passport, { caPublicKey: kp2.publicKey });
    expect(newKeyResult.valid).toBe(true);

    const oldKeyResult = verifyPassport(passport, { caPublicKey: kp1.publicKey });
    expect(oldKeyResult.valid).toBe(false);
    if (!oldKeyResult.valid) expect(oldKeyResult.code).toBe('SIGNATURE_INVALID');
  });

  it('old key still verifies passport during grace period', () => {
    const kp1 = generateKeyPair(); // original key (retired)
    const kp2 = generateKeyPair(); // new key after rotation

    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-grace');

    // Passport signed with the old key before rotation
    const passport = issuePassport({
      agentId: 'agent-grace',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      privateKeyPem: kp1.privateKey,
      publicKeyPem: kp1.publicKey,
    });

    // After rotation the current key is kp2 and kp1 is within the grace period.
    // Simulate the server's multi-key fallback: try current key first, then retired.
    const candidateKeys = [kp2.publicKey, kp1.publicKey];
    let result = verifyPassport(passport, { caPublicKey: candidateKeys[0] });

    if (!result.valid && result.code === 'SIGNATURE_INVALID') {
      for (const key of candidateKeys.slice(1)) {
        const r = verifyPassport(passport, { caPublicKey: key });
        if (r.valid || r.code !== 'SIGNATURE_INVALID') { result = r; break; }
      }
    }

    expect(result.valid).toBe(true);
  });

  it('old key is rejected after grace period expires (key no longer in candidate set)', () => {
    const kp1 = generateKeyPair(); // original key
    const kp2 = generateKeyPair(); // key after rotation

    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-expired-grace');

    const passport = issuePassport({
      agentId: 'agent-expired-grace',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      ttl: PASSPORT_TTL_MAX,
      privateKeyPem: kp1.privateKey,
      publicKeyPem: kp1.publicKey,
    });

    // After grace period: only the new key is in the candidate set (kp1 is gone).
    const result = verifyPassport(passport, { caPublicKey: kp2.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('SIGNATURE_INVALID');
  });
});

// ── Revocation list retrieval (structure) ────────────────────────────────────

describe('Revocation list format', () => {
  // The fetchRevocationList option takes an async function that returns string[].
  // Verify that the middleware correctly handles lists of various sizes and
  // that the JTI lookup is an exact match (no prefix collisions).

  it('correctly identifies a JTI in a multi-entry revocation list', async () => {
    const kp = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');
    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
    const jti = (JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as { jti: string }).jti;

    const revocationList = [randomUUID(), randomUUID(), jti, randomUUID()];
    const vane = createVaneMiddleware({
      vanePublicKey: kp.publicKey,
      fetchRevocationList: async () => revocationList,
    });

    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const response = await middleware(req, async () => new Response('ok'));
    expect(response.status).toBe(401);
    const body = await response.json() as { code?: string };
    expect(body.code).toBe('PASSPORT_REVOKED');
  });

  it('does not confuse a JTI prefix with a full match', async () => {
    const kp = generateKeyPair();
    const orgId = companySpiffeId('acme');
    const agentId = agentSpiffeId('acme', 'agent-1');
    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
    const jti = (JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as { jti: string }).jti;

    // Revocation list contains a truncated JTI (prefix), NOT the full JTI.
    const vane = createVaneMiddleware({
      vanePublicKey: kp.publicKey,
      fetchRevocationList: async () => [jti.slice(0, 8)],
    });

    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    let nextCalled = false;
    const response = await middleware(req, async () => {
      nextCalled = true;
      return new Response('ok');
    });

    expect(nextCalled).toBe(true);
    expect(response.status).toBe(200);
  });
});

// ── Cross-org delegation tokens ──────────────────────────────────────────────

describe('Cross-org token issuance', () => {
  it('issues a valid XORG+JWT token', () => {
    const kp = generateKeyPair();
    const agentSId = agentSpiffeId('acme', 'billing-agent');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');

    const token = issueCrossOrgToken({
      agentId: 'billing-agent',
      agentSpiffeId: agentSId,
      originOrg: 'acme',
      originOrgSpiffeId: originOrgSId,
      targetOrg: 'exa',
      targetOrgSpiffeId: targetOrgSId,
      scopes: ['tool:search'],
      delegationChain: [originOrgSId, agentSId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });

    expect(token.split('.').length).toBe(3);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(header['typ']).toBe('XORG+JWT');
    expect(header['alg']).toBe('EdDSA');
  });

  it('rejects TTL exceeding 15 minutes', () => {
    const kp = generateKeyPair();
    const agentSId = agentSpiffeId('acme', 'agent-1');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');

    expect(() =>
      issueCrossOrgToken({
        agentId: 'agent-1',
        agentSpiffeId: agentSId,
        originOrg: 'acme',
        originOrgSpiffeId: originOrgSId,
        targetOrg: 'exa',
        targetOrgSpiffeId: targetOrgSId,
        scopes: ['tool:search'],
        delegationChain: [originOrgSId, agentSId],
        ttl: CROSS_ORG_MAX_TTL + 1,
        privateKeyPem: kp.privateKey,
        publicKeyPem: kp.publicKey,
      }),
    ).toThrow(/exceeds maximum/);
  });

  it('rejects when delegationChain tail does not match agentSpiffeId', () => {
    const kp = generateKeyPair();
    const agentSId  = agentSpiffeId('acme', 'agent-1');
    const wrongSId  = agentSpiffeId('acme', 'other-agent');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');

    expect(() =>
      issueCrossOrgToken({
        agentId: 'agent-1',
        agentSpiffeId: agentSId,
        originOrg: 'acme',
        originOrgSpiffeId: originOrgSId,
        targetOrg: 'exa',
        targetOrgSpiffeId: targetOrgSId,
        scopes: ['tool:search'],
        delegationChain: [originOrgSId, wrongSId],
        privateKeyPem: kp.privateKey,
        publicKeyPem: kp.publicKey,
      }),
    ).toThrow(/delegationChain tail/);
  });
});

describe('Cross-org token verification', () => {
  function makeXorgToken(kp: { publicKey: string; privateKey: string }) {
    const agentSId = agentSpiffeId('acme', 'billing-agent');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');
    return issueCrossOrgToken({
      agentId: 'billing-agent',
      agentSpiffeId: agentSId,
      originOrg: 'acme',
      originOrgSpiffeId: originOrgSId,
      targetOrg: 'exa',
      targetOrgSpiffeId: targetOrgSId,
      scopes: ['tool:search', 'tool:summarize'],
      delegationChain: [originOrgSId, agentSId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
  }

  it('verifies a valid cross-org token successfully', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    const result = verifyCrossOrgToken(token, kp.publicKey);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.claims.vane_xorg.originOrg).toBe('acme');
      expect(result.claims.vane_xorg.targetOrg).toBe('exa');
      expect(result.claims.vane_xorg.scopes).toContain('tool:search');
    }
  });

  it('rejects an expired cross-org token', () => {
    const kp = generateKeyPair();
    const agentSId = agentSpiffeId('acme', 'billing-agent');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');
    const token = issueCrossOrgToken({
      agentId: 'billing-agent',
      agentSpiffeId: agentSId,
      originOrg: 'acme',
      originOrgSpiffeId: originOrgSId,
      targetOrg: 'exa',
      targetOrgSpiffeId: targetOrgSId,
      scopes: ['tool:search'],
      delegationChain: [originOrgSId, agentSId],
      ttl: 60,
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
    const futureNow = Math.floor(Date.now() / 1000) + 61;
    const result = verifyCrossOrgToken(token, kp.publicKey, { now: futureNow });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('TOKEN_EXPIRED');
  });

  it('rejects a token signed by the wrong key', () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = makeXorgToken(kpA);
    const result = verifyCrossOrgToken(token, kpB.publicKey);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects a token targeting the wrong org', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    const result = verifyCrossOrgToken(token, kp.publicKey, { expectedTargetOrg: 'stripe' });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('TARGET_MISMATCH');
  });

  it('accepts when expectedTargetOrg matches the token target', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    const result = verifyCrossOrgToken(token, kp.publicKey, { expectedTargetOrg: 'exa' });
    expect(result.valid).toBe(true);
  });

  it('rejects when requested tool scope is not in the token', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp); // scopes: ['tool:search', 'tool:summarize']
    const result = verifyCrossOrgToken(token, kp.publicKey, { tool: 'write' });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('SCOPE_DENIED');
  });

  it('grants the matching scope for a valid tool call', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    const result = verifyCrossOrgToken(token, kp.publicKey, { tool: 'search' });
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.scopeGranted).toBe('tool:search');
  });

  it('rejects a regular CAP+JWT passport presented as a cross-org token', () => {
    const kp = generateKeyPair();
    const orgSId   = companySpiffeId('acme');
    const agentSId = agentSpiffeId('acme', 'agent-1');
    const passport = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentSId,
      org: 'acme',
      orgSpiffeId: orgSId,
      scopes: ['tool:*'],
      delegationChain: [orgSId, agentSId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
    const result = verifyCrossOrgToken(passport, kp.publicKey);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('WRONG_TOKEN_TYPE');
  });
});

describe('Cross-org tokens in mcp-middleware fetchMiddleware', () => {
  function makeXorgToken(kp: { publicKey: string; privateKey: string }) {
    const agentSId = agentSpiffeId('acme', 'billing-agent');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');
    return issueCrossOrgToken({
      agentId: 'billing-agent',
      agentSpiffeId: agentSId,
      originOrg: 'acme',
      originOrgSpiffeId: originOrgSId,
      targetOrg: 'exa',
      targetOrgSpiffeId: targetOrgSId,
      scopes: ['tool:search'],
      delegationChain: [originOrgSId, agentSId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
  }

  it('accepts a cross-org token when resolveCrossOrgPublicKey is configured', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = makeXorgToken(kpA);

    const vane = createVaneMiddleware({
      vanePublicKey: kpB.publicKey,
      expectedTargetOrg: 'exa',
      resolveCrossOrgPublicKey: async (originOrg) =>
        originOrg === 'acme' ? kpA.publicKey : null,
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

    expect(nextCalled).toBe(true);
    expect(response.status).toBe(200);
  });

  it('rejects a cross-org token when resolveCrossOrgPublicKey is not configured', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = makeXorgToken(kpA);

    const vane = createVaneMiddleware({ vanePublicKey: kpB.publicKey });
    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/call', params: { name: 'search' } }),
    });

    const response = await middleware(req, async () => new Response('ok'));
    expect(response.status).toBe(401);
    const body = await response.json() as { code?: string };
    expect(body.code).toBe('CROSS_ORG_NOT_ACCEPTED');
  });

  it('rejects a cross-org token targeting the wrong org', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = makeXorgToken(kpA); // targets 'exa'

    const vane = createVaneMiddleware({
      vanePublicKey: kpB.publicKey,
      expectedTargetOrg: 'stripe',
      resolveCrossOrgPublicKey: async () => kpA.publicKey,
    });

    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/call', params: { name: 'search' } }),
    });

    const response = await middleware(req, async () => new Response('ok'));
    expect(response.status).toBe(401);
    const body = await response.json() as { code?: string };
    expect(body.code).toBe('TARGET_MISMATCH');
  });

  it('rejects when resolveCrossOrgPublicKey returns null', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = makeXorgToken(kpA);

    const vane = createVaneMiddleware({
      vanePublicKey: kpB.publicKey,
      resolveCrossOrgPublicKey: async () => null,
    });

    const middleware = vane.fetchMiddleware();
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/call', params: { name: 'search' } }),
    });

    const response = await middleware(req, async () => new Response('ok'));
    expect(response.status).toBe(401);
    const body = await response.json() as { code?: string };
    expect(body.code).toBe('CROSS_ORG_UNKNOWN_ORIGIN');
  });

  it('attaches crossOrg context to the attestation receipt', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = makeXorgToken(kpA);

    const vane = createVaneMiddleware({
      vanePublicKey: kpB.publicKey,
      expectedTargetOrg: 'exa',
      resolveCrossOrgPublicKey: async (originOrg) =>
        originOrg === 'acme' ? kpA.publicKey : null,
    });

    const { decodeReceipt, RECEIPT_HEADER } = await import('../packages/mcp-middleware/src/middleware.js');
    const middleware = vane.fetchMiddleware();
    let capturedReceipt: unknown;
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/call', params: { name: 'search' } }),
    });

    await middleware(req, async (modifiedReq) => {
      const encoded = modifiedReq.headers.get(RECEIPT_HEADER);
      if (encoded) capturedReceipt = decodeReceipt(encoded);
      return new Response('ok');
    });

    expect(capturedReceipt).toBeDefined();
    const r = capturedReceipt as Record<string, unknown>;
    expect(r['org']).toBe('acme');
    expect((r['crossOrg'] as Record<string, unknown>)?.['targetOrg']).toBe('exa');
  });

  it('server and middleware verifyCrossOrgToken produce consistent results', () => {
    const kp = generateKeyPair();
    const agentSId = agentSpiffeId('acme', 'billing-agent');
    const originOrgSId = companySpiffeId('acme');
    const targetOrgSId = companySpiffeId('exa');
    const token = issueCrossOrgToken({
      agentId: 'billing-agent',
      agentSpiffeId: agentSId,
      originOrg: 'acme',
      originOrgSpiffeId: originOrgSId,
      targetOrg: 'exa',
      targetOrgSpiffeId: targetOrgSId,
      scopes: ['tool:search'],
      delegationChain: [originOrgSId, agentSId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });

    const serverResult = verifyCrossOrgToken(token, kp.publicKey);
    const mwResult     = middlewareVerifyCrossOrg(token, kp.publicKey);

    expect(serverResult.valid).toBe(true);
    expect(mwResult.valid).toBe(true);
    if (serverResult.valid && mwResult.valid) {
      expect(serverResult.claims.vane_xorg.targetOrg).toBe(mwResult.claims.vane_xorg.targetOrg);
      expect(serverResult.scopeGranted).toBe(mwResult.scopeGranted);
    }
  });
});

// ── Algorithm confusion hardening ─────────────────────────────────────────────
//
// Tests every alg-bypass vector against verifyJwtSvid (the base SVID verifier)
// and verifyPassport (the passport verifier used by the middleware).
// Changes to either verifier must keep all six cases passing.

describe('Algorithm confusion hardening — verifyJwtSvid', () => {
  const kp = generateKeyPair();
  const sub = companySpiffeId('acme');

  function craftSvid(headerAlg: string | null): string {
    const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    // null signals "omit alg entirely from header"
    const headerObj: Record<string, unknown> = headerAlg === null
      ? { typ: 'JWT' }
      : { alg: headerAlg, typ: 'JWT' };
    const header  = b64url(JSON.stringify(headerObj));
    const payload = b64url(JSON.stringify({ sub, aud: ['vane'], iat: now, exp: now + 3600, jti: randomUUID() }));
    const si  = `${header}.${payload}`;
    const sig = cryptoSign(null, Buffer.from(si), createPrivateKey(kp.privateKey)).toString('base64url');
    return `${si}.${sig}`;
  }

  it('rejects alg:none', () => {
    expect(() => verifyJwtSvid(craftSvid('none'), kp.publicKey)).toThrow(/none/i);
  });

  it('rejects alg:RS256', () => {
    expect(() => verifyJwtSvid(craftSvid('RS256'), kp.publicKey)).toThrow(/RS256|Unsupported/i);
  });

  it('rejects alg:HS256', () => {
    expect(() => verifyJwtSvid(craftSvid('HS256'), kp.publicKey)).toThrow(/HS256|Unsupported/i);
  });

  it('rejects missing alg header', () => {
    expect(() => verifyJwtSvid(craftSvid(null), kp.publicKey)).toThrow(/missing|alg/i);
  });

  it('rejects token signed with RSA key but alg header claims EdDSA', () => {
    const { privateKey: rsaPriv } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPrivPem = rsaPriv.export({ type: 'pkcs8', format: 'pem' }) as string;
    const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
    const now    = Math.floor(Date.now() / 1000);
    const header  = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ sub, aud: ['vane'], iat: now, exp: now + 3600, jti: randomUUID() }));
    const si  = `${header}.${payload}`;
    const sig = cryptoSign('sha256', Buffer.from(si), rsaPrivPem).toString('base64url');
    const token = `${si}.${sig}`;
    // RSA signature does not verify under an Ed25519 public key
    expect(() => verifyJwtSvid(token, kp.publicKey)).toThrow();
  });

  it('accepts a correct EdDSA token', () => {
    const claims = verifyJwtSvid(craftSvid('EdDSA'), kp.publicKey);
    expect(claims.sub).toBe(sub);
  });
});

describe('Algorithm confusion hardening — verifyPassport', () => {
  const kp = generateKeyPair();
  const orgId   = companySpiffeId('acme');
  const agentId = agentSpiffeId('acme', 'agent-1');

  function craftPassportWithAlg(headerAlg: string | null): string {
    const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const headerObj: Record<string, unknown> = headerAlg === null
      ? { typ: 'CAP+JWT' }
      : { alg: headerAlg, typ: 'CAP+JWT' };
    const header  = b64url(JSON.stringify(headerObj));
    const payload = b64url(JSON.stringify({
      iss: 'spiffe://vane.local/ca',
      sub: agentId,
      aud: ['vane:passport:v1'],
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      nbf: now,
      vane: { v: 1, agentId: 'agent-1', org: 'acme', orgSpiffeId: orgId, scopes: ['tool:*'], delegationChain: [orgId, agentId] },
    }));
    const si  = `${header}.${payload}`;
    const sig = cryptoSign(null, Buffer.from(si), createPrivateKey(kp.privateKey)).toString('base64url');
    return `${si}.${sig}`;
  }

  it('rejects alg:none', () => {
    const result = verifyPassport(craftPassportWithAlg('none'), { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('ALGORITHM_MISMATCH');
  });

  it('rejects alg:RS256', () => {
    const result = verifyPassport(craftPassportWithAlg('RS256'), { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('ALGORITHM_MISMATCH');
  });

  it('rejects alg:HS256', () => {
    const result = verifyPassport(craftPassportWithAlg('HS256'), { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('ALGORITHM_MISMATCH');
  });

  it('rejects missing alg header', () => {
    const result = verifyPassport(craftPassportWithAlg(null), { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('ALGORITHM_MISMATCH');
  });

  it('rejects token signed with RSA key but alg header claims EdDSA', () => {
    const { privateKey: rsaPriv } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPrivPem = rsaPriv.export({ type: 'pkcs8', format: 'pem' }) as string;
    const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
    const now    = Math.floor(Date.now() / 1000);
    const header  = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'CAP+JWT' }));
    const payload = b64url(JSON.stringify({
      iss: 'spiffe://vane.local/ca',
      sub: agentId,
      aud: ['vane:passport:v1'],
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      nbf: now,
      vane: { v: 1, agentId: 'agent-1', org: 'acme', orgSpiffeId: orgId, scopes: ['tool:*'], delegationChain: [orgId, agentId] },
    }));
    const si  = `${header}.${payload}`;
    const sig = cryptoSign('sha256', Buffer.from(si), rsaPrivPem).toString('base64url');
    const token = `${si}.${sig}`;
    const result = verifyPassport(token, { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('accepts a correct EdDSA passport', () => {
    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      privateKeyPem: kp.privateKey,
      publicKeyPem: kp.publicKey,
    });
    const result = verifyPassport(token, { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(true);
  });
});
