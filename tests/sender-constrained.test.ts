import { describe, it, expect } from 'vitest';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { agentSpiffeId, companySpiffeId } from '../src/crypto/spiffe.js';
import {
  issuePassport,
  generateNonce,
  computeRequestHash,
} from '../src/passport/credential.js';
import { verifyPassport } from '../src/passport/verify.js';

// Sender-constrained passports: nonce binding, recipient-audience enforcement,
// and request binding. Each constraint must be enforced when the verifier asks
// for it, and must never weaken the existing plain-bearer path when it does not.

const ORG_ID = companySpiffeId('acme');
const AGENT_ID = agentSpiffeId('acme', 'agent-1');

/** Issues a passport with the standard fixtures plus any extra sender-constraint fields. */
function makePassport(
  kp: { publicKey: string; privateKey: string },
  extra: { nonce?: string; audience?: string; requestHash?: string } = {},
): string {
  return issuePassport({
    agentId: 'agent-1',
    agentSpiffeId: AGENT_ID,
    org: 'acme',
    orgSpiffeId: ORG_ID,
    scopes: ['tool:*'],
    delegationChain: [ORG_ID, AGENT_ID],
    privateKeyPem: kp.privateKey,
    publicKeyPem: kp.publicKey,
    ...extra,
  });
}

// ── Nonce binding ──────────────────────────────────────────────────────────────

describe('Passport nonce binding', () => {
  it('verifies with the correct nonce', () => {
    const kp = generateKeyPair();
    const nonce = generateNonce();
    const token = makePassport(kp, { nonce });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, expectedNonce: nonce });
    expect(result.valid).toBe(true);
  });

  it('fails with NONCE_MISMATCH when the wrong nonce is provided', () => {
    const kp = generateKeyPair();
    const nonce = generateNonce();
    const token = makePassport(kp, { nonce });

    const wrongNonce = generateNonce();
    const result = verifyPassport(token, { caPublicKey: kp.publicKey, expectedNonce: wrongNonce });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('NONCE_MISMATCH');
  });

  it('fails with MISSING_NONCE when the passport has no nonce but expectedNonce is provided', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp); // no nonce embedded

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, expectedNonce: generateNonce() });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('MISSING_NONCE');
  });

  it('generateNonce produces a 128-bit hex value', () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
  });

  it('issuePassport rejects a malformed nonce', () => {
    const kp = generateKeyPair();
    expect(() => makePassport(kp, { nonce: 'not-hex' })).toThrow(/128-bit hex/);
  });
});

// ── Recipient audience enforcement ───────────────────────────────────────────

describe('Passport recipient-audience enforcement', () => {
  const AUDIENCE = 'https://api.example.com';

  it('verifies with the correct audience', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp, { audience: AUDIENCE });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, expectedAudience: AUDIENCE });
    expect(result.valid).toBe(true);
  });

  it('fails with AUDIENCE_MISMATCH for a wrong audience', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp, { audience: AUDIENCE });

    const result = verifyPassport(token, {
      caPublicKey: kp.publicKey,
      expectedAudience: 'https://evil.example.net',
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('AUDIENCE_MISMATCH');
  });

  it('fails with MISSING_AUDIENCE when the passport has no recipient audience but one is expected', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp); // no recipient audience embedded

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, expectedAudience: AUDIENCE });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('MISSING_AUDIENCE');
  });
});

// ── Request binding ──────────────────────────────────────────────────────────

describe('Passport request binding', () => {
  const request = {
    method: 'POST',
    url: 'https://api.example.com/v1/charge',
    body: JSON.stringify({ amount: 100 }),
  };

  it('verifies when the request hash matches', () => {
    const kp = generateKeyPair();
    const requestHash = computeRequestHash(request);
    const token = makePassport(kp, { requestHash });

    const result = verifyPassport(token, {
      caPublicKey: kp.publicKey,
      expectedRequestHash: computeRequestHash(request),
    });
    expect(result.valid).toBe(true);
  });

  it('fails with REQUEST_MISMATCH when the request differs', () => {
    const kp = generateKeyPair();
    const requestHash = computeRequestHash(request);
    const token = makePassport(kp, { requestHash });

    // A different body produces a different canonical hash.
    const tamperedHash = computeRequestHash({ ...request, body: JSON.stringify({ amount: 999999 }) });
    const result = verifyPassport(token, {
      caPublicKey: kp.publicKey,
      expectedRequestHash: tamperedHash,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('REQUEST_MISMATCH');
  });

  it('fails with REQUEST_MISMATCH when a request-bound passport is verified with no expectedRequestHash', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp, { requestHash: computeRequestHash(request) });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('REQUEST_MISMATCH');
  });
});

// ── Backward compatibility ───────────────────────────────────────────────────

describe('Passport sender-constraint backward compatibility', () => {
  it('a passport issued without any constraint verifies when the verifier requires none', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp); // no nonce, audience, or requestHash

    const result = verifyPassport(token, { caPublicKey: kp.publicKey });
    expect(result.valid).toBe(true);
  });

  it('a fully sender-constrained passport verifies when every constraint is satisfied', () => {
    const kp = generateKeyPair();
    const nonce = generateNonce();
    const audience = 'https://api.example.com';
    const request = { method: 'GET', url: 'https://api.example.com/v1/search?q=x' };
    const requestHash = computeRequestHash(request);

    const token = makePassport(kp, { nonce, audience, requestHash });

    const result = verifyPassport(token, {
      caPublicKey: kp.publicKey,
      expectedNonce: nonce,
      expectedAudience: audience,
      expectedRequestHash: computeRequestHash(request),
    });
    expect(result.valid).toBe(true);
  });
});

// ── No verification function returns undefined ───────────────────────────────

describe('Passport verification never returns undefined under sender-constraint options', () => {
  it('returns a defined { valid: boolean } result for every constraint combination', () => {
    const kp = generateKeyPair();
    const nonce = generateNonce();
    const token = makePassport(kp, { nonce, audience: 'https://api.example.com' });

    const cases = [
      { caPublicKey: kp.publicKey },
      { caPublicKey: kp.publicKey, expectedNonce: nonce },
      { caPublicKey: kp.publicKey, expectedNonce: 'deadbeefdeadbeefdeadbeefdeadbeef' },
      { caPublicKey: kp.publicKey, expectedAudience: 'https://api.example.com' },
      { caPublicKey: kp.publicKey, expectedAudience: 'https://other.example.com' },
      { caPublicKey: kp.publicKey, expectedRequestHash: 'a'.repeat(64) },
      { caPublicKey: 'not-a-real-key', expectedNonce: nonce },
    ];

    for (const opts of cases) {
      const result = verifyPassport(token, opts);
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
    }
  });
});
