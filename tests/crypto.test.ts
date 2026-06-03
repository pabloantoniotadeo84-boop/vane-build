import { describe, it, expect } from 'vitest';
import { sign as cryptoSign, createPrivateKey, randomUUID } from 'node:crypto';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { signPayload, verifyPayload } from '../src/crypto/signer.js';
import { AttestationChain } from '../src/crypto/chain.js';
import { deriveKeyId } from '../src/crypto/svid.js';
import { agentSpiffeId, companySpiffeId } from '../src/crypto/spiffe.js';
import { issueJwtSvid, verifyJwtSvid } from '../src/crypto/svid.js';
import { exchangeToken, extractDelegationChain } from '../src/crypto/token-exchange.js';
import { issuePassport, PASSPORT_AUDIENCE } from '../src/passport/credential.js';
import { verifyPassport } from '../src/passport/verify.js';
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

    // Issue a passport with a 1-second TTL
    const token = issuePassport({
      agentId: 'agent-1',
      agentSpiffeId: agentId,
      org: 'acme',
      orgSpiffeId: orgId,
      scopes: ['tool:*'],
      delegationChain: [orgId, agentId],
      ttl: 1,
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    // Advance the clock by 10 seconds — the passport is now expired
    const futureNow = Math.floor(Date.now() / 1000) + 10;
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
