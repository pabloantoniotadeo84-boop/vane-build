import { describe, it, expect } from 'vitest';
import { sign as cryptoSign, createPrivateKey, randomUUID } from 'node:crypto';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { agentSpiffeId, companySpiffeId } from '../src/crypto/spiffe.js';
import {
  issueJwtSvid,
  verifyJwtSvid,
  deriveKeyId,
  DEFAULT_CLOCK_SKEW_SECONDS,
} from '../src/crypto/svid.js';
import { issuePassport, PASSPORT_AUDIENCE } from '../src/passport/credential.js';
import { verifyPassport } from '../src/passport/verify.js';
import { issueCrossOrgToken, verifyCrossOrgToken } from '../src/crypto/cross-org.js';
import { verifyPassport as mwVerifyPassport } from '../packages/mcp-middleware/src/verify.js';
import { VaneClient } from '../packages/sidecar/src/vane.js';

// Clock-skew leeway and not-before (nbf) handling. The leeway absorbs small
// clock differences between the issuer and the verifier: a token is valid while
// (exp + leeway) > now and is rejected as not-yet-valid only when
// (nbf - leeway) > now. Default leeway is 30 s; a negative leeway throws.

const ORG_ID = companySpiffeId('acme');
const AGENT_ID = agentSpiffeId('acme', 'agent-1');

function makePassport(kp: { publicKey: string; privateKey: string }): string {
  return issuePassport({
    agentId: 'agent-1',
    agentSpiffeId: AGENT_ID,
    org: 'acme',
    orgSpiffeId: ORG_ID,
    scopes: ['tool:*'],
    delegationChain: [ORG_ID, AGENT_ID],
    privateKeyPem: kp.privateKey,
    publicKeyPem: kp.publicKey,
  });
}

function makeXorgToken(kp: { publicKey: string; privateKey: string }): string {
  return issueCrossOrgToken({
    agentId: 'agent-1',
    agentSpiffeId: AGENT_ID,
    originOrg: 'acme',
    originOrgSpiffeId: ORG_ID,
    targetOrg: 'exa',
    targetOrgSpiffeId: companySpiffeId('exa'),
    scopes: ['tool:search'],
    delegationChain: [ORG_ID, AGENT_ID],
    privateKeyPem: kp.privateKey,
    publicKeyPem: kp.publicKey,
  });
}

function decodeClaims(token: string): Record<string, number> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

/** Signs a CAP+JWT passport with explicit time claims (for future-nbf cases). */
function craftPassport(
  kp: { publicKey: string; privateKey: string },
  times: { iat: number; exp: number; nbf: number },
): string {
  const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'CAP+JWT', kid: deriveKeyId(kp.publicKey) }));
  const payload = b64url(JSON.stringify({
    iss: 'spiffe://vane.local/ca',
    sub: AGENT_ID,
    aud: [PASSPORT_AUDIENCE],
    jti: randomUUID(),
    iat: times.iat,
    exp: times.exp,
    nbf: times.nbf,
    vane: { v: 1, agentId: 'agent-1', org: 'acme', orgSpiffeId: ORG_ID, scopes: ['tool:*'], delegationChain: [ORG_ID, AGENT_ID] },
  }));
  const si = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(si), createPrivateKey(kp.privateKey)).toString('base64url');
  return `${si}.${sig}`;
}

/** Signs a JWT-SVID with explicit time claims. */
function craftSvid(
  kp: { publicKey: string; privateKey: string },
  times: { iat: number; exp: number; nbf: number },
): string {
  const b64url = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: deriveKeyId(kp.publicKey) }));
  const payload = b64url(JSON.stringify({
    sub: companySpiffeId('acme'),
    aud: ['vane'],
    iat: times.iat,
    exp: times.exp,
    nbf: times.nbf,
    jti: randomUUID(),
  }));
  const si = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(si), createPrivateKey(kp.privateKey)).toString('base64url');
  return `${si}.${sig}`;
}

// ── The default ──────────────────────────────────────────────────────────────

describe('Clock-skew leeway default', () => {
  it('is 30 seconds', () => {
    expect(DEFAULT_CLOCK_SKEW_SECONDS).toBe(30);
  });
});

// ── Passport: the core scenarios from the task ───────────────────────────────

describe('Passport clock-skew leeway', () => {
  it('verifies a freshly issued passport when the verifier clock is 30s behind', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    const { nbf } = decodeClaims(token);

    // Verifier 30s behind the issuer: its "now" sits 30s before nbf.
    const result = verifyPassport(token, { caPublicKey: kp.publicKey, now: nbf - 30 });
    expect(result.valid).toBe(true);
  });

  it('rejects with a 31s skew when leeway is 30 (just outside the window)', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    const { nbf } = decodeClaims(token);

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, now: nbf - 31 });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('TOKEN_NOT_YET_VALID');
  });

  it('rejects a passport whose nbf is 60s in the future with NOT_YET_VALID', () => {
    const kp = generateKeyPair();
    const base = Math.floor(Date.now() / 1000);
    const token = craftPassport(kp, { iat: base + 60, exp: base + 3660, nbf: base + 60 });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, now: base });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('TOKEN_NOT_YET_VALID');
  });

  it('accepts a passport whose nbf is in the future but within the leeway window', () => {
    const kp = generateKeyPair();
    const base = Math.floor(Date.now() / 1000);
    // nbf 20s ahead — inside the 30s leeway.
    const token = craftPassport(kp, { iat: base + 20, exp: base + 3620, nbf: base + 20 });

    const result = verifyPassport(token, { caPublicKey: kp.publicKey, now: base });
    expect(result.valid).toBe(true);
  });

  it('throws when clockSkewSeconds is negative', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    expect(() => verifyPassport(token, { caPublicKey: kp.publicKey, clockSkewSeconds: -1 }))
      .toThrow(/must not be negative/);
  });

  it('a custom leeway widens the not-yet-valid window', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    const { nbf } = decodeClaims(token);

    // 45s behind would fail at the default 30s, but passes with a 60s leeway.
    const tight = verifyPassport(token, { caPublicKey: kp.publicKey, now: nbf - 45 });
    expect(tight.valid).toBe(false);
    const wide = verifyPassport(token, { caPublicKey: kp.publicKey, now: nbf - 45, clockSkewSeconds: 60 });
    expect(wide.valid).toBe(true);
  });
});

// ── mcp-middleware passport verifier mirrors the server ──────────────────────

describe('mcp-middleware passport clock-skew leeway', () => {
  it('verifies under a 30s skew and rejects at 31s', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    const { nbf } = decodeClaims(token);

    expect(mwVerifyPassport(token, kp.publicKey, { now: nbf - 30 }).valid).toBe(true);
    const late = mwVerifyPassport(token, kp.publicKey, { now: nbf - 31 });
    expect(late.valid).toBe(false);
    if (!late.valid) expect(late.code).toBe('TOKEN_NOT_YET_VALID');
  });

  it('throws when clockSkewSeconds is negative', () => {
    const kp = generateKeyPair();
    const token = makePassport(kp);
    expect(() => mwVerifyPassport(token, kp.publicKey, { clockSkewSeconds: -1 }))
      .toThrow(/must not be negative/);
  });
});

// ── JWT-SVID: now issues nbf and validates it with leeway ────────────────────

describe('JWT-SVID clock-skew leeway and nbf', () => {
  it('issueJwtSvid now embeds nbf equal to iat', () => {
    const kp = generateKeyPair();
    const token = issueJwtSvid(companySpiffeId('acme'), kp.privateKey, kp.publicKey);
    const { iat, nbf } = decodeClaims(token);
    expect(nbf).toBe(iat);
  });

  it('accepts an SVID whose nbf is within the leeway window', () => {
    const kp = generateKeyPair();
    const base = Math.floor(Date.now() / 1000);
    const token = craftSvid(kp, { iat: base + 20, exp: base + 3620, nbf: base + 20 });
    const claims = verifyJwtSvid(token, kp.publicKey);
    expect(claims.sub).toBe(companySpiffeId('acme'));
  });

  it('rejects an SVID whose nbf is 60s in the future', () => {
    const kp = generateKeyPair();
    const base = Math.floor(Date.now() / 1000);
    const token = craftSvid(kp, { iat: base + 60, exp: base + 3660, nbf: base + 60 });
    expect(() => verifyJwtSvid(token, kp.publicKey)).toThrow(/not yet valid/i);
  });

  it('throws when clockSkewSeconds is negative', () => {
    const kp = generateKeyPair();
    const token = issueJwtSvid(companySpiffeId('acme'), kp.privateKey, kp.publicKey);
    expect(() => verifyJwtSvid(token, kp.publicKey, 'vane', -1)).toThrow(/must not be negative/);
  });
});

// ── Cross-org token leeway and nbf ───────────────────────────────────────────

describe('Cross-org token clock-skew leeway and nbf', () => {
  it('verifies under a 30s skew and rejects at 31s with NOT_YET_VALID', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    const { nbf } = decodeClaims(token);

    expect(verifyCrossOrgToken(token, kp.publicKey, { now: nbf - 30 }).valid).toBe(true);
    const late = verifyCrossOrgToken(token, kp.publicKey, { now: nbf - 31 });
    expect(late.valid).toBe(false);
    if (!late.valid) expect(late.code).toBe('TOKEN_NOT_YET_VALID');
  });

  it('throws when clockSkewSeconds is negative', () => {
    const kp = generateKeyPair();
    const token = makeXorgToken(kp);
    expect(() => verifyCrossOrgToken(token, kp.publicKey, { clockSkewSeconds: -1 }))
      .toThrow(/must not be negative/);
  });
});

// ── Sidecar verifyPassportLocal leeway and nbf ───────────────────────────────

describe('Sidecar verifyPassportLocal clock-skew leeway and nbf', () => {
  function clientWithKey(pub: string): VaneClient {
    const client = new VaneClient({
      apiUrl: 'http://localhost:3000',
      apiKey: 'vane_test',
      agentId: 'agent-1',
      companyId: 'acme',
    });
    // Inject the cached CA public key the sidecar would normally fetch.
    (client as unknown as { caPublicKey: string }).caPublicKey = pub;
    return client;
  }

  it('accepts a valid passport and one with nbf within the leeway window', () => {
    const kp = generateKeyPair();
    const client = clientWithKey(kp.publicKey);
    expect(client.verifyPassportLocal(makePassport(kp))).toBe(true);

    const base = Math.floor(Date.now() / 1000);
    const within = craftPassport(kp, { iat: base + 20, exp: base + 3620, nbf: base + 20 });
    expect(client.verifyPassportLocal(within)).toBe(true);
  });

  it('rejects a passport whose nbf is 60s in the future', () => {
    const kp = generateKeyPair();
    const client = clientWithKey(kp.publicKey);
    const base = Math.floor(Date.now() / 1000);
    const future = craftPassport(kp, { iat: base + 60, exp: base + 3660, nbf: base + 60 });
    expect(client.verifyPassportLocal(future)).toBe(false);
  });

  it('throws when clockSkewSeconds is negative', () => {
    const kp = generateKeyPair();
    const client = clientWithKey(kp.publicKey);
    expect(() => client.verifyPassportLocal(makePassport(kp), -1)).toThrow(/must not be negative/);
  });
});
