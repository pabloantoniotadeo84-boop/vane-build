#!/usr/bin/env -S npx tsx
// =============================================================================
// Conformance vector generator for the Vane Agent Passport protocol.
//
//     npx tsx conformance/generate-vectors.ts
//
// Produces conformance/vectors.json: a self-contained, deterministic-shape set
// of test vectors. Every time claim is pinned to a fixed reference epoch and
// every vector carries an explicit `now`, so the suite verifies identically
// regardless of wall-clock — the vectors never "expire".
//
// The committed vectors.json is the artifact of record. Re-running this script
// regenerates semantically identical vectors with fresh keys/signatures; the
// pass/fail expectations are unchanged. Tokens are crafted directly with
// node:crypto (not via src/) so this generator stays independent of the code
// under test.
// =============================================================================

import {
  sign as cryptoSign,
  createPrivateKey,
  createPublicKey,
  createHash,
  generateKeyPairSync,
  randomUUID,
} from 'node:crypto';
import { writeFileSync } from 'node:fs';

// ── Fixtures ─────────────────────────────────────────────────────────────────

interface KeyPair { publicKey: string; privateKey: string }

function genKeyPair(): KeyPair {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/** kid = first 16 hex of SHA-256(SPKI DER), matching deriveKeyId in src. */
function deriveKid(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' }) as Buffer;
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

const b64url = (s: string): string => Buffer.from(s, 'utf8').toString('base64url');

/** Sign a JWT from explicit header + payload objects. Full control over every field. */
function signJwt(kp: KeyPair, headerObj: unknown, payloadObj: unknown): string {
  const header = b64url(JSON.stringify(headerObj));
  const payload = b64url(JSON.stringify(payloadObj));
  const signingInput = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(signingInput), createPrivateKey(kp.privateKey)).toString('base64url');
  return `${signingInput}.${sig}`;
}

// The Vane CA key all valid vectors are signed with. `wrongKp` is an unrelated
// key used only to forge an invalid signature.
const ca = genKeyPair();
const wrongKp = genKeyPair();
const CA_PUBLIC_KEY = ca.publicKey;

const TRUST_DOMAIN = 'vane.local';
const CA_ISS = `spiffe://${TRUST_DOMAIN}/ca`;
const ORG_ACME = `spiffe://${TRUST_DOMAIN}/company/acme`;
const ORG_GLOBEX = `spiffe://${TRUST_DOMAIN}/company/globex`;
const AGENT_ACME = `spiffe://${TRUST_DOMAIN}/company/acme/agent/agent-7`;

// Fixed reference epoch (2025-06-15T...Z). All time claims hang off this.
const BASE = 1750000000;
// Default verification time: 60s after issuance, comfortably inside the window.
const NOW = BASE + 60;

const NONCE = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';     // 128-bit hex
const OTHER_NONCE = 'ffffffffffffffffffffffffffffffff';
const REQUEST_HASH = 'a'.repeat(64);                    // 256-bit hex

const STD_HEADER = { alg: 'EdDSA', typ: 'CAP+JWT', kid: deriveKid(CA_PUBLIC_KEY) };

interface Vane {
  v: number;
  agentId: string;
  org: string;
  orgSpiffeId: string;
  scopes: string[];
  delegationChain: string[];
  nonce?: string;
  aud?: string;
  requestHash?: string;
  delegationId?: string;
}

interface Claims {
  iss: string;
  sub: string;
  aud: string[];
  jti: string;
  iat: number;
  exp: number;
  nbf: number;
  vane: Vane;
}

/** A baseline valid claims set; pass overrides to mutate any field. */
function baseClaims(over: Partial<Claims> = {}, vaneOver: Partial<Vane> = {}): Claims {
  return {
    iss: CA_ISS,
    sub: AGENT_ACME,
    aud: ['vane:passport:v1'],
    jti: randomUUID(),
    iat: BASE,
    exp: BASE + 3600,
    nbf: BASE,
    vane: {
      v: 1,
      agentId: 'agent-7',
      org: 'acme',
      orgSpiffeId: ORG_ACME,
      scopes: ['tool:search', 'data:read'],
      delegationChain: [ORG_ACME, AGENT_ACME],
      ...vaneOver,
    },
    ...over,
  };
}

// ── Vector model ─────────────────────────────────────────────────────────────

interface VectorInputs {
  caPublicKey: string;
  now?: number;
  tool?: string;
  expectedNonce?: string;
  expectedAudience?: string;
  expectedRequestHash?: string;
  clockSkewSeconds?: number;
  revokedJtis?: string[];
}

interface Vector {
  name: string;
  description: string;
  token: string;
  inputs: VectorInputs;
  expected:
    | { valid: true; scopeGranted: string }
    | { valid: false; code: string };
}

const vectors: Vector[] = [];

function add(v: Vector): void { vectors.push(v); }

// 1 — Valid passport, no tool requested → broadest scope returned.
add({
  name: 'valid-passport',
  description: 'A well-formed, in-window passport that must verify.',
  token: signJwt(ca, STD_HEADER, baseClaims()),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: true, scopeGranted: 'tool:search' },
});

// 2 — Valid passport with a tool whose scope is explicitly granted.
add({
  name: 'valid-with-tool',
  description: 'Passport granting tool:search, verified with tool="search".',
  token: signJwt(ca, STD_HEADER, baseClaims()),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, tool: 'search' },
  expected: { valid: true, scopeGranted: 'tool:search' },
});

// 3 — Wildcard scope covers any tool in the category.
add({
  name: 'valid-wildcard-scope',
  description: 'Passport with scope "tool:*" must cover tool="delete".',
  token: signJwt(ca, STD_HEADER, baseClaims({}, { scopes: ['tool:*'] })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, tool: 'delete' },
  expected: { valid: true, scopeGranted: 'tool:*' },
});

// 4 — Expired passport.
add({
  name: 'expired-passport',
  description: 'exp is in the past beyond the clock-skew leeway → TOKEN_EXPIRED.',
  token: signJwt(ca, STD_HEADER, baseClaims({ iat: BASE - 7200, exp: BASE - 3600, nbf: BASE - 7200 })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'TOKEN_EXPIRED' },
});

// 5 — Not-yet-valid passport (nbf in the future, beyond leeway).
add({
  name: 'nbf-in-future',
  description: 'nbf is 600s ahead of now (beyond the 30s leeway) → TOKEN_NOT_YET_VALID.',
  token: signJwt(ca, STD_HEADER, baseClaims({ iat: BASE, exp: BASE + 3600, nbf: BASE + 600 })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: BASE },
  expected: { valid: false, code: 'TOKEN_NOT_YET_VALID' },
});

// 6 — Bad signature: signed by an unrelated key, verified against the CA key.
add({
  name: 'bad-signature',
  description: 'Token signed with a non-CA key → SIGNATURE_INVALID.',
  token: signJwt(wrongKp, { ...STD_HEADER, kid: deriveKid(wrongKp.publicKey) }, baseClaims()),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'SIGNATURE_INVALID' },
});

// 7 — Tampered payload: a valid token whose payload was mutated after signing.
add((() => {
  const token = signJwt(ca, STD_HEADER, baseClaims());
  const [h, p, s] = token.split('.');
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  claims.vane.agentId = 'agent-EVIL';          // mutate a field, keep the original sig
  claims.vane.scopes = ['*'];                   // privilege escalation attempt
  const tampered = `${h}.${Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url')}.${s}`;
  return {
    name: 'tampered-payload',
    description: 'A valid token whose payload was edited after signing → SIGNATURE_INVALID.',
    token: tampered,
    inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
    expected: { valid: false, code: 'SIGNATURE_INVALID' },
  } as Vector;
})());

// 8 — Wrong recipient audience (vane.aud != expectedAudience).
add({
  name: 'wrong-audience',
  description: 'Passport recipient audience does not match expectedAudience → AUDIENCE_MISMATCH.',
  token: signJwt(ca, STD_HEADER, baseClaims({}, { aud: 'https://evil.example.com' })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, expectedAudience: 'https://api.example.com' },
  expected: { valid: false, code: 'AUDIENCE_MISMATCH' },
});

// 9 — Wrong protocol audience (top-level aud lacks vane:passport:v1).
add({
  name: 'wrong-protocol-audience',
  description: 'Top-level aud does not contain "vane:passport:v1" → AUDIENCE_MISMATCH.',
  token: signJwt(ca, STD_HEADER, baseClaims({ aud: ['urn:some:other:audience'] })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'AUDIENCE_MISMATCH' },
});

// 10 & 11 — One nonce-bound token, verified two ways.
const nonceToken = signJwt(ca, STD_HEADER, baseClaims({}, { nonce: NONCE }));
add({
  name: 'nonce-correct',
  description: 'Nonce-bound passport verified with the matching expectedNonce → valid.',
  token: nonceToken,
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, expectedNonce: NONCE },
  expected: { valid: true, scopeGranted: 'tool:search' },
});
add({
  name: 'nonce-mismatch',
  description: 'Same nonce-bound passport verified with a different expectedNonce → NONCE_MISMATCH.',
  token: nonceToken,
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, expectedNonce: OTHER_NONCE },
  expected: { valid: false, code: 'NONCE_MISMATCH' },
});

// 12 — expectedNonce demanded but the passport carries none.
add({
  name: 'missing-nonce',
  description: 'Verifier demands a nonce but the passport has none → MISSING_NONCE.',
  token: signJwt(ca, STD_HEADER, baseClaims()),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, expectedNonce: NONCE },
  expected: { valid: false, code: 'MISSING_NONCE' },
});

// 13 — Incoherent delegation chain: tail != sub.
add({
  name: 'invalid-delegation-chain',
  description: 'delegationChain tail does not equal sub → CHAIN_INCOHERENT.',
  token: signJwt(ca, STD_HEADER, baseClaims({}, {
    delegationChain: [ORG_ACME, `spiffe://${TRUST_DOMAIN}/company/acme/agent/someone-else`],
  })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'CHAIN_INCOHERENT' },
});

// 14 — Cross-org delegation expressed as a CAP+JWT passport.
//   globex → acme → acme's agent. The chain origin is a different org than the
//   subject's org, yet the passport is coherent (tail == sub) and must verify.
add({
  name: 'cross-org-valid',
  description: 'Cross-org delegation chain [globex, acme, acme-agent] with tail == sub → valid.',
  token: signJwt(ca, STD_HEADER, baseClaims({}, {
    org: 'acme',
    orgSpiffeId: ORG_ACME,
    delegationChain: [ORG_GLOBEX, ORG_ACME, AGENT_ACME],
    scopes: ['tool:search'],
  })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: true, scopeGranted: 'tool:search' },
});

// 15 — Revoked passport.
const revokedClaims = baseClaims();
add({
  name: 'revoked-passport',
  description: 'An otherwise-valid passport whose jti is in the revoked set → PASSPORT_REVOKED.',
  token: signJwt(ca, STD_HEADER, revokedClaims),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, revokedJtis: [revokedClaims.jti] },
  expected: { valid: false, code: 'PASSPORT_REVOKED' },
});

// 16 — Unsupported schema version.
add({
  name: 'unsupported-version',
  description: 'vane.v is 2, which this protocol version does not understand → UNSUPPORTED_VERSION.',
  token: signJwt(ca, STD_HEADER, baseClaims({}, { v: 2 })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'UNSUPPORTED_VERSION' },
});

// 17 — alg:none downgrade attempt.
add({
  name: 'alg-none',
  description: 'Header alg is "none" (signature stripped) → ALGORITHM_MISMATCH.',
  token: (() => {
    const h = b64url(JSON.stringify({ alg: 'none', typ: 'CAP+JWT' }));
    const p = b64url(JSON.stringify(baseClaims()));
    return `${h}.${p}.`; // empty signature segment
  })(),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'ALGORITHM_MISMATCH' },
});

// 18 — Wrong token type (an SVID "JWT" presented as a passport).
add({
  name: 'wrong-token-type',
  description: 'Header typ is "JWT" (an SVID), not "CAP+JWT" → WRONG_TOKEN_TYPE.',
  token: signJwt(ca, { alg: 'EdDSA', typ: 'JWT', kid: STD_HEADER.kid }, baseClaims()),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'WRONG_TOKEN_TYPE' },
});

// 19 — Structurally malformed token.
add({
  name: 'malformed-token',
  description: 'Token is not three dot-separated segments → MALFORMED_TOKEN.',
  token: 'this-is-not-a-jwt',
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'MALFORMED_TOKEN' },
});

// 20 — Scope denied for the requested tool.
add({
  name: 'scope-denied',
  description: 'Passport grants only data:read but tool="search" is requested → SCOPE_DENIED.',
  token: signJwt(ca, STD_HEADER, baseClaims({}, { scopes: ['data:read'] })),
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, tool: 'search' },
  expected: { valid: false, code: 'SCOPE_DENIED' },
});

// 21 & 22 — One request-bound token, verified two ways.
const reqBoundToken = signJwt(ca, STD_HEADER, baseClaims({}, { requestHash: REQUEST_HASH }));
add({
  name: 'request-bound-match',
  description: 'Request-bound passport verified with the matching expectedRequestHash → valid.',
  token: reqBoundToken,
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW, expectedRequestHash: REQUEST_HASH },
  expected: { valid: true, scopeGranted: 'tool:search' },
});
add({
  name: 'request-bound-unbound-verifier',
  description: 'Same request-bound passport but the verifier supplies no request hash → REQUEST_MISMATCH (fail closed).',
  token: reqBoundToken,
  inputs: { caPublicKey: CA_PUBLIC_KEY, now: NOW },
  expected: { valid: false, code: 'REQUEST_MISMATCH' },
});

// ── Emit ─────────────────────────────────────────────────────────────────────

const out = {
  description:
    'Conformance test vectors for the Vane Agent Passport (CAP+JWT) verification protocol. ' +
    'Each vector pins all time claims to a fixed epoch and supplies an explicit `now`, so ' +
    'results are stable forever. See conformance/README.md for the full specification.',
  protocol: {
    tokenType: 'CAP+JWT',
    algorithm: 'EdDSA (Ed25519, PureEdDSA)',
    protocolAudience: 'vane:passport:v1',
    supportedVersions: [1],
    defaultClockSkewSeconds: 30,
    referenceEpoch: BASE,
  },
  vectorCount: vectors.length,
  vectors,
};

const target = new URL('./vectors.json', import.meta.url);
writeFileSync(target, JSON.stringify(out, null, 2) + '\n');
console.log(`Wrote ${vectors.length} vectors to ${target.pathname}`);
