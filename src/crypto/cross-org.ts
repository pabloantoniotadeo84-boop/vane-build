import {
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
  randomUUID,
} from 'node:crypto';
import { validateSpiffeId, TRUST_DOMAIN } from './spiffe.js';
import { deriveKeyId } from './svid.js';
import type { CrossOrgDelegationClaims } from './types.js';

export const CROSS_ORG_TOKEN_TYPE = 'XORG+JWT';
export const CROSS_ORG_AUDIENCE   = 'vane:xorg:v1';
// Hard cap enforced at both issuance and verification. Cross-org tokens travel
// outside the originating organization's trust boundary, so a shorter blast
// radius limits damage from interception or credential leak.
export const CROSS_ORG_MAX_TTL = 900; // 15 minutes

function b64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

export interface IssueCrossOrgTokenOptions {
  agentId: string;
  agentSpiffeId: string;
  originOrg: string;
  originOrgSpiffeId: string;
  targetOrg: string;
  targetOrgSpiffeId: string;
  scopes: string[];
  delegationChain: string[];  // [originOrgSpiffeId, ..., agentSpiffeId]
  ttl?: number;               // seconds, defaults to and capped at CROSS_ORG_MAX_TTL
  privateKeyPem: string;
  publicKeyPem: string;
}

/**
 * Issues a cross-org delegation token (XORG+JWT).
 *
 * Signed with the originating company's private key. The receiving MCP server
 * verifies it offline using the originating company's CA public key (fetched
 * once from GET /v1/ca/public-key?companyId=<originOrg>).
 *
 * Security invariants:
 *   - typ "XORG+JWT" prevents replay as a regular passport (CAP+JWT)
 *   - aud "vane:xorg:v1" is distinct from all other Vane token audiences
 *   - TTL is capped at CROSS_ORG_MAX_TTL (900 s / 15 min)
 *   - delegationChain tail must equal agentSpiffeId before signing
 */
export function issueCrossOrgToken(opts: IssueCrossOrgTokenOptions): string {
  if (!validateSpiffeId(opts.agentSpiffeId)) {
    throw new Error(`Invalid agent SPIFFE ID: ${opts.agentSpiffeId}`);
  }
  if (!validateSpiffeId(opts.originOrgSpiffeId)) {
    throw new Error(`Invalid origin org SPIFFE ID: ${opts.originOrgSpiffeId}`);
  }
  if (!validateSpiffeId(opts.targetOrgSpiffeId)) {
    throw new Error(`Invalid target org SPIFFE ID: ${opts.targetOrgSpiffeId}`);
  }
  if (opts.scopes.length === 0) {
    throw new Error('Cross-org token must include at least one scope');
  }
  if (opts.delegationChain.length === 0) {
    throw new Error('Cross-org token must include a delegation chain');
  }
  const chainTail = opts.delegationChain[opts.delegationChain.length - 1];
  if (chainTail !== opts.agentSpiffeId) {
    throw new Error(
      `delegationChain tail (${chainTail}) must equal agentSpiffeId (${opts.agentSpiffeId})`,
    );
  }

  const ttl = opts.ttl ?? CROSS_ORG_MAX_TTL;
  if (ttl > CROSS_ORG_MAX_TTL) {
    throw new Error(
      `Cross-org token TTL ${ttl}s exceeds maximum ${CROSS_ORG_MAX_TTL}s (15 minutes)`,
    );
  }
  if (ttl <= 0) {
    throw new Error('Cross-org token TTL must be positive');
  }

  const now = Math.floor(Date.now() / 1000);
  const kid = deriveKeyId(opts.publicKeyPem);

  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: CROSS_ORG_TOKEN_TYPE, kid }));

  const claims: CrossOrgDelegationClaims = {
    iss: `spiffe://${TRUST_DOMAIN}/ca`,
    sub: opts.agentSpiffeId,
    aud: [CROSS_ORG_AUDIENCE],
    jti: randomUUID(),
    iat: now,
    exp: now + ttl,
    nbf: now,
    vane_xorg: {
      v: 1,
      agentId: opts.agentId,
      originOrg: opts.originOrg,
      originOrgSpiffeId: opts.originOrgSpiffeId,
      targetOrg: opts.targetOrg,
      targetOrgSpiffeId: opts.targetOrgSpiffeId,
      scopes: opts.scopes,
      delegationChain: opts.delegationChain,
    },
  };

  const payload = b64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(signingInput), createPrivateKey(opts.privateKeyPem))
    .toString('base64url');

  return `${signingInput}.${sig}`;
}

export type CrossOrgErrorCode =
  | 'MALFORMED_TOKEN'
  | 'ALGORITHM_MISMATCH'
  | 'WRONG_TOKEN_TYPE'
  | 'SIGNATURE_INVALID'
  | 'TOKEN_EXPIRED'
  | 'AUDIENCE_MISMATCH'
  | 'INVALID_ISSUER'
  | 'INVALID_SUBJECT'
  | 'UNSUPPORTED_VERSION'
  | 'MALFORMED_CLAIMS'
  | 'CHAIN_INCOHERENT'
  | 'TARGET_MISMATCH'
  | 'SCOPE_DENIED';

export type CrossOrgVerificationResult =
  | { valid: true; claims: CrossOrgDelegationClaims; scopeGranted: string }
  | { valid: false; error: string; code: CrossOrgErrorCode };

function fail(code: CrossOrgErrorCode, error: string): CrossOrgVerificationResult {
  return { valid: false, error, code };
}

export interface CrossOrgVerifyOptions {
  expectedTargetOrg?: string;  // if provided, vane_xorg.targetOrg must match
  tool?: string;               // if provided, scopes must cover "tool:<tool>"
  now?: number;                // override current time for testing
}

const SPIFFE_RE = /^spiffe:\/\/[^/]+\/.+$/;

/**
 * Verifies a cross-org delegation token (XORG+JWT) offline.
 *
 * Requires only the originating org's CA public key, which callers fetch
 * once from GET /v1/ca/public-key?companyId=<originOrg> and cache.
 *
 * Verification steps:
 *   1.  Parse — split by ".", decode header and payload
 *   2.  Algorithm — header.alg must be "EdDSA"
 *   3.  Token type — header.typ must be "XORG+JWT"
 *   4.  Signature — Ed25519 over "header.payload" using originOrgPublicKey
 *   5.  Expiry — exp must be in the future
 *   6.  Audience — aud must include "vane:xorg:v1"
 *   7.  Issuer — iss must be a valid SPIFFE URI
 *   8.  Subject — sub must be a valid SPIFFE URI
 *   9.  Claims — "vane_xorg" object must be present with v=1
 *   10. Chain coherence — delegationChain tail must equal sub
 *   11. Target match — if expectedTargetOrg provided, vane_xorg.targetOrg must match
 *   12. Scope — if tool provided, scopes must cover "tool:<tool>"
 */
export function verifyCrossOrgToken(
  token: string,
  originOrgPublicKey: string,
  opts: CrossOrgVerifyOptions = {},
): CrossOrgVerificationResult {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return fail('MALFORMED_TOKEN', 'Expected header.payload.signature');
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let rawClaims: Record<string, unknown>;
  try {
    header    = JSON.parse(fromB64url(headerB64).toString('utf8'));
    rawClaims = JSON.parse(fromB64url(payloadB64).toString('utf8'));
  } catch {
    return fail('MALFORMED_TOKEN', 'Could not decode header or payload');
  }

  // Algorithm check — first guard, explicit rejection for every bypass vector.
  const alg = header['alg'];
  if (alg === undefined || alg === null) {
    return fail('ALGORITHM_MISMATCH', 'JWT alg header is missing');
  }
  if (alg === 'none') {
    return fail('ALGORITHM_MISMATCH', 'JWT alg:none is not allowed');
  }
  if (alg !== 'EdDSA') {
    return fail('ALGORITHM_MISMATCH', `Expected EdDSA, got ${String(alg)}`);
  }

  if (header['typ'] !== CROSS_ORG_TOKEN_TYPE) {
    return fail('WRONG_TOKEN_TYPE', `Expected ${CROSS_ORG_TOKEN_TYPE}, got ${String(header['typ'])}`);
  }

  let sigValid: boolean;
  try {
    const keyObj = createPublicKey(originOrgPublicKey);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      return fail('SIGNATURE_INVALID', `Origin org public key must be Ed25519, got ${keyObj.asymmetricKeyType}`);
    }
    sigValid = cryptoVerify(
      null,
      Buffer.from(`${headerB64}.${payloadB64}`),
      keyObj,
      fromB64url(sigB64),
    );
  } catch {
    return fail('SIGNATURE_INVALID', 'Origin org public key is malformed or incompatible');
  }
  if (!sigValid) {
    return fail('SIGNATURE_INVALID', 'Origin org signature verification failed');
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);

  const exp = rawClaims['exp'];
  if (typeof exp !== 'number' || exp < now) {
    return fail('TOKEN_EXPIRED', 'Cross-org token has expired');
  }

  const aud = rawClaims['aud'];
  if (!Array.isArray(aud) || !aud.includes(CROSS_ORG_AUDIENCE)) {
    return fail('AUDIENCE_MISMATCH', `Token audience must include "${CROSS_ORG_AUDIENCE}"`);
  }

  const iss = rawClaims['iss'];
  if (typeof iss !== 'string' || !SPIFFE_RE.test(iss)) {
    return fail('INVALID_ISSUER', `iss is not a valid SPIFFE ID: ${String(iss)}`);
  }

  const sub = rawClaims['sub'];
  if (typeof sub !== 'string' || !SPIFFE_RE.test(sub)) {
    return fail('INVALID_SUBJECT', `sub is not a valid SPIFFE ID: ${String(sub)}`);
  }

  const xorg = rawClaims['vane_xorg'];
  if (xorg === null || typeof xorg !== 'object' || Array.isArray(xorg)) {
    return fail('MALFORMED_CLAIMS', 'Missing or malformed "vane_xorg" claim object');
  }
  const c = xorg as Record<string, unknown>;

  if (c['v'] !== 1) {
    return fail('UNSUPPORTED_VERSION', `Unsupported cross-org token version: ${String(c['v'])}`);
  }
  if (!Array.isArray(c['scopes']) || (c['scopes'] as unknown[]).length === 0) {
    return fail('MALFORMED_CLAIMS', '"vane_xorg.scopes" must be a non-empty array');
  }
  const scopes = c['scopes'] as string[];

  if (!Array.isArray(c['delegationChain']) || (c['delegationChain'] as unknown[]).length === 0) {
    return fail('MALFORMED_CLAIMS', '"vane_xorg.delegationChain" must be a non-empty array');
  }
  const chain = c['delegationChain'] as string[];

  const chainTail = chain[chain.length - 1];
  if (chainTail !== sub) {
    return fail(
      'CHAIN_INCOHERENT',
      `delegationChain tail "${chainTail}" does not match sub "${sub}"`,
    );
  }

  if (opts.expectedTargetOrg !== undefined) {
    const targetOrg = c['targetOrg'];
    if (targetOrg !== opts.expectedTargetOrg) {
      return fail(
        'TARGET_MISMATCH',
        `Token targets org "${String(targetOrg)}", expected "${opts.expectedTargetOrg}"`,
      );
    }
  }

  let scopeGranted: string;
  if (opts.tool !== undefined) {
    const requested = `tool:${opts.tool}`;
    const match = matchScope(scopes, requested);
    if (match === null) {
      return fail('SCOPE_DENIED', `Scopes [${scopes.join(', ')}] do not cover "${requested}"`);
    }
    scopeGranted = match;
  } else {
    scopeGranted = scopes[0];
  }

  return { valid: true, claims: rawClaims as unknown as CrossOrgDelegationClaims, scopeGranted };
}

function matchScope(granted: string[], requested: string): string | null {
  for (const g of granted) {
    if (g === '*') return g;
    if (g === requested) return g;
    if (g.endsWith(':*') && requested.startsWith(g.slice(0, -1))) return g;
  }
  return null;
}
