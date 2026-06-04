// Offline Vane token verification.
//
// This file has zero external dependencies. It uses only node:crypto, which
// ships with every Node.js >= 12 installation. Copy this file to implement
// passport verification in any language or runtime — the algorithm is fully
// specified in the comments below.
//
// Regular passport (CAP+JWT) — 13 steps:
//
//   1.  PARSE        — split token by ".", decode base64url header + payload JSON
//   2.  ALGORITHM    — header.alg must be "EdDSA"
//   3.  TOKEN TYPE   — header.typ must be "CAP+JWT"
//   4.  SIGNATURE    — Ed25519 signature over "header.payload" (ASCII, not decoded)
//   5.  EXPIRY       — exp must be > now (Unix seconds)
//   6.  NOT-BEFORE   — nbf must be <= now if present
//   7.  AUDIENCE     — aud must contain "vane:passport:v1"
//   8.  ISSUER       — iss must match SPIFFE URI pattern
//   9.  SUBJECT      — sub must match SPIFFE URI pattern
//   10. CLAIMS       — "vane" object must be present
//   11. VERSION      — vane.v must be 1 (only supported version)
//   12. CHAIN        — delegationChain.at(-1) must equal sub
//   13. SCOPE        — if tool provided, scopes must cover "tool:<tool>"
//
// Cross-org delegation token (XORG+JWT) — 12 steps:
//   Same as above except:
//   - step 3: header.typ must be "XORG+JWT"
//   - step 7: aud must contain "vane:xorg:v1"
//   - step 10: "vane_xorg" object instead of "vane"
//   - step 11: targetOrg must match expectedTargetOrg if provided
//   - no NOT-BEFORE check (step 6 is skipped for cross-org tokens)
//
// Scope matching rules:
//   "*"      — covers any scope
//   "cat:*"  — covers any scope starting with "cat:"
//   "cat:x"  — covers exactly "cat:x"

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import type {
  VanePassportClaims,
  CrossOrgDelegationClaims,
  PassportErrorCode,
  PassportVerificationResult,
  VerifyOptions,
} from './types.js';

const PASSPORT_AUDIENCE   = 'vane:passport:v1';
const CROSS_ORG_AUDIENCE  = 'vane:xorg:v1';
export const CROSS_ORG_TOKEN_TYPE = 'XORG+JWT';
const SUPPORTED_VERSIONS  = new Set([1]);
const SPIFFE_RE           = /^spiffe:\/\/[^/]+\/.+$/;

function fromB64url(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function fail(code: PassportErrorCode, error: string): PassportVerificationResult {
  return { valid: false, error, code };
}

/**
 * Verifies a Vane Agent Passport.
 *
 * @param token     — the raw CAP+JWT string from the Authorization Bearer header
 * @param caPublicKey — Ed25519 SPKI PEM of the Vane CA root key
 * @param opts      — optional tool name for scope checking
 */
export function verifyPassport(
  token: string,
  caPublicKey: string,
  opts: VerifyOptions = {},
): PassportVerificationResult {
  // Fail-closed wrapper: any error, ambiguity, or unexpected state during
  // verification resolves to a DENY. An exception thrown in any step below
  // becomes a structured failure result here — it must never escape this
  // function and never fall through to a caller as an absent/undefined value.
  try {
    return verifyPassportImpl(token, caPublicKey, opts);
  } catch (err) {
    return fail('VERIFICATION_ERROR', `Unexpected verification error: ${(err as Error).message}`);
  }
}

function verifyPassportImpl(
  token: string,
  caPublicKey: string,
  opts: VerifyOptions = {},
): PassportVerificationResult {
  // Step 1 — parse
  const parts = token.split('.');
  if (parts.length !== 3) {
    return fail('MALFORMED_TOKEN', 'Expected header.payload.signature');
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let rawClaims: Record<string, unknown>;
  try {
    header = JSON.parse(fromB64url(headerB64).toString('utf8'));
    rawClaims = JSON.parse(fromB64url(payloadB64).toString('utf8'));
  } catch {
    return fail('MALFORMED_TOKEN', 'Could not decode header or payload');
  }

  // Step 2 — algorithm (first guard, explicit rejection for every bypass vector)
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

  // Step 3 — token type (CAP+JWT distinguishes passports from SVID tokens)
  if (header['typ'] !== 'CAP+JWT') {
    return fail('WRONG_TOKEN_TYPE', `Expected CAP+JWT, got ${String(header['typ'])}`);
  }

  // Step 4 — signature (key-type guard before cryptoVerify)
  let sigValid: boolean;
  try {
    const keyObj = createPublicKey(caPublicKey);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      return fail('SIGNATURE_INVALID', `CA public key must be Ed25519, got ${keyObj.asymmetricKeyType}`);
    }
    sigValid = cryptoVerify(
      null,
      Buffer.from(`${headerB64}.${payloadB64}`),
      keyObj,
      fromB64url(sigB64),
    );
  } catch {
    return fail('SIGNATURE_INVALID', 'CA public key is malformed or incompatible');
  }
  if (!sigValid) {
    return fail('SIGNATURE_INVALID', 'CA signature verification failed');
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);

  // Step 5 — expiry
  const exp = rawClaims['exp'];
  if (typeof exp !== 'number' || exp < now) {
    return fail('TOKEN_EXPIRED', 'Passport has expired');
  }

  // Step 6 — not-before
  const nbf = rawClaims['nbf'];
  if (typeof nbf === 'number' && nbf > now) {
    return fail('TOKEN_NOT_YET_VALID', 'Passport is not yet valid');
  }

  // Step 7 — audience
  const aud = rawClaims['aud'];
  if (!Array.isArray(aud) || !aud.includes(PASSPORT_AUDIENCE)) {
    return fail('AUDIENCE_MISMATCH', `Passport audience must include "${PASSPORT_AUDIENCE}"`);
  }

  // Step 8 — issuer
  const iss = rawClaims['iss'];
  if (typeof iss !== 'string' || !SPIFFE_RE.test(iss)) {
    return fail('INVALID_ISSUER', `iss is not a valid SPIFFE ID: ${String(iss)}`);
  }

  // Step 9 — subject
  const sub = rawClaims['sub'];
  if (typeof sub !== 'string' || !SPIFFE_RE.test(sub)) {
    return fail('INVALID_SUBJECT', `sub is not a valid SPIFFE ID: ${String(sub)}`);
  }

  // Step 10 — vane claims
  const vane = rawClaims['vane'];
  if (vane === null || typeof vane !== 'object' || Array.isArray(vane)) {
    return fail('MALFORMED_CLAIMS', 'Missing or malformed "vane" claim object');
  }
  const c = vane as Record<string, unknown>;

  // Step 11 — version
  if (!SUPPORTED_VERSIONS.has(c['v'] as number)) {
    return fail('UNSUPPORTED_VERSION', `Unsupported passport version: ${String(c['v'])}`);
  }

  if (!Array.isArray(c['scopes']) || (c['scopes'] as unknown[]).length === 0) {
    return fail('MALFORMED_CLAIMS', '"vane.scopes" must be a non-empty array');
  }
  const scopes = c['scopes'] as string[];

  if (!Array.isArray(c['delegationChain']) || (c['delegationChain'] as unknown[]).length === 0) {
    return fail('MALFORMED_CLAIMS', '"vane.delegationChain" must be a non-empty array');
  }
  const chain = c['delegationChain'] as string[];

  // Step 12 — chain coherence
  const chainTail = chain[chain.length - 1];
  if (chainTail !== sub) {
    return fail(
      'CHAIN_INCOHERENT',
      `delegationChain tail "${chainTail}" does not match sub "${sub}"`,
    );
  }

  // Step 13 — scope
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

  return { valid: true, claims: rawClaims as unknown as VanePassportClaims, scopeGranted };
}

/**
 * Returns the first scope in `granted` that covers `requested`, or null.
 * Exported for use in custom authorization logic.
 */
export function matchScope(granted: string[], requested: string): string | null {
  for (const g of granted) {
    if (g === '*') return g;
    if (g === requested) return g;
    if (g.endsWith(':*') && requested.startsWith(g.slice(0, -1))) return g;
  }
  return null;
}

export interface CrossOrgVerifyOptions extends VerifyOptions {
  // If provided, vane_xorg.targetOrg in the token must equal this value.
  expectedTargetOrg?: string;
}

/**
 * Verifies a cross-org delegation token (XORG+JWT) offline.
 *
 * @param token              — raw XORG+JWT string
 * @param originOrgPublicKey — Ed25519 SPKI PEM of the originating org's CA key
 *                             (fetch once from GET /v1/ca/public-key?companyId=<originOrg>)
 * @param opts               — optional tool name and target org for scope / org checks
 *
 * Verification steps (12):
 *   1.  Parse          — split ".", decode base64url header + payload
 *   2.  Algorithm      — header.alg must be "EdDSA"
 *   3.  Token type     — header.typ must be "XORG+JWT"
 *   4.  Signature      — Ed25519 over "header.payload" using originOrgPublicKey
 *   5.  Expiry         — exp must be in the future
 *   6.  Audience       — aud must include "vane:xorg:v1"
 *   7.  Issuer         — iss must be a valid SPIFFE URI
 *   8.  Subject        — sub must be a valid SPIFFE URI
 *   9.  Claims         — "vane_xorg" object must be present with v=1
 *   10. Chain          — delegationChain.at(-1) must equal sub
 *   11. Target match   — if expectedTargetOrg provided, vane_xorg.targetOrg must match
 *   12. Scope          — if tool provided, scopes must cover "tool:<tool>"
 */
type CrossOrgResult =
  | Extract<PassportVerificationResult, { valid: false }>
  | { valid: true; claims: CrossOrgDelegationClaims; scopeGranted: string; tokenType: 'cross-org' };

export function verifyCrossOrgToken(
  token: string,
  originOrgPublicKey: string,
  opts: CrossOrgVerifyOptions = {},
): CrossOrgResult {
  // Fail-closed wrapper: any error, ambiguity, or unexpected state during
  // verification resolves to a DENY. An exception thrown in any step below
  // becomes a structured failure result here — it must never escape this
  // function and never fall through to a caller as an absent/undefined value.
  try {
    return verifyCrossOrgTokenImpl(token, originOrgPublicKey, opts);
  } catch (err) {
    return { valid: false, error: `Unexpected verification error: ${(err as Error).message}`, code: 'VERIFICATION_ERROR' };
  }
}

function verifyCrossOrgTokenImpl(
  token: string,
  originOrgPublicKey: string,
  opts: CrossOrgVerifyOptions = {},
): CrossOrgResult {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'Expected header.payload.signature', code: 'MALFORMED_TOKEN' };
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let rawClaims: Record<string, unknown>;
  try {
    header    = JSON.parse(fromB64url(headerB64).toString('utf8'));
    rawClaims = JSON.parse(fromB64url(payloadB64).toString('utf8'));
  } catch {
    return { valid: false, error: 'Could not decode header or payload', code: 'MALFORMED_TOKEN' };
  }

  // Algorithm check — first guard, explicit rejection for every bypass vector.
  const alg = header['alg'];
  if (alg === undefined || alg === null) {
    return { valid: false, error: 'JWT alg header is missing', code: 'ALGORITHM_MISMATCH' };
  }
  if (alg === 'none') {
    return { valid: false, error: 'JWT alg:none is not allowed', code: 'ALGORITHM_MISMATCH' };
  }
  if (alg !== 'EdDSA') {
    return { valid: false, error: `Expected EdDSA, got ${String(alg)}`, code: 'ALGORITHM_MISMATCH' };
  }
  if (header['typ'] !== CROSS_ORG_TOKEN_TYPE) {
    return { valid: false, error: `Expected ${CROSS_ORG_TOKEN_TYPE}, got ${String(header['typ'])}`, code: 'WRONG_TOKEN_TYPE' };
  }

  let sigValid: boolean;
  try {
    const keyObj = createPublicKey(originOrgPublicKey);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      return { valid: false, error: `Origin org public key must be Ed25519, got ${keyObj.asymmetricKeyType}`, code: 'SIGNATURE_INVALID' };
    }
    sigValid = cryptoVerify(
      null,
      Buffer.from(`${headerB64}.${payloadB64}`),
      keyObj,
      fromB64url(sigB64),
    );
  } catch {
    return { valid: false, error: 'Origin org public key is malformed or incompatible', code: 'SIGNATURE_INVALID' };
  }
  if (!sigValid) {
    return { valid: false, error: 'Origin org signature verification failed', code: 'SIGNATURE_INVALID' };
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);

  const exp = rawClaims['exp'];
  if (typeof exp !== 'number' || exp < now) {
    return { valid: false, error: 'Cross-org token has expired', code: 'TOKEN_EXPIRED' };
  }

  const aud = rawClaims['aud'];
  if (!Array.isArray(aud) || !aud.includes(CROSS_ORG_AUDIENCE)) {
    return { valid: false, error: `Token audience must include "${CROSS_ORG_AUDIENCE}"`, code: 'AUDIENCE_MISMATCH' };
  }

  const iss = rawClaims['iss'];
  if (typeof iss !== 'string' || !SPIFFE_RE.test(iss)) {
    return { valid: false, error: `iss is not a valid SPIFFE ID: ${String(iss)}`, code: 'INVALID_ISSUER' };
  }

  const sub = rawClaims['sub'];
  if (typeof sub !== 'string' || !SPIFFE_RE.test(sub)) {
    return { valid: false, error: `sub is not a valid SPIFFE ID: ${String(sub)}`, code: 'INVALID_SUBJECT' };
  }

  const xorg = rawClaims['vane_xorg'];
  if (xorg === null || typeof xorg !== 'object' || Array.isArray(xorg)) {
    return { valid: false, error: 'Missing or malformed "vane_xorg" claim object', code: 'MALFORMED_CLAIMS' };
  }
  const c = xorg as Record<string, unknown>;

  if (!SUPPORTED_VERSIONS.has(c['v'] as number)) {
    return { valid: false, error: `Unsupported cross-org token version: ${String(c['v'])}`, code: 'UNSUPPORTED_VERSION' };
  }
  if (!Array.isArray(c['scopes']) || (c['scopes'] as unknown[]).length === 0) {
    return { valid: false, error: '"vane_xorg.scopes" must be a non-empty array', code: 'MALFORMED_CLAIMS' };
  }
  const scopes = c['scopes'] as string[];

  if (!Array.isArray(c['delegationChain']) || (c['delegationChain'] as unknown[]).length === 0) {
    return { valid: false, error: '"vane_xorg.delegationChain" must be a non-empty array', code: 'MALFORMED_CLAIMS' };
  }
  const chain = c['delegationChain'] as string[];

  const chainTail = chain[chain.length - 1];
  if (chainTail !== sub) {
    return {
      valid: false,
      error: `delegationChain tail "${chainTail}" does not match sub "${sub}"`,
      code: 'CHAIN_INCOHERENT',
    };
  }

  if (opts.expectedTargetOrg !== undefined) {
    const targetOrg = c['targetOrg'];
    if (targetOrg !== opts.expectedTargetOrg) {
      return {
        valid: false,
        error: `Token targets org "${String(targetOrg)}", expected "${opts.expectedTargetOrg}"`,
        code: 'TARGET_MISMATCH',
      };
    }
  }

  let scopeGranted: string;
  if (opts.tool !== undefined) {
    const requested = `tool:${opts.tool}`;
    const match = matchScope(scopes, requested);
    if (match === null) {
      return { valid: false, error: `Scopes [${scopes.join(', ')}] do not cover "${requested}"`, code: 'SCOPE_DENIED' };
    }
    scopeGranted = match;
  } else {
    scopeGranted = scopes[0];
  }

  return {
    valid: true,
    tokenType: 'cross-org',
    claims: rawClaims as unknown as CrossOrgDelegationClaims,
    scopeGranted,
  };
}
