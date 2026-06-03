// Offline Vane Agent Passport (CAP+JWT) verification.
//
// This file has zero external dependencies. It uses only node:crypto, which
// ships with every Node.js >= 12 installation. Copy this file to implement
// passport verification in any language or runtime — the algorithm is fully
// specified in the comments below.
//
// Algorithm (13 steps, all must pass):
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
// Scope matching rules:
//   "*"      — covers any scope
//   "cat:*"  — covers any scope starting with "cat:"
//   "cat:x"  — covers exactly "cat:x"

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import type {
  VanePassportClaims,
  PassportErrorCode,
  PassportVerificationResult,
  VerifyOptions,
} from './types.js';

const PASSPORT_AUDIENCE = 'vane:passport:v1';
const SUPPORTED_VERSIONS = new Set([1]);
const SPIFFE_RE = /^spiffe:\/\/[^/]+\/.+$/;

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

  // Step 2 — algorithm
  if (header['alg'] !== 'EdDSA') {
    return fail('ALGORITHM_MISMATCH', `Expected EdDSA, got ${String(header['alg'])}`);
  }

  // Step 3 — token type (CAP+JWT distinguishes passports from SVID tokens)
  if (header['typ'] !== 'CAP+JWT') {
    return fail('WRONG_TOKEN_TYPE', `Expected CAP+JWT, got ${String(header['typ'])}`);
  }

  // Step 4 — signature (Ed25519 over the raw ASCII signing input, not decoded bytes)
  let sigValid: boolean;
  try {
    sigValid = cryptoVerify(
      null,
      Buffer.from(`${headerB64}.${payloadB64}`),
      createPublicKey(caPublicKey),
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
