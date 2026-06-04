import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { validateSpiffeId } from '../crypto/spiffe.js';
import type { VanePassportClaims, PassportErrorCode, PassportVerificationResult } from './types.js';

export { PASSPORT_AUDIENCE } from './credential.js';

const SUPPORTED_VERSIONS = new Set([1]);

function fromB64url(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

export interface VerifyPassportOptions {
  // Ed25519 SPKI PEM of the Vane CA root key.
  caPublicKey: string;

  // If provided, the passport must grant a scope covering "tool:<tool>".
  tool?: string;

  // ── Sender-constraint enforcement (all optional) ────────────────────────────
  // When supplied, the corresponding constraint is enforced; the passport must
  // carry a matching value or verification fails closed. When omitted, the
  // constraint is not checked, so passports issued without these claims still
  // verify (backward compatible).

  // The exact nonce the caller bound into the passport at issuance. If set, the
  // passport's vane.nonce must equal it (NONCE_MISMATCH otherwise); a passport
  // with no nonce fails MISSING_NONCE.
  expectedNonce?: string;

  // The recipient audience of *this* deployment (e.g. "https://api.example.com").
  // If set, the passport's vane.aud must equal it (AUDIENCE_MISMATCH otherwise);
  // a passport with no recipient audience fails MISSING_AUDIENCE.
  expectedAudience?: string;

  // The canonical hash of the live request (see computeRequestHash). Required to
  // satisfy a request-bound passport: if the passport carries vane.requestHash it
  // must equal this value (REQUEST_MISMATCH otherwise, including when this option
  // is absent — a request-bound passport cannot be accepted unbound).
  expectedRequestHash?: string;

  // Override current time for testing. Unix seconds.
  now?: number;
}

/**
 * Verifies a Vane Agent Passport (CAP+JWT) offline.
 *
 * This function makes no network calls. It requires only:
 *   1. The raw passport token
 *   2. The Vane CA public key (published, static)
 *
 * Verification steps (in order):
 *   1.  Parse — split by ".", decode header and payload JSON
 *   2.  Algorithm — header.alg must be "EdDSA"
 *   3.  Token type — header.typ must be "CAP+JWT"
 *   4.  Signature — Ed25519 over "header.payload" using caPublicKey
 *   5.  Expiry — exp must be in the future
 *   6.  Not-before — nbf must be in the past (if present)
 *   7.  Audience — aud must include "vane:passport:v1"
 *   8.  Issuer — iss must be a valid SPIFFE URI
 *   9.  Subject — sub must be a valid SPIFFE URI
 *   10. Vane claims — "vane" object must be present
 *   11. Version — vane.v must be in SUPPORTED_VERSIONS
 *   12. Chain coherence — delegationChain tail must equal sub
 *   13. Nonce — if expectedNonce is set, vane.nonce must match it exactly
 *   14. Audience — if expectedAudience is set, vane.aud must match it exactly
 *   15. Request binding — if vane.requestHash is present, it must match
 *       expectedRequestHash
 *   16. Scope — if tool is provided, scopes must cover "tool:<tool>"
 */
export function verifyPassport(
  token: string,
  opts: VerifyPassportOptions,
): PassportVerificationResult {
  // Fail-closed wrapper: any error, ambiguity, or unexpected state during
  // verification resolves to a DENY. An exception thrown in any step below
  // becomes a structured failure result here — it must never escape this
  // function and never fall through to a caller as an absent/undefined value.
  try {
    return verifyPassportImpl(token, opts);
  } catch (err) {
    return fail('VERIFICATION_ERROR', `Unexpected verification error: ${(err as Error).message}`);
  }
}

function verifyPassportImpl(
  token: string,
  opts: VerifyPassportOptions,
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

  // Step 3 — token type
  if (header['typ'] !== 'CAP+JWT') {
    return fail('WRONG_TOKEN_TYPE', `Expected CAP+JWT, got ${String(header['typ'])}`);
  }

  // Step 4 — signature (key-type guard before cryptoVerify)
  let sigValid: boolean;
  try {
    const keyObj = createPublicKey(opts.caPublicKey);
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
  if (!Array.isArray(aud) || !aud.includes('vane:passport:v1')) {
    return fail('AUDIENCE_MISMATCH', 'Passport audience must include "vane:passport:v1"');
  }

  // Step 8 — issuer
  const iss = rawClaims['iss'];
  if (typeof iss !== 'string' || !validateSpiffeId(iss)) {
    return fail('INVALID_ISSUER', `iss is not a valid SPIFFE ID: ${String(iss)}`);
  }

  // Step 9 — subject
  const sub = rawClaims['sub'];
  if (typeof sub !== 'string' || !validateSpiffeId(sub)) {
    return fail('INVALID_SUBJECT', `sub is not a valid SPIFFE ID: ${String(sub)}`);
  }

  // Step 10 — vane claims object
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

  // Step 12 — chain coherence: tail must be the passport subject
  const chainTail = chain[chain.length - 1];
  if (chainTail !== sub) {
    return fail(
      'CHAIN_INCOHERENT',
      `delegationChain tail "${chainTail}" does not match sub "${sub}"`,
    );
  }

  // Step 13 — nonce binding. Only enforced when the caller supplies the nonce it
  // bound at issuance. A passport that lacks a nonce cannot satisfy a nonce
  // requirement, so MISSING_NONCE rather than NONCE_MISMATCH.
  if (opts.expectedNonce !== undefined) {
    const nonce = c['nonce'];
    if (nonce === undefined || nonce === null) {
      return fail('MISSING_NONCE', 'expectedNonce was supplied but the passport carries no nonce');
    }
    if (typeof nonce !== 'string' || nonce !== opts.expectedNonce) {
      return fail('NONCE_MISMATCH', 'Passport nonce does not match the expected nonce');
    }
  }

  // Step 14 — recipient audience. The per-deployment audience (vane.aud) is
  // distinct from the top-level protocol audience checked in step 7. Only
  // enforced when expectedAudience is supplied.
  if (opts.expectedAudience !== undefined) {
    const recipientAud = c['aud'];
    if (recipientAud === undefined || recipientAud === null) {
      return fail('MISSING_AUDIENCE', 'expectedAudience was supplied but the passport carries no recipient audience');
    }
    if (typeof recipientAud !== 'string' || recipientAud !== opts.expectedAudience) {
      return fail('AUDIENCE_MISMATCH', `Passport recipient audience "${String(recipientAud)}" does not match expected "${opts.expectedAudience}"`);
    }
  }

  // Step 15 — request binding. Gated by the *presence of the claim*: a
  // request-bound passport asserts it is valid for exactly one request, so any
  // verifier must check it. If it cannot (no expectedRequestHash supplied), the
  // passport is denied — fail closed.
  const requestHash = c['requestHash'];
  if (requestHash !== undefined && requestHash !== null) {
    if (typeof requestHash !== 'string') {
      return fail('REQUEST_MISMATCH', 'Passport requestHash claim is malformed');
    }
    if (opts.expectedRequestHash === undefined) {
      return fail('REQUEST_MISMATCH', 'Passport is request-bound but no expectedRequestHash was supplied');
    }
    if (requestHash !== opts.expectedRequestHash) {
      return fail('REQUEST_MISMATCH', 'Passport requestHash does not match the request');
    }
  }

  // Step 16 — scope
  let scopeGranted: string;
  if (opts.tool !== undefined) {
    const requested = `tool:${opts.tool}`;
    const match = matchScope(scopes, requested);
    if (match === null) {
      return fail(
        'SCOPE_DENIED',
        `Scopes [${scopes.join(', ')}] do not cover "${requested}"`,
      );
    }
    scopeGranted = match;
  } else {
    // No specific tool requested — return the broadest granted scope.
    scopeGranted = scopes[0];
  }

  return { valid: true, claims: rawClaims as unknown as VanePassportClaims, scopeGranted };
}

/**
 * Returns the first scope in `granted` that covers `requested`, or null.
 *
 * Matching rules:
 *   "*"       — covers everything
 *   "cat:*"   — covers any scope whose prefix is "cat:"
 *   "cat:x"   — covers exactly "cat:x"
 */
export function matchScope(granted: string[], requested: string): string | null {
  for (const g of granted) {
    if (g === '*') return g;
    if (g === requested) return g;
    if (g.endsWith(':*') && requested.startsWith(g.slice(0, -1))) return g;
  }
  return null;
}

function fail(code: PassportErrorCode, error: string): PassportVerificationResult {
  return { valid: false, error, code };
}
