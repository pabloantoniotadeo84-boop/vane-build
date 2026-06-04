// =============================================================================
// Vane Agent Passport — REFERENCE VERIFIER
// =============================================================================
//
// This is the canonical, standalone description of how to verify a Vane Agent
// Passport (a "CAP+JWT"). It is written to be *read as a specification*: a
// developer at a third-party company should be able to port this file to any
// language and produce a byte-for-byte compatible verifier without ever reading
// the Vane server source.
//
// It depends ONLY on Node.js built-ins (`node:crypto`). It imports nothing from
// `src/`. Every constant and rule needed to verify a passport is defined here.
//
// -----------------------------------------------------------------------------
// THE SIGNED BYTES
// -----------------------------------------------------------------------------
// A passport is a standard JWS compact-serialization JWT:
//
//     token = base64url(headerJSON) + "." + base64url(payloadJSON) + "." + base64url(sig)
//
// The signature is Ed25519 (PureEdDSA, no pre-hash) over the ASCII bytes of:
//
//     base64url(headerJSON) + "." + base64url(payloadJSON)
//
// i.e. the first two dot-separated segments of the token, EXACTLY as received.
// The verifier MUST verify over the received bytes. It MUST NOT re-serialize or
// canonicalize (JCS/RFC-8785) the JSON — passports are not canonicalized; the
// signature covers the literal transmitted base64url text.
//
// -----------------------------------------------------------------------------
// REVOCATION
// -----------------------------------------------------------------------------
// The cryptographic + claims verification below never consults a revocation
// list. Revocation is a SEPARATE step layered on top: after a passport is
// otherwise valid, the verifier checks whether its `jti` appears in the set of
// revoked passport IDs (obtained out of band, e.g. GET /v1/passports/revoked).
// This reference verifier performs that check as its final step (step 14) when
// the caller supplies `revokedJtis`, returning PASSPORT_REVOKED. This mirrors
// the production server (store.isPassportRevoked after verifyPassport) and the
// mcp-middleware (checkRevocation after verifyPassport).
// =============================================================================

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';

// ── Protocol constants ───────────────────────────────────────────────────────

/** Top-level protocol audience every passport must carry in its `aud` array. */
export const PASSPORT_AUDIENCE = 'vane:passport:v1';

/** The only JWT `typ` accepted for passports. */
export const PASSPORT_TOKEN_TYPE = 'CAP+JWT';

/** The only signature algorithm accepted. */
export const PASSPORT_ALG = 'EdDSA';

/** Passport schema versions this verifier understands. Unknown → reject. */
export const SUPPORTED_VERSIONS = new Set<number>([1]);

/**
 * Default clock-skew leeway, in seconds, applied to `exp` and `nbf`. A token is
 * valid while (exp + leeway) >= now, and not-yet-valid only when
 * (nbf - leeway) > now. Absorbs small clock drift between issuer and verifier.
 */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;

/** A SPIFFE ID must be `spiffe://<trust-domain>/<path>` with a non-empty path. */
const SPIFFE_RE = /^spiffe:\/\/[^/]+\/.+$/;

// ── Result types (identical shape to src/passport/types.ts) ──────────────────

export type PassportErrorCode =
  | 'MALFORMED_TOKEN'
  | 'ALGORITHM_MISMATCH'
  | 'WRONG_TOKEN_TYPE'
  | 'SIGNATURE_INVALID'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_NOT_YET_VALID'
  | 'AUDIENCE_MISMATCH'
  | 'MISSING_NONCE'
  | 'NONCE_MISMATCH'
  | 'MISSING_AUDIENCE'
  | 'REQUEST_MISMATCH'
  | 'INVALID_ISSUER'
  | 'INVALID_SUBJECT'
  | 'UNSUPPORTED_VERSION'
  | 'MALFORMED_CLAIMS'
  | 'CHAIN_INCOHERENT'
  | 'SCOPE_DENIED'
  | 'PASSPORT_REVOKED'
  | 'VERIFICATION_ERROR';

export type ReferenceVerificationResult =
  | { valid: true; claims: Record<string, unknown>; scopeGranted: string }
  | { valid: false; error: string; code: PassportErrorCode };

export interface ReferenceVerifyOptions {
  /** Ed25519 SPKI PEM of the Vane CA root key. The single trust anchor. */
  caPublicKey: string;

  /** If set, the passport's scopes must cover `tool:<tool>` (else SCOPE_DENIED). */
  tool?: string;

  /** If set, `vane.nonce` must equal this exactly (else MISSING_NONCE/NONCE_MISMATCH). */
  expectedNonce?: string;

  /** If set, `vane.aud` must equal this exactly (else MISSING_AUDIENCE/AUDIENCE_MISMATCH). */
  expectedAudience?: string;

  /** Required to satisfy a request-bound passport: if `vane.requestHash` is present it must equal this. */
  expectedRequestHash?: string;

  /** Override "now" (Unix seconds) for deterministic verification. */
  now?: number;

  /** Clock-skew leeway in seconds. Defaults to 30. Negative throws. */
  clockSkewSeconds?: number;

  /**
   * Revoked passport IDs (jti values). When the otherwise-valid passport's jti
   * appears here, verification fails with PASSPORT_REVOKED. Omit to skip the
   * revocation check entirely.
   */
  revokedJtis?: string[];
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function fail(code: PassportErrorCode, error: string): ReferenceVerificationResult {
  return { valid: false, error, code };
}

/** Resolve the effective leeway. Negative values throw (they would shrink the validity window). */
function resolveClockSkew(clockSkewSeconds?: number): number {
  const leeway = clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  if (leeway < 0) throw new Error('clockSkewSeconds must not be negative');
  return leeway;
}

/** A SPIFFE ID is `spiffe://<trust-domain>/<path>` with a non-empty path. */
function isValidSpiffeId(id: unknown): id is string {
  return typeof id === 'string' && SPIFFE_RE.test(id);
}

/**
 * Returns the first scope in `granted` that covers `requested`, or null.
 *
 *   "*"      — covers any scope
 *   "cat:*"  — covers any scope whose prefix is "cat:"
 *   "cat:x"  — covers exactly "cat:x"
 */
export function matchScope(granted: string[], requested: string): string | null {
  for (const g of granted) {
    if (g === '*') return g;
    if (g === requested) return g;
    if (g.endsWith(':*') && requested.startsWith(g.slice(0, -1))) return g;
  }
  return null;
}

/**
 * Verifies a Vane Agent Passport (CAP+JWT) offline.
 *
 * Fail-closed: every error path resolves to a structured `{ valid: false }`
 * result. The only thing that escapes as a thrown exception is a negative
 * `clockSkewSeconds` (a caller misconfiguration), which is resolved before the
 * try/catch so it surfaces loudly rather than being swallowed into a DENY.
 */
export function verifyPassportReference(
  token: string,
  opts: ReferenceVerifyOptions,
): ReferenceVerificationResult {
  const leeway = resolveClockSkew(opts.clockSkewSeconds);
  try {
    return verifyImpl(token, opts, leeway);
  } catch (err) {
    return fail('VERIFICATION_ERROR', `Unexpected verification error: ${(err as Error).message}`);
  }
}

function verifyImpl(
  token: string,
  opts: ReferenceVerifyOptions,
  leeway: number,
): ReferenceVerificationResult {
  // Step 1 — PARSE. Exactly three dot-separated segments.
  const parts = token.split('.');
  if (parts.length !== 3) {
    return fail('MALFORMED_TOKEN', 'Expected header.payload.signature');
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = JSON.parse(fromB64url(headerB64).toString('utf8'));
    claims = JSON.parse(fromB64url(payloadB64).toString('utf8'));
  } catch {
    return fail('MALFORMED_TOKEN', 'Could not decode header or payload');
  }

  // Step 2 — ALGORITHM. Reject missing, "none", and anything but EdDSA.
  const alg = header['alg'];
  if (alg === undefined || alg === null) {
    return fail('ALGORITHM_MISMATCH', 'JWT alg header is missing');
  }
  if (alg === 'none') {
    return fail('ALGORITHM_MISMATCH', 'JWT alg:none is not allowed');
  }
  if (alg !== PASSPORT_ALG) {
    return fail('ALGORITHM_MISMATCH', `Expected EdDSA, got ${String(alg)}`);
  }

  // Step 3 — TOKEN TYPE. CAP+JWT distinguishes passports from SVIDs / XORG tokens.
  if (header['typ'] !== PASSPORT_TOKEN_TYPE) {
    return fail('WRONG_TOKEN_TYPE', `Expected ${PASSPORT_TOKEN_TYPE}, got ${String(header['typ'])}`);
  }

  // Step 4 — SIGNATURE. Ed25519 over the literal "headerB64.payloadB64" bytes.
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

  // Step 5 — EXPIRY. Valid while (exp + leeway) >= now.
  const exp = claims['exp'];
  if (typeof exp !== 'number' || exp + leeway < now) {
    return fail('TOKEN_EXPIRED', 'Passport has expired');
  }

  // Step 6 — NOT-BEFORE. Premature only when (nbf - leeway) > now. Optional claim.
  const nbf = claims['nbf'];
  if (typeof nbf === 'number' && nbf - leeway > now) {
    return fail('TOKEN_NOT_YET_VALID', 'Passport is not yet valid');
  }

  // Step 7 — PROTOCOL AUDIENCE. aud array must contain PASSPORT_AUDIENCE.
  const aud = claims['aud'];
  if (!Array.isArray(aud) || !aud.includes(PASSPORT_AUDIENCE)) {
    return fail('AUDIENCE_MISMATCH', `Passport audience must include "${PASSPORT_AUDIENCE}"`);
  }

  // Step 8 — ISSUER. Must be a syntactically valid SPIFFE ID.
  const iss = claims['iss'];
  if (!isValidSpiffeId(iss)) {
    return fail('INVALID_ISSUER', `iss is not a valid SPIFFE ID: ${String(iss)}`);
  }

  // Step 9 — SUBJECT. Must be a syntactically valid SPIFFE ID.
  const sub = claims['sub'];
  if (!isValidSpiffeId(sub)) {
    return fail('INVALID_SUBJECT', `sub is not a valid SPIFFE ID: ${String(sub)}`);
  }

  // Step 10 — VANE CLAIMS. The "vane" namespace object must be present.
  const vane = claims['vane'];
  if (vane === null || typeof vane !== 'object' || Array.isArray(vane)) {
    return fail('MALFORMED_CLAIMS', 'Missing or malformed "vane" claim object');
  }
  const c = vane as Record<string, unknown>;

  // Step 11 — VERSION. Only known schema versions are accepted.
  if (!SUPPORTED_VERSIONS.has(c['v'] as number)) {
    return fail('UNSUPPORTED_VERSION', `Unsupported passport version: ${String(c['v'])}`);
  }

  // Step 12 — SHAPE. scopes and delegationChain must be non-empty arrays.
  if (!Array.isArray(c['scopes']) || (c['scopes'] as unknown[]).length === 0) {
    return fail('MALFORMED_CLAIMS', '"vane.scopes" must be a non-empty array');
  }
  const scopes = c['scopes'] as string[];

  if (!Array.isArray(c['delegationChain']) || (c['delegationChain'] as unknown[]).length === 0) {
    return fail('MALFORMED_CLAIMS', '"vane.delegationChain" must be a non-empty array');
  }
  const chain = c['delegationChain'] as string[];

  // Step 12b — CHAIN COHERENCE. The chain tail must be the passport subject.
  const chainTail = chain[chain.length - 1];
  if (chainTail !== sub) {
    return fail('CHAIN_INCOHERENT', `delegationChain tail "${chainTail}" does not match sub "${sub}"`);
  }

  // Step 13a — NONCE BINDING. Caller-gated: only enforced when expectedNonce is set.
  if (opts.expectedNonce !== undefined) {
    const nonce = c['nonce'];
    if (nonce === undefined || nonce === null) {
      return fail('MISSING_NONCE', 'expectedNonce was supplied but the passport carries no nonce');
    }
    if (typeof nonce !== 'string' || nonce !== opts.expectedNonce) {
      return fail('NONCE_MISMATCH', 'Passport nonce does not match the expected nonce');
    }
  }

  // Step 13b — RECIPIENT AUDIENCE. Caller-gated: only enforced when expectedAudience is set.
  if (opts.expectedAudience !== undefined) {
    const recipientAud = c['aud'];
    if (recipientAud === undefined || recipientAud === null) {
      return fail('MISSING_AUDIENCE', 'expectedAudience was supplied but the passport carries no recipient audience');
    }
    if (typeof recipientAud !== 'string' || recipientAud !== opts.expectedAudience) {
      return fail('AUDIENCE_MISMATCH', `Passport recipient audience "${String(recipientAud)}" does not match expected "${opts.expectedAudience}"`);
    }
  }

  // Step 13c — REQUEST BINDING. Claim-gated: enforced whenever vane.requestHash is
  // present. A request-bound passport cannot be accepted unbound — fail closed.
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

  // Step 13d — SCOPE. Only checked when a tool is requested.
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

  // Step 14 — REVOCATION (final step, after the passport is otherwise valid).
  // Mirrors the production server: signature + claims + scope are checked first;
  // only then is the jti tested against the revoked set.
  if (opts.revokedJtis !== undefined) {
    const jti = claims['jti'];
    if (typeof jti === 'string' && opts.revokedJtis.includes(jti)) {
      return fail('PASSPORT_REVOKED', 'Passport has been revoked');
    }
  }

  return { valid: true, claims, scopeGranted };
}
