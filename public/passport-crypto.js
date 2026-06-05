/**
 * Vane Passport Crypto
 *
 * Browser-native Ed25519 passport signing and verification using the Web
 * Crypto API (SubtleCrypto). Works without modification in Node.js 22+
 * because globalThis.crypto.subtle now supports Ed25519 there too.
 *
 * All exports are pure functions (or async functions over Web Crypto).
 * No DOM, no window, no side effects — safe to import from tests.
 */

// ── Base64url utilities ────────────────────────────────────────────────────

/** Encode a Uint8Array to a base64url string. */
export function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Encode a UTF-8 string to base64url. */
export function b64urlStr(str) {
  return b64url(new TextEncoder().encode(str));
}

/** Decode a base64url string to a Uint8Array. */
export function b64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad === 2) b64 += '==';
  else if (pad === 3) b64 += '=';
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// ── Key generation ─────────────────────────────────────────────────────────

/**
 * Generate a new Ed25519 key pair.
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateKeyPair() {
  return globalThis.crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,           // extractable so tests can inspect / export
    ['sign', 'verify']
  );
}

/**
 * Export a public key as an SPKI-encoded base64url string.
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKeyRaw(publicKey) {
  const spki = await globalThis.crypto.subtle.exportKey('spki', publicKey);
  return b64url(new Uint8Array(spki));
}

// ── Claims construction ────────────────────────────────────────────────────

/**
 * Build a Vane Passport JWT claims object (CAP+JWT).
 *
 * @param {{
 *   agentName: string,
 *   scopes: string[],
 *   delegation?: string,
 *   companyId?: string
 * }} opts
 * @returns {object}
 */
export function buildPassportClaims({ agentName, scopes, delegation, companyId = 'demo' }) {
  const now = Math.floor(Date.now() / 1000);
  const agentSpiffe = `spiffe://vane.local/company/${companyId}/agent/${agentName}`;
  const orgSpiffe   = `spiffe://vane.local/company/${companyId}`;

  const delegationChain = delegation
    ? [orgSpiffe, delegation, agentSpiffe]
    : [orgSpiffe, agentSpiffe];

  const claims = {
    iss: 'vane-demo',
    sub: agentSpiffe,
    aud: ['vane'],
    iat: now,
    exp: now + 3600,
    nbf: now,
    jti: globalThis.crypto.randomUUID(),
    vane: {
      v: 1,
      agentId: agentName,
      org: companyId,
      orgSpiffeId: orgSpiffe,
      scopes,
      delegationChain,
    },
  };

  if (delegation) {
    claims.act = { sub: agentSpiffe, delegatedBy: delegation };
  }

  return claims;
}

// ── Sign ───────────────────────────────────────────────────────────────────

/**
 * Sign a passport claims object and return a JWT string (CAP+JWT format).
 *
 * The JWT header is: { alg: "EdDSA", typ: "CAP+JWT", kid: "browser-demo" }
 *
 * @param {object}    claims     — result of buildPassportClaims()
 * @param {CryptoKey} privateKey — Ed25519 private key with "sign" usage
 * @returns {Promise<string>}    — signed JWT (header.payload.signature)
 */
export async function signPassport(claims, privateKey) {
  const header = { alg: 'EdDSA', typ: 'CAP+JWT', kid: 'browser-demo' };
  const h = b64urlStr(JSON.stringify(header));
  const p = b64urlStr(JSON.stringify(claims));
  const sigInput = `${h}.${p}`;

  const sigBytes = await globalThis.crypto.subtle.sign(
    'Ed25519',
    privateKey,
    new TextEncoder().encode(sigInput)
  );

  return `${sigInput}.${b64url(new Uint8Array(sigBytes))}`;
}

// ── Verify ─────────────────────────────────────────────────────────────────

/**
 * Verify an Ed25519 passport JWT against the given public key.
 *
 * Checks: signature validity, 3-part structure, decodable payload.
 * Does NOT check exp/nbf/aud — this is an in-browser demo; full
 * validation lives in src/passport/verify.ts.
 *
 * @param {string}    token     — the JWT to verify
 * @param {CryptoKey} publicKey — Ed25519 public key with "verify" usage
 * @returns {Promise<{ valid: boolean, claims?: object, error?: string }>}
 */
export async function verifyPassport(token, publicKey) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: `malformed token: expected 3 parts, got ${parts.length}` };
  }
  const [h, p, s] = parts;
  try {
    const sigBytes = b64urlDecode(s);
    const valid = await globalThis.crypto.subtle.verify(
      'Ed25519',
      publicKey,
      sigBytes,
      new TextEncoder().encode(`${h}.${p}`)
    );
    if (!valid) return { valid: false, error: 'Ed25519 signature verification failed' };
    const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
    return { valid: true, claims };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// ── Tamper ─────────────────────────────────────────────────────────────────

/**
 * Flip a single byte in the payload segment to simulate tampering.
 * The JWT structure (3 parts) is preserved so verification runs but fails.
 *
 * @param {string} token
 * @returns {string}
 */
export function tamperToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return token;
  const [h, p, s] = parts;
  const bytes = b64urlDecode(p);
  const mid   = Math.floor(bytes.length / 2);
  bytes[mid]  ^= 0xff;
  return `${h}.${b64url(bytes)}.${s}`;
}

// ── Decode (no verification) ───────────────────────────────────────────────

/**
 * Decode the payload segment of a JWT without verifying the signature.
 * @param {string} token
 * @returns {object|null}
 */
export function decodePayload(token) {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  } catch {
    return null;
  }
}

/**
 * Decode the header segment of a JWT without verifying the signature.
 * @param {string} token
 * @returns {object|null}
 */
export function decodeHeader(token) {
  const parts = token.split('.');
  if (parts.length < 1) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
  } catch {
    return null;
  }
}

// ── Structure validation (sync, no crypto) ────────────────────────────────

/**
 * Validate JWT structure without verifying the signature.
 * Checks: 3 base64url parts, parseable header and payload.
 *
 * @param {unknown} token
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateJwtStructure(token) {
  if (typeof token !== 'string') return { valid: false, error: 'not a string' };
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: `expected 3 parts, got ${parts.length}` };
  }
  for (const part of parts) {
    if (!/^[A-Za-z0-9_-]+$/.test(part)) {
      return { valid: false, error: 'part contains invalid base64url characters' };
    }
  }
  const header  = decodeHeader(token);
  if (!header)  return { valid: false, error: 'header is not valid JSON' };
  const payload = decodePayload(token);
  if (!payload) return { valid: false, error: 'payload is not valid JSON' };
  return { valid: true };
}
