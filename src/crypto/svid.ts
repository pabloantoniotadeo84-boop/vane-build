import {
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
  createHash,
  randomUUID,
} from 'node:crypto';
import { validateSpiffeId } from './spiffe.js';
import type { JwtSvidClaims } from './types.js';

const DEFAULT_TTL = 3600;
export const SVID_AUDIENCE = 'vane';

// Clock-skew leeway (seconds) applied to every time-based claim check. A token
// is treated as still valid if (exp + leeway) > now, and as not-yet-valid only
// if (nbf - leeway) > now. This absorbs small clock differences between the
// issuer and the verifier so a freshly issued token is not rejected when the
// verifier's clock runs slightly behind the issuer's. This is the single source
// of truth for the default; other src/ verifiers import it.
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;

// Resolves the effective leeway from a caller-supplied value, applying the
// default and rejecting negative values (which would shrink the validity window
// and could let an expired token through).
export function resolveClockSkew(clockSkewSeconds?: number): number {
  const leeway = clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  if (leeway < 0) throw new Error('clockSkewSeconds must not be negative');
  return leeway;
}

function b64url(data: string | Buffer): string {
  return (typeof data === 'string' ? Buffer.from(data, 'utf8') : data).toString('base64url');
}

function fromB64url(str: string): Buffer {
  return Buffer.from(str, 'base64url');
}

// Stable key identifier: first 16 hex chars of SHA-256(SPKI DER).
export function deriveKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' }) as Buffer;
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * Issues a SPIFFE JWT-SVID (EdDSA / Ed25519) for the given SPIFFE ID.
 * extraClaims is used by token-exchange to embed the `act` delegation chain.
 */
export function issueJwtSvid(
  spiffeId: string,
  privateKeyPem: string,
  publicKeyPem: string,
  ttl = DEFAULT_TTL,
  extraClaims: Record<string, unknown> = {},
): string {
  if (!validateSpiffeId(spiffeId)) throw new Error(`Invalid SPIFFE ID: ${spiffeId}`);

  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: deriveKeyId(publicKeyPem) }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({
    sub: spiffeId,
    aud: [SVID_AUDIENCE],
    iat: now,
    exp: now + ttl,
    nbf: now,
    jti: randomUUID(),
    ...extraClaims,
  }));

  const signingInput = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(signingInput), createPrivateKey(privateKeyPem))
    .toString('base64url');

  return `${signingInput}.${sig}`;
}

/**
 * Verifies a JWT-SVID signature, expiry, audience, and SPIFFE ID format.
 * Throws on any failure; returns claims on success.
 */
export function verifyJwtSvid(
  token: string,
  publicKeyPem: string,
  requiredAudience = SVID_AUDIENCE,
  clockSkewSeconds?: number,
): JwtSvidClaims {
  // Resolved up front so a negative leeway throws before any token parsing.
  const leeway = resolveClockSkew(clockSkewSeconds);

  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT: expected header.payload.signature');

  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(fromB64url(headerB64).toString('utf8'));

  // Algorithm check is the first guard — explicit rejection for every bypass vector.
  const alg = header.alg;
  if (alg === undefined || alg === null) throw new Error('JWT alg header is missing');
  if (alg === 'none') throw new Error('JWT alg:none is not allowed');
  if (alg !== 'EdDSA') throw new Error(`Unsupported JWT algorithm: ${alg}`);

  // Key-type guard — rejects non-Ed25519 keys before cryptoVerify is called.
  const keyObj = createPublicKey(publicKeyPem);
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`Public key must be Ed25519 for JWT-SVID verification, got ${keyObj.asymmetricKeyType}`);
  }

  const valid = cryptoVerify(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`),
    keyObj,
    fromB64url(sigB64),
  );
  if (!valid) throw new Error('JWT signature verification failed');

  const claims = JSON.parse(fromB64url(payloadB64).toString('utf8')) as JwtSvidClaims;
  const now = Math.floor(Date.now() / 1000);

  // Expiry — valid while (exp + leeway) > now.
  if (claims.exp + leeway < now) throw new Error('JWT-SVID has expired');
  // Not-before — premature only when (nbf - leeway) > now. Skipped when the
  // token carries no nbf (older tokens), so this stays backward compatible.
  if (typeof claims.nbf === 'number' && claims.nbf - leeway > now) {
    throw new Error('JWT-SVID is not yet valid');
  }
  if (!Array.isArray(claims.aud) || !claims.aud.includes(requiredAudience)) {
    throw new Error(`JWT-SVID audience mismatch: expected "${requiredAudience}"`);
  }
  if (!validateSpiffeId(claims.sub)) {
    throw new Error(`JWT-SVID sub is not a valid SPIFFE ID: ${claims.sub}`);
  }

  return claims;
}
