/**
 * Tests for the Vane in-browser passport crypto module.
 *
 * Runs in Node.js 22+ (globalThis.crypto supports Ed25519 natively).
 * Import path is relative so vitest resolves public/passport-crypto.js
 * directly without any build step.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKeyPair,
  buildPassportClaims,
  signPassport,
  verifyPassport,
  tamperToken,
  decodePayload,
  decodeHeader,
  validateJwtStructure,
  b64url,
  b64urlDecode,
  b64urlStr,
} from '../public/passport-crypto.js';

// ── b64url round-trip ──────────────────────────────────────────────────────

describe('b64url utilities', () => {
  it('encodes bytes to url-safe base64 (no +, /, or =)', () => {
    const bytes = new Uint8Array([0, 1, 62, 63, 64, 128, 255]);
    const encoded = b64url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it('round-trips arbitrary bytes through encode→decode', () => {
    const input = new Uint8Array([1, 2, 3, 4, 128, 254, 255, 0]);
    expect(b64urlDecode(b64url(input))).toEqual(input);
  });

  it('round-trips a UTF-8 string through b64urlStr→b64urlDecode', () => {
    const str = '{"hello":"wörld 🌍"}';
    const decoded = new TextDecoder().decode(b64urlDecode(b64urlStr(str)));
    expect(decoded).toBe(str);
  });

  it('handles single-byte arrays (padding edge cases)', () => {
    for (let b = 0; b < 256; b++) {
      const input = new Uint8Array([b]);
      expect(b64urlDecode(b64url(input))).toEqual(input);
    }
  });
});

// ── generateKeyPair ─────────────────────────────────────────────────────────

describe('generateKeyPair', () => {
  let kp: CryptoKeyPair;

  beforeAll(async () => {
    kp = await generateKeyPair();
  });

  it('returns a CryptoKeyPair with publicKey and privateKey', () => {
    expect(kp).toBeDefined();
    expect(kp.publicKey).toBeDefined();
    expect(kp.privateKey).toBeDefined();
  });

  it('uses the Ed25519 algorithm', () => {
    expect(kp.publicKey.algorithm.name).toBe('Ed25519');
    expect(kp.privateKey.algorithm.name).toBe('Ed25519');
  });

  it('privateKey has "sign" usage', () => {
    expect(kp.privateKey.usages).toContain('sign');
  });

  it('publicKey has "verify" usage', () => {
    expect(kp.publicKey.usages).toContain('verify');
  });

  it('two calls produce different key pairs', async () => {
    const kp2 = await generateKeyPair();
    // Export and compare public keys
    const [pub1, pub2] = await Promise.all([
      globalThis.crypto.subtle.exportKey('spki', kp.publicKey),
      globalThis.crypto.subtle.exportKey('spki', kp2.publicKey),
    ]);
    const hex = (buf: ArrayBuffer) =>
      [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    expect(hex(pub1)).not.toBe(hex(pub2));
  });
});

// ── buildPassportClaims ────────────────────────────────────────────────────

describe('buildPassportClaims', () => {
  const opts = { agentName: 'test-agent', scopes: ['attest:write', 'tool:*'], companyId: 'acme' };

  it('includes all required JWT fields', () => {
    const c = buildPassportClaims(opts);
    expect(c.iss).toBe('vane-demo');
    expect(c.sub).toBeDefined();
    expect(c.aud).toContain('vane');
    expect(c.iat).toBeTypeOf('number');
    expect(c.exp).toBeTypeOf('number');
    expect(c.nbf).toBeTypeOf('number');
    expect(c.jti).toBeTypeOf('string');
  });

  it('exp is exactly 3600 seconds after iat', () => {
    const c = buildPassportClaims(opts);
    expect(c.exp - c.iat).toBe(3600);
  });

  it('nbf equals iat', () => {
    const c = buildPassportClaims(opts);
    expect(c.nbf).toBe(c.iat);
  });

  it('sub is a valid SPIFFE agent ID', () => {
    const c = buildPassportClaims(opts);
    expect(c.sub).toBe('spiffe://vane.local/company/acme/agent/test-agent');
  });

  it('includes the provided scopes in vane.scopes', () => {
    const c = buildPassportClaims(opts);
    expect(c.vane.scopes).toEqual(['attest:write', 'tool:*']);
  });

  it('uses default companyId "demo" when omitted', () => {
    const c = buildPassportClaims({ agentName: 'x', scopes: [] });
    expect(c.sub).toContain('/company/demo/');
  });

  it('delegationChain without delegation has 2 entries (org → agent)', () => {
    const c = buildPassportClaims(opts);
    expect(c.vane.delegationChain).toHaveLength(2);
    expect(c.vane.delegationChain[0]).toContain('/company/acme');
    expect(c.vane.delegationChain[1]).toContain('/agent/test-agent');
    expect(c.act).toBeUndefined();
  });

  it('delegation chain with delegation has 3 entries and sets act', () => {
    const c = buildPassportClaims({ ...opts, delegation: 'engineering-lead' });
    expect(c.vane.delegationChain).toHaveLength(3);
    expect(c.vane.delegationChain[1]).toBe('engineering-lead');
    expect(c.act).toBeDefined();
    expect(c.act.delegatedBy).toBe('engineering-lead');
  });

  it('each call produces a unique jti', () => {
    const a = buildPassportClaims(opts);
    const b = buildPassportClaims(opts);
    expect(a.jti).not.toBe(b.jti);
  });
});

// ── signPassport ────────────────────────────────────────────────────────────

describe('signPassport', () => {
  let kp: CryptoKeyPair;
  let claims: ReturnType<typeof buildPassportClaims>;
  let token: string;

  beforeAll(async () => {
    kp     = await generateKeyPair();
    claims = buildPassportClaims({ agentName: 'sign-agent', scopes: ['attest:write'] });
    token  = await signPassport(claims, kp.privateKey);
  });

  it('produces a 3-part JWT string', () => {
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    parts.forEach(p => expect(p).toMatch(/^[A-Za-z0-9_-]+$/));
  });

  it('header decodes to EdDSA CAP+JWT', () => {
    const h = decodeHeader(token);
    expect(h?.alg).toBe('EdDSA');
    expect(h?.typ).toBe('CAP+JWT');
    expect(h?.kid).toBe('browser-demo');
  });

  it('payload contains the original claims', () => {
    const p = decodePayload(token);
    expect(p?.sub).toBe(claims.sub);
    expect(p?.vane.agentId).toBe('sign-agent');
    expect(p?.vane.scopes).toEqual(['attest:write']);
  });

  it('signature segment is non-empty', () => {
    const [, , s] = token.split('.');
    expect(s.length).toBeGreaterThan(10);
  });
});

// ── verifyPassport ──────────────────────────────────────────────────────────

describe('verifyPassport', () => {
  let kp: CryptoKeyPair;
  let token: string;
  let claims: ReturnType<typeof buildPassportClaims>;

  beforeAll(async () => {
    kp     = await generateKeyPair();
    claims = buildPassportClaims({ agentName: 'verify-agent', scopes: ['tool:*'], companyId: 'corp' });
    token  = await signPassport(claims, kp.privateKey);
  });

  it('valid token passes verification', async () => {
    const result = await verifyPassport(token, kp.publicKey);
    expect(result.valid).toBe(true);
    expect(result.claims).toBeDefined();
    expect(result.claims?.sub).toBe(claims.sub);
  });

  it('verified claims contain the original vane block', async () => {
    const result = await verifyPassport(token, kp.publicKey);
    expect(result.claims?.vane.scopes).toEqual(['tool:*']);
    expect(result.claims?.vane.org).toBe('corp');
  });

  it('tampered token fails verification', async () => {
    const tampered = tamperToken(token);
    const result   = await verifyPassport(tampered, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.claims).toBeUndefined();
  });

  it('wrong key fails verification', async () => {
    const other  = await generateKeyPair();
    const result = await verifyPassport(token, other.publicKey);
    expect(result.valid).toBe(false);
  });

  it('malformed (2-part) token returns error', async () => {
    const result = await verifyPassport('a.b', kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/malformed/);
  });

  it('empty string returns error', async () => {
    const result = await verifyPassport('', kp.publicKey);
    expect(result.valid).toBe(false);
  });
});

// ── tamperToken ─────────────────────────────────────────────────────────────

describe('tamperToken', () => {
  let token: string;

  beforeAll(async () => {
    const kp    = await generateKeyPair();
    const c     = buildPassportClaims({ agentName: 'tamper-test', scopes: ['read'] });
    token       = await signPassport(c, kp.privateKey);
  });

  it('returns a different token', () => {
    expect(tamperToken(token)).not.toBe(token);
  });

  it('maintains 3-part JWT structure', () => {
    const tampered = tamperToken(token);
    expect(tampered.split('.')).toHaveLength(3);
  });

  it('only modifies the payload segment (header and sig unchanged)', () => {
    const tampered = tamperToken(token);
    const [h1, , s1] = token.split('.');
    const [h2, , s2] = tampered.split('.');
    expect(h1).toBe(h2);   // header unchanged
    expect(s1).toBe(s2);   // original signature unchanged
  });

  it('raw payload bytes differ from original', () => {
    const tampered = tamperToken(token);
    const [, p1]   = token.split('.');
    const [, p2]   = tampered.split('.');
    expect(p1).not.toBe(p2);
  });

  it('is idempotent when applied twice (double-flip restores original)', () => {
    // XOR with 0xff twice is the identity
    const roundtrip = tamperToken(tamperToken(token));
    expect(roundtrip).toBe(token);
  });

  it('tampered token fails Ed25519 verification', async () => {
    const kp      = await generateKeyPair();
    const c       = buildPassportClaims({ agentName: 'ta', scopes: [] });
    const t       = await signPassport(c, kp.privateKey);
    const tampered = tamperToken(t);
    const result  = await verifyPassport(tampered, kp.publicKey);
    expect(result.valid).toBe(false);
  });
});

// ── validateJwtStructure ────────────────────────────────────────────────────

describe('validateJwtStructure', () => {
  it('accepts a well-formed signed token', async () => {
    const kp  = await generateKeyPair();
    const c   = buildPassportClaims({ agentName: 'v', scopes: [] });
    const tok = await signPassport(c, kp.privateKey);
    expect(validateJwtStructure(tok).valid).toBe(true);
  });

  it('rejects null', () => {
    expect(validateJwtStructure(null as unknown as string).valid).toBe(false);
  });

  it('rejects a number', () => {
    expect(validateJwtStructure(42 as unknown as string).valid).toBe(false);
  });

  it('rejects a 2-part token', () => {
    expect(validateJwtStructure('abc.def').valid).toBe(false);
    expect(validateJwtStructure('abc.def').error).toMatch(/parts/);
  });

  it('rejects a 4-part token', () => {
    expect(validateJwtStructure('a.b.c.d').valid).toBe(false);
  });

  it('rejects a part with invalid base64url chars', () => {
    expect(validateJwtStructure('a b.c.d').valid).toBe(false);
  });
});
