import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

import { verifyPassport, type VerifyPassportOptions } from '../src/passport/verify.js';
import {
  verifyPassportReference,
  type ReferenceVerifyOptions,
  type ReferenceVerificationResult,
} from '../conformance/reference-verifier.js';

// =============================================================================
// Conformance harness.
//
// Every vector in conformance/vectors.json is run through TWO independent
// verifiers and the results are required to agree, both with each other and
// with the vector's recorded expectation:
//
//   1. The PRODUCTION verifier — src/passport/verify.ts (verifyPassport).
//      It is the offline cryptographic + claims core. It does NOT consult a
//      revocation list, so the harness layers revocation on top exactly as the
//      Vane server does (app.ts: store.isPassportRevoked AFTER verifyPassport).
//
//   2. The REFERENCE verifier — conformance/reference-verifier.ts. A
//      self-contained re-implementation that a third party would port. It
//      performs the revocation check internally as its final step.
//
// If the two ever drift, this test fails and pinpoints the offending vector.
// =============================================================================

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

interface VectorFile {
  vectorCount: number;
  vectors: Vector[];
}

const vectorFile = JSON.parse(
  readFileSync(new URL('../conformance/vectors.json', import.meta.url), 'utf8'),
) as VectorFile;

const VECTORS = vectorFile.vectors;

// A normalized view used for comparison across the two verifiers.
interface NormalResult {
  valid: boolean;
  code?: string;
  scopeGranted?: string;
}

function normalize(
  r: ReferenceVerificationResult | ReturnType<typeof verifyPassport>,
): NormalResult {
  return r.valid
    ? { valid: true, scopeGranted: r.scopeGranted }
    : { valid: false, code: r.code };
}

/**
 * Production verification as the live Vane stack performs it: the offline
 * verifyPassport core, then a revocation check keyed on the passport's jti.
 * This mirrors src/api/app.ts (verifyPassport → store.isPassportRevoked).
 */
function runProduction(v: Vector): NormalResult {
  const opts: VerifyPassportOptions = {
    caPublicKey: v.inputs.caPublicKey,
    ...(v.inputs.tool !== undefined && { tool: v.inputs.tool }),
    ...(v.inputs.expectedNonce !== undefined && { expectedNonce: v.inputs.expectedNonce }),
    ...(v.inputs.expectedAudience !== undefined && { expectedAudience: v.inputs.expectedAudience }),
    ...(v.inputs.expectedRequestHash !== undefined && { expectedRequestHash: v.inputs.expectedRequestHash }),
    ...(v.inputs.now !== undefined && { now: v.inputs.now }),
    ...(v.inputs.clockSkewSeconds !== undefined && { clockSkewSeconds: v.inputs.clockSkewSeconds }),
  };

  const result = verifyPassport(v.token, opts);

  if (result.valid && v.inputs.revokedJtis?.includes(result.claims.jti)) {
    return { valid: false, code: 'PASSPORT_REVOKED' };
  }
  return normalize(result);
}

/** Reference verification: the full algorithm including revocation, in one call. */
function runReference(v: Vector): NormalResult {
  const opts: ReferenceVerifyOptions = {
    caPublicKey: v.inputs.caPublicKey,
    ...(v.inputs.tool !== undefined && { tool: v.inputs.tool }),
    ...(v.inputs.expectedNonce !== undefined && { expectedNonce: v.inputs.expectedNonce }),
    ...(v.inputs.expectedAudience !== undefined && { expectedAudience: v.inputs.expectedAudience }),
    ...(v.inputs.expectedRequestHash !== undefined && { expectedRequestHash: v.inputs.expectedRequestHash }),
    ...(v.inputs.now !== undefined && { now: v.inputs.now }),
    ...(v.inputs.clockSkewSeconds !== undefined && { clockSkewSeconds: v.inputs.clockSkewSeconds }),
    ...(v.inputs.revokedJtis !== undefined && { revokedJtis: v.inputs.revokedJtis }),
  };
  return normalize(verifyPassportReference(v.token, opts));
}

describe('Passport conformance vectors', () => {
  it('loads at least 10 vectors', () => {
    expect(VECTORS.length).toBeGreaterThanOrEqual(10);
    expect(VECTORS.length).toBe(vectorFile.vectorCount);
  });

  it.each(VECTORS.map((v) => [v.name, v] as const))(
    'vector "%s": production and reference verifiers agree and match the expectation',
    (_name, v) => {
      const prod = runProduction(v);
      const ref = runReference(v);

      // 1. The two verifiers must agree with each other (catches spec drift).
      expect(prod).toEqual(ref);

      // 2. Both must match the vector's recorded expectation.
      expect(prod.valid).toBe(v.expected.valid);
      if (v.expected.valid) {
        expect(prod.scopeGranted).toBe(v.expected.scopeGranted);
      } else {
        expect(prod.code).toBe(v.expected.code);
      }
    },
  );
});

// ── Coverage assertion ───────────────────────────────────────────────────────
// Guards that the required scenarios from the conformance brief are all present,
// so the suite can never silently lose a case during a future regeneration.
describe('Conformance coverage', () => {
  const byName = new Map(VECTORS.map((v) => [v.name, v]));
  const codeOf = (name: string) => {
    const e = byName.get(name)?.expected;
    return e && !e.valid ? e.code : undefined;
  };

  it('covers every required scenario', () => {
    // valid that must verify
    expect(byName.get('valid-passport')?.expected.valid).toBe(true);
    // a cross-org token that must verify
    expect(byName.get('cross-org-valid')?.expected.valid).toBe(true);
    // a nonce passport that passes with the correct nonce
    expect(byName.get('nonce-correct')?.expected.valid).toBe(true);

    // each required failure maps to its required code
    expect(codeOf('expired-passport')).toBe('TOKEN_EXPIRED');
    expect(codeOf('bad-signature')).toBe('SIGNATURE_INVALID');
    expect(codeOf('tampered-payload')).toBe('SIGNATURE_INVALID');
    expect(codeOf('wrong-audience')).toBe('AUDIENCE_MISMATCH');
    expect(codeOf('nonce-mismatch')).toBe('NONCE_MISMATCH');
    expect(codeOf('nbf-in-future')).toBe('TOKEN_NOT_YET_VALID');
    expect(codeOf('invalid-delegation-chain')).toBe('CHAIN_INCOHERENT');
    expect(codeOf('revoked-passport')).toBe('PASSPORT_REVOKED');
  });
});
