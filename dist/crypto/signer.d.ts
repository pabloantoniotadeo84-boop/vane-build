import type { VerificationResult } from './types.js';
/**
 * Deterministic JSON serialization: keys sorted recursively.
 * Accepts any JSON-serializable value; undefined/Symbol/function are not supported.
 */
export declare function canonicalize(value: unknown): string;
export declare function signPayload(payload: unknown, privateKeyPem: string): string;
export declare function verifyPayload(payload: unknown, signature: string, publicKeyPem: string): VerificationResult;
//# sourceMappingURL=signer.d.ts.map