import type { AttestationRecord, VerificationResult } from './types.js';
export declare class AttestationChain {
    private readonly records;
    /** Load pre-existing records (e.g. from DB) without re-signing. */
    hydrate(records: AttestationRecord[]): void;
    /**
     * Appends a new record, signs its hash with the given private key,
     * and links it to the previous record's hash.
     */
    append(payload: unknown, privateKeyPem: string): AttestationRecord;
    /**
     * Verifies the entire chain:
     *   1. Each record's hash matches recomputed hash of its fields.
     *   2. Each previousHash matches the prior record's hash (chain linkage).
     *   3. Each signature over the hash is valid under the given public key.
     *
     * Any single failure indicates tampering and returns which record broke and why.
     */
    verify(publicKeyPem: string): VerificationResult;
    getRecords(): ReadonlyArray<AttestationRecord>;
    get length(): number;
}
//# sourceMappingURL=chain.d.ts.map