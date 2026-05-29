export interface KeyPair {
    publicKey: string;
    privateKey: string;
}
export interface AttestationRecord {
    index: number;
    timestamp: string;
    payload: unknown;
    previousHash: string;
    hash: string;
    signature: string;
}
export interface VerificationResult {
    valid: boolean;
    failedAtIndex?: number;
    error?: string;
}
//# sourceMappingURL=types.d.ts.map