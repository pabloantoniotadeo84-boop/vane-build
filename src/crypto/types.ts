export interface KeyPair {
  publicKey: string;  // SPKI PEM
  privateKey: string; // PKCS8 PEM
}

export interface AttestationRecord {
  index: number;
  timestamp: string;    // ISO 8601
  payload: unknown;
  previousHash: string; // SHA-256 hex; 64 zeros for the genesis record
  hash: string;         // SHA-256 hex of this record's canonical preimage
  signature: string;    // Ed25519 sig over `hash`, base64url-encoded
}

export interface VerificationResult {
  valid: boolean;
  failedAtIndex?: number;
  error?: string;
}
