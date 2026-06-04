import { createHash } from 'node:crypto';
import { canonicalize, signPayload, verifyPayload } from './signer.js';
import { computeRoot, buildProof, verifyProof, type MerkleProof } from './merkle.js';
import type { AttestationRecord, DelegationInfo, VerificationResult } from './types.js';

export type { MerkleProof } from './merkle.js';

export interface InclusionProof {
  record: AttestationRecord;
  proof: MerkleProof;
  root: string;
}

function leafPreimage(index: number, timestamp: string, payload: unknown, delegation?: DelegationInfo): string {
  const base = `${index}|${timestamp}|${canonicalize(payload)}`;
  return delegation ? `${base}|${canonicalize(delegation)}` : base;
}

function sha256hex(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

export class AttestationChain {
  private readonly records: AttestationRecord[] = [];

  hydrate(records: AttestationRecord[]): void {
    if (this.records.length > 0) throw new Error('hydrate() must be called on an empty chain');
    this.records.push(...records);
  }

  append(payload: unknown, privateKeyPem: string, delegation?: DelegationInfo): AttestationRecord {
    const index = this.records.length;
    const timestamp = new Date().toISOString();
    const hash = sha256hex(leafPreimage(index, timestamp, payload, delegation));
    const signature = signPayload(hash, privateKeyPem);
    const record: AttestationRecord = { index, timestamp, payload, ...(delegation && { delegation }), hash, signature };
    this.records.push(record);
    return record;
  }

  /**
   * Verifies every record's hash and signature, then returns the Merkle root.
   * Full-chain integrity check is O(n); single-record proof verification via
   * getProof() is O(log n).
   */
  verify(publicKeyPem: string): VerificationResult {
    const leafHashes: string[] = [];

    for (let i = 0; i < this.records.length; i++) {
      const rec = this.records[i];

      // Fail closed: a throw while recomputing the hash (e.g. an un-canonicalizable
      // payload) means the record cannot be trusted — treat it as a verification
      // failure at this index, never as a pass.
      try {
        const expectedHash = sha256hex(leafPreimage(rec.index, rec.timestamp, rec.payload, rec.delegation));
        if (rec.hash !== expectedHash) {
          return { valid: false, failedAtIndex: i, error: `record ${i}: hash mismatch` };
        }

        const sigCheck = verifyPayload(rec.hash, rec.signature, publicKeyPem);
        if (!sigCheck.valid) {
          return { valid: false, failedAtIndex: i, error: `record ${i}: invalid signature` };
        }

        leafHashes.push(rec.hash);
      } catch (err) {
        return { valid: false, failedAtIndex: i, error: `record ${i}: verification error: ${(err as Error).message}` };
      }
    }

    try {
      return { valid: true, merkleRoot: computeRoot(leafHashes) };
    } catch (err) {
      return { valid: false, error: `merkle root computation failed: ${(err as Error).message}` };
    }
  }

  /** O(log n): returns an inclusion proof any external auditor can verify independently. */
  getProof(index: number): InclusionProof {
    if (index < 0 || index >= this.records.length) {
      throw new RangeError(`index ${index} out of bounds (chain length: ${this.records.length})`);
    }
    const leafHashes = this.records.map((r) => r.hash);
    return {
      record: this.records[index],
      proof: buildProof(leafHashes, index),
      root: computeRoot(leafHashes),
    };
  }

  /** Verify a proof externally without access to the full chain. */
  static verifyProof(leafHash: string, proof: MerkleProof, root: string): boolean {
    return verifyProof(leafHash, proof, root);
  }

  getRecords(): ReadonlyArray<AttestationRecord> {
    return this.records;
  }

  get length(): number {
    return this.records.length;
  }
}
