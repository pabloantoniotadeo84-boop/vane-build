import { createHash } from 'node:crypto';
import { canonicalize, signPayload, verifyPayload } from './signer.js';
import type { AttestationRecord, VerificationResult } from './types.js';

const GENESIS_HASH = '0'.repeat(64);

function buildPreimage(
  index: number,
  timestamp: string,
  payload: unknown,
  previousHash: string,
): string {
  // Pipe-delimited with canonicalized payload — unambiguous across field types.
  return `${index}|${timestamp}|${canonicalize(payload)}|${previousHash}`;
}

function sha256hex(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

export class AttestationChain {
  private readonly records: AttestationRecord[] = [];

  /** Load pre-existing records (e.g. from DB) without re-signing. */
  hydrate(records: AttestationRecord[]): void {
    if (this.records.length > 0) throw new Error('hydrate() must be called on an empty chain');
    this.records.push(...records);
  }

  /**
   * Appends a new record, signs its hash with the given private key,
   * and links it to the previous record's hash.
   */
  append(payload: unknown, privateKeyPem: string): AttestationRecord {
    const index = this.records.length;
    const timestamp = new Date().toISOString();
    const previousHash = index === 0 ? GENESIS_HASH : this.records[index - 1].hash;

    const hash = sha256hex(buildPreimage(index, timestamp, payload, previousHash));
    const signature = signPayload(hash, privateKeyPem);

    const record: AttestationRecord = { index, timestamp, payload, previousHash, hash, signature };
    this.records.push(record);
    return record;
  }

  /**
   * Verifies the entire chain:
   *   1. Each record's hash matches recomputed hash of its fields.
   *   2. Each previousHash matches the prior record's hash (chain linkage).
   *   3. Each signature over the hash is valid under the given public key.
   *
   * Any single failure indicates tampering and returns which record broke and why.
   */
  verify(publicKeyPem: string): VerificationResult {
    for (let i = 0; i < this.records.length; i++) {
      const rec = this.records[i];

      const expectedPrev = i === 0 ? GENESIS_HASH : this.records[i - 1].hash;
      if (rec.previousHash !== expectedPrev) {
        return { valid: false, failedAtIndex: i, error: `record ${i}: chain linkage broken` };
      }

      const expectedHash = sha256hex(
        buildPreimage(rec.index, rec.timestamp, rec.payload, rec.previousHash),
      );
      if (rec.hash !== expectedHash) {
        return { valid: false, failedAtIndex: i, error: `record ${i}: hash mismatch — record was tampered` };
      }

      const sigCheck = verifyPayload(rec.hash, rec.signature, publicKeyPem);
      if (!sigCheck.valid) {
        return { valid: false, failedAtIndex: i, error: `record ${i}: invalid signature` };
      }
    }
    return { valid: true };
  }

  getRecords(): ReadonlyArray<AttestationRecord> {
    return this.records;
  }

  get length(): number {
    return this.records.length;
  }
}
