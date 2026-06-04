import { createHash } from 'node:crypto';
import { canonicalize } from './signer.js';
import type { AttestationRecord, DelegationInfo } from './types.js';

/**
 * The record "leaf data" hashing, factored into one place so the append path
 * (`AttestationChain`) and every standalone verifier compute byte-identical
 * record hashes. A second copy of this logic would be a silent
 * forgery-acceptance bug the day the two drifted apart.
 *
 * Preimage:  index | timestamp | canonicalize(payload) [ | canonicalize(delegation) ]
 * Record hash = SHA-256(preimage), lowercase hex. This hash is the leaf DATA the
 * RFC 6962 Merkle tree (and thus every Signed Tree Head) commits to.
 */
export function recordLeafPreimage(
  index: number,
  timestamp: string,
  payload: unknown,
  delegation?: DelegationInfo,
): string {
  const base = `${index}|${timestamp}|${canonicalize(payload)}`;
  return delegation ? `${base}|${canonicalize(delegation)}` : base;
}

/** SHA-256 (hex) of a record's leaf preimage — the value stored as `record.hash`. */
export function computeRecordHash(
  record: Pick<AttestationRecord, 'index' | 'timestamp' | 'payload' | 'delegation'>,
): string {
  return createHash('sha256')
    .update(recordLeafPreimage(record.index, record.timestamp, record.payload, record.delegation))
    .digest('hex');
}
