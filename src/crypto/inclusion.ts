import { computeRecordHash } from './record-hash.js';
import {
  rfc6962RootHex,
  rfc6962LeafHashHex,
  inclusionProofHex,
  verifyInclusionHex,
  type InclusionProofNode,
} from './rfc6962.js';
import { verifySTH, type SignedTreeHead } from './sth.js';
import type { AttestationRecord } from './types.js';

/**
 * A self-contained inclusion proof: everything a third party needs to verify
 * that one attestation record is committed by a CA-signed Signed Tree Head,
 * using ONLY this object and the CA public key — no database, no trust in the
 * Vane server.
 *
 * The Merkle proof is built on the SAME RFC 6962 tree the STH commits to, so
 * `root === sth.rootHash`. (The legacy `GET /v1/proof/:index` instead used the
 * pad-to-power-of-two tree in merkle.ts, whose root is unsigned and never
 * equals an STH root — it could not be anchored to the CA key.)
 */
export interface InclusionProofResponse {
  companyId: string;
  agentId: string;
  /** Chain index of the record == its Merkle leaf index. */
  index: number;
  /** Tree size the proof is built against == sth.treeSize. */
  treeSize: number;
  record: AttestationRecord;
  /** RFC 6962 leaf hash = SHA-256(0x00 || record.hash), lowercase hex. */
  leafHash: string;
  /** RFC 6962 audit path, leaf → root. */
  proof: InclusionProofNode[];
  /** RFC 6962 root over the first `treeSize` leaves == sth.rootHash. */
  root: string;
  /** The CA-signed commitment the root is anchored to. */
  sth: SignedTreeHead;
  /** CA public key (SPKI PEM) — convenience only; a careful auditor pins their own. */
  caPublicKey: string;
  caKid: string;
  signatureAlgorithm: 'EdDSA';
}

export interface BuildInclusionProofOptions {
  companyId: string;
  agentId: string;
  index: number;
  record: AttestationRecord;
  /** All record (leaf) hashes for the company in chain order. */
  leafHashes: string[];
  /** Latest CA-signed STH for the company. */
  sth: SignedTreeHead;
  caPublicKey: string;
  caKid: string;
}

/**
 * Builds an inclusion proof against the tree the STH commits to (`sth.treeSize`).
 * Throws if `index` is not within that checkpointed tree — a record not yet
 * covered by a checkpoint has no anchored proof.
 */
export function buildInclusionProof(opts: BuildInclusionProofOptions): InclusionProofResponse {
  const { companyId, agentId, index, record, leafHashes, sth, caPublicKey, caKid } = opts;
  const size = sth.treeSize;
  if (!Number.isInteger(index) || index < 0 || index >= size) {
    throw new RangeError(`index ${index} is not within the checkpointed tree size ${size}`);
  }
  if (leafHashes.length < size) {
    throw new RangeError(`have ${leafHashes.length} leaves but the checkpoint commits to ${size}`);
  }
  // Build the proof and root over exactly the leaves the STH commits to, so the
  // reconstructed root equals sth.rootHash even if the chain has since grown.
  const leaves = leafHashes.slice(0, size);
  return {
    companyId,
    agentId,
    index,
    treeSize: size,
    record,
    leafHash: rfc6962LeafHashHex(record.hash),
    proof: inclusionProofHex(index, leaves),
    root: rfc6962RootHex(leaves),
    sth,
    caPublicKey,
    caKid,
    signatureAlgorithm: 'EdDSA',
  };
}

/**
 * Structured result of a standalone inclusion verification. On success the
 * verified anchor (index, treeSize, root) is echoed back; on failure `reason`
 * names the exact check that failed.
 */
export interface InclusionVerificationResult {
  valid: boolean;
  reason?: string;
  index?: number;
  treeSize?: number;
  root?: string;
}

function fail(reason: string): InclusionVerificationResult {
  return { valid: false, reason };
}

/**
 * Standalone inclusion-proof verifier. A third party runs this with nothing but
 * the proof JSON and a pinned CA public key — no Vane server, no database, no
 * network. It depends only on the crypto primitives (RFC 6962 Merkle math, the
 * record-hash rule, and STH signature verification).
 *
 * It verifies, in order:
 *   1. the STH signature is valid under the supplied CA public key;
 *   2. the record's `hash` is the correct hash of the record contents;
 *   3. the RFC 6962 leaf hash is correctly derived from that record hash;
 *   4. the Merkle path from the leaf reconstructs the claimed root;
 *   5. the claimed root equals the root the STH commits to.
 *
 * Fail-closed: any malformed field or thrown error yields { valid: false }.
 */
export function verifyInclusionProof(
  proof: InclusionProofResponse,
  caPublicKey: string,
): InclusionVerificationResult {
  try {
    if (!proof || typeof proof !== 'object') return fail('proof is missing or not an object');
    const { record, sth } = proof;
    if (!record || typeof record !== 'object') return fail('proof.record is missing');
    if (!sth || typeof sth !== 'object') return fail('proof.sth is missing');
    if (typeof caPublicKey !== 'string' || !caPublicKey) return fail('CA public key is missing');

    // 1. The Signed Tree Head must be authentic under the pinned CA key. This is
    //    the only trust anchor; everything else hangs off it.
    if (!verifySTH(sth, caPublicKey)) {
      return fail('STH signature is not valid under the provided CA public key');
    }

    // 2. The record's self-reported hash must be the true hash of its contents.
    let recomputedHash: string;
    try {
      recomputedHash = computeRecordHash(record);
    } catch (err) {
      return fail(`record hash could not be computed: ${(err as Error).message}`);
    }
    if (record.hash !== recomputedHash) {
      return fail('record hash does not match the record contents (record was altered)');
    }

    // 3. The RFC 6962 leaf hash must be derived from that record hash.
    const expectedLeafHash = rfc6962LeafHashHex(recomputedHash);
    if (proof.leafHash !== expectedLeafHash) {
      return fail('leaf hash is not SHA-256(0x00 || record.hash)');
    }

    // 4. The Merkle path must reconstruct the claimed root from the leaf.
    if (!verifyInclusionHex(expectedLeafHash, proof.proof, proof.root)) {
      return fail('Merkle inclusion path does not reconstruct the claimed root');
    }

    // 5. The claimed root must be exactly what the CA-signed STH commits to.
    if (proof.root !== sth.rootHash) {
      return fail('proof root does not match the CA-signed STH root');
    }

    return { valid: true, index: record.index, treeSize: sth.treeSize, root: proof.root };
  } catch (err) {
    return fail(`verification error: ${(err as Error).message}`);
  }
}
