import { rfc6962RootHex } from '../crypto/rfc6962.js';
import { signSTH, type SignedTreeHead } from '../crypto/sth.js';
import type { AttestationChain } from '../crypto/chain.js';
import type { AttestationRecord, DelegationInfo } from '../crypto/types.js';

/**
 * Atomic persistence port for an attestation append.
 *
 * Implementations MUST persist the record and its Signed Tree Head inside a
 * single transaction. `buildSth` is invoked *inside* that transaction; if it
 * throws (a signing failure), the implementation MUST roll back so the record
 * is not written. The committed STH is returned.
 *
 * The Postgres implementation is `Store.appendRecordWithSTH`. Tests inject an
 * in-memory implementation that snapshots/rolls back the same way, so the
 * orchestration below is exercised without a database.
 */
export type AtomicAppend = (
  record: AttestationRecord,
  buildSth: () => SignedTreeHead,
) => Promise<SignedTreeHead>;

export interface AppendResult {
  record: AttestationRecord;
  sth: SignedTreeHead;
}

export interface AppendOptions {
  chain: AttestationChain;
  /** Per-company key — signs the attestation record. */
  signingPrivateKey: string;
  /** Global Vane CA key — signs the Signed Tree Head. */
  caPrivateKey: string;
  payload: unknown;
  delegation?: DelegationInfo;
  persist: AtomicAppend;
  /** Injectable clock (epoch ms) for deterministic tests. Defaults to Date.now. */
  now?: () => number;
}

/**
 * Appends one record to the log and atomically commits a Signed Tree Head over
 * the new tree state.
 *
 * Ordering is the safety property: the in-memory chain only advances *after*
 * the persistence layer has committed both the record and a valid STH. If
 * signing fails or the transaction is rolled back, `persist` throws and the
 * in-memory chain is left untouched — there is never a record without an STH,
 * in memory or on disk.
 */
export async function appendWithCheckpoint(opts: AppendOptions): Promise<AppendResult> {
  const { chain, signingPrivateKey, caPrivateKey, payload, delegation, persist } = opts;
  const now = opts.now ?? Date.now;

  // 1. Compute the next record without mutating the chain.
  const record = chain.computeNextRecord(payload, signingPrivateKey, delegation);

  // 2. The STH must commit to every existing leaf plus this new one.
  const leaves = [...chain.currentLeafHashes(), record.hash];

  // 3. STH builder, invoked inside the persistence transaction. A throw here
  //    (e.g. CA signing failure) rolls the whole append back.
  const buildSth = (): SignedTreeHead =>
    signSTH({ rootHash: rfc6962RootHex(leaves), treeSize: leaves.length, timestamp: now() }, caPrivateKey);

  // 4. Atomically persist record + STH. Throws (without committing) on failure.
  const sth = await persist(record, buildSth);

  // 5. Commit succeeded — advance in-memory state.
  chain.push(record);
  chain.setLatestSth(sth);

  return { record, sth };
}

/**
 * Per-key async serializer. Calls submitted for the same key run strictly one
 * at a time, in submission order; a failed call does not block later calls.
 *
 * Appends for one company are serialized through this so each STH commits to
 * the exact in-memory leaf set that matches the persisted log — concurrent
 * appends would otherwise compute the same index / tree size and collide on the
 * (company_id, idx) / (company_id, tree_size) primary keys.
 */
export function createKeyedQueue(): <T>(key: string, fn: () => Promise<T>) => Promise<T> {
  const tails = new Map<string, Promise<unknown>>();
  return function run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = tails.get(key) ?? Promise.resolve();
    const next = prev.then(fn, fn); // run regardless of whether the prior call failed
    // The stored tail must never reject, or the next call would inherit it.
    tails.set(key, next.then(() => undefined, () => undefined));
    return next;
  };
}
