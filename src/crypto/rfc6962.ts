import { createHash } from 'node:crypto';

/**
 * RFC 6962 (Certificate Transparency) Merkle tree primitives.
 *
 * This module is intentionally separate from `merkle.ts`. `merkle.ts` implements
 * the original Vane inclusion-proof tree (pad-to-power-of-two by repeating the
 * last leaf) and is kept unchanged so existing inclusion proofs and their tests
 * keep working. The Signed-Tree-Head / checkpoint subsystem instead uses the
 * *standard* RFC 6962 tree, because Step 4's consistency proofs are defined only
 * for that construction (RFC 6962 §2.1.2) and are interoperable with CT tooling.
 *
 * RFC 6962 §2.1 tree hashing:
 *   - empty tree:   MTH({})      = SHA-256()                       (hash of empty input)
 *   - single leaf:  MTH({d0})    = SHA-256(0x00 || d0)             (leaf hash)
 *   - n > 1 leaves: MTH(D[n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
 *                   where k is the largest power of two strictly less than n.
 *
 * Leaf "data" here is the 32 raw bytes of each attestation record's SHA-256
 * `hash` field. All public functions take/return lowercase hex strings to match
 * the rest of the codebase; bytes are used only internally.
 */

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...chunks: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const c of chunks) h.update(c);
  return h.digest();
}

/** RFC 6962 leaf hash: SHA-256(0x00 || leafData). */
function hashLeaf(leafData: Buffer): Buffer {
  return sha256(LEAF_PREFIX, leafData);
}

/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
function hashChildren(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

/** Largest power of two strictly less than n (n > 1). e.g. 7→4, 8→4, 2→1. */
function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/** RFC 6962 §2.1 Merkle Tree Hash over a list of leaf-data buffers. */
function merkleTreeHash(leaves: Buffer[]): Buffer {
  const n = leaves.length;
  if (n === 0) return sha256(Buffer.alloc(0));
  if (n === 1) return hashLeaf(leaves[0]);
  const k = largestPowerOfTwoLessThan(n);
  return hashChildren(merkleTreeHash(leaves.slice(0, k)), merkleTreeHash(leaves.slice(k, n)));
}

/**
 * RFC 6962 §2.1.2 SUBPROOF(m, D, b). Returns the ordered list of node hashes
 * that prove the tree of size `m` is a prefix of the tree over `leaves`.
 * `b` is true while this subtree's root is the (known) root of the old tree.
 */
function subproof(m: number, leaves: Buffer[], b: boolean): Buffer[] {
  const n = leaves.length;
  if (m === n) {
    // The whole subtree is the old tree. If b, the verifier already has its
    // root (the old STH root) and no node is emitted; otherwise emit it.
    return b ? [] : [merkleTreeHash(leaves)];
  }
  const k = largestPowerOfTwoLessThan(n);
  if (m <= k) {
    // Old tree lives entirely in the left child; prove there, then pin the
    // right child's hash.
    return [...subproof(m, leaves.slice(0, k), b), merkleTreeHash(leaves.slice(k, n))];
  }
  // Left child is fully shared; recurse into the right child (no longer the
  // old root, so b=false), then pin the left child's hash.
  return [...subproof(m - k, leaves.slice(k, n), false), merkleTreeHash(leaves.slice(0, k))];
}

// ── Public hex API ─────────────────────────────────────────────────────────────

function toLeaves(leafHashesHex: string[]): Buffer[] {
  return leafHashesHex.map((h) => Buffer.from(h, 'hex'));
}

/** RFC 6962 Merkle Tree Hash (root) over the given record hashes. Hex in, hex out. */
export function rfc6962RootHex(leafHashesHex: string[]): string {
  return merkleTreeHash(toLeaves(leafHashesHex)).toString('hex');
}

/**
 * RFC 6962 §2.1.2 consistency proof that the tree of size `first` is a prefix
 * of the tree over `leafHashesHex` (whose length is the second/larger size).
 *
 * Returns a list of SHA-256 node hashes (hex). Trivial cases (first === 0,
 * first === second) return an empty proof.
 */
export function consistencyProofHex(first: number, leafHashesHex: string[]): string[] {
  const n = leafHashesHex.length;
  if (!Number.isInteger(first) || first < 0 || first > n) {
    throw new RangeError(`consistency proof: first=${first} out of range [0, ${n}]`);
  }
  if (first === 0 || first === n) return [];
  return subproof(first, toLeaves(leafHashesHex), true).map((b) => b.toString('hex'));
}

/**
 * Standalone RFC 6962 consistency-proof verifier.
 *
 * Reconstructs both the old root (size `first`) and the new root (size
 * `second`) purely from the two sizes and the proof — it needs NO access to the
 * log, the leaves, or any database. A third party holding two Signed Tree Heads
 * (which carry `rootHash` and `treeSize`) plus the proof can call this directly.
 *
 * Fail-closed: any malformed input, bad length, or unconsumed/over-consumed
 * proof node returns `false` rather than throwing.
 */
export function verifyConsistencyHex(
  first: number,
  second: number,
  firstRootHex: string,
  secondRootHex: string,
  proofHex: string[],
): boolean {
  try {
    if (
      !Number.isInteger(first) || !Number.isInteger(second) ||
      first < 0 || second < 0 || first > second
    ) {
      return false;
    }
    if (!Array.isArray(proofHex)) return false;

    // Empty old tree is consistent with anything; the proof must be empty.
    if (first === 0) return proofHex.length === 0;
    // Equal sizes: identical roots, empty proof.
    if (first === second) return proofHex.length === 0 && firstRootHex === secondRootHex;

    const firstRoot = Buffer.from(firstRootHex, 'hex');
    const secondRoot = Buffer.from(secondRootHex, 'hex');
    if (firstRoot.length !== 32 || secondRoot.length !== 32) return false;

    const cursor = { items: proofHex.map((h) => Buffer.from(h, 'hex')), i: 0 };
    const [oldRoot, newRoot] = subverify(first, second, true, cursor, firstRoot);

    // Every proof node must be consumed exactly once, and both reconstructed
    // roots must match the claimed STH roots.
    return cursor.i === cursor.items.length && oldRoot.equals(firstRoot) && newRoot.equals(secondRoot);
  } catch {
    return false;
  }
}

interface Cursor {
  items: Buffer[];
  i: number;
}

function nextNode(cursor: Cursor): Buffer {
  if (cursor.i >= cursor.items.length) throw new RangeError('consistency proof: ran out of nodes');
  const node = cursor.items[cursor.i++];
  if (node.length !== 32) throw new RangeError('consistency proof: node is not 32 bytes');
  return node;
}

/**
 * Mirror of `subproof` that consumes proof nodes from the front in the exact
 * order the prover appended them, returning the reconstructed
 * [oldRoot, newRoot] for the (m, n) subtree.
 */
function subverify(m: number, n: number, b: boolean, cursor: Cursor, firstRoot: Buffer): [Buffer, Buffer] {
  if (m === n) {
    // b: this subtree IS the old tree → its root (old and new) is the known
    // old root. Otherwise the prover supplied the shared subtree root.
    if (b) return [firstRoot, firstRoot];
    const node = nextNode(cursor);
    return [node, node];
  }
  const k = largestPowerOfTwoLessThan(n);
  if (m <= k) {
    const [oldLeft, newLeft] = subverify(m, k, b, cursor, firstRoot);
    const right = nextNode(cursor); // MTH(right child) appended by the prover
    // Old tree is wholly within the left child; new tree combines both.
    return [oldLeft, hashChildren(newLeft, right)];
  }
  const [oldRight, newRight] = subverify(m - k, n - k, false, cursor, firstRoot);
  const left = nextNode(cursor); // MTH(left child) appended by the prover
  return [hashChildren(left, oldRight), hashChildren(left, newRight)];
}
