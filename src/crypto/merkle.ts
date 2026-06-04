import { createHash } from 'node:crypto';

export interface ProofNode {
  sibling: string;
  position: 'left' | 'right'; // position of the sibling in the pair
}

export type MerkleProof = ProofNode[];

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function hashPair(left: string, right: string): string {
  return sha256(left + right);
}

// Pad to the next power of two by repeating the last leaf.
function pad(hashes: string[]): string[] {
  let size = 1;
  while (size < hashes.length) size <<= 1;
  const out = [...hashes];
  while (out.length < size) out.push(hashes[hashes.length - 1]);
  return out;
}

// Returns levels[0] = padded leaves, levels[last] = [root].
function buildLevels(leaves: string[]): string[][] {
  const levels: string[][] = [pad(leaves)];
  let current = levels[0];
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(hashPair(current[i], current[i + 1]));
    }
    levels.push(next);
    current = next;
  }
  return levels;
}

export function computeRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) return '0'.repeat(64);
  const levels = buildLevels(leafHashes);
  return levels[levels.length - 1][0];
}

export function buildProof(leafHashes: string[], index: number): MerkleProof {
  if (index < 0 || index >= leafHashes.length) {
    throw new RangeError(`index ${index} out of bounds (length: ${leafHashes.length})`);
  }
  const levels = buildLevels(leafHashes);
  const proof: MerkleProof = [];
  let idx = index;
  for (let level = 0; level < levels.length - 1; level++) {
    const isRightChild = idx % 2 === 1;
    const siblingIdx = isRightChild ? idx - 1 : idx + 1;
    proof.push({
      sibling: levels[level][siblingIdx],
      position: isRightChild ? 'left' : 'right',
    });
    idx = Math.floor(idx / 2);
  }
  return proof;
}

// O(log n): walk the proof path and compare against the expected root.
// Fail closed: any error while walking a malformed proof returns false (proof
// not verified), never a throw that a caller might treat as inconclusive/allow.
export function verifyProof(leafHash: string, proof: MerkleProof, root: string): boolean {
  try {
    let current = leafHash;
    for (const node of proof) {
      current = node.position === 'left'
        ? hashPair(node.sibling, current)
        : hashPair(current, node.sibling);
    }
    return current === root;
  } catch {
    return false;
  }
}
