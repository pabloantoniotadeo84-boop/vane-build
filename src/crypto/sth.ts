import {
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';

/**
 * Signed Tree Head (STH) — a CA-signed commitment to the state of an
 * attestation log at a point in time.
 *
 * The STH is signed with Vane's *global* CA key, never a per-company key. That
 * is the whole point: a company key lives in the same database the operator
 * controls, so a self-signed root proves nothing against a malicious operator.
 * The CA key is the instance-wide root of trust; an external auditor needs only
 * the CA public key to verify any checkpoint from any company.
 *
 * The signature covers (rootHash || treeSize || timestamp) under a fixed
 * domain-separation context so an STH signature can never be replayed as some
 * other Vane signature (and vice-versa). The serialization below is injective:
 * rootHash is fixed-width lowercase hex and treeSize/timestamp are decimal
 * integers, so the '\n' delimiter cannot occur inside any field.
 */
export interface SignedTreeHead {
  rootHash: string;  // RFC 6962 Merkle Tree Hash of the log, lowercase hex
  treeSize: number;  // number of records the root commits to
  timestamp: number; // issuance time, Unix epoch milliseconds
  signature: string; // Ed25519 over the signing input, base64url
}

/** The (rootHash, treeSize, timestamp) tuple before it is signed. */
export type STHFields = Omit<SignedTreeHead, 'signature'>;

const STH_CONTEXT = 'vane.sth.v1';
const ROOT_HEX = /^[0-9a-f]{64}$/;

/** Injective, domain-separated serialization of (root || treeSize || timestamp). */
function sthSigningInput(fields: STHFields): Buffer {
  return Buffer.from(`${STH_CONTEXT}\n${fields.rootHash}\n${fields.treeSize}\n${fields.timestamp}`, 'utf8');
}

function assertValidFields(fields: STHFields): void {
  if (typeof fields.rootHash !== 'string' || !ROOT_HEX.test(fields.rootHash)) {
    throw new Error('STH rootHash must be a 32-byte lowercase hex string');
  }
  if (!Number.isInteger(fields.treeSize) || fields.treeSize < 0) {
    throw new Error('STH treeSize must be a non-negative integer');
  }
  if (!Number.isInteger(fields.timestamp) || fields.timestamp < 0) {
    throw new Error('STH timestamp must be a non-negative integer');
  }
}

/**
 * Signs an STH with the global CA key. Throws on any invalid field or a
 * non-Ed25519 / malformed key — callers run this inside the append transaction
 * so a signing failure rolls the whole append back (no record without an STH).
 */
export function signSTH(fields: STHFields, caPrivateKeyPem: string): SignedTreeHead {
  assertValidFields(fields);
  const key = createPrivateKey(caPrivateKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`CA signing key must be Ed25519, got ${key.asymmetricKeyType}`);
  }
  const signature = cryptoSign(null, sthSigningInput(fields), key).toString('base64url');
  return { rootHash: fields.rootHash, treeSize: fields.treeSize, timestamp: fields.timestamp, signature };
}

/**
 * Verifies an STH signature against the global CA public key.
 *
 * Fail-closed: malformed STH, wrong key type, or any thrown error returns
 * `false` — never undefined, never a throw that a caller might treat as a pass.
 */
export function verifySTH(sth: SignedTreeHead, caPublicKeyPem: string): boolean {
  try {
    if (
      !sth ||
      typeof sth.rootHash !== 'string' ||
      typeof sth.signature !== 'string' ||
      !Number.isInteger(sth.treeSize) ||
      !Number.isInteger(sth.timestamp) ||
      !ROOT_HEX.test(sth.rootHash)
    ) {
      return false;
    }
    const key = createPublicKey(caPublicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') return false;
    return cryptoVerify(
      null,
      sthSigningInput({ rootHash: sth.rootHash, treeSize: sth.treeSize, timestamp: sth.timestamp }),
      key,
      Buffer.from(sth.signature, 'base64url'),
    );
  } catch {
    return false;
  }
}
