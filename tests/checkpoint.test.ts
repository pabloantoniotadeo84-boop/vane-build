import { describe, it, expect } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { Hono } from 'hono';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { canonicalize, signPayload } from '../src/crypto/signer.js';
import { AttestationChain } from '../src/crypto/chain.js';
import { deriveKeyId } from '../src/crypto/svid.js';
import { rfc6962RootHex, consistencyProofHex, verifyConsistencyHex } from '../src/crypto/rfc6962.js';
import { signSTH, verifySTH, type SignedTreeHead } from '../src/crypto/sth.js';
import { appendWithCheckpoint, createKeyedQueue, type AtomicAppend } from '../src/checkpoint/log.js';
import { createCheckpointRoutes } from '../src/api/checkpoint-routes.js';
import type { AttestationRecord } from '../src/crypto/types.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────
// One per-company signing key (signs records) and one GLOBAL CA key (signs every
// Signed Tree Head). The split is the whole point: the CA key is the only trust
// anchor an auditor needs, and it is distinct from any tenant key.

const companyKey = generateKeyPair();
const caKey = generateKeyPair();

/**
 * In-memory stand-in for the Postgres atomic-append transaction. It pushes the
 * record, runs the STH signer INSIDE the "transaction", and rolls both back if
 * signing throws — exactly the contract Store.appendRecordWithSTH implements
 * with BEGIN/COMMIT/ROLLBACK. Lets the orchestration be tested with no database.
 */
function makeMemoryStore() {
  const log: { records: AttestationRecord[]; sths: SignedTreeHead[] } = { records: [], sths: [] };
  const persist: AtomicAppend = async (record, buildSth) => {
    const recCount = log.records.length;
    const sthCount = log.sths.length;
    try {
      log.records.push(record);
      const sth = buildSth(); // signing inside the transaction
      log.sths.push(sth);
      return sth;
    } catch (err) {
      log.records.length = recCount; // ROLLBACK
      log.sths.length = sthCount;
      throw err;
    }
  };
  return { log, persist };
}

type MemoryStore = ReturnType<typeof makeMemoryStore>;

async function appendN(
  chain: AttestationChain,
  store: MemoryStore,
  n: number,
  opts: { caPrivateKey?: string } = {},
): Promise<void> {
  for (let i = 0; i < n; i++) {
    await appendWithCheckpoint({
      chain,
      signingPrivateKey: companyKey.privateKey,
      caPrivateKey: opts.caPrivateKey ?? caKey.privateKey,
      payload: { agentId: 'agent-1', companyId: 'acme', actionType: 'data-query', payload: { seq: i } },
      persist: store.persist,
    });
  }
}

// Mounts the real checkpoint route handlers over an in-memory log (no Postgres).
function makeCheckpointApp(chain: AttestationChain, store: MemoryStore): Hono {
  const app = new Hono();
  app.route('/', createCheckpointRoutes({
    caPublicKey: caKey.publicKey,
    caKid: deriveKeyId(caKey.publicKey),
    latestCheckpoint: async (companyId) =>
      companyId === 'acme' ? (chain.getLatestSth() ?? null) : null,
    checkpointAt: async (companyId, size) =>
      companyId === 'acme' ? (store.log.sths.find((s) => s.treeSize === size) ?? null) : null,
    leafHashes: async (companyId) =>
      companyId === 'acme' ? chain.currentLeafHashes() : null,
  }));
  return app;
}

// Re-derives a record's hash + signature exactly as AttestationChain does. Models
// a malicious operator who, holding the company key, rewrites a payload and
// re-signs the record so it stays internally self-consistent.
function forgeRecord(index: number, timestamp: string, payload: unknown): AttestationRecord {
  const preimage = `${index}|${timestamp}|${canonicalize(payload)}`;
  const hash = createHash('sha256').update(preimage).digest('hex');
  const signature = signPayload(hash, companyKey.privateKey);
  return { index, timestamp, payload, hash, signature };
}

function randomLeaves(n: number): string[] {
  return Array.from({ length: n }, () => createHash('sha256').update(randomBytes(16)).digest('hex'));
}

// ── RFC 6962 tree-hash known-answer vectors ───────────────────────────────────

describe('RFC 6962 Merkle tree hash', () => {
  it('empty tree hashes the empty string', () => {
    const expected = createHash('sha256').update(Buffer.alloc(0)).digest('hex');
    expect(rfc6962RootHex([])).toBe(expected);
    expect(expected).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('single leaf is SHA-256(0x00 || leafData)', () => {
    const [h] = randomLeaves(1);
    const expected = createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(h, 'hex')]))
      .digest('hex');
    expect(rfc6962RootHex([h])).toBe(expected);
  });

  it('two leaves is SHA-256(0x01 || leafHash(d0) || leafHash(d1))', () => {
    const leaves = randomLeaves(2);
    const lh = (h: string) =>
      createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(h, 'hex')])).digest();
    const expected = createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x01]), lh(leaves[0]), lh(leaves[1])]))
      .digest('hex');
    expect(rfc6962RootHex(leaves)).toBe(expected);
  });
});

// ── RFC 6962 consistency proof round-trips ────────────────────────────────────

describe('RFC 6962 consistency proofs', () => {
  it('round-trips for every (first, second) pair up to 33 leaves', () => {
    const leaves = randomLeaves(33);
    for (let second = 1; second <= 33; second++) {
      const secondRoot = rfc6962RootHex(leaves.slice(0, second));
      for (let first = 0; first <= second; first++) {
        const firstRoot = rfc6962RootHex(leaves.slice(0, first));
        const proof = consistencyProofHex(first, leaves.slice(0, second));
        expect(verifyConsistencyHex(first, second, firstRoot, secondRoot, proof))
          .toBe(true);
      }
    }
  });

  it('rejects a proof with a corrupted node', () => {
    const leaves = randomLeaves(9);
    const proof = consistencyProofHex(4, leaves);
    const firstRoot = rfc6962RootHex(leaves.slice(0, 4));
    const secondRoot = rfc6962RootHex(leaves);
    expect(verifyConsistencyHex(4, 9, firstRoot, secondRoot, proof)).toBe(true);

    const corrupted = [...proof];
    corrupted[0] = 'f'.repeat(64);
    expect(verifyConsistencyHex(4, 9, firstRoot, secondRoot, corrupted)).toBe(false);
  });

  it('rejects when either claimed root is wrong', () => {
    const leaves = randomLeaves(7);
    const proof = consistencyProofHex(3, leaves);
    const firstRoot = rfc6962RootHex(leaves.slice(0, 3));
    const secondRoot = rfc6962RootHex(leaves);
    expect(verifyConsistencyHex(3, 7, 'a'.repeat(64), secondRoot, proof)).toBe(false);
    expect(verifyConsistencyHex(3, 7, firstRoot, 'b'.repeat(64), proof)).toBe(false);
  });

  it('rejects a proof of the wrong length (extra node)', () => {
    const leaves = randomLeaves(6);
    const proof = consistencyProofHex(2, leaves);
    const firstRoot = rfc6962RootHex(leaves.slice(0, 2));
    const secondRoot = rfc6962RootHex(leaves);
    expect(verifyConsistencyHex(2, 6, firstRoot, secondRoot, [...proof, '0'.repeat(64)])).toBe(false);
  });

  it('detects a rewritten prefix (consistency breaks)', () => {
    const leaves = randomLeaves(8);
    const firstRoot = rfc6962RootHex(leaves.slice(0, 5));
    const proof = consistencyProofHex(5, leaves);
    // Rewrite leaf 2, recompute the "new" root — the old root no longer fits.
    const rewritten = [...leaves];
    rewritten[2] = randomLeaves(1)[0];
    const tamperedSecondRoot = rfc6962RootHex(rewritten);
    expect(verifyConsistencyHex(5, 8, firstRoot, tamperedSecondRoot, proof)).toBe(false);
  });

  it('is fail-closed on malformed input', () => {
    expect(verifyConsistencyHex(2, 4, 'a'.repeat(64), 'b'.repeat(64), null as never)).toBe(false);
    expect(verifyConsistencyHex(-1, 4, 'a'.repeat(64), 'b'.repeat(64), [])).toBe(false);
    expect(verifyConsistencyHex(5, 4, 'a'.repeat(64), 'b'.repeat(64), [])).toBe(false);
    expect(verifyConsistencyHex(2, 4, 'xyz', 'b'.repeat(64), ['z'.repeat(64)])).toBe(false);
  });
});

// ── STH signing / verification ────────────────────────────────────────────────

describe('Signed Tree Head signing', () => {
  it('signs and verifies under the CA key', () => {
    const sth = signSTH({ rootHash: 'a'.repeat(64), treeSize: 3, timestamp: 1_700_000_000_000 }, caKey.privateKey);
    expect(verifySTH(sth, caKey.publicKey)).toBe(true);
  });

  it('rejects a tampered field', () => {
    const sth = signSTH({ rootHash: 'a'.repeat(64), treeSize: 3, timestamp: 1_700_000_000_000 }, caKey.privateKey);
    expect(verifySTH({ ...sth, treeSize: 4 }, caKey.publicKey)).toBe(false);
    expect(verifySTH({ ...sth, rootHash: 'b'.repeat(64) }, caKey.publicKey)).toBe(false);
    expect(verifySTH({ ...sth, timestamp: sth.timestamp + 1 }, caKey.publicKey)).toBe(false);
  });

  it('does not verify under a different (non-CA) key', () => {
    const sth = signSTH({ rootHash: 'a'.repeat(64), treeSize: 1, timestamp: 1 }, caKey.privateKey);
    expect(verifySTH(sth, companyKey.publicKey)).toBe(false);
    expect(verifySTH(sth, generateKeyPair().publicKey)).toBe(false);
  });

  it('refuses to sign an invalid root', () => {
    expect(() => signSTH({ rootHash: 'nope', treeSize: 1, timestamp: 1 }, caKey.privateKey)).toThrow(/rootHash/);
  });
});

// ── Step 5.1: append writes a valid STH ───────────────────────────────────────

describe('checkpointed append', () => {
  it('writes a valid STH committing to the new tree on append', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();

    await appendN(chain, store, 1);

    expect(store.log.records).toHaveLength(1);
    expect(store.log.sths).toHaveLength(1);

    const sth = chain.getLatestSth()!;
    expect(sth).toBeDefined();
    expect(verifySTH(sth, caKey.publicKey)).toBe(true);
    expect(sth.treeSize).toBe(1);
    expect(sth.rootHash).toBe(rfc6962RootHex(store.log.records.map((r) => r.hash)));
    expect(chain.length).toBe(1);
  });

  it('commits one STH per record, each over the running tree', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();

    await appendN(chain, store, 5);

    expect(store.log.sths).toHaveLength(5);
    for (let size = 1; size <= 5; size++) {
      const sth = store.log.sths[size - 1];
      expect(sth.treeSize).toBe(size);
      expect(verifySTH(sth, caKey.publicKey)).toBe(true);
      expect(sth.rootHash).toBe(rfc6962RootHex(store.log.records.slice(0, size).map((r) => r.hash)));
    }
  });

  // ── Step 5.2: tamper after append → checkpoint no longer matches ─────────────

  it('a record tampered after append no longer matches its CA-signed checkpoint', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 4);

    const sth = chain.getLatestSth()!;
    // Honest log matches the signed checkpoint.
    expect(verifySTH(sth, caKey.publicKey)).toBe(true);
    expect(rfc6962RootHex(store.log.records.map((r) => r.hash))).toBe(sth.rootHash);

    // Operator rewrites record #1 and re-signs it with the company key.
    const tampered = store.log.records.map((r) => ({ ...r }));
    tampered[1] = forgeRecord(tampered[1].index, tampered[1].timestamp, { evil: true });

    const tamperedRoot = rfc6962RootHex(tampered.map((r) => r.hash));
    // The checkpoint signature is still authentic …
    expect(verifySTH(sth, caKey.publicKey)).toBe(true);
    // … but it no longer describes the mutated log. Detected with only the CA key.
    expect(tamperedRoot).not.toBe(sth.rootHash);
  });

  // ── Step 5.5: simulated signing failure rolls the append back ────────────────

  it('rejects the append and writes nothing when STH signing fails', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 2);

    await expect(
      appendWithCheckpoint({
        chain,
        signingPrivateKey: companyKey.privateKey,
        caPrivateKey: 'not-a-valid-ca-key', // signSTH throws inside the transaction
        payload: { agentId: 'agent-1', actionType: 'data-query', payload: {} },
        persist: store.persist,
      }),
    ).rejects.toThrow();

    // Nothing was written; the chain did not advance; the prior checkpoint stands.
    expect(store.log.records).toHaveLength(2);
    expect(store.log.sths).toHaveLength(2);
    expect(chain.length).toBe(2);
    expect(chain.getLatestSth()!.treeSize).toBe(2);
    expect(verifySTH(chain.getLatestSth()!, caKey.publicKey)).toBe(true);
  });
});

// ── Step 5.3: GET /v1/checkpoint matches the stored STH ────────────────────────

describe('GET /v1/checkpoint', () => {
  it('returns the latest stored STH', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 3);
    const stored = chain.getLatestSth()!;

    const app = makeCheckpointApp(chain, store);
    const res = await app.request('/v1/checkpoint?companyId=acme');
    expect(res.status).toBe(200);

    const body = await res.json() as Record<string, unknown>;
    expect(body.treeSize).toBe(stored.treeSize);
    expect(body.rootHash).toBe(stored.rootHash);
    expect(body.timestamp).toBe(stored.timestamp);
    expect(body.signature).toBe(stored.signature);
    expect(body.caPublicKey).toBe(caKey.publicKey);
  });

  it('404s for a company with no checkpoint and 400s with no companyId', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    const app = makeCheckpointApp(chain, store);

    expect((await app.request('/v1/checkpoint?companyId=acme')).status).toBe(404); // empty log
    expect((await app.request('/v1/checkpoint')).status).toBe(400); // missing companyId
  });
});

// ── Step 5.4: consistency proof over the endpoint + standalone verify ──────────

describe('GET /v1/checkpoint/consistency', () => {
  it('returns a proof between size N and N+K that verifies against the two STHs', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 9);

    const app = makeCheckpointApp(chain, store);
    const res = await app.request('/v1/checkpoint/consistency?companyId=acme&from=4&to=9');
    expect(res.status).toBe(200);

    const body = await res.json() as {
      from: number; to: number; proof: string[]; sthFrom: SignedTreeHead; sthTo: SignedTreeHead;
    };

    // Standalone verification — only the two STHs (root + size) and the proof.
    // No leaves, no database access.
    expect(verifyConsistencyHex(body.from, body.to, body.sthFrom.rootHash, body.sthTo.rootHash, body.proof))
      .toBe(true);
    // Both anchoring STHs are themselves CA-signed.
    expect(verifySTH(body.sthFrom, caKey.publicKey)).toBe(true);
    expect(verifySTH(body.sthTo, caKey.publicKey)).toBe(true);
  });

  it('proof verifies directly from two stored STHs (third party, no DB)', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 12);

    const N = 5;
    const M = 12;
    const sthN = store.log.sths.find((s) => s.treeSize === N)!;
    const sthM = store.log.sths.find((s) => s.treeSize === M)!;
    const proof = consistencyProofHex(N, chain.currentLeafHashes().slice(0, M));

    expect(verifyConsistencyHex(N, M, sthN.rootHash, sthM.rootHash, proof)).toBe(true);
  });

  it('validates query parameters', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 3);
    const app = makeCheckpointApp(chain, store);

    expect((await app.request('/v1/checkpoint/consistency?companyId=acme&from=2&to=99')).status).toBe(400);
    expect((await app.request('/v1/checkpoint/consistency?companyId=acme&from=3&to=1')).status).toBe(400);
    expect((await app.request('/v1/checkpoint/consistency?companyId=acme&from=-1&to=2')).status).toBe(400);
  });
});

// ── Per-tenant append serialization ───────────────────────────────────────────

describe('createKeyedQueue serialization', () => {
  const tick = () => new Promise((r) => setTimeout(r, 0));

  it('runs same-key tasks one at a time (no lost updates across awaits)', async () => {
    const queue = createKeyedQueue();
    const shared = { counter: 0 };

    const bump = () => queue('acme', async () => {
      const seen = shared.counter; // read
      await tick();                // yield — an unserialized impl would interleave here
      shared.counter = seen + 1;   // write
    });

    await Promise.all(Array.from({ length: 25 }, bump));
    expect(shared.counter).toBe(25);
  });

  it('preserves submission order for a key', async () => {
    const queue = createKeyedQueue();
    const order: number[] = [];
    await Promise.all(
      [0, 1, 2, 3, 4].map((i) => queue('acme', async () => { await tick(); order.push(i); })),
    );
    expect(order).toEqual([0, 1, 2, 3, 4]);
  });

  it('a rejected task does not poison the queue', async () => {
    const queue = createKeyedQueue();
    await expect(queue('acme', async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    // The next submission for the same key still runs and resolves.
    await expect(queue('acme', async () => 'ok')).resolves.toBe('ok');
  });

  it('different keys are independent', async () => {
    const queue = createKeyedQueue();
    const a = queue('a', async () => { await tick(); return 'a'; });
    const b = queue('b', async () => 'b');
    expect(await Promise.all([a, b])).toEqual(['a', 'b']);
  });
});

// ── Step 5.6: third-party auditor verifies with only the CA public key ─────────

describe('third-party auditor', () => {
  it('verifies the latest checkpoint using only the CA public key and the /v1/checkpoint response', async () => {
    // Server side: build a log and expose the public checkpoint endpoint.
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 5);
    const app = makeCheckpointApp(chain, store);

    // ── Auditor side ──────────────────────────────────────────────────────────
    // The auditor holds ONLY the CA public key, pinned out of band. It performs
    // NO database queries — it sees only the HTTP response.
    const PINNED_CA_PUBLIC_KEY = caKey.publicKey;

    const res = await app.request('/v1/checkpoint?companyId=acme');
    const body = await res.json() as SignedTreeHead & { caPublicKey: string };

    const sth: SignedTreeHead = {
      rootHash: body.rootHash,
      treeSize: body.treeSize,
      timestamp: body.timestamp,
      signature: body.signature,
    };

    expect(verifySTH(sth, PINNED_CA_PUBLIC_KEY)).toBe(true);
    // The checkpoint is bound to the real CA: a different key must not verify it.
    expect(verifySTH(sth, generateKeyPair().publicKey)).toBe(false);
  });
});
