import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import { generateKeyPair } from '../src/crypto/keypair.js';
import { AttestationChain } from '../src/crypto/chain.js';
import { deriveKeyId } from '../src/crypto/svid.js';
import { verifySTH, type SignedTreeHead } from '../src/crypto/sth.js';
import { verifyInclusionProof, type InclusionProofResponse } from '../src/crypto/inclusion.js';
import { appendWithCheckpoint, type AtomicAppend } from '../src/checkpoint/log.js';
import { createInclusionProofRoutes } from '../src/api/inclusion-routes.js';
import type { AttestationRecord } from '../src/crypto/types.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────
// A per-company signing key (signs records) and a GLOBAL CA key (signs every
// Signed Tree Head). The CA key is the ONLY trust anchor an auditor needs.

const companyKey = generateKeyPair();
const caKey = generateKeyPair();
const caKid = deriveKeyId(caKey.publicKey);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TSX_BIN = resolve(REPO_ROOT, 'node_modules/.bin/tsx');
const VERIFY_SCRIPT = resolve(REPO_ROOT, 'scripts/verify-proof.ts');

// In-memory stand-in for the Postgres atomic-append transaction (record + STH
// committed together, rolled back together). Lets the real append + route run
// with no database.
function makeMemoryStore() {
  const log: { records: AttestationRecord[]; sths: SignedTreeHead[] } = { records: [], sths: [] };
  const persist: AtomicAppend = async (record, buildSth) => {
    const recCount = log.records.length;
    const sthCount = log.sths.length;
    try {
      log.records.push(record);
      const sth = buildSth();
      log.sths.push(sth);
      return sth;
    } catch (err) {
      log.records.length = recCount;
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
  agentId = 'agent-1',
): Promise<void> {
  for (let i = 0; i < n; i++) {
    await appendWithCheckpoint({
      chain,
      signingPrivateKey: companyKey.privateKey,
      caPrivateKey: caKey.privateKey,
      payload: { agentId, companyId: 'acme', actionType: 'data-query', payload: { seq: i } },
      persist: store.persist,
    });
  }
}

// Mounts the REAL inclusion-proof handler over an in-memory log. A parent
// middleware sets companyId exactly as the production auth middleware does, so
// the mounted route reads it from context.
function makeApp(chain: AttestationChain): Hono<{ Variables: { companyId: string } }> {
  const app = new Hono<{ Variables: { companyId: string } }>();
  app.use('/v1/*', async (c, next) => { c.set('companyId', 'acme'); await next(); });
  app.route('/', createInclusionProofRoutes({
    caPublicKey: caKey.publicKey,
    caKid,
    agentBelongs: async (companyId, agentId) =>
      companyId === 'acme' && (agentId === 'agent-1' || agentId === 'agent-2'),
    recordAt: async (companyId, index) => {
      if (companyId !== 'acme') return null;
      const recs = chain.getRecords();
      return index >= 0 && index < recs.length ? recs[index] : null;
    },
    leafHashes: async (companyId) => (companyId === 'acme' ? chain.currentLeafHashes() : null),
    latestCheckpoint: async (companyId) => (companyId === 'acme' ? (chain.getLatestSth() ?? null) : null),
  }));
  return app;
}

async function fetchProof(app: Hono<{ Variables: { companyId: string } }>, agentId: string, index: number) {
  const res = await app.request(`/v1/agents/${agentId}/attestations/${index}/proof`);
  return { res, body: (await res.json()) as InclusionProofResponse & { error?: string } };
}

function flipSignature(sig: string): string {
  const buf = Buffer.from(sig, 'base64url');
  buf[0] ^= 0xff;
  return buf.toString('base64url');
}

// ── Endpoint shape ────────────────────────────────────────────────────────────

describe('GET /v1/agents/:agentId/attestations/:index/proof', () => {
  it('returns a proof whose root matches the CA-signed STH', async () => {
    const chain = new AttestationChain();
    await appendN(chain, makeMemoryStore(), 5);
    const app = makeApp(chain);

    const { res, body } = await fetchProof(app, 'agent-1', 2);
    expect(res.status).toBe(200);

    expect(body.index).toBe(2);
    expect(body.treeSize).toBe(5);
    expect(body.record.index).toBe(2);
    expect(body.caPublicKey).toBe(caKey.publicKey);
    expect(body.caKid).toBe(caKid);
    // The whole point: the inclusion-proof root IS the CA-signed STH root.
    expect(body.root).toBe(body.sth.rootHash);
    expect(verifySTH(body.sth, caKey.publicKey)).toBe(true);
  });

  it('404s for an unknown agent, a missing record, and a wrong-agent leaf', async () => {
    const chain = new AttestationChain();
    const store = makeMemoryStore();
    await appendN(chain, store, 2, 'agent-1');      // indices 0,1 → agent-1
    await appendN(chain, store, 1, 'agent-2');      // index   2  → agent-2
    const app = makeApp(chain);

    expect((await fetchProof(app, 'ghost', 0)).res.status).toBe(404);   // unknown agent
    expect((await fetchProof(app, 'agent-1', 99)).res.status).toBe(404); // no such record
    expect((await fetchProof(app, 'agent-1', 2)).res.status).toBe(404);  // leaf 2 is agent-2's
    expect((await fetchProof(app, 'agent-2', 2)).res.status).toBe(200);  // correct owner
  });

  it('rejects a non-integer index', async () => {
    const chain = new AttestationChain();
    await appendN(chain, makeMemoryStore(), 1);
    const app = makeApp(chain);
    expect((await fetchProof(app, 'agent-1', -1 as unknown as number)).res.status).toBe(400);
    const res = await app.request('/v1/agents/agent-1/attestations/abc/proof');
    expect(res.status).toBe(400);
  });
});

// ── Step 5: fetch a proof and verify it passes ─────────────────────────────────

describe('verifyInclusionProof', () => {
  async function buildValidProof(n = 6, index = 3): Promise<InclusionProofResponse> {
    const chain = new AttestationChain();
    await appendN(chain, makeMemoryStore(), n);
    const app = makeApp(chain);
    const { res, body } = await fetchProof(app, 'agent-1', index);
    expect(res.status).toBe(200);
    return body;
  }

  it('passes for a freshly fetched, untampered proof', async () => {
    const proof = await buildValidProof();
    const result = verifyInclusionProof(proof, caKey.publicKey);
    expect(result.valid).toBe(true);
    expect(result.index).toBe(3);
    expect(result.root).toBe(proof.sth.rootHash);
  });

  it('verifies a single-record proof (empty Merkle path)', async () => {
    const proof = await buildValidProof(1, 0);
    expect(proof.proof).toHaveLength(0);
    expect(verifyInclusionProof(proof, caKey.publicKey).valid).toBe(true);
  });

  // Tamper #1 — the record.
  it('FAILS when the record is tampered', async () => {
    const proof = await buildValidProof();
    const payload = proof.record.payload as Record<string, unknown>;
    const tampered: InclusionProofResponse = {
      ...proof,
      record: { ...proof.record, payload: { ...payload, evil: true } },
    };
    const result = verifyInclusionProof(tampered, caKey.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/record hash does not match/);
  });

  // Tamper #1b — rewrite the record AND re-hash it so it is internally
  // consistent (a malicious operator holding the company key). Still fails,
  // because the re-hashed leaf is no longer the one the CA-signed root commits to.
  it('FAILS when the record is rewritten and re-hashed consistently', async () => {
    const proof = await buildValidProof();
    const { createHash } = await import('node:crypto');
    const { canonicalize } = await import('../src/crypto/signer.js');
    const payload = { ...(proof.record.payload as Record<string, unknown>), evil: true };
    const preimage = `${proof.record.index}|${proof.record.timestamp}|${canonicalize(payload)}`;
    const newHash = createHash('sha256').update(preimage).digest('hex');
    const tampered: InclusionProofResponse = {
      ...proof,
      record: { ...proof.record, payload, hash: newHash },
    };
    // record.hash now matches its contents, so it gets past the hash check, but
    // the leaf hash no longer matches the proof's leafHash.
    expect(verifyInclusionProof(tampered, caKey.publicKey).valid).toBe(false);
  });

  // Tamper #2 — the leaf hash.
  it('FAILS when the leaf hash is tampered', async () => {
    const proof = await buildValidProof();
    const tampered: InclusionProofResponse = { ...proof, leafHash: 'a'.repeat(64) };
    const result = verifyInclusionProof(tampered, caKey.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/leaf hash/);
  });

  // Tamper #3 — the STH signature.
  it('FAILS when the STH signature is tampered', async () => {
    const proof = await buildValidProof();
    const tampered: InclusionProofResponse = {
      ...proof,
      sth: { ...proof.sth, signature: flipSignature(proof.sth.signature) },
    };
    const result = verifyInclusionProof(tampered, caKey.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/STH signature/);
  });

  // Tamper #4 — swap a sibling hash in the Merkle path.
  it('FAILS when a sibling hash in the Merkle path is swapped', async () => {
    const proof = await buildValidProof();
    expect(proof.proof.length).toBeGreaterThan(0);
    const swapped = proof.proof.map((node, i) =>
      i === 0 ? { ...node, sibling: 'c'.repeat(64) } : node);
    const tampered: InclusionProofResponse = { ...proof, proof: swapped };
    const result = verifyInclusionProof(tampered, caKey.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/Merkle inclusion path/);
  });

  // Tamper #5 — a valid proof but verified under the WRONG CA key.
  it('FAILS under a different CA public key', async () => {
    const proof = await buildValidProof();
    const result = verifyInclusionProof(proof, generateKeyPair().publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/STH signature/);
  });
});

// ── Step 5: the CLI exits 0 on valid, 1 on tampered ────────────────────────────

describe('scripts/verify-proof.ts CLI', () => {
  it('exits 0 on a valid proof and 1 on a tampered proof', async () => {
    const chain = new AttestationChain();
    await appendN(chain, makeMemoryStore(), 4);
    const app = makeApp(chain);
    const { body: proof } = await fetchProof(app, 'agent-1', 1);

    const dir = mkdtempSync(join(tmpdir(), 'vane-proof-'));
    const caFile = join(dir, 'ca.pem');
    const validFile = join(dir, 'valid.json');
    const tamperedFile = join(dir, 'tampered.json');
    writeFileSync(caFile, caKey.publicKey);
    writeFileSync(validFile, JSON.stringify(proof));
    writeFileSync(
      tamperedFile,
      JSON.stringify({ ...proof, sth: { ...proof.sth, signature: flipSignature(proof.sth.signature) } }),
    );

    // Valid → exit 0, prints VALID.
    const out = execFileSync(TSX_BIN, [VERIFY_SCRIPT, validFile, caFile], { encoding: 'utf8' });
    expect(out).toMatch(/VALID/);

    // Tampered → exit 1.
    let code = 0;
    let stdout = '';
    try {
      execFileSync(TSX_BIN, [VERIFY_SCRIPT, tamperedFile, caFile], { encoding: 'utf8', stdio: 'pipe' });
    } catch (err) {
      const e = err as { status: number; stdout: string };
      code = e.status;
      stdout = e.stdout;
    }
    expect(code).toBe(1);
    expect(stdout).toMatch(/INVALID/);
  }, 60_000);
});

// ── Step 5: third-party auditor, only the proof JSON + the CA key, no DB ────────

describe('third-party auditor', () => {
  it('verifies inclusion from only the proof JSON and the pinned CA key', async () => {
    // Server side: build a log and expose the inclusion-proof endpoint.
    const chain = new AttestationChain();
    await appendN(chain, makeMemoryStore(), 7);
    const app = makeApp(chain);
    const { body } = await fetchProof(app, 'agent-1', 4);

    // ── Auditor side ────────────────────────────────────────────────────────
    // The proof crosses a trust boundary as plain JSON. The auditor holds ONLY
    // the CA public key (pinned out of band) and performs NO database queries.
    const wire = JSON.parse(JSON.stringify(body)) as InclusionProofResponse;
    const PINNED_CA_PUBLIC_KEY = caKey.publicKey;

    const result = verifyInclusionProof(wire, PINNED_CA_PUBLIC_KEY);
    expect(result.valid).toBe(true);
    expect(result.index).toBe(4);

    // A proof is bound to the real CA: a different key must not verify it.
    expect(verifyInclusionProof(wire, generateKeyPair().publicKey).valid).toBe(false);
  });
});
