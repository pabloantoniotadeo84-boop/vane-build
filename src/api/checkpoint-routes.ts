import { Hono } from 'hono';
import { consistencyProofHex, rfc6962RootHex } from '../crypto/rfc6962.js';
import type { SignedTreeHead } from '../crypto/sth.js';

/**
 * Dependencies for the public checkpoint routes. app.ts wires these to the live
 * per-tenant chains + Postgres store; tests wire them to an in-memory log so the
 * exact same HTTP handlers run without a database.
 */
export interface CheckpointDeps {
  /** Global CA public key (SPKI PEM) that signs every STH — returned for convenience. */
  caPublicKey: string;
  /** Key id of the CA public key. */
  caKid: string;
  /** Latest committed STH for a company, or null if the company is unknown / its log is empty. */
  latestCheckpoint(companyId: string): Promise<SignedTreeHead | null>;
  /** Stored STH at an exact tree size, or null. */
  checkpointAt(companyId: string, treeSize: number): Promise<SignedTreeHead | null>;
  /** All record (leaf) hashes for a company in chain order, or null if the company is unknown. */
  leafHashes(companyId: string): Promise<string[] | null>;
}

/**
 * Builds the public, unauthenticated checkpoint routes:
 *
 *   GET /v1/checkpoint?companyId=            → latest Signed Tree Head (the anchor)
 *   GET /v1/checkpoint/consistency?...       → RFC 6962 consistency proof
 *
 * Both are deliberately unauthenticated: an external auditor must be able to
 * fetch and gossip checkpoints without holding any tenant credential.
 */
export function createCheckpointRoutes(deps: CheckpointDeps): Hono {
  const routes = new Hono();

  routes.get('/v1/checkpoint', async (c) => {
    const companyId = c.req.query('companyId');
    if (!companyId) return c.json({ error: 'Missing required query parameter: companyId' }, 400);

    const sth = await deps.latestCheckpoint(companyId);
    if (!sth) return c.json({ error: `No checkpoint found for company: ${companyId}` }, 404);

    // A checkpoint is a live commitment; never let an intermediary serve a stale one.
    c.header('Cache-Control', 'no-store');
    return c.json({
      companyId,
      treeSize: sth.treeSize,
      rootHash: sth.rootHash,
      timestamp: sth.timestamp,
      signature: sth.signature,
      signatureAlgorithm: 'EdDSA',
      caPublicKey: deps.caPublicKey,
      caKid: deps.caKid,
    });
  });

  routes.get('/v1/checkpoint/consistency', async (c) => {
    const companyId = c.req.query('companyId');
    if (!companyId) return c.json({ error: 'Missing required query parameter: companyId' }, 400);

    const from = Number(c.req.query('from'));
    const to = Number(c.req.query('to'));
    if (!Number.isInteger(from) || from < 0) {
      return c.json({ error: 'from must be a non-negative integer' }, 400);
    }
    if (!Number.isInteger(to) || to < 0) {
      return c.json({ error: 'to must be a non-negative integer' }, 400);
    }
    if (from > to) return c.json({ error: 'from must be <= to' }, 400);

    const leaves = await deps.leafHashes(companyId);
    if (leaves === null) return c.json({ error: `Unknown company: ${companyId}` }, 404);
    if (to > leaves.length) {
      return c.json({ error: `to=${to} exceeds current tree size ${leaves.length}` }, 400);
    }

    let proof: string[];
    try {
      proof = consistencyProofHex(from, leaves.slice(0, to));
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400);
    }

    const firstRoot = rfc6962RootHex(leaves.slice(0, from));
    const secondRoot = rfc6962RootHex(leaves.slice(0, to));
    const sthFrom = await deps.checkpointAt(companyId, from);
    const sthTo = await deps.checkpointAt(companyId, to);

    c.header('Cache-Control', 'no-store');
    return c.json({
      companyId,
      from,
      to,
      firstRoot,
      secondRoot,
      proof,
      // The signed checkpoints at these sizes, when they exist. A careful auditor
      // verifies the proof against the STHs they saved earlier, not these.
      ...(sthFrom && { sthFrom }),
      ...(sthTo && { sthTo }),
      caPublicKey: deps.caPublicKey,
    });
  });

  return routes;
}
