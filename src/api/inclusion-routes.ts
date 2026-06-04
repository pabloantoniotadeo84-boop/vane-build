import { Hono } from 'hono';
import { buildInclusionProof } from '../crypto/inclusion.js';
import type { AttestationRecord } from '../crypto/types.js';
import type { SignedTreeHead } from '../crypto/sth.js';

type Env = { Variables: { companyId: string } };

/**
 * Dependencies for the authenticated inclusion-proof route. app.ts wires these
 * to the live per-tenant chains + Postgres store; tests wire them to an
 * in-memory log so the exact same handler runs without a database.
 *
 * `companyId` is taken from the request context (set by the auth middleware),
 * never from the URL — the proof is always scoped to the authenticated tenant.
 */
export interface InclusionProofDeps {
  /** Global CA public key (SPKI PEM) that signs every STH. */
  caPublicKey: string;
  /** Key id of the CA public key. */
  caKid: string;
  /** True if `agentId` is a registered agent of `companyId`. */
  agentBelongs(companyId: string, agentId: string): Promise<boolean>;
  /** The record at chain index `index`, or null if out of range / unknown company. */
  recordAt(companyId: string, index: number): Promise<AttestationRecord | null>;
  /** All record (leaf) hashes for the company in chain order, or null if unknown. */
  leafHashes(companyId: string): Promise<string[] | null>;
  /** Latest committed STH for the company, or null if its log is empty. */
  latestCheckpoint(companyId: string): Promise<SignedTreeHead | null>;
}

/**
 * Builds the authenticated inclusion-proof route:
 *
 *   GET /v1/agents/:agentId/attestations/:index/proof
 *
 * `:index` is the record's chain index (the same `index` exposed on the record
 * and timeline) — which is exactly its Merkle leaf index. The response carries
 * everything needed to verify inclusion offline against the CA public key:
 * the record, its leaf hash, the RFC 6962 audit path, the tree root, and the
 * CA-signed STH the root is anchored to.
 */
export function createInclusionProofRoutes(deps: InclusionProofDeps): Hono<Env> {
  const routes = new Hono<Env>();

  routes.get('/v1/agents/:agentId/attestations/:index/proof', async (c) => {
    const companyId = c.get('companyId');
    const agentId = c.req.param('agentId');

    const idx = Number(c.req.param('index'));
    if (!Number.isInteger(idx) || idx < 0) {
      return c.json({ error: 'index must be a non-negative integer' }, 400);
    }

    if (!(await deps.agentBelongs(companyId, agentId))) {
      return c.json({ error: `Agent not found: ${agentId}` }, 404);
    }

    const record = await deps.recordAt(companyId, idx);
    if (!record) {
      return c.json({ error: `No attestation at index ${idx}` }, 404);
    }
    // The leaf at this index must actually be this agent's attestation.
    if ((record.payload as Record<string, unknown> | null)?.agentId !== agentId) {
      return c.json({ error: `Attestation ${idx} does not belong to agent ${agentId}` }, 404);
    }

    const sth = await deps.latestCheckpoint(companyId);
    if (!sth) {
      return c.json({ error: 'No signed tree head is available for this log yet' }, 409);
    }
    if (idx >= sth.treeSize) {
      // The record exists but the latest checkpoint does not yet cover it, so it
      // cannot be anchored to a CA signature. Fail rather than return an
      // unanchored proof.
      return c.json({ error: `Attestation ${idx} is not yet covered by a signed checkpoint` }, 409);
    }

    const leaves = await deps.leafHashes(companyId);
    if (leaves === null) {
      return c.json({ error: `Unknown company: ${companyId}` }, 404);
    }

    try {
      const proof = buildInclusionProof({
        companyId,
        agentId,
        index: idx,
        record,
        leafHashes: leaves,
        sth,
        caPublicKey: deps.caPublicKey,
        caKid: deps.caKid,
      });
      // The record content is tenant data; never let an intermediary cache it.
      c.header('Cache-Control', 'no-store');
      return c.json(proof);
    } catch (err) {
      return c.json({ error: (err as Error).message }, 400);
    }
  });

  return routes;
}
