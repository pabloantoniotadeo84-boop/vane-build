import { Hono } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';
import { generateKeyPair, AttestationChain, signPayload, verifyPayload, rfc6962RootHex, signSTH } from '../crypto/index.js';
import {
  agentSpiffeId,
  companySpiffeId,
  issueJwtSvid,
  verifyJwtSvid,
  exchangeToken,
  extractDelegationChain,
  GRANT_TYPE,
  TOKEN_TYPE_JWT,
  TRUST_DOMAIN,
  deriveKeyId,
  issueCrossOrgToken,
  CROSS_ORG_MAX_TTL,
} from '../crypto/index.js';
import type { DelegationInfo, KeyPair } from '../crypto/index.js';
import { Store } from '../db/store.js';
import { issuePassport, verifyPassport, PASSPORT_TTL_DEFAULT, PASSPORT_TTL_MIN, PASSPORT_TTL_MAX, PASSPORT_AUDIENCE } from '../passport/index.js';
import type { AttestationReceipt, VerifyPassportOptions, PassportVerificationResult } from '../passport/index.js';
import { broadcast } from './ws.js';
import { fireWebhookEvent, startWebhookScheduler } from '../webhooks/index.js';
import type { IncomingMessage } from 'node:http';
import type { TLSSocket, PeerCertificate } from 'node:tls';
import { randomUUID, createPublicKey, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { logger } from '../logger.js';
import { captureException } from '../sentry.js';
import { rateLimitMiddleware } from './rate-limit.js';
import { createIssuanceRateLimitMiddleware } from './issuance-rate-limit.js';
import { appendWithCheckpoint, createKeyedQueue } from '../checkpoint/log.js';
import { createCheckpointRoutes } from './checkpoint-routes.js';
import { createInclusionProofRoutes } from './inclusion-routes.js';

// ── Per-company in-memory state ───────────────────────────────────────────────

interface Tenant {
  keys: KeyPair;
  chain: AttestationChain;
}

const store = new Store();
logger.info('Connecting to database');
await store.init();
logger.info('Database ready');

// ── Global CA key ───────────────────────────────────────────────────────────────
// One instance-wide Ed25519 key signs every Signed Tree Head, so an external
// auditor needs only this single public key to verify any checkpoint from any
// company. It is persisted in the DB (envelope-encrypted when VANE_MASTER_KEY is
// set); VANE_CA_PRIVATE_KEY + VANE_CA_PUBLIC_KEY (raw PEM) override it for
// operators who provision and pin the CA key externally.
async function initCaKey(): Promise<KeyPair> {
  const envPriv = process.env.VANE_CA_PRIVATE_KEY;
  const envPub = process.env.VANE_CA_PUBLIC_KEY;
  if (envPriv && envPub) {
    logger.info('Using CA key from VANE_CA_PRIVATE_KEY / VANE_CA_PUBLIC_KEY');
    return { privateKey: envPriv, publicKey: envPub };
  }
  let ca = await store.getCaKey();
  if (!ca) {
    ca = generateKeyPair();
    await store.saveCaKey(ca);
    logger.info('Generated and persisted a new global CA key for Signed Tree Heads');
  }
  return ca;
}

const caKeys = await initCaKey();
const caKid = deriveKeyId(caKeys.publicKey);

const tenants = new Map<string, Tenant>();

async function initTenant(companyId: string): Promise<Tenant> {
  let keys = await store.getKeys(companyId);
  if (!keys) {
    keys = generateKeyPair();
    await store.saveKeys(companyId, keys);
  }
  const chain = new AttestationChain();
  chain.hydrate(await store.getAllRecords(companyId));

  // Anchor the in-memory chain to its latest checkpoint. If records exist
  // without a covering STH (e.g. data created before checkpoints existed), mint
  // one now so /v1/checkpoint is always consistent with the persisted log.
  let sth = await store.getLatestSTH(companyId);
  if (chain.length > 0 && (!sth || sth.treeSize < chain.length)) {
    sth = signSTH(
      { rootHash: rfc6962RootHex(chain.currentLeafHashes()), treeSize: chain.length, timestamp: Date.now() },
      caKeys.privateKey,
    );
    await store.insertSTH(companyId, sth);
    logger.info({ companyId, treeSize: chain.length }, 'Backfilled checkpoint for pre-existing records');
  }
  if (sth) chain.setLatestSth(sth);

  const tenant: Tenant = { keys, chain };
  tenants.set(companyId, tenant);
  return tenant;
}

// Appends for a single company are serialized so each STH commits to the exact
// in-memory leaf set that matches the persisted log (see createKeyedQueue).
const withAppendLock = createKeyedQueue();

// Returns the cached tenant, hydrating it on demand. Null if the company is unknown.
async function ensureTenant(companyId: string): Promise<Tenant | null> {
  const cached = tenants.get(companyId);
  if (cached) return cached;
  const company = await store.getCompany(companyId);
  if (!company) return null;
  return initTenant(companyId);
}

// Hydrate all existing tenants from the DB on startup.
const companies = await store.listCompanies();
logger.info({ count: companies.length }, 'Hydrating tenants');
for (const company of companies) {
  await initTenant(company.companyId);
}
logger.info({ count: tenants.size }, 'Tenants ready');

startWebhookScheduler(store);
logger.info('Webhook retry scheduler started');

// ── Key-rotation grace period ─────────────────────────────────────────────────
// Passports signed with a retired key remain verifiable for this many hours.

const GRACE_PERIOD_HOURS = Number(process.env.VANE_KEY_ROTATION_GRACE_PERIOD_HOURS ?? 24);

// Returns the current key followed by all retired keys within the grace window.
async function getCandidatePublicKeys(companyId: string): Promise<string[]> {
  const tenant = tenants.get(companyId)!;
  const cutoff = new Date(Date.now() - GRACE_PERIOD_HOURS * 3600 * 1000).toISOString();
  const retired = await store.getRetiredKeys(companyId, cutoff);
  return [tenant.keys.publicKey, ...retired.map(r => r.publicKey)];
}

// Tries each candidate key in order. On SIGNATURE_INVALID continues to the
// next key; on any other failure returns immediately (e.g. TOKEN_EXPIRED).
function verifyPassportMultiKey(
  token: string,
  publicKeys: string[],
  opts: Omit<VerifyPassportOptions, 'caPublicKey'> = {},
): PassportVerificationResult {
  let sigFailure: PassportVerificationResult | null = null;
  for (const key of publicKeys) {
    const result = verifyPassport(token, { ...opts, caPublicKey: key });
    if (result.valid) return result;
    if (result.code === 'SIGNATURE_INVALID') { sigFailure = result; continue; }
    return result;
  }
  return sigFailure ?? { valid: false, error: 'No public keys available', code: 'SIGNATURE_INVALID' };
}

// ── App ───────────────────────────────────────────────────────────────────────

type Env = { Variables: { companyId: string; requestId: string } };

export const app = new Hono<Env>();

// ── Request ID + structured logging ──────────────────────────────────────────

app.use('*', async (c, next) => {
  const requestId = c.req.header('X-Request-ID') ?? randomUUID();
  c.set('requestId', requestId);
  c.header('X-Request-ID', requestId);
  const start = Date.now();
  await next();
  logger.info({
    requestId,
    method: c.req.method,
    path: c.req.path,
    status: c.res.status,
    durationMs: Date.now() - start,
    companyId: c.get('companyId') ?? null,
  }, 'request');
});

// ── Rate limiting ─────────────────────────────────────────────────────────────

app.use('*', rateLimitMiddleware());

// Tighter sliding-window limits for credential issuance endpoints.
// Applied after the auth middleware so companyId is available.
// Limits: 60/min per API key · 1000/hr per API key · 10000/day per company.
const issuanceRateLimiter = createIssuanceRateLimitMiddleware(store);
app.on('POST', '/v1/agents/:agentId/passport', issuanceRateLimiter);
app.on('POST', '/v1/agents/:agentId/passport/rotate', issuanceRateLimiter);

// ── Marketing site ────────────────────────────────────────────────────────────

const MARKETING_HTML = resolve(dirname(fileURLToPath(import.meta.url)), '../../public/index.html');

app.get('/', async (c) => {
  const html = await readFile(MARKETING_HTML, 'utf-8');
  return c.html(html);
});

// ── Auth middleware ───────────────────────────────────────────────────────────
// Resolution order:
//   1. mTLS client certificate CN → companyId (when VANE_MTLS_CA_CERT is set)
//   2. Bearer <api_key>           → api_keys table
//   3. Bearer <oauth_token>       → oauth_tokens table (prefix: "oauth_")

app.use('/v1/*', async (c, next) => {
  const isPublic =
    (c.req.method === 'GET'  && c.req.path === '/v1/health') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/ca/public-key') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/ca/public-keys') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/ca/well-known') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/ca/checkpoint-key') ||
    // External auditors must reach checkpoints with no tenant credential.
    (c.req.method === 'GET'  && c.req.path === '/v1/checkpoint') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/checkpoint/consistency') ||
    (c.req.method === 'POST' && c.req.path === '/v1/companies') ||
    (c.req.method === 'POST' && c.req.path === '/v1/setup') ||
    (c.req.method === 'POST' && c.req.path === '/v1/recover-key') ||
    (c.req.method === 'POST' && c.req.path === '/v1/oauth/token') ||
    // Timeline HTML view handles its own auth (accepts ?token= query param for browser access)
    (c.req.method === 'GET'  && /^\/v1\/agents\/[^/]+\/timeline\/view$/.test(c.req.path));
  if (isPublic) return next();

  // 1. mTLS: extract CN from a verified client certificate.
  //    Only attempted when the server was started with VANE_MTLS_CA_CERT set
  //    (i.e., the underlying socket is a TLSSocket).
  if (process.env.VANE_MTLS_CA_CERT) {
    try {
      const incoming = (c.env as unknown as { incoming?: IncomingMessage }).incoming;
      const socket = incoming?.socket as TLSSocket | undefined;
      if (typeof socket?.getPeerCertificate === 'function') {
        const cert: PeerCertificate = socket.getPeerCertificate();
        // subject.CN may be string or string[] depending on the certificate.
        const rawCN = cert?.subject?.CN;
        const cn = Array.isArray(rawCN) ? rawCN[0] : rawCN;
        if (typeof cn === 'string' && cn) {
          const company = await store.getCompany(cn);
          if (company) {
            if (!tenants.has(cn)) await initTenant(cn);
            c.set('companyId', cn);
            return next();
          }
        }
      }
    } catch {
      // Socket may not be a TLS socket in test contexts; fall through to token auth.
    }
  }

  // 2 & 3. Bearer token auth (API key or OAuth token).
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  const token = auth.slice(7);

  const result =
    (await store.validateApiKey(token)) ??
    (await store.validateOAuthToken(token));

  if (!result) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  c.set('companyId', result.companyId);
  return next();
});

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/v1/health', (c) => c.json({ status: 'ok' }));

// ── Checkpoints (public) ──────────────────────────────────────────────────────
// GET /v1/checkpoint and GET /v1/checkpoint/consistency. Mounted here, after the
// auth middleware (which allowlists these paths), so an external auditor can
// fetch the CA-signed log state with no tenant credential.

app.route('/', createCheckpointRoutes({
  caPublicKey: caKeys.publicKey,
  caKid,
  async latestCheckpoint(companyId) {
    const tenant = await ensureTenant(companyId);
    return tenant?.chain.getLatestSth() ?? null;
  },
  async checkpointAt(companyId, treeSize) {
    if (!(await store.getCompany(companyId))) return null;
    return store.getSTH(companyId, treeSize);
  },
  async leafHashes(companyId) {
    const tenant = await ensureTenant(companyId);
    return tenant ? tenant.chain.currentLeafHashes() : null;
  },
}));

// GET /v1/agents/:agentId/attestations/:index/proof — authenticated inclusion
// proof. Mounted after the auth middleware so companyId is resolved from the
// Bearer token; the proof is scoped to that tenant. The response verifies
// offline against the CA public key (see scripts/verify-proof.ts).
app.route('/', createInclusionProofRoutes({
  caPublicKey: caKeys.publicKey,
  caKid,
  async agentBelongs(companyId, agentId) {
    return !!(await store.getAgent(agentId, companyId));
  },
  async recordAt(companyId, index) {
    const tenant = await ensureTenant(companyId);
    if (!tenant) return null;
    const records = tenant.chain.getRecords();
    return index >= 0 && index < records.length ? records[index] : null;
  },
  async leafHashes(companyId) {
    const tenant = await ensureTenant(companyId);
    return tenant ? tenant.chain.currentLeafHashes() : null;
  },
  async latestCheckpoint(companyId) {
    const tenant = await ensureTenant(companyId);
    return tenant?.chain.getLatestSth() ?? null;
  },
}));

// GET /v1/ca/checkpoint-key — the global CA public key that signs every STH.
// This is the single trust anchor an external auditor pins.
app.get('/v1/ca/checkpoint-key', (c) => {
  const jwk = pemToJwk(caKeys.publicKey, caKid);
  c.header('Cache-Control', 'public, max-age=3600');
  return c.json({
    kid: caKid,
    pem: caKeys.publicKey,
    jwk,
    fingerprint: pemFingerprint(caKeys.publicKey),
    algorithm: 'EdDSA',
    usage: 'signed-tree-head',
    keys: [jwk],
  });
});

// ── Company registration ──────────────────────────────────────────────────────

app.post('/v1/companies', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { companyId, metadata } = body;
  if (typeof companyId !== 'string' || !companyId) {
    return c.json({ error: 'Missing or invalid field: companyId is required' }, 400);
  }
  if (await store.getCompany(companyId)) {
    return c.json({ error: `Company already exists: ${companyId}` }, 409);
  }

  const spiffeId = companySpiffeId(companyId);
  const company = await store.createCompany(
    companyId,
    spiffeId,
    metadata && typeof metadata === 'object' && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : undefined,
  );

  await initTenant(companyId);
  const apiKey = await store.createApiKey(companyId, 'bootstrap');

  return c.json({ companyId, spiffeId, registeredAt: company.registeredAt, apiKey }, 201);
});

// Backward-compatible alias for POST /v1/companies.
app.post('/v1/setup', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { companyId, metadata } = body;
  if (typeof companyId !== 'string' || !companyId) {
    return c.json({ error: 'Missing or invalid field: companyId is required' }, 400);
  }
  if (await store.getCompany(companyId)) {
    return c.json({ error: `Company already exists: ${companyId}` }, 409);
  }

  const spiffeId = companySpiffeId(companyId);
  const company = await store.createCompany(
    companyId,
    spiffeId,
    metadata && typeof metadata === 'object' && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : undefined,
  );

  await initTenant(companyId);
  const apiKey = await store.createApiKey(companyId, 'bootstrap');

  return c.json({ companyId, spiffeId, registeredAt: company.registeredAt, apiKey }, 201);
});

// Returns the authenticated company's own record. Used by the Terraform provider Read.
app.get('/v1/company', async (c) => {
  const companyId = c.get('companyId');
  const company = await store.getCompany(companyId);
  if (!company) return c.json({ error: 'Company not found' }, 404);
  return c.json({
    companyId: company.companyId,
    spiffeId: company.spiffeId,
    registeredAt: company.registeredAt,
    ...(company.metadata !== undefined && { metadata: company.metadata }),
  });
});

// Emergency key recovery — localhost only, no auth required.
app.post('/v1/recover-key', async (c) => {
  const info = getConnInfo(c);
  const ip = info.remote.address;
  if (ip !== '127.0.0.1' && ip !== '::1') {
    return c.json({ error: 'Forbidden' }, 403);
  }

  let body: Record<string, unknown> = {};
  try { body = await c.req.json(); } catch { /* body optional */ }

  const { companyId } = body;
  if (typeof companyId !== 'string' || !companyId) {
    return c.json({ error: 'companyId is required' }, 400);
  }

  const entry = await store.getFirstApiKey(companyId);
  if (!entry) {
    return c.json({ error: `No API keys found for company: ${companyId}` }, 404);
  }
  return c.json({ key: entry.key, label: entry.label, createdAt: entry.createdAt });
});

// ── API key management ────────────────────────────────────────────────────────

app.post('/v1/keys', async (c) => {
  const companyId = c.get('companyId');
  let label: string | undefined;
  try {
    const b = await c.req.json() as Record<string, unknown>;
    if (typeof b.label === 'string' && b.label) label = b.label;
  } catch { /* label is optional */ }
  const key = await store.createApiKey(companyId, label);
  return c.json({ key, createdAt: new Date().toISOString() }, 201);
});

app.get('/v1/keys', async (c) => {
  const companyId = c.get('companyId');
  const keys = await store.listApiKeys(companyId);
  return c.json({ keys });
});

app.delete('/v1/keys/:key', async (c) => {
  const companyId = c.get('companyId');
  const key = c.req.param('key');
  const deleted = await store.deleteApiKey(companyId, key);
  if (!deleted) return c.json({ error: 'API key not found' }, 404);
  return c.json({ deleted: true });
});

// ── OAuth 2.0 client credentials flow ────────────────────────────────────────

/**
 * POST /v1/oauth/token
 *
 * RFC 6749 §4.4 client credentials grant. Accepts both
 * application/x-www-form-urlencoded (standard) and application/json.
 *
 * Returns a short-lived opaque Bearer token (TTL 3600 s) that the auth
 * middleware accepts alongside existing API keys.
 */
app.post('/v1/oauth/token', async (c) => {
  const contentType = c.req.header('Content-Type') ?? '';
  let grantType = '', clientId = '', clientSecret = '';

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const text = await c.req.text();
    const params = new URLSearchParams(text);
    grantType    = params.get('grant_type')    ?? '';
    clientId     = params.get('client_id')     ?? '';
    clientSecret = params.get('client_secret') ?? '';
  } else {
    let body: Record<string, unknown>;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'invalid_request', error_description: 'Request body must be valid JSON or form-encoded' }, 400);
    }
    grantType    = String(body['grant_type']    ?? '');
    clientId     = String(body['client_id']     ?? '');
    clientSecret = String(body['client_secret'] ?? '');
  }

  if (grantType !== 'client_credentials') {
    return c.json({ error: 'unsupported_grant_type' }, 400);
  }
  if (!clientId || !clientSecret) {
    return c.json({ error: 'invalid_request', error_description: 'client_id and client_secret are required' }, 400);
  }

  const result = await store.validateOAuthCredentials(clientId, clientSecret);
  if (!result) {
    return c.json({ error: 'invalid_client' }, 401);
  }

  const TTL = 3600;
  const accessToken = await store.createOAuthToken(result.companyId, TTL);
  return c.json({ access_token: accessToken, token_type: 'bearer', expires_in: TTL });
});

// POST /v1/oauth/clients — create an OAuth client for the authenticated company.
// Returns client_id and client_secret (secret shown once).
app.post('/v1/oauth/clients', async (c) => {
  const companyId = c.get('companyId');
  const { clientId, clientSecret } = await store.createOAuthClient(companyId);
  return c.json({ clientId, clientSecret, companyId, createdAt: new Date().toISOString() }, 201);
});

// GET /v1/oauth/clients — list OAuth client IDs for the authenticated company (no secrets).
app.get('/v1/oauth/clients', async (c) => {
  const companyId = c.get('companyId');
  const clients = await store.listOAuthClients(companyId);
  return c.json({ clients });
});

// ── Agent registration ────────────────────────────────────────────────────────

app.post('/v1/agents/register', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, metadata } = body;
  if (typeof agentId !== 'string' || !agentId) {
    return c.json({ error: 'Missing or invalid field: agentId is required' }, 400);
  }

  const spiffeId = agentSpiffeId(companyId, agentId);
  const registeredAt = new Date().toISOString();

  await store.registerAgent({
    agentId,
    spiffeId,
    companyId,
    registeredAt,
    metadata:
      metadata && typeof metadata === 'object' && !Array.isArray(metadata)
        ? (metadata as Record<string, unknown>)
        : undefined,
  });

  const svid = issueJwtSvid(spiffeId, tenant.keys.privateKey, tenant.keys.publicKey);
  return c.json({ agentId, spiffeId, svid, registeredAt }, 201);
});

// GET /v1/agents/:agentId — fetch agent metadata (used by Terraform provider Read).
app.get('/v1/agents/:agentId', async (c) => {
  const companyId = c.get('companyId');
  const agentId = c.req.param('agentId');
  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);
  return c.json({
    agentId: agent.agentId,
    spiffeId: agent.spiffeId,
    companyId: agent.companyId,
    registeredAt: agent.registeredAt,
    ...(agent.metadata !== undefined && { metadata: agent.metadata }),
  });
});

app.get('/v1/agents/:agentId/svid', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const agentId = c.req.param('agentId');
  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);
  const svid = issueJwtSvid(agent.spiffeId, tenant.keys.privateKey, tenant.keys.publicKey);
  return c.json({ agentId, spiffeId: agent.spiffeId, svid });
});

// ── Agent timeline ────────────────────────────────────────────────────────────

app.get('/v1/agents/:agentId/timeline', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const agentId = c.req.param('agentId');

  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);

  const allRecords = tenant.chain.getRecords();
  const timeline = allRecords
    .filter(r => (r.payload as Record<string, unknown>)?.agentId === agentId)
    .map(r => {
      const p = r.payload as Record<string, unknown>;
      const verified = verifyPayload(r.hash, r.signature, tenant.keys.publicKey).valid;
      const prev = r.index > 0 ? allRecords[r.index - 1] : null;
      return {
        index: r.index,
        timestamp: r.timestamp,
        actionType: timelineHumanizeAction(String(p.actionType ?? '')),
        payload: r.payload,
        hash: r.hash,
        verified,
        link: prev ? { chainIndex: prev.index, hash: prev.hash } : null,
      };
    });

  return c.json({
    agentId,
    companyId,
    spiffeId: agent.spiffeId,
    totalRecords: timeline.length,
    timeline,
  });
});

app.get('/v1/agents/:agentId/timeline/view', async (c) => {
  const agentId = c.req.param('agentId');

  // Accept Bearer header OR ?token= query param for browser-friendly access.
  let companyId: string | undefined;
  const bearerAuth = c.req.header('Authorization');
  const queryToken = c.req.query('token');
  const rawToken = bearerAuth?.startsWith('Bearer ') ? bearerAuth.slice(7) : queryToken;

  if (rawToken) {
    const result = (await store.validateApiKey(rawToken)) ?? (await store.validateOAuthToken(rawToken));
    if (result) companyId = result.companyId;
  }

  if (!companyId) {
    return c.html(timelineLoginPage(agentId), rawToken ? 401 : 200);
  }

  if (!tenants.has(companyId)) await initTenant(companyId);
  const tenant = tenants.get(companyId)!;

  const agent = await store.getAgent(agentId, companyId);
  if (!agent) {
    return c.html(
      `<html><body style="background:#0a1628;color:#f0ede8;font-family:sans-serif;padding:2rem"><h2>Agent not found: ${timelineEscHtml(agentId)}</h2></body></html>`,
      404,
    );
  }

  const allRecords = tenant.chain.getRecords();
  const entries = allRecords
    .filter(r => (r.payload as Record<string, unknown>)?.agentId === agentId)
    .map(r => {
      const p = r.payload as Record<string, unknown>;
      const verified = verifyPayload(r.hash, r.signature, tenant.keys.publicKey).valid;
      const prev = r.index > 0 ? allRecords[r.index - 1] : null;
      return {
        index: r.index,
        timestamp: r.timestamp,
        actionType: timelineHumanizeAction(String(p.actionType ?? '')),
        actionPayload: p.payload,
        hash: r.hash,
        verified,
        link: prev ? { chainIndex: prev.index, hash: prev.hash } : null,
        hasDelegation: !!r.delegation,
      };
    });

  return c.html(timelineDashboard({ agentId, spiffeId: agent.spiffeId, companyId, entries }));
});

// ── Agent passport ────────────────────────────────────────────────────────────

app.post('/v1/agents/:agentId/passport', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const agentId = c.req.param('agentId');
  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);

  let body: Record<string, unknown> = {};
  try { body = await c.req.json(); } catch { /* body optional */ }

  const rawScopes = body['scopes'];
  const scopes =
    Array.isArray(rawScopes) && rawScopes.every((s): s is string => typeof s === 'string')
      ? rawScopes
      : ['tool:*', 'attest:write'];

  const rawTtl = body['ttl'];
  let ttl = PASSPORT_TTL_DEFAULT;
  if (rawTtl !== undefined) {
    if (typeof rawTtl !== 'number' || !Number.isFinite(rawTtl) || !Number.isInteger(rawTtl)) {
      return c.json({ error: 'ttl must be a positive integer (seconds)' }, 400);
    }
    if (rawTtl < PASSPORT_TTL_MIN || rawTtl > PASSPORT_TTL_MAX) {
      return c.json({
        error: `ttl must be between ${PASSPORT_TTL_MIN} (5 minutes) and ${PASSPORT_TTL_MAX} (1 hour) seconds`,
      }, 400);
    }
    ttl = rawTtl;
  }

  const orgSpiffeId = companySpiffeId(companyId);
  const delegationChain = [orgSpiffeId, agent.spiffeId];

  const passport = issuePassport({
    agentId,
    agentSpiffeId: agent.spiffeId,
    org: companyId,
    orgSpiffeId,
    scopes,
    delegationChain,
    ttl,
    privateKeyPem: tenant.keys.privateKey,
    publicKeyPem: tenant.keys.publicKey,
  });

  const passportResponse = {
    agentId,
    spiffeId: agent.spiffeId,
    org: companyId,
    orgSpiffeId,
    scopes,
    delegationChain,
    passport,
    expiresIn: ttl,
    caPublicKey: tenant.keys.publicKey,
  };
  void fireWebhookEvent(store, companyId, 'passport.issued', passportResponse);
  return c.json(passportResponse, 201);
});

app.post('/v1/agents/:agentId/passport/rotate', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const agentId = c.req.param('agentId');

  const currentPassport = c.req.header('Vane-Passport');
  if (!currentPassport) {
    return c.json({ error: 'Missing Vane-Passport header' }, 400);
  }

  const candidateKeysForRotate = await getCandidatePublicKeys(companyId);
  const verification = verifyPassportMultiKey(currentPassport, candidateKeysForRotate);
  if (!verification.valid) {
    return c.json({ error: verification.error, code: verification.code }, 401);
  }
  const { claims } = verification;

  if (claims.vane.agentId !== agentId) {
    return c.json({ error: 'Passport does not belong to the specified agent' }, 403);
  }
  if (claims.vane.org !== companyId) {
    return c.json({ error: 'Passport was not issued by the authenticated company' }, 403);
  }

  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);

  if (await store.isPassportRevoked(companyId, claims.jti)) {
    return c.json({ error: 'Passport has already been revoked', code: 'PASSPORT_REVOKED' }, 409);
  }

  await store.revokePassport(companyId, claims.jti, 'rotated');

  const ttl = claims.exp - claims.iat;
  const newPassport = issuePassport({
    agentId,
    agentSpiffeId: agent.spiffeId,
    org: claims.vane.org,
    orgSpiffeId: claims.vane.orgSpiffeId,
    scopes: claims.vane.scopes,
    delegationChain: claims.vane.delegationChain,
    ...(claims.vane.delegationId !== undefined && { delegationId: claims.vane.delegationId }),
    ttl,
    privateKeyPem: tenant.keys.privateKey,
    publicKeyPem: tenant.keys.publicKey,
  });

  const rotateResponse = {
    agentId,
    spiffeId: agent.spiffeId,
    org: companyId,
    orgSpiffeId: claims.vane.orgSpiffeId,
    scopes: claims.vane.scopes,
    delegationChain: claims.vane.delegationChain,
    passport: newPassport,
    expiresIn: ttl,
    caPublicKey: tenant.keys.publicKey,
    rotatedFrom: claims.jti,
  };
  void fireWebhookEvent(store, companyId, 'passport.rotated', rotateResponse);
  return c.json(rotateResponse, 200);
});

app.post('/v1/passport/verify', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { passport, tool } = body;
  if (typeof passport !== 'string' || !passport) {
    return c.json({ error: 'Missing or invalid field: passport is required' }, 400);
  }

  const candidateKeys = await getCandidatePublicKeys(companyId);
  const result = verifyPassportMultiKey(passport, candidateKeys, {
    tool: typeof tool === 'string' ? tool : undefined,
  });

  if (!result.valid) {
    return c.json({ valid: false, error: result.error, code: result.code }, 400);
  }

  const { claims, scopeGranted } = result;

  if (await store.isPassportRevoked(companyId, claims.jti)) {
    return c.json({ valid: false, error: 'Passport has been revoked', code: 'PASSPORT_REVOKED' }, 400);
  }

  const receipt: AttestationReceipt = {
    v: 1,
    type: 'VaneAttestationReceipt',
    passportId: claims.jti,
    agentId: claims.vane.agentId,
    agentSpiffeId: claims.sub,
    org: claims.vane.org,
    orgSpiffeId: claims.vane.orgSpiffeId,
    tool: typeof tool === 'string' ? tool : '(not checked)',
    scopeGranted,
    delegationChain: claims.vane.delegationChain,
    issuedBy: claims.iss,
    passportIssuedAt: new Date(claims.iat * 1000).toISOString(),
    passportExpiresAt: new Date(claims.exp * 1000).toISOString(),
    verifiedAt: new Date().toISOString(),
    verifier: 'vane-server/0.1.0',
  };

  return c.json({ valid: true, claims, scopeGranted, receipt });
});

// ── Passport revocation ───────────────────────────────────────────────────────

app.post('/v1/passports/:jti/revoke', async (c) => {
  const companyId = c.get('companyId');
  const jti = c.req.param('jti');

  if (!jti || typeof jti !== 'string') {
    return c.json({ error: 'Missing passport ID' }, 400);
  }

  let reason: string | undefined;
  try {
    const b = await c.req.json() as Record<string, unknown>;
    if (typeof b.reason === 'string' && b.reason) reason = b.reason;
  } catch { /* reason is optional */ }

  if (await store.isPassportRevoked(companyId, jti)) {
    return c.json({ error: 'Passport is already revoked' }, 409);
  }

  await store.revokePassport(companyId, jti, reason);
  const revokeResponse = { jti, revokedAt: new Date().toISOString(), ...(reason !== undefined && { reason }) };
  void fireWebhookEvent(store, companyId, 'passport.revoked', revokeResponse);
  return c.json(revokeResponse, 200);
});

app.get('/v1/passports/revoked', async (c) => {
  const companyId = c.get('companyId');
  const revoked = await store.getRevokedPassports(companyId);
  return c.json({ revoked });
});

// ── OCSP — passport status ─────────────────────────────────────────────────────

app.get('/v1/ocsp/:jti', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const jti = c.req.param('jti');

  if (!jti || typeof jti !== 'string') {
    return c.json({ error: 'Missing passport ID' }, 400);
  }

  const isRevoked = await store.isPassportRevoked(companyId, jti);
  const checkedAt = new Date().toISOString();

  const responseData: Record<string, unknown> = {
    jti,
    companyId,
    status: isRevoked ? 'revoked' : 'valid',
    checkedAt,
  };

  if (isRevoked) {
    const details = await store.getPassportRevocationDetails(companyId, jti);
    if (details) {
      responseData['revokedAt'] = details.revokedAt;
      if (details.reason !== undefined) responseData['reason'] = details.reason;
    }
  }

  const signature = signPayload(responseData, tenant.keys.privateKey);

  c.header('Cache-Control', 'public, max-age=300');
  return c.json({ ...responseData, caPublicKey: tenant.keys.publicKey, signature });
});

// ── Company SVID ──────────────────────────────────────────────────────────────

app.post('/v1/companies/svid', (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const spiffeId = companySpiffeId(companyId);
  const svid = issueJwtSvid(spiffeId, tenant.keys.privateKey, tenant.keys.publicKey);
  return c.json({ companyId, spiffeId, svid });
});

// ── RFC 8693 Token Exchange ───────────────────────────────────────────────────

app.post('/v1/token/exchange', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  if (body['grant_type'] !== GRANT_TYPE) {
    return c.json({ error: `unsupported_grant_type: expected ${GRANT_TYPE}` }, 400);
  }
  if (body['subject_token_type'] !== TOKEN_TYPE_JWT || body['actor_token_type'] !== TOKEN_TYPE_JWT) {
    return c.json({ error: `unsupported_token_type: both token types must be ${TOKEN_TYPE_JWT}` }, 400);
  }

  const subjectToken = body['subject_token'];
  const actorToken = body['actor_token'];
  if (typeof subjectToken !== 'string' || !subjectToken) {
    return c.json({ error: 'Missing or invalid field: subject_token is required' }, 400);
  }
  if (typeof actorToken !== 'string' || !actorToken) {
    return c.json({ error: 'Missing or invalid field: actor_token is required' }, 400);
  }

  try {
    const response = exchangeToken(subjectToken, actorToken, tenant.keys.privateKey, tenant.keys.publicKey);
    const claims = verifyJwtSvid(response.access_token, tenant.keys.publicKey);
    return c.json({ ...response, delegation_chain: extractDelegationChain(claims) });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 400);
  }
});

// ── Simple delegation token issuance ─────────────────────────────────────────

app.post('/v1/token-exchange', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, actingOn, scope } = body;
  if (typeof agentId !== 'string' || !agentId) {
    return c.json({ error: 'Missing or invalid field: agentId is required' }, 400);
  }
  if (typeof actingOn !== 'string' || !actingOn) {
    return c.json({ error: 'Missing or invalid field: actingOn is required' }, 400);
  }
  if (typeof scope !== 'string' || !scope) {
    return c.json({ error: 'Missing or invalid field: scope is required' }, 400);
  }

  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);

  const subSpiffeId = companySpiffeId(actingOn);
  const actSpiffeId = agentSpiffeId(companyId, agentId);

  const token = issueJwtSvid(subSpiffeId, tenant.keys.privateKey, tenant.keys.publicKey, 3600, {
    act: { sub: actSpiffeId },
    scope,
  });
  const claims = verifyJwtSvid(token, tenant.keys.publicKey);

  return c.json({ token, sub: claims.sub, act: claims.act, jti: claims.jti, scope: claims.scope }, 201);
});

// ── Cross-org delegation tokens ───────────────────────────────────────────────

/**
 * POST /v1/token/cross-org
 *
 * Issues a cross-org delegation token (XORG+JWT) that Company A's agent can
 * present to Company B's MCP server.
 *
 * The token is signed with the authenticated company's private key and
 * carries the agent's delegation chain plus the target org and requested
 * scopes. Company B verifies it offline using Company A's CA public key
 * (fetched once from GET /v1/ca/public-key?companyId=<originOrg>).
 *
 * TTL is capped at CROSS_ORG_MAX_TTL (900 s / 15 minutes).
 */
app.post('/v1/token/cross-org', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, targetOrg, targetOrgSpiffeId, scopes, ttl } = body;

  if (typeof agentId !== 'string' || !agentId) {
    return c.json({ error: 'Missing or invalid field: agentId is required' }, 400);
  }
  if (typeof targetOrg !== 'string' || !targetOrg) {
    return c.json({ error: 'Missing or invalid field: targetOrg is required' }, 400);
  }
  if (
    !Array.isArray(scopes) ||
    scopes.length === 0 ||
    !scopes.every((s): s is string => typeof s === 'string')
  ) {
    return c.json({ error: 'Missing or invalid field: scopes must be a non-empty array of strings' }, 400);
  }

  const agent = await store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);

  const resolvedTargetOrgSpiffeId =
    typeof targetOrgSpiffeId === 'string' && targetOrgSpiffeId
      ? targetOrgSpiffeId
      : companySpiffeId(targetOrg);

  let resolvedTtl = CROSS_ORG_MAX_TTL;
  if (ttl !== undefined) {
    if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl <= 0) {
      return c.json({ error: 'ttl must be a positive integer (seconds, max 900)' }, 400);
    }
    if (ttl > CROSS_ORG_MAX_TTL) {
      return c.json(
        { error: `Cross-org token TTL may not exceed ${CROSS_ORG_MAX_TTL} seconds (15 minutes)` },
        400,
      );
    }
    resolvedTtl = ttl;
  }

  const originOrgSpiffeId = companySpiffeId(companyId);
  const delegationChain   = [originOrgSpiffeId, agent.spiffeId];

  const token = issueCrossOrgToken({
    agentId,
    agentSpiffeId: agent.spiffeId,
    originOrg: companyId,
    originOrgSpiffeId,
    targetOrg,
    targetOrgSpiffeId: resolvedTargetOrgSpiffeId,
    scopes,
    delegationChain,
    ttl: resolvedTtl,
    privateKeyPem: tenant.keys.privateKey,
    publicKeyPem: tenant.keys.publicKey,
  });

  return c.json({
    token,
    originOrg: companyId,
    originOrgSpiffeId,
    targetOrg,
    targetOrgSpiffeId: resolvedTargetOrgSpiffeId,
    agentId,
    agentSpiffeId: agent.spiffeId,
    delegationChain,
    scopes,
    caPublicKey: tenant.keys.publicKey,
    expiresIn: resolvedTtl,
  }, 201);
});

// ── Attestation ───────────────────────────────────────────────────────────────

app.post('/v1/attest', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, actionType, payload, delegation: delegationToken } = body;
  if (
    typeof agentId !== 'string' || !agentId ||
    typeof actionType !== 'string' || !actionType ||
    payload === undefined
  ) {
    return c.json(
      { error: 'Missing or invalid fields: agentId, actionType, payload are required' },
      400,
    );
  }

  const attestationPayload: Record<string, unknown> = { agentId, companyId, actionType, payload };

  let delegation: DelegationInfo | undefined;
  if (typeof delegationToken === 'string' && delegationToken) {
    try {
      const claims = verifyJwtSvid(delegationToken, tenant.keys.publicKey);
      delegation = {
        subject: claims.sub,
        delegationChain: extractDelegationChain(claims),
        act: claims.act ?? null,
        tokenId: claims.jti,
      };
    } catch (err) {
      return c.json({ error: `Invalid delegation: ${(err as Error).message}` }, 400);
    }
  }

  // Append the record and atomically commit a CA-signed Signed Tree Head over
  // the new tree state. If the STH signing or the transaction fails, this throws
  // and the in-memory chain is left untouched — no record without a checkpoint.
  // Serialized per company so the STH leaf set matches the committed log.
  const { record, sth } = await withAppendLock(companyId, () =>
    appendWithCheckpoint({
      chain: tenant.chain,
      signingPrivateKey: tenant.keys.privateKey,
      caPrivateKey: caKeys.privateKey,
      payload: attestationPayload,
      delegation,
      persist: (rec, buildSth) => store.appendRecordWithSTH(companyId, rec, buildSth),
    }),
  );

  const verifyResult = tenant.chain.verify(tenant.keys.publicKey);
  broadcast({
    type: 'record',
    record,
    checkpoint: sth,
    valid: verifyResult.valid,
    ...(verifyResult.valid ? { merkleRoot: verifyResult.merkleRoot } : { failedAtIndex: verifyResult.failedAtIndex }),
  });
  void fireWebhookEvent(store, companyId, 'attestation.created', { record: record as unknown as Record<string, unknown> });
  return c.json(record, 201);
});

app.get('/v1/chain', (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  return c.json({ records: tenant.chain.getRecords() });
});

app.get('/v1/verify', (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const result = tenant.chain.verify(tenant.keys.publicKey);
  if (result.valid) return c.json({ valid: true, merkleRoot: result.merkleRoot });
  return c.json({ valid: false, failedAtIndex: result.failedAtIndex, error: result.error });
});

app.get('/v1/proof/:index', (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const idx = Number(c.req.param('index'));
  if (!Number.isInteger(idx) || idx < 0) {
    return c.json({ error: 'index must be a non-negative integer' }, 400);
  }
  try {
    const { record, proof, root } = tenant.chain.getProof(idx);
    return c.json({ record, proof, root });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 404);
  }
});

// ── Key rotation ──────────────────────────────────────────────────────────────

/**
 * POST /v1/companies/rotate-keys
 *
 * Generates a new Ed25519 keypair for the authenticated company.
 * The old key is moved to keys_history and remains valid for verifying
 * passports it signed during the VANE_KEY_ROTATION_GRACE_PERIOD_HOURS window
 * (default 24 h). New passports are immediately signed with the new key.
 */
app.post('/v1/companies/rotate-keys', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const oldKeys = tenant.keys;

  await store.retireCurrentKey(companyId);

  const newKeys = generateKeyPair();
  await store.saveKeys(companyId, newKeys);
  tenant.keys = newKeys;

  const rotatedAt = new Date().toISOString();
  const newKid = deriveKeyId(newKeys.publicKey);
  const oldKid = deriveKeyId(oldKeys.publicKey);

  return c.json({
    companyId,
    rotatedAt,
    gracePeriodHours: GRACE_PERIOD_HOURS,
    newKey: {
      kid: newKid,
      pem: newKeys.publicKey,
      fingerprint: pemFingerprint(newKeys.publicKey),
      jwk: pemToJwk(newKeys.publicKey, newKid),
    },
    retiredKey: {
      kid: oldKid,
      pem: oldKeys.publicKey,
      fingerprint: pemFingerprint(oldKeys.publicKey),
      verifiableUntil: new Date(Date.now() + GRACE_PERIOD_HOURS * 3600 * 1000).toISOString(),
    },
  });
});

// ── CA public-key & discovery ─────────────────────────────────────────────────

// Convert an Ed25519 SPKI PEM to a JWK object with Vane-standard fields.
function pemToJwk(publicKeyPem: string, kid: string): Record<string, unknown> {
  const raw = createPublicKey(publicKeyPem).export({ format: 'jwk' }) as Record<string, unknown>;
  return { ...raw, kid, alg: 'EdDSA', use: 'sig' };
}

// SHA-256 of the SPKI DER, formatted as "SHA256:<base64url>" (SSH-style).
function pemFingerprint(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' }) as Buffer;
  const b64 = createHash('sha256').update(der).digest('base64').replace(/=+$/, '');
  return `SHA256:${b64}`;
}

/**
 * GET /v1/ca/public-key?companyId=<id>
 *
 * Returns the company's CA public key in three formats:
 *   - pem        — SPKI PEM (copy-paste ready)
 *   - jwk        — RFC 7517 JSON Web Key (include in your JWKS endpoint)
 *   - fingerprint— SHA-256 of the SPKI DER, base64-encoded (SSH-style)
 *
 * No authentication required. Intended to be cached and fetched on startup
 * by verifiers that need to validate passports offline.
 */
app.get('/v1/ca/public-key', async (c) => {
  const companyId = c.req.query('companyId');
  if (!companyId) {
    return c.json({ error: 'Missing required query parameter: companyId' }, 400);
  }

  const company = await store.getCompany(companyId);
  if (!company) return c.json({ error: `Company not found: ${companyId}` }, 404);

  if (!tenants.has(companyId)) await initTenant(companyId);
  const tenant = tenants.get(companyId)!;

  const kid = deriveKeyId(tenant.keys.publicKey);
  const jwk = pemToJwk(tenant.keys.publicKey, kid);
  const fingerprint = pemFingerprint(tenant.keys.publicKey);

  c.header('Cache-Control', 'public, max-age=3600');
  return c.json({
    companyId,
    spiffeId: company.spiffeId,
    kid,
    pem: tenant.keys.publicKey,
    jwk,
    fingerprint,
    // Convenience JWKS-compatible wrapper so this URL can be used directly
    // as a jwks_uri — verifiers only need to look at keys[0].
    keys: [jwk],
  });
});

/**
 * GET /v1/ca/public-keys?companyId=<id>
 *
 * Returns all public keys for the company: the active key and any retired keys
 * still within the grace period. External verifiers should use this endpoint
 * (instead of /v1/ca/public-key) so they can verify passports signed with a
 * recently rotated-out key.
 *
 * No authentication required.
 */
app.get('/v1/ca/public-keys', async (c) => {
  const companyId = c.req.query('companyId');
  if (!companyId) {
    return c.json({ error: 'Missing required query parameter: companyId' }, 400);
  }

  const company = await store.getCompany(companyId);
  if (!company) return c.json({ error: `Company not found: ${companyId}` }, 404);

  if (!tenants.has(companyId)) await initTenant(companyId);
  const tenant = tenants.get(companyId)!;

  const cutoff = new Date(Date.now() - GRACE_PERIOD_HOURS * 3600 * 1000).toISOString();
  const retiredKeyRecords = await store.getRetiredKeys(companyId, cutoff);

  const activeKid = deriveKeyId(tenant.keys.publicKey);
  const activeEntry = {
    kid: activeKid,
    pem: tenant.keys.publicKey,
    jwk: pemToJwk(tenant.keys.publicKey, activeKid),
    fingerprint: pemFingerprint(tenant.keys.publicKey),
    status: 'active',
  };

  const retiredEntries = retiredKeyRecords.map(r => {
    const kid = deriveKeyId(r.publicKey);
    return {
      kid,
      pem: r.publicKey,
      jwk: pemToJwk(r.publicKey, kid),
      fingerprint: pemFingerprint(r.publicKey),
      status: 'retired',
      retiredAt: r.retiredAt,
      verifiableUntil: new Date(new Date(r.retiredAt).getTime() + GRACE_PERIOD_HOURS * 3600 * 1000).toISOString(),
    };
  });

  const allKeys = [activeEntry, ...retiredEntries];

  c.header('Cache-Control', 'public, max-age=300');
  return c.json({
    companyId,
    spiffeId: company.spiffeId,
    gracePeriodHours: GRACE_PERIOD_HOURS,
    // JWKS-compatible: all keys a verifier needs to check any in-window passport.
    keys: allKeys,
  });
});

/**
 * GET /v1/ca/well-known?companyId=<id>
 *
 * OpenID Connect-style discovery document for the company's CA.
 * Describes the cryptographic configuration, key location, and
 * passport format expected by verifiers.
 *
 * Verifiers should fetch this once, cache it, and use jwks_uri
 * to obtain the current key set for offline passport verification.
 *
 * No authentication required.
 */
app.get('/v1/ca/well-known', async (c) => {
  const companyId = c.req.query('companyId');
  if (!companyId) {
    return c.json({ error: 'Missing required query parameter: companyId' }, 400);
  }

  const company = await store.getCompany(companyId);
  if (!company) return c.json({ error: `Company not found: ${companyId}` }, 404);

  if (!tenants.has(companyId)) await initTenant(companyId);
  const tenant = tenants.get(companyId)!;

  const kid = deriveKeyId(tenant.keys.publicKey);
  const jwk = pemToJwk(tenant.keys.publicKey, kid);
  const fingerprint = pemFingerprint(tenant.keys.publicKey);

  // Construct the base URL from the request so the document is self-describing.
  // VANE_BASE_URL env var overrides inference from Host + X-Forwarded-Proto.
  const proto = process.env.VANE_BASE_URL
    ? ''
    : (c.req.header('X-Forwarded-Proto') ?? 'http');
  const host = c.req.header('Host') ?? 'localhost:3000';
  const baseUrl = process.env.VANE_BASE_URL ?? `${proto}://${host}`;
  const jwksUri = `${baseUrl}/v1/ca/public-key?companyId=${encodeURIComponent(companyId)}`;

  c.header('Cache-Control', 'public, max-age=3600');
  return c.json({
    // OIDC-compatible fields
    issuer: `spiffe://${TRUST_DOMAIN}/ca`,
    jwks_uri: jwksUri,
    id_token_signing_alg_values_supported: ['EdDSA'],
    response_types_supported: ['token'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],

    // Vane-specific identity context
    company_id: companyId,
    company_spiffe_id: company.spiffeId,
    trust_domain: TRUST_DOMAIN,

    // Cryptographic configuration
    algorithms_supported: ['EdDSA'],
    key_type: 'OKP',
    curve: 'Ed25519',
    kid,
    fingerprint,

    // Inline JWKS for verifiers that don't want a second round-trip
    keys: [jwk],

    // Vane Agent Passport (CAP) format specification
    passport_format: {
      version: 1,
      token_type: 'CAP+JWT',
      audience: PASSPORT_AUDIENCE,
      claims_namespace: 'vane',
      scope_format: 'category:name',
      scope_wildcards_supported: true,
    },

    // SDK and server metadata
    vane_version: '0.1.0',
  });
});

// ── Webhooks ──────────────────────────────────────────────────────────────────

app.post('/v1/webhooks', async (c) => {
  const companyId = c.get('companyId');

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { url, events } = body;
  if (typeof url !== 'string' || !url) {
    return c.json({ error: 'Missing or invalid field: url is required' }, 400);
  }
  if (!Array.isArray(events) || events.length === 0 || !events.every((e): e is string => typeof e === 'string')) {
    return c.json({ error: 'Missing or invalid field: events must be a non-empty array of strings' }, 400);
  }

  try {
    new URL(url);
  } catch {
    return c.json({ error: 'Invalid url: must be a valid URL' }, 400);
  }

  const { webhook, rawSecret } = await store.createWebhook(companyId, url, events);
  return c.json({ ...webhook, secret: rawSecret }, 201);
});

app.get('/v1/webhooks', async (c) => {
  const companyId = c.get('companyId');
  const webhooks = await store.listWebhooks(companyId);
  return c.json({ webhooks });
});

app.delete('/v1/webhooks/:id', async (c) => {
  const companyId = c.get('companyId');
  const id = c.req.param('id');
  const deleted = await store.deleteWebhook(id, companyId);
  if (!deleted) return c.json({ error: 'Webhook not found' }, 404);
  return c.json({ deleted: true });
});

app.post('/v1/webhooks/:id/test', async (c) => {
  const companyId = c.get('companyId');
  const id = c.req.param('id');

  const webhook = await store.getWebhookById(id, companyId);
  if (!webhook) return c.json({ error: 'Webhook not found' }, 404);

  const wh = await store.getWebhookForDelivery(id);
  if (!wh) return c.json({ error: 'Webhook not found or inactive' }, 404);

  const event = 'webhook.test';
  const payload: Record<string, unknown> = {
    webhookId: id,
    url: webhook.url,
    events: webhook.events,
    sentAt: new Date().toISOString(),
  };

  const delivery = await store.createDelivery(id, event, payload);

  const { attemptDelivery } = await import('../webhooks/delivery.js');
  const result = await attemptDelivery(wh.url, wh.rawSecret, event, payload);

  if (result.success) {
    await store.markDeliveryDelivered(delivery.id, 1);
  } else {
    await store.markDeliveryFailed(delivery.id, 1, result.error ?? 'delivery failed');
  }

  return c.json({
    success: result.success,
    deliveryId: delivery.id,
    ...(result.statusCode !== undefined && { statusCode: result.statusCode }),
    ...(result.error !== undefined && { error: result.error }),
  });
});

// ── Timeline view HTML helpers ────────────────────────────────────────────────

function timelineHumanizeAction(actionType: string): string {
  return (
    actionType
      .replace(/([a-z])([A-Z])/g, '$1 $2')
      .replace(/[-_]+/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase())
      .trim() || actionType
  );
}

function timelineEscHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function timelineSafeJson(data: unknown): string {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
}

function timelineLoginPage(agentId: string): string {
  const ea = timelineEscHtml(agentId);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authenticate · Vane Timeline</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0a1628;color:#f0ede8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.wrap{width:100%;max-width:420px;padding:2rem}
.logo{font-size:.8rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#b5451b;margin-bottom:2.5rem}
h1{font-size:1.5rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.02em}
.agent{font-family:'SF Mono','Fira Code',monospace;font-size:.82rem;color:#6b7fa3;margin-bottom:2rem;word-break:break-all}
p{font-size:.88rem;color:#6b7fa3;margin-bottom:1rem}
.card{background:#0e1e38;border:1px solid #1e3a5f;border-radius:.75rem;padding:1.5rem}
input{width:100%;background:#0a1628;border:1px solid #1e3a5f;border-radius:.5rem;padding:.65rem 1rem;color:#f0ede8;font-size:.88rem;margin-bottom:.75rem;outline:none;transition:border-color .2s;font-family:inherit}
input:focus{border-color:#b5451b}
input::placeholder{color:#3d5a7a}
button{width:100%;background:#b5451b;border:none;border-radius:.5rem;padding:.7rem 1rem;color:#f0ede8;font-size:.88rem;font-weight:600;cursor:pointer;transition:background .2s;font-family:inherit}
button:hover{background:#d4563f}
.divider{text-align:center;color:#3d5a7a;font-size:.75rem;margin:1.25rem 0}
.cmd{background:#060e1a;border:1px solid #1e3a5f;border-radius:.5rem;padding:.9rem 1rem;font-family:'SF Mono','Fira Code',monospace;font-size:.72rem;color:#6b7fa3;white-space:pre;overflow-x:auto}
.cmd em{color:#b5451b;font-style:normal}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">Vane</div>
  <h1>Agent Timeline</h1>
  <div class="agent">${ea}</div>
  <div class="card">
    <p>Enter your API key to view this agent's action history.</p>
    <form onsubmit="go(event)">
      <input type="password" id="k" placeholder="vane_…" autocomplete="off" spellcheck="false">
      <button type="submit">View Timeline →</button>
    </form>
    <div class="divider">or use the API directly</div>
    <div class="cmd">curl \\
  -H "<em>Authorization: Bearer &lt;key&gt;</em>" \\
  /v1/agents/${ea}/timeline</div>
  </div>
</div>
<script>function go(e){e.preventDefault();var k=document.getElementById('k').value.trim();if(k)window.location.search='?token='+encodeURIComponent(k);}</script>
</body>
</html>`;
}

interface TimelineDashboardEntry {
  index: number;
  timestamp: string;
  actionType: string;
  actionPayload: unknown;
  hash: string;
  verified: boolean;
  link: { chainIndex: number; hash: string } | null;
  hasDelegation: boolean;
}

function timelineDashboard(opts: {
  agentId: string;
  spiffeId: string;
  companyId: string;
  entries: TimelineDashboardEntry[];
}): string {
  const { agentId, spiffeId, companyId, entries } = opts;
  const verifiedCount = entries.filter(e => e.verified).length;
  const data = timelineSafeJson({ agentId, spiffeId, companyId, entries, verifiedCount });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${timelineEscHtml(agentId)} · Timeline · Vane</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --navy:#0a1628;--card:#0e1e38;--card-hover:#122444;--border:#1e3a5f;--border-hover:#2a4f7a;
  --off-white:#f0ede8;--muted:#5a7a9e;--dim:#3d5a7a;
  --terra:#b5451b;--terra-light:#d4563f;
  --green:#22c55e;--red:#ef4444;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:'SF Mono','Fira Code','Consolas',monospace;
}
body{background:var(--navy);color:var(--off-white);font-family:var(--sans);min-height:100vh;-webkit-font-smoothing:antialiased}

/* Header */
header{position:sticky;top:0;z-index:100;height:3.25rem;border-bottom:1px solid var(--border);
  background:rgba(10,22,40,.92);backdrop-filter:blur(12px);
  display:flex;align-items:center;justify-content:space-between;padding:0 1.5rem}
.brand{display:flex;align-items:center;gap:.4rem;font-weight:700;font-size:.82rem;
  letter-spacing:.1em;text-transform:uppercase;color:var(--terra)}
.live{display:flex;align-items:center;gap:.45rem;font-size:.75rem;color:var(--dim)}
.live-dot{width:6px;height:6px;background:var(--terra);border-radius:50%;
  animation:pulse 2s ease infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.75)}}
.hdr-stat{font-size:.8rem;color:var(--muted)}
.hdr-stat .ok{color:var(--green);font-weight:600}
.hdr-stat .bad{color:var(--red);font-weight:600}

/* Hero */
.hero{max-width:800px;margin:0 auto;padding:2.5rem 1.5rem 1.75rem}
.hero-agent{font-size:1.75rem;font-weight:700;letter-spacing:-.025em;margin-bottom:.4rem}
.hero-spiffe{font-family:var(--mono);font-size:.72rem;color:var(--dim);word-break:break-all;margin-bottom:.75rem}
.hero-meta{font-size:.82rem;color:var(--muted)}
.hero-meta strong{color:var(--off-white)}

/* Timeline */
.tl-wrap{max-width:800px;margin:0 auto;padding:.5rem 1.5rem 5rem}
.tl{position:relative;padding-left:2.25rem}
.tl::before{content:'';position:absolute;left:.45rem;top:.5rem;bottom:.5rem;width:2px;
  background:linear-gradient(to bottom,var(--terra) 0%,var(--border) 100%);
  transform-origin:top;animation:drawLine .7s cubic-bezier(.4,0,.2,1) forwards}
@keyframes drawLine{from{transform:scaleY(0)}to{transform:scaleY(1)}}

.entry{position:relative;margin-bottom:1.25rem;opacity:0;
  animation:slideIn .38s ease forwards;animation-delay:calc(var(--i)*75ms + 150ms)}
@keyframes slideIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:translateX(0)}}
.entry-new{animation:newRecord .6s ease}
@keyframes newRecord{0%,100%{box-shadow:none}30%{box-shadow:0 0 0 2px var(--terra)}}

.dot{position:absolute;left:-1.85rem;top:1.1rem;width:10px;height:10px;border-radius:50%;
  background:var(--green);box-shadow:0 0 8px rgba(34,197,94,.35);border:2px solid var(--navy)}
.dot.fail{background:var(--red);box-shadow:0 0 8px rgba(239,68,68,.35)}

.card{background:var(--card);border:1px solid var(--border);border-radius:.75rem;
  padding:1.1rem 1.25rem;transition:border-color .2s}
.card:hover{border-color:var(--border-hover)}

.card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:.75rem;margin-bottom:.5rem}
.action{font-size:.95rem;font-weight:600;color:var(--off-white);flex:1;line-height:1.3}

.badge{display:inline-flex;align-items:center;gap:.25rem;padding:.18rem .6rem;
  border-radius:999px;font-size:.68rem;font-weight:700;letter-spacing:.04em;white-space:nowrap;flex-shrink:0}
.badge-ok{background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.22)}
.badge-fail{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.22)}

.card-meta{display:flex;flex-wrap:wrap;gap:.6rem;font-size:.75rem;color:var(--muted);margin-bottom:.75rem}
.ts-abs{opacity:.7}
.chain-idx{font-family:var(--mono);opacity:.6}
.deleg-tag{color:var(--terra);opacity:.8}

/* Payload accordion */
.pay-btn{display:flex;align-items:center;gap:.35rem;font-size:.74rem;color:var(--dim);
  cursor:pointer;background:none;border:none;font-family:var(--sans);padding:.15rem 0;
  transition:color .15s;text-align:left}
.pay-btn:hover{color:var(--muted)}
.pay-caret{font-size:.55rem;transition:transform .2s;display:inline-block}
.pay-btn.open .pay-caret{transform:rotate(90deg)}
.pay-body{display:none;margin-top:.5rem;background:rgba(0,0,0,.22);border:1px solid var(--border);
  border-radius:.45rem;padding:.65rem .85rem;font-family:var(--mono);font-size:.7rem;
  color:var(--off-white);white-space:pre;overflow-x:auto;max-height:280px;overflow-y:auto;
  line-height:1.5}
.pay-body.open{display:block}

/* Crypto rows */
.crypto{display:flex;align-items:center;gap:.5rem;font-size:.69rem;margin-top:.45rem}
.cl{font-family:var(--mono);color:var(--dim);min-width:36px;flex-shrink:0;opacity:.7}
.cv{font-family:var(--mono);color:var(--dim);overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;flex:1;letter-spacing:.03em}
.cv-genesis{color:var(--terra);font-family:var(--sans);font-style:italic;font-size:.69rem}

/* Empty state */
.empty{max-width:800px;margin:4rem auto;padding:3rem 1.5rem;text-align:center}
.empty-title{font-size:1.1rem;color:var(--muted);margin-bottom:1.25rem}
.empty-cmd{display:inline-block;background:var(--card);border:1px solid var(--border);
  border-radius:.6rem;padding:.85rem 1.1rem;font-family:var(--mono);font-size:.72rem;
  color:var(--off-white);text-align:left;line-height:1.6}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>

<header>
  <div class="brand">Vane</div>
  <div class="live" id="live-ind" style="display:none">
    <span class="live-dot"></span><span>live</span>
  </div>
  <div class="hdr-stat" id="hdr-stat"></div>
</header>

<div class="hero">
  <div class="hero-agent" id="h-agent"></div>
  <div class="hero-spiffe" id="h-spiffe"></div>
  <div class="hero-meta" id="h-meta"></div>
</div>

<div class="tl-wrap">
  <div class="tl" id="tl"></div>
  <div class="empty" id="empty" style="display:none">
    <div class="empty-title">No attestations recorded yet.</div>
    <div class="empty-cmd">curl -X POST http://localhost:3000/v1/attest \\<br>  -H "Authorization: Bearer &lt;key&gt;" \\<br>  -H "Content-Type: application/json" \\<br>  -d '{"agentId":"${timelineEscHtml(agentId)}","actionType":"my-action","payload":{}}'</div>
  </div>
</div>

<script>
var D = ${data};

function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function rel(iso){
  var d=(Date.now()-new Date(iso))/1000;
  if(d<5)return 'just now';
  if(d<60)return Math.round(d)+'s ago';
  if(d<3600)return Math.round(d/60)+'m ago';
  if(d<86400)return Math.round(d/3600)+'h ago';
  if(d<604800)return Math.round(d/86400)+'d ago';
  return new Date(iso).toLocaleDateString();
}

function fmtAbs(iso){
  var d=new Date(iso);
  var mo=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  var pad=function(n){return n<10?'0'+n:n};
  return mo[d.getUTCMonth()]+' '+d.getUTCDate()+', '+d.getUTCFullYear()+
    ' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())+' UTC';
}

function card(e,i){
  var badgeCls=e.verified?'badge-ok':'badge-fail';
  var badgeTxt=e.verified?'&#10003; verified':'&#10007; failed';
  var dotCls=e.verified?'dot':'dot fail';
  var payStr=JSON.stringify(e.actionPayload,null,2);
  var linkHtml=e.link===null
    ?'<span class="cv-genesis">&#8854; genesis &mdash; first record in chain</span>'
    :'<span class="cv" title="'+esc(e.link.hash)+'">&#8592; #'+e.link.chainIndex+' &middot; '+esc(e.link.hash.slice(0,16))+'&hellip;</span>';
  var delegTag=e.hasDelegation?'<span class="deleg-tag">delegated</span>':'';
  return '<div class="entry" style="--i:'+i+'" id="e'+e.index+'">'+
    '<div class="'+dotCls+'"></div>'+
    '<div class="card">'+
      '<div class="card-top">'+
        '<span class="action">'+esc(e.actionType)+'</span>'+
        '<span class="badge '+badgeCls+'">'+badgeTxt+'</span>'+
      '</div>'+
      '<div class="card-meta">'+
        '<span class="ts-rel" data-iso="'+esc(e.timestamp)+'">'+rel(e.timestamp)+'</span>'+
        '<span class="ts-abs">'+fmtAbs(e.timestamp)+'</span>'+
        '<span class="chain-idx">#'+e.index+'</span>'+
        delegTag+
      '</div>'+
      '<div>'+
        '<button class="pay-btn" onclick="tog(this)">'+
          '<span class="pay-caret">&#9654;</span> action data'+
        '</button>'+
        '<div class="pay-body">'+esc(payStr)+'</div>'+
      '</div>'+
      '<div class="crypto"><span class="cl">hash</span>'+
        '<span class="cv" title="'+esc(e.hash)+'">'+esc(e.hash.slice(0,20))+'&hellip;'+esc(e.hash.slice(-8))+'</span>'+
      '</div>'+
      '<div class="crypto"><span class="cl">link</span>'+linkHtml+'</div>'+
    '</div>'+
  '</div>';
}

function tog(btn){
  btn.classList.toggle('open');
  btn.nextElementSibling.classList.toggle('open');
}

function render(entries){
  var tl=document.getElementById('tl');
  var em=document.getElementById('empty');
  if(!entries.length){tl.style.display='none';em.style.display='block';return;}
  tl.style.display='';em.style.display='none';
  tl.innerHTML=entries.map(function(e,i){return card(e,i);}).join('');
}

function updateHeader(entries){
  var v=entries.filter(function(e){return e.verified;}).length;
  var t=entries.length;
  var el=document.getElementById('hdr-stat');
  if(t===0){el.innerHTML='no actions yet';return;}
  var cls=v===t?'ok':'bad';
  el.innerHTML='<span class="'+cls+'">'+v+'/'+t+'</span> verified';
}

function updateHero(entries){
  document.getElementById('h-agent').textContent=D.agentId;
  document.getElementById('h-spiffe').textContent=D.spiffeId;
  var t=entries.length;
  if(t===0){
    document.getElementById('h-meta').textContent='No actions recorded yet.';
  } else {
    var last=new Date(entries[entries.length-1].timestamp);
    document.getElementById('h-meta').innerHTML=
      '<strong>'+t+'</strong> action'+(t===1?'':'s')+' recorded &mdash; last seen '+rel(entries[entries.length-1].timestamp);
  }
}

// Tick relative timestamps every 30s
function tickRel(){
  document.querySelectorAll('[data-iso]').forEach(function(el){
    el.textContent=rel(el.getAttribute('data-iso'));
  });
}
setInterval(tickRel,30000);

// Live refresh when token is in URL
var _token=(new URLSearchParams(window.location.search)).get('token');
var _count=D.entries.length;

if(_token){
  document.getElementById('live-ind').style.display='flex';
  setInterval(function(){
    fetch('/v1/agents/'+encodeURIComponent(D.agentId)+'/timeline',
      {headers:{Authorization:'Bearer '+_token}})
      .then(function(r){return r.ok?r.json():null;})
      .then(function(data){
        if(!data||data.totalRecords===_count)return;
        _count=data.totalRecords;
        var entries=data.timeline;
        render(entries);
        updateHeader(entries);
        updateHero(entries);
        // Flash new entries
        var newIdx=document.querySelectorAll('.entry');
        if(newIdx.length){newIdx[newIdx.length-1].classList.add('entry-new');}
      })
      .catch(function(){});
  }, 8000);
}

// Initial paint
render(D.entries);
updateHeader(D.entries);
updateHero(D.entries);
</script>
</body>
</html>`;
}

// ── Unhandled error handler ───────────────────────────────────────────────────

app.onError((err, c) => {
  const requestId = c.get('requestId') ?? null;
  logger.error({ err, requestId }, 'Unhandled error');
  captureException(err);
  return c.json({ error: 'Internal Server Error' }, 500);
});
