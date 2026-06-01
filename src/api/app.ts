import { Hono } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';
import { generateKeyPair, AttestationChain, signPayload } from '../crypto/index.js';
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
} from '../crypto/index.js';
import type { DelegationInfo, KeyPair } from '../crypto/index.js';
import { Store } from '../db/store.js';
import { issuePassport, verifyPassport, PASSPORT_TTL_DEFAULT, PASSPORT_AUDIENCE } from '../passport/index.js';
import type { AttestationReceipt } from '../passport/index.js';
import { broadcast } from './ws.js';
import { fireWebhookEvent, startWebhookScheduler } from '../webhooks/index.js';
import type { IncomingMessage } from 'node:http';
import type { TLSSocket, PeerCertificate } from 'node:tls';
import { randomUUID, createPublicKey, createHash } from 'node:crypto';
import { logger } from '../logger.js';
import { captureException } from '../sentry.js';
import { rateLimitMiddleware } from './rate-limit.js';

// ── Per-company in-memory state ───────────────────────────────────────────────

interface Tenant {
  keys: KeyPair;
  chain: AttestationChain;
}

const store = new Store();
logger.info('Connecting to database');
await store.init();
logger.info('Database ready');

const tenants = new Map<string, Tenant>();

async function initTenant(companyId: string): Promise<Tenant> {
  let keys = await store.getKeys(companyId);
  if (!keys) {
    keys = generateKeyPair();
    await store.saveKeys(companyId, keys);
  }
  const chain = new AttestationChain();
  chain.hydrate(await store.getAllRecords(companyId));
  const tenant: Tenant = { keys, chain };
  tenants.set(companyId, tenant);
  return tenant;
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

// ── Auth middleware ───────────────────────────────────────────────────────────
// Resolution order:
//   1. mTLS client certificate CN → companyId (when COUNSEL_MTLS_CA_CERT is set)
//   2. Bearer <api_key>           → api_keys table
//   3. Bearer <oauth_token>       → oauth_tokens table (prefix: "oauth_")

app.use('/v1/*', async (c, next) => {
  const isPublic =
    (c.req.method === 'GET'  && c.req.path === '/v1/health') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/ca/public-key') ||
    (c.req.method === 'GET'  && c.req.path === '/v1/ca/well-known') ||
    (c.req.method === 'POST' && c.req.path === '/v1/companies') ||
    (c.req.method === 'POST' && c.req.path === '/v1/setup') ||
    (c.req.method === 'POST' && c.req.path === '/v1/recover-key') ||
    (c.req.method === 'POST' && c.req.path === '/v1/oauth/token');
  if (isPublic) return next();

  // 1. mTLS: extract CN from a verified client certificate.
  //    Only attempted when the server was started with COUNSEL_MTLS_CA_CERT set
  //    (i.e., the underlying socket is a TLSSocket).
  if (process.env.COUNSEL_MTLS_CA_CERT) {
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
  const ttl =
    typeof rawTtl === 'number' && rawTtl > 0 && rawTtl <= 86400
      ? rawTtl
      : PASSPORT_TTL_DEFAULT;

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

  const currentPassport = c.req.header('Counsel-Passport');
  if (!currentPassport) {
    return c.json({ error: 'Missing Counsel-Passport header' }, 400);
  }

  const verification = verifyPassport(currentPassport, { caPublicKey: tenant.keys.publicKey });
  if (!verification.valid) {
    return c.json({ error: verification.error, code: verification.code }, 401);
  }
  const { claims } = verification;

  if (claims.counsel.agentId !== agentId) {
    return c.json({ error: 'Passport does not belong to the specified agent' }, 403);
  }
  if (claims.counsel.org !== companyId) {
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
    org: claims.counsel.org,
    orgSpiffeId: claims.counsel.orgSpiffeId,
    scopes: claims.counsel.scopes,
    delegationChain: claims.counsel.delegationChain,
    ...(claims.counsel.delegationId !== undefined && { delegationId: claims.counsel.delegationId }),
    ttl,
    privateKeyPem: tenant.keys.privateKey,
    publicKeyPem: tenant.keys.publicKey,
  });

  const rotateResponse = {
    agentId,
    spiffeId: agent.spiffeId,
    org: companyId,
    orgSpiffeId: claims.counsel.orgSpiffeId,
    scopes: claims.counsel.scopes,
    delegationChain: claims.counsel.delegationChain,
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

  const result = verifyPassport(passport, {
    caPublicKey: tenant.keys.publicKey,
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
    type: 'CounselAttestationReceipt',
    passportId: claims.jti,
    agentId: claims.counsel.agentId,
    agentSpiffeId: claims.sub,
    org: claims.counsel.org,
    orgSpiffeId: claims.counsel.orgSpiffeId,
    tool: typeof tool === 'string' ? tool : '(not checked)',
    scopeGranted,
    delegationChain: claims.counsel.delegationChain,
    issuedBy: claims.iss,
    passportIssuedAt: new Date(claims.iat * 1000).toISOString(),
    passportExpiresAt: new Date(claims.exp * 1000).toISOString(),
    verifiedAt: new Date().toISOString(),
    verifier: 'counsel-server/0.1.0',
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

  const record = tenant.chain.append(attestationPayload, tenant.keys.privateKey, delegation);
  await store.insertRecord(companyId, record);
  const verifyResult = tenant.chain.verify(tenant.keys.publicKey);
  broadcast({
    type: 'record',
    record,
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

// ── CA public-key & discovery ─────────────────────────────────────────────────

// Convert an Ed25519 SPKI PEM to a JWK object with Counsel-standard fields.
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
  // COUNSEL_BASE_URL env var overrides inference from Host + X-Forwarded-Proto.
  const proto = process.env.COUNSEL_BASE_URL
    ? ''
    : (c.req.header('X-Forwarded-Proto') ?? 'http');
  const host = c.req.header('Host') ?? 'localhost:3000';
  const baseUrl = process.env.COUNSEL_BASE_URL ?? `${proto}://${host}`;
  const jwksUri = `${baseUrl}/v1/ca/public-key?companyId=${encodeURIComponent(companyId)}`;

  c.header('Cache-Control', 'public, max-age=3600');
  return c.json({
    // OIDC-compatible fields
    issuer: `spiffe://${TRUST_DOMAIN}/ca`,
    jwks_uri: jwksUri,
    id_token_signing_alg_values_supported: ['EdDSA'],
    response_types_supported: ['token'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],

    // Counsel-specific identity context
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

    // Counsel Agent Passport (CAP) format specification
    passport_format: {
      version: 1,
      token_type: 'CAP+JWT',
      audience: PASSPORT_AUDIENCE,
      claims_namespace: 'counsel',
      scope_format: 'category:name',
      scope_wildcards_supported: true,
    },

    // SDK and server metadata
    counsel_version: '0.1.0',
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

// ── Unhandled error handler ───────────────────────────────────────────────────

app.onError((err, c) => {
  const requestId = c.get('requestId') ?? null;
  logger.error({ err, requestId }, 'Unhandled error');
  captureException(err);
  return c.json({ error: 'Internal Server Error' }, 500);
});
