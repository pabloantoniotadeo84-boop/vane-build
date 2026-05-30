import { Hono } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';
import { generateKeyPair, AttestationChain } from '../crypto/index.js';
import {
  agentSpiffeId,
  companySpiffeId,
  issueJwtSvid,
  verifyJwtSvid,
  exchangeToken,
  extractDelegationChain,
  GRANT_TYPE,
  TOKEN_TYPE_JWT,
} from '../crypto/index.js';
import type { DelegationInfo, KeyPair } from '../crypto/index.js';
import { Store } from '../db/store.js';
import { issuePassport, verifyPassport, PASSPORT_TTL_DEFAULT } from '../passport/index.js';
import type { AttestationReceipt } from '../passport/index.js';

// ── Per-company in-memory state ───────────────────────────────────────────────

interface Tenant {
  keys: KeyPair;
  chain: AttestationChain;
}

const store = new Store();
const tenants = new Map<string, Tenant>();

function initTenant(companyId: string): Tenant {
  let keys = store.getKeys(companyId);
  if (!keys) {
    keys = generateKeyPair();
    store.saveKeys(companyId, keys);
  }
  const chain = new AttestationChain();
  chain.hydrate(store.getAllRecords(companyId));
  const tenant: Tenant = { keys, chain };
  tenants.set(companyId, tenant);
  return tenant;
}

// Hydrate all existing tenants from the DB on startup.
for (const company of store.listCompanies()) {
  initTenant(company.companyId);
}

// ── App ───────────────────────────────────────────────────────────────────────

type Env = { Variables: { companyId: string } };

export const app = new Hono<Env>();

// Auth middleware — resolves Bearer key → companyId for all authenticated routes.
app.use('/v1/*', async (c, next) => {
  const isPublic =
    (c.req.method === 'GET'  && c.req.path === '/v1/health') ||
    (c.req.method === 'POST' && c.req.path === '/v1/companies') ||
    (c.req.method === 'POST' && c.req.path === '/v1/setup') ||
    (c.req.method === 'POST' && c.req.path === '/v1/recover-key');
  if (isPublic) return next();

  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  const key = auth.slice(7);
  const result = store.validateApiKey(key);
  if (!result) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  c.set('companyId', result.companyId);
  return next();
});

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/v1/health', (c) => c.json({ status: 'ok' }));

// ── Company registration ──────────────────────────────────────────────────────

/**
 * Creates a new company tenant with its own Ed25519 key pair, attestation chain,
 * and agent registry. Returns a bootstrap API key (shown once — store it).
 * No authentication required; company creation is open and first-come-first-served.
 */
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
  if (store.getCompany(companyId)) {
    return c.json({ error: `Company already exists: ${companyId}` }, 409);
  }

  const spiffeId = companySpiffeId(companyId);
  const company = store.createCompany(
    companyId,
    spiffeId,
    metadata && typeof metadata === 'object' && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : undefined,
  );

  initTenant(companyId);
  const apiKey = store.createApiKey(companyId, 'bootstrap');

  return c.json({
    companyId,
    spiffeId,
    registeredAt: company.registeredAt,
    apiKey,
  }, 201);
});

// Backward-compatible alias for POST /v1/companies (retained for callers that pre-date multi-tenancy).
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
  if (store.getCompany(companyId)) {
    return c.json({ error: `Company already exists: ${companyId}` }, 409);
  }

  const spiffeId = companySpiffeId(companyId);
  const company = store.createCompany(
    companyId,
    spiffeId,
    metadata && typeof metadata === 'object' && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : undefined,
  );

  initTenant(companyId);
  const apiKey = store.createApiKey(companyId, 'bootstrap');

  return c.json({ companyId, spiffeId, registeredAt: company.registeredAt, apiKey }, 201);
});

// Emergency key recovery — localhost only, no auth required.
// Returns the first API key for the given companyId.
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

  const entry = store.getFirstApiKey(companyId);
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
  const key = store.createApiKey(companyId, label);
  return c.json({ key, createdAt: new Date().toISOString() }, 201);
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

  store.registerAgent({
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

app.get('/v1/agents/:agentId/svid', (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const agentId = c.req.param('agentId');
  const agent = store.getAgent(agentId, companyId);
  if (!agent) return c.json({ error: `Agent not found: ${agentId}` }, 404);
  const svid = issueJwtSvid(agent.spiffeId, tenant.keys.privateKey, tenant.keys.publicKey);
  return c.json({ agentId, spiffeId: agent.spiffeId, svid });
});

// ── Agent passport ────────────────────────────────────────────────────────────

app.post('/v1/agents/:agentId/passport', async (c) => {
  const companyId = c.get('companyId');
  const tenant = tenants.get(companyId)!;
  const agentId = c.req.param('agentId');
  const agent = store.getAgent(agentId, companyId);
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

  return c.json({
    agentId,
    spiffeId: agent.spiffeId,
    org: companyId,
    orgSpiffeId,
    scopes,
    delegationChain,
    passport,
    expiresIn: ttl,
    caPublicKey: tenant.keys.publicKey,
  }, 201);
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

  if (store.isPassportRevoked(companyId, claims.jti)) {
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

  if (store.isPassportRevoked(companyId, jti)) {
    return c.json({ error: 'Passport is already revoked' }, 409);
  }

  store.revokePassport(companyId, jti, reason);
  return c.json({ jti, revokedAt: new Date().toISOString(), ...(reason !== undefined && { reason }) }, 200);
});

app.get('/v1/passports/revoked', (c) => {
  const companyId = c.get('companyId');
  const revoked = store.getRevokedPassports(companyId);
  return c.json({ revoked });
});

// ── Company SVID ──────────────────────────────────────────────────────────────

// Issues a JWT-SVID for the authenticated company identity.
// Used as the subject_token for RFC 8693 token exchange.
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

  const agent = store.getAgent(agentId, companyId);
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

  // companyId is authoritative from auth — not accepted from the request body.
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
  store.insertRecord(companyId, record);
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
