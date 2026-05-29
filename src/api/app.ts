import { Hono } from 'hono';
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
import type { DelegationInfo } from '../crypto/index.js';
import { Store } from '../db/store.js';
import { issuePassport, verifyPassport, PASSPORT_TTL_DEFAULT } from '../passport/index.js';
import type { AttestationReceipt } from '../passport/index.js';

const store = new Store();

const keys = store.getKeys() ?? (() => {
  const fresh = generateKeyPair();
  store.saveKeys(fresh);
  return fresh;
})();

const chain = new AttestationChain();
chain.hydrate(store.getAllRecords());

// Bootstrap: on first boot, generate and log a key so the operator can authenticate.
if (!store.hasApiKeys()) {
  const bootstrapKey = store.createApiKey('bootstrap');
  console.log(`\n  Bootstrap API key (shown once): ${bootstrapKey}\n`);
}

export const app = new Hono();

// Auth middleware — all routes except GET /v1/health and POST /v1/setup require a valid Bearer key.
app.use('/v1/*', async (c, next) => {
  if (c.req.method === 'GET' && c.req.path === '/v1/health') return next();
  if (c.req.method === 'POST' && c.req.path === '/v1/setup') return next();

  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  const key = auth.slice(7);
  if (!store.validateApiKey(key)) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  return next();
});

app.get('/v1/health', (c) => {
  return c.json({ status: 'ok' });
});

// One-time setup: creates the first API key with no auth required.
// Returns 403 once any key already exists.
app.post('/v1/setup', (c) => {
  if (store.hasApiKeys()) {
    return c.json({ error: 'Setup already completed' }, 403);
  }
  const key = store.createApiKey('setup');
  return c.json({ key, createdAt: new Date().toISOString() }, 201);
});

// ── API key management ────────────────────────────────────────────────────────

app.post('/v1/keys', async (c) => {
  let label: string | undefined;
  try {
    const body = await c.req.json() as Record<string, unknown>;
    if (typeof body.label === 'string' && body.label) label = body.label;
  } catch {
    // label is optional; empty or absent body is fine
  }
  const key = store.createApiKey(label);
  return c.json({ key, createdAt: new Date().toISOString() }, 201);
});

// ── Agent registration ────────────────────────────────────────────────────────

/**
 * Registers an agent workload and issues its SPIFFE JWT-SVID.
 * In production, this endpoint would require node-attestation before issuance.
 */
app.post('/v1/agents/register', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, companyId, metadata } = body;

  if (typeof agentId !== 'string' || !agentId) {
    return c.json({ error: 'Missing or invalid field: agentId is required' }, 400);
  }

  const spiffeId = agentSpiffeId(agentId);
  const registeredAt = new Date().toISOString();

  store.registerAgent({
    agentId,
    spiffeId,
    companyId: typeof companyId === 'string' ? companyId : undefined,
    registeredAt,
    metadata: metadata && typeof metadata === 'object' && !Array.isArray(metadata)
      ? metadata as Record<string, unknown>
      : undefined,
  });

  const svid = issueJwtSvid(spiffeId, keys.privateKey, keys.publicKey);

  return c.json({ agentId, spiffeId, svid, registeredAt }, 201);
});

/**
 * Issues a fresh JWT-SVID for a registered agent.
 * In production, this would require the caller to prove workload identity first.
 */
app.get('/v1/agents/:agentId/svid', (c) => {
  const agentId = c.req.param('agentId');
  const agent = store.getAgent(agentId);
  if (!agent) {
    return c.json({ error: `Agent not found: ${agentId}` }, 404);
  }
  const svid = issueJwtSvid(agent.spiffeId, keys.privateKey, keys.publicKey);
  return c.json({ agentId, spiffeId: agent.spiffeId, svid });
});

// ── Agent passport issuance ───────────────────────────────────────────────────

/**
 * Issues a Counsel Agent Passport (CAP+JWT) for a registered agent.
 *
 * The passport is a self-contained credential verifiable offline by any party
 * that holds the Counsel CA public key. No network call to Counsel is required
 * at verification time.
 *
 * Request body (all optional):
 *   scopes  — string[]  authorization scopes; defaults to ["tool:*", "attest:write"]
 *   ttl     — number    seconds until expiry; max 86400 (24 h), defaults to 3600 (1 h)
 *
 * Response 201:
 *   passport    — the signed CAP+JWT token
 *   caPublicKey — the CA public key needed to verify this passport offline
 *   (+ metadata fields for convenience)
 */
app.post('/v1/agents/:agentId/passport', async (c) => {
  const agentId = c.req.param('agentId');
  const agent = store.getAgent(agentId);
  if (!agent) {
    return c.json({ error: `Agent not found: ${agentId}` }, 404);
  }

  let body: Record<string, unknown> = {};
  try { body = await c.req.json(); } catch { /* body is optional */ }

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

  // Build the delegation chain. For a solo agent with no company, the chain
  // is a single-element array [agentSpiffeId] — the agent is self-authorizing.
  const org = agent.companyId ?? agentId;
  const orgSpiffeId = agent.companyId
    ? companySpiffeId(agent.companyId)
    : agent.spiffeId;
  const delegationChain = agent.companyId
    ? [orgSpiffeId, agent.spiffeId]
    : [agent.spiffeId];

  const passport = issuePassport({
    agentId,
    agentSpiffeId: agent.spiffeId,
    org,
    orgSpiffeId,
    scopes,
    delegationChain,
    ttl,
    privateKeyPem: keys.privateKey,
    publicKeyPem: keys.publicKey,
  });

  return c.json({
    agentId,
    spiffeId: agent.spiffeId,
    org,
    orgSpiffeId,
    scopes,
    delegationChain,
    passport,
    expiresIn: ttl,
    caPublicKey: keys.publicKey,
  }, 201);
});

/**
 * Verifies a Counsel Agent Passport offline and returns its claims.
 * Primarily a debugging and integration-testing endpoint; production
 * verifiers should call verifyPassport() directly with the CA public key.
 */
app.post('/v1/passport/verify', async (c) => {
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
    caPublicKey: keys.publicKey,
    tool: typeof tool === 'string' ? tool : undefined,
  });

  if (!result.valid) {
    return c.json({ valid: false, error: result.error, code: result.code }, 400);
  }

  const { claims, scopeGranted } = result;
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

// ── Company SVID issuance ─────────────────────────────────────────────────────

/**
 * Issues a JWT-SVID for a company identity (the delegation subject).
 * Used to obtain the subject_token for RFC 8693 token exchange.
 */
app.post('/v1/companies/svid', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { companyId } = body;
  if (typeof companyId !== 'string' || !companyId) {
    return c.json({ error: 'Missing or invalid field: companyId is required' }, 400);
  }

  const spiffeId = companySpiffeId(companyId);
  const svid = issueJwtSvid(spiffeId, keys.privateKey, keys.publicKey);
  return c.json({ companyId, spiffeId, svid });
});

// ── RFC 8693 Token Exchange ───────────────────────────────────────────────────

/**
 * RFC 8693 §2 token exchange endpoint.
 *
 * Accepts JSON body:
 *   grant_type       = "urn:ietf:params:oauth:grant-type:token-exchange"
 *   subject_token    = JWT-SVID of the entity being acted upon
 *   subject_token_type = "urn:ietf:params:oauth:token-type:jwt"
 *   actor_token      = JWT-SVID of the acting agent
 *   actor_token_type = "urn:ietf:params:oauth:token-type:jwt"
 *
 * Returns a delegation token with:
 *   sub = subject's SPIFFE ID
 *   act = { sub: actor's SPIFFE ID, act: <prior chain if any> }
 */
app.post('/v1/token/exchange', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  if (body['grant_type'] !== GRANT_TYPE) {
    return c.json(
      { error: `unsupported_grant_type: expected ${GRANT_TYPE}` },
      400,
    );
  }
  if (
    body['subject_token_type'] !== TOKEN_TYPE_JWT ||
    body['actor_token_type'] !== TOKEN_TYPE_JWT
  ) {
    return c.json(
      { error: `unsupported_token_type: both token types must be ${TOKEN_TYPE_JWT}` },
      400,
    );
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
    const response = exchangeToken(subjectToken, actorToken, keys.privateKey, keys.publicKey);
    const claims = verifyJwtSvid(response.access_token, keys.publicKey);
    return c.json({
      ...response,
      delegation_chain: extractDelegationChain(claims),
    });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 400);
  }
});

// ── Simple delegation token issuance ─────────────────────────────────────────

/**
 * Issues a signed JWT delegation token from first-party inputs.
 *
 * Accepts JSON body:
 *   agentId   — the acting agent (becomes act.sub as its SPIFFE ID)
 *   companyId — company context; must match the registered agent's companyId
 *   actingOn  — entity being acted upon (becomes sub as its SPIFFE ID)
 *   scope     — space-separated permission scope string
 *
 * Returns a signed JWT with sub, act, jti, and scope claims.
 * Pass the `token` value as the `delegation` field in POST /v1/attest.
 */
app.post('/v1/token-exchange', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, companyId, actingOn, scope } = body;

  if (typeof agentId !== 'string' || !agentId) {
    return c.json({ error: 'Missing or invalid field: agentId is required' }, 400);
  }
  if (typeof companyId !== 'string' || !companyId) {
    return c.json({ error: 'Missing or invalid field: companyId is required' }, 400);
  }
  if (typeof actingOn !== 'string' || !actingOn) {
    return c.json({ error: 'Missing or invalid field: actingOn is required' }, 400);
  }
  if (typeof scope !== 'string' || !scope) {
    return c.json({ error: 'Missing or invalid field: scope is required' }, 400);
  }

  const agent = store.getAgent(agentId);
  if (!agent) {
    return c.json({ error: `Agent not found: ${agentId}` }, 404);
  }
  if (agent.companyId && agent.companyId !== companyId) {
    return c.json({ error: `Agent ${agentId} is not registered under company ${companyId}` }, 403);
  }

  const subSpiffeId = companySpiffeId(actingOn);
  const actSpiffeId = agentSpiffeId(agentId);

  const token = issueJwtSvid(subSpiffeId, keys.privateKey, keys.publicKey, 3600, {
    act: { sub: actSpiffeId },
    scope,
  });

  const claims = verifyJwtSvid(token, keys.publicKey);

  return c.json({
    token,
    sub: claims.sub,
    act: claims.act,
    jti: claims.jti,
    scope: claims.scope,
  }, 201);
});

// ── Attestation ───────────────────────────────────────────────────────────────

app.post('/v1/attest', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, companyId, actionType, payload, delegation: delegationToken } = body;

  if (
    typeof agentId !== 'string' || !agentId ||
    typeof companyId !== 'string' || !companyId ||
    typeof actionType !== 'string' || !actionType ||
    payload === undefined
  ) {
    return c.json(
      { error: 'Missing or invalid fields: agentId, companyId, actionType, payload are required' },
      400,
    );
  }

  const attestationPayload: Record<string, unknown> = { agentId, companyId, actionType, payload };

  let delegation: DelegationInfo | undefined;
  if (typeof delegationToken === 'string' && delegationToken) {
    try {
      const claims = verifyJwtSvid(delegationToken, keys.publicKey);
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

  const record = chain.append(attestationPayload, keys.privateKey, delegation);
  store.insertRecord(record);

  return c.json(record, 201);
});

app.get('/v1/chain', (c) => {
  return c.json({ records: chain.getRecords() });
});

app.get('/v1/verify', (c) => {
  const result = chain.verify(keys.publicKey);
  if (result.valid) {
    return c.json({ valid: true, merkleRoot: result.merkleRoot });
  }
  return c.json({ valid: false, failedAtIndex: result.failedAtIndex, error: result.error });
});

// Returns a Merkle inclusion proof for a single record.
// An external auditor can verify this proof in O(log n) without the full chain.
app.get('/v1/proof/:index', (c) => {
  const idx = Number(c.req.param('index'));
  if (!Number.isInteger(idx) || idx < 0) {
    return c.json({ error: 'index must be a non-negative integer' }, 400);
  }
  try {
    const { record, proof, root } = chain.getProof(idx);
    return c.json({ record, proof, root });
  } catch (err) {
    return c.json({ error: (err as Error).message }, 404);
  }
});
