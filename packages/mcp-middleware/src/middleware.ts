import { verifyPassport, verifyCrossOrgToken, CROSS_ORG_TOKEN_TYPE } from './verify.js';
import type {
  AttestationReceipt,
  VaneMiddlewareOptions,
  VanePassportClaims,
  CrossOrgDelegationClaims,
  PassportVerificationResult,
  VerifyOptions,
} from './types.js';

const PACKAGE_VERSION = '@vane.build/mcp-middleware@0.1.0';

// Header name used to pass the attestation receipt to downstream handlers.
// Value is a base64url-encoded JSON AttestationReceipt.
export const RECEIPT_HEADER = 'x-vane-receipt';

// ── Receipt construction ──────────────────────────────────────────────────────

function buildReceipt(
  result: Extract<PassportVerificationResult, { valid: true }>,
  tool: string,
): AttestationReceipt {
  if (result.tokenType === 'cross-org') {
    const claims = result.claims as CrossOrgDelegationClaims;
    const xorg = claims.vane_xorg;
    return {
      v: 1,
      type: 'VaneAttestationReceipt',
      passportId: claims.jti,
      agentId: xorg.agentId,
      agentSpiffeId: claims.sub,
      org: xorg.originOrg,
      orgSpiffeId: xorg.originOrgSpiffeId,
      tool,
      scopeGranted: result.scopeGranted,
      delegationChain: xorg.delegationChain,
      issuedBy: claims.iss,
      passportIssuedAt: new Date(claims.iat * 1000).toISOString(),
      passportExpiresAt: new Date(claims.exp * 1000).toISOString(),
      verifiedAt: new Date().toISOString(),
      verifier: PACKAGE_VERSION,
      crossOrg: { targetOrg: xorg.targetOrg, targetOrgSpiffeId: xorg.targetOrgSpiffeId },
    };
  }

  const claims = result.claims as VanePassportClaims;
  return {
    v: 1,
    type: 'VaneAttestationReceipt',
    passportId: claims.jti,
    agentId: claims.vane.agentId,
    agentSpiffeId: claims.sub,
    org: claims.vane.org,
    orgSpiffeId: claims.vane.orgSpiffeId,
    tool,
    scopeGranted: result.scopeGranted,
    delegationChain: claims.vane.delegationChain,
    issuedBy: claims.iss,
    passportIssuedAt: new Date(claims.iat * 1000).toISOString(),
    passportExpiresAt: new Date(claims.exp * 1000).toISOString(),
    verifiedAt: new Date().toISOString(),
    verifier: PACKAGE_VERSION,
  };
}

function encodeReceipt(receipt: AttestationReceipt): string {
  return Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64url');
}

export function decodeReceipt(encoded: string): AttestationReceipt {
  return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as AttestationReceipt;
}

// ── Revocation check ─────────────────────────────────────────────────────────

// Returns a PASSPORT_REVOKED failure result if the JTI is in the list.
async function checkRevocation(
  jti: string,
  fetcher: (() => Promise<string[]>) | undefined,
): Promise<Extract<PassportVerificationResult, { valid: false }> | null> {
  if (!fetcher) return null;
  const revoked = await fetcher();
  if (revoked.includes(jti)) {
    return { valid: false, code: 'PASSPORT_REVOKED', error: 'Passport has been revoked' };
  }
  return null;
}

// ── Token extraction ──────────────────────────────────────────────────────────

function extractBearer(authHeader: string | null | undefined): string | null {
  if (!authHeader) return null;
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  return token.length > 0 ? token : null;
}

// Extract MCP tool name from a JSON-RPC 2.0 tools/call request body.
function extractMcpTool(body: unknown): string | null {
  if (body === null || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;
  if (b['method'] !== 'tools/call') return null;
  const params = b['params'];
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return null;
  const name = (params as Record<string, unknown>)['name'];
  return typeof name === 'string' ? name : null;
}

// ── 401 response helpers ──────────────────────────────────────────────────────

function unauthorizedJson(
  result: Extract<PassportVerificationResult, { valid: false }>,
  expose: boolean,
): string {
  if (!expose) return JSON.stringify({ error: 'Unauthorized' });
  return JSON.stringify({ error: 'Unauthorized', code: result.code, message: result.error });
}

// ── Middleware factory ────────────────────────────────────────────────────────

export function createVaneMiddleware(opts: VaneMiddlewareOptions) {
  const {
    vanePublicKey,
    exposeErrors = true,
    fetchRevocationList,
    resolveCrossOrgPublicKey,
    expectedTargetOrg,
  } = opts;

  // Peek at the token header (without verification) to identify the token type.
  function peekTokenType(token: string): string | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>;
      return typeof header['typ'] === 'string' ? header['typ'] : null;
    } catch {
      return null;
    }
  }

  // Extract originOrg from an unverified XORG+JWT payload. Used only to route
  // to the correct public key — the subsequent signature check is what provides
  // security, not this read.
  function peekOriginOrg(token: string): string | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      const raw = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
      const xorg = raw['vane_xorg'];
      if (!xorg || typeof xorg !== 'object' || Array.isArray(xorg)) return null;
      const originOrg = (xorg as Record<string, unknown>)['originOrg'];
      return typeof originOrg === 'string' ? originOrg : null;
    } catch {
      return null;
    }
  }

  /**
   * Pure synchronous verification for regular CAP+JWT passports.
   * For cross-org tokens use verifyAsync, which may need to fetch a public key.
   */
  function verify(token: string, verifyOpts: VerifyOptions = {}): PassportVerificationResult {
    const tokenType = peekTokenType(token);
    if (tokenType === CROSS_ORG_TOKEN_TYPE) {
      return { valid: false, error: 'Use verifyAsync for cross-org tokens', code: 'CROSS_ORG_NOT_ACCEPTED' };
    }
    const result = verifyPassport(token, vanePublicKey, verifyOpts);
    if (!result.valid) return result;
    return { ...result, tokenType: 'passport' };
  }

  /**
   * Async verification — handles both regular passports and cross-org tokens.
   * Required when resolveCrossOrgPublicKey may make a network call.
   */
  async function verifyAsync(token: string, verifyOpts: VerifyOptions = {}): Promise<PassportVerificationResult> {
    const tokenType = peekTokenType(token);

    if (tokenType === CROSS_ORG_TOKEN_TYPE) {
      if (!resolveCrossOrgPublicKey) {
        return { valid: false, error: 'Cross-org tokens are not accepted by this server', code: 'CROSS_ORG_NOT_ACCEPTED' };
      }
      const originOrg = peekOriginOrg(token);
      if (!originOrg) {
        return { valid: false, error: 'Could not extract originOrg from cross-org token', code: 'MALFORMED_CLAIMS' };
      }
      const originPublicKey = await resolveCrossOrgPublicKey(originOrg);
      if (!originPublicKey) {
        return { valid: false, error: `Cannot resolve public key for origin org: ${originOrg}`, code: 'CROSS_ORG_UNKNOWN_ORIGIN' };
      }
      return verifyCrossOrgToken(token, originPublicKey, { ...verifyOpts, expectedTargetOrg });
    }

    const result = verifyPassport(token, vanePublicKey, verifyOpts);
    if (!result.valid) return result;
    return { ...result, tokenType: 'passport' };
  }

  /**
   * Fetch-compatible middleware (Hono, Next.js Edge, Cloudflare Workers).
   *
   * Reads the Authorization: Bearer <passport> header, parses the MCP JSON-RPC
   * body to extract the tool name, verifies the passport (or cross-org token),
   * and:
   *   - On success: forwards the request with X-Vane-Receipt added
   *   - On failure: returns 401 with a JSON error body
   *
   * The downstream handler reads the receipt with:
   *   const receipt = decodeReceipt(req.headers.get('x-vane-receipt'));
   */
  function fetchMiddleware(): (
    req: Request,
    next: (req: Request) => Promise<Response>,
  ) => Promise<Response> {
    return async (req, next) => {
      const token = extractBearer(req.headers.get('authorization'));
      if (!token) {
        return new Response(
          JSON.stringify({ error: 'Unauthorized', code: 'MALFORMED_TOKEN', message: 'Missing Authorization: Bearer header' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      }

      // Buffer the body so we can extract the tool name and pass it downstream.
      const rawBody = await req.text();
      let parsedBody: unknown;
      try { parsedBody = JSON.parse(rawBody); } catch { parsedBody = null; }
      const tool = extractMcpTool(parsedBody) ?? undefined;

      const result = await verifyAsync(token, { tool });
      if (!result.valid) {
        return new Response(
          unauthorizedJson(result, exposeErrors),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      }

      const revocationFailure = await checkRevocation(result.claims.jti, fetchRevocationList);
      if (revocationFailure) {
        return new Response(
          unauthorizedJson(revocationFailure, exposeErrors),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      }

      const receipt = buildReceipt(result, tool ?? '(not an MCP tool call)');
      const newReq = new Request(req, { body: rawBody });
      newReq.headers.set(RECEIPT_HEADER, encodeReceipt(receipt));

      return next(newReq);
    };
  }

  /**
   * Express/Connect-compatible middleware.
   *
   * Assumes req.body has already been parsed (e.g., by express.json()).
   * Attaches the decoded AttestationReceipt to req.vaneReceipt on success.
   *
   * Usage:
   *   app.use(express.json());
   *   app.use(vane.expressMiddleware());
   *   app.post('/mcp', (req, res) => {
   *     console.log(req.vaneReceipt);
   *   });
   */
  function expressMiddleware(): (req: unknown, res: unknown, next: (err?: unknown) => void) => void {
    return async (req, res, next) => {
      const r = req as Record<string, unknown>;
      const headers = r['headers'] as Record<string, string | undefined>;
      const token = extractBearer(headers['authorization']);

      if (!token) {
        const response = res as { status: (n: number) => { json: (body: unknown) => void } };
        response.status(401).json({ error: 'Unauthorized', code: 'MALFORMED_TOKEN', message: 'Missing Authorization: Bearer header' });
        return;
      }

      const tool = extractMcpTool(r['body']) ?? undefined;
      const result = await verifyAsync(token, { tool });

      if (!result.valid) {
        const response = res as { status: (n: number) => { json: (body: unknown) => void } };
        if (exposeErrors) {
          response.status(401).json({ error: 'Unauthorized', code: result.code, message: result.error });
        } else {
          response.status(401).json({ error: 'Unauthorized' });
        }
        return;
      }

      const revocationFailure = await checkRevocation(result.claims.jti, fetchRevocationList);
      if (revocationFailure) {
        const response = res as { status: (n: number) => { json: (body: unknown) => void } };
        if (exposeErrors) {
          response.status(401).json({ error: 'Unauthorized', code: revocationFailure.code, message: revocationFailure.error });
        } else {
          response.status(401).json({ error: 'Unauthorized' });
        }
        return;
      }

      const receipt = buildReceipt(result, tool ?? '(not an MCP tool call)');
      r['vaneReceipt'] = receipt;
      next();
    };
  }

  /**
   * MCP SDK handler wrapper.
   *
   * Wraps a CallToolRequest handler. The passport must be passed in
   * request._meta.authorization (set this in the MCP client or transport).
   *
   * Usage:
   *   server.setRequestHandler(
   *     CallToolRequestSchema,
   *     vane.mcpHandler(async (request, receipt) => {
   *       // receipt is a verified AttestationReceipt
   *       return { content: [{ type: 'text', text: 'ok' }] };
   *     })
   *   );
   */
  function mcpHandler<TRequest extends { params: { name: string; _meta?: Record<string, unknown> } }, TResult>(
    handler: (request: TRequest, receipt: AttestationReceipt) => Promise<TResult>,
  ): (request: TRequest) => Promise<TResult> {
    return async (request) => {
      const meta = request.params._meta;
      const rawToken = meta?.['authorization'];
      const token = typeof rawToken === 'string' ? extractBearer(`Bearer ${rawToken}`) ?? rawToken : null;

      if (!token) {
        throw new McpAuthError('MALFORMED_TOKEN', 'Missing authorization in request._meta.authorization');
      }

      const tool = request.params.name;
      const result = await verifyAsync(token, { tool });

      if (!result.valid) {
        throw new McpAuthError(result.code, result.error);
      }

      const revocationFailure = await checkRevocation(result.claims.jti, fetchRevocationList);
      if (revocationFailure) {
        throw new McpAuthError(revocationFailure.code, revocationFailure.error);
      }

      const receipt = buildReceipt(result, tool);
      return handler(request, receipt);
    };
  }

  return { verify, verifyAsync, fetchMiddleware, expressMiddleware, mcpHandler };
}

// ── Error type ────────────────────────────────────────────────────────────────

export class McpAuthError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'McpAuthError';
    this.code = code;
  }
}
