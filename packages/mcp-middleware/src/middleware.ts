import { verifyPassport } from './verify.js';
import type {
  AttestationReceipt,
  CounselMiddlewareOptions,
  CounselPassportClaims,
  PassportVerificationResult,
  VerifyOptions,
} from './types.js';

const PACKAGE_VERSION = '@vane.build/mcp-middleware@0.1.0';

// Header name used to pass the attestation receipt to downstream handlers.
// Value is a base64url-encoded JSON AttestationReceipt.
export const RECEIPT_HEADER = 'x-counsel-receipt';

// ── Receipt construction ──────────────────────────────────────────────────────

function buildReceipt(
  claims: CounselPassportClaims,
  scopeGranted: string,
  tool: string,
): AttestationReceipt {
  return {
    v: 1,
    type: 'CounselAttestationReceipt',
    passportId: claims.jti,
    agentId: claims.counsel.agentId,
    agentSpiffeId: claims.sub,
    org: claims.counsel.org,
    orgSpiffeId: claims.counsel.orgSpiffeId,
    tool,
    scopeGranted,
    delegationChain: claims.counsel.delegationChain,
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

export function createCounselMiddleware(opts: CounselMiddlewareOptions) {
  const { counselPublicKey, exposeErrors = true } = opts;

  /**
   * Pure verification — call this when you already have the passport token
   * and want to verify it outside of a request context.
   */
  function verify(token: string, verifyOpts: VerifyOptions = {}): PassportVerificationResult {
    return verifyPassport(token, counselPublicKey, verifyOpts);
  }

  /**
   * Fetch-compatible middleware (Hono, Next.js Edge, Cloudflare Workers).
   *
   * Reads the Authorization: Bearer <passport> header, parses the MCP JSON-RPC
   * body to extract the tool name, verifies the passport, and:
   *   - On success: forwards the request with X-Counsel-Receipt added
   *   - On failure: returns 401 with a JSON error body
   *
   * The downstream handler reads the receipt with:
   *   const receipt = decodeReceipt(req.headers.get('x-counsel-receipt'));
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

      const result = verify(token, { tool });
      if (!result.valid) {
        return new Response(
          unauthorizedJson(result, exposeErrors),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      }

      const receipt = buildReceipt(result.claims, result.scopeGranted, tool ?? '(not an MCP tool call)');
      const newReq = new Request(req, { body: rawBody });
      newReq.headers.set(RECEIPT_HEADER, encodeReceipt(receipt));

      return next(newReq);
    };
  }

  /**
   * Express/Connect-compatible middleware.
   *
   * Assumes req.body has already been parsed (e.g., by express.json()).
   * Attaches the decoded AttestationReceipt to req.counselReceipt on success.
   *
   * Usage:
   *   app.use(express.json());
   *   app.use(counsel.expressMiddleware());
   *   app.post('/mcp', (req, res) => {
   *     console.log(req.counselReceipt);
   *   });
   */
  function expressMiddleware(): (req: unknown, res: unknown, next: (err?: unknown) => void) => void {
    return (req, res, next) => {
      const r = req as Record<string, unknown>;
      const headers = r['headers'] as Record<string, string | undefined>;
      const token = extractBearer(headers['authorization']);

      if (!token) {
        const response = res as { status: (n: number) => { json: (body: unknown) => void } };
        response.status(401).json({ error: 'Unauthorized', code: 'MALFORMED_TOKEN', message: 'Missing Authorization: Bearer header' });
        return;
      }

      const tool = extractMcpTool(r['body']) ?? undefined;
      const result = verify(token, { tool });

      if (!result.valid) {
        const response = res as { status: (n: number) => { json: (body: unknown) => void } };
        if (exposeErrors) {
          response.status(401).json({ error: 'Unauthorized', code: result.code, message: result.error });
        } else {
          response.status(401).json({ error: 'Unauthorized' });
        }
        return;
      }

      const receipt = buildReceipt(result.claims, result.scopeGranted, tool ?? '(not an MCP tool call)');
      r['counselReceipt'] = receipt;
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
   *     counsel.mcpHandler(async (request, receipt) => {
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
      const result = verify(token, { tool });

      if (!result.valid) {
        throw new McpAuthError(result.code, result.error);
      }

      const receipt = buildReceipt(result.claims, result.scopeGranted, tool);
      return handler(request, receipt);
    };
  }

  return { verify, fetchMiddleware, expressMiddleware, mcpHandler };
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
