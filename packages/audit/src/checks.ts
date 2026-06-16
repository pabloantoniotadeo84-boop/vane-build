import type { CheckResult, AuditReport, ProbeContext } from './types.js';

const FIX_URL = 'https://vane.build/docs';
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 3;

// JSON-RPC 2.0 tools/list — the most innocuous MCP request that still exercises
// the tool-call path the middleware is supposed to guard.
const TOOLS_LIST_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/list',
  params: {},
});

// ── HTTP helper ─────────────────────────────────────────────────────────────

interface HttpResult {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
}

// Lowercase header map so callers can look headers up case-insensitively.
function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * One HTTP request with a hard 10s timeout and manual redirect following capped
 * at MAX_REDIRECTS hops. Throws only on a genuine network/timeout error or when
 * the redirect budget is exceeded — every non-2xx status is returned normally
 * so checks can reason about 401/404/500 themselves.
 */
async function httpRequest(
  url: string,
  init: { method: 'GET' | 'POST'; body?: string; headers?: Record<string, string> },
  hop = 0,
): Promise<HttpResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method,
      body: init.body,
      headers: init.headers,
      redirect: 'manual',
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  // Follow 3xx redirects by hand so we can enforce the hop cap precisely.
  if (res.status >= 300 && res.status < 400) {
    const location = res.headers.get('location');
    if (location && hop < MAX_REDIRECTS) {
      const nextUrl = new URL(location, url).toString();
      return httpRequest(nextUrl, init, hop + 1);
    }
  }

  const bodyText = await res.text().catch(() => '');
  return { status: res.status, headers: headersToObject(res.headers), bodyText };
}

// ── Small parsing utilities ─────────────────────────────────────────────────

// Decode a base64url segment to a UTF-8 string. Returns null on any failure.
function decodeB64UrlJson(segment: string): Record<string, unknown> | null {
  try {
    const json = Buffer.from(segment, 'base64url').toString('utf8');
    const parsed = JSON.parse(json) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

// Pull a bearer/raw JWT out of an authorization header value and decode its
// payload. Accepts "Bearer <jwt>", "Agent <jwt>", or a bare "<jwt>".
function decodeJwtFromAuth(authValue: string | null): Record<string, unknown> | null {
  if (!authValue) return null;
  const trimmed = authValue.trim();
  const token = trimmed.includes(' ') ? trimmed.slice(trimmed.indexOf(' ') + 1).trim() : trimmed;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  return decodeB64UrlJson(parts[1]);
}

// Recursively test whether any of `keys` appears as an object key anywhere in
// `value`. Used to find "signature"/"attestation"/delegation claims at any depth.
function hasKeyDeep(value: unknown, keys: string[], depth = 0): boolean {
  if (depth > 8 || value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) {
    return value.some((item) => hasKeyDeep(item, keys, depth + 1));
  }
  const obj = value as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (keys.includes(k.toLowerCase())) {
      const v = obj[k];
      // A key counts only when it carries a non-empty value.
      if (v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0)) {
        return true;
      }
    }
    if (hasKeyDeep(obj[k], keys, depth + 1)) return true;
  }
  return false;
}

function nonEmptyHeader(headers: Record<string, string> | null, name: string): string | null {
  if (!headers) return null;
  const v = headers[name.toLowerCase()];
  return typeof v === 'string' && v.trim().length > 0 ? v : null;
}

// ── Probe ───────────────────────────────────────────────────────────────────

/**
 * Touch the network exactly once and gather every piece of evidence the four
 * checks need. Each sub-request is independently guarded — a failure on one
 * (e.g. no /mcp endpoint) never aborts the others. If nothing answers at all,
 * `reachable` stays false and every check renders the "could not connect"
 * failure.
 */
export async function buildProbe(url: string): Promise<ProbeContext> {
  const ctx: ProbeContext = {
    url,
    reachable: false,
    baseStatus: null,
    baseHeaders: null,
    baseBodyText: null,
    mcpStatus: null,
    mcpHeaders: null,
    mcpBodyText: null,
    mcpJson: null,
    mcpJsonParseFailed: false,
    authHeader: null,
    jwtPayload: null,
    receipt: null,
    attestationReachable: false,
    healthMentionsVane: false,
  };

  const base = new URL(url);
  const root = `${base.protocol}//${base.host}`;

  // 1. GET <url>
  try {
    const r = await httpRequest(url, { method: 'GET' });
    ctx.reachable = true;
    ctx.baseStatus = r.status;
    ctx.baseHeaders = r.headers;
    ctx.baseBodyText = r.bodyText;
  } catch {
    /* recorded by reachable staying false unless a later request succeeds */
  }

  // 2. POST <url>/mcp  tools/list
  const mcpUrl = url.endsWith('/') ? `${url}mcp` : `${url}/mcp`;
  try {
    const r = await httpRequest(mcpUrl, {
      method: 'POST',
      body: TOOLS_LIST_BODY,
      headers: { 'content-type': 'application/json', accept: 'application/json' },
    });
    ctx.reachable = true;
    ctx.mcpStatus = r.status;
    ctx.mcpHeaders = r.headers;
    ctx.mcpBodyText = r.bodyText;
    if (r.bodyText.trim().length > 0) {
      try {
        ctx.mcpJson = JSON.parse(r.bodyText);
      } catch {
        ctx.mcpJsonParseFailed = true;
      }
    }
  } catch {
    /* leave mcp* null */
  }

  // Authorization response header (base or mcp) + decoded JWT payload.
  ctx.authHeader =
    nonEmptyHeader(ctx.mcpHeaders, 'authorization') ??
    nonEmptyHeader(ctx.baseHeaders, 'authorization');
  ctx.jwtPayload = decodeJwtFromAuth(ctx.authHeader);

  // x-vane-receipt — the genuine middleware downstream signal.
  const receiptHeader =
    nonEmptyHeader(ctx.mcpHeaders, 'x-vane-receipt') ??
    nonEmptyHeader(ctx.baseHeaders, 'x-vane-receipt');
  ctx.receipt = receiptHeader ? decodeB64UrlJson(receiptHeader) : null;

  // 3. Attestation surface. Spec paths plus the two real Vane endpoints
  //    (/v1/health, /v1/chain) so a live Vane server is recognized.
  const attestationPaths = ['/v1/attestations', '/attestations', '/v1/chain'];
  for (const path of attestationPaths) {
    try {
      const r = await httpRequest(`${root}${path}`, { method: 'GET' });
      ctx.reachable = true;
      if (r.status !== 404 && r.status !== 500) {
        ctx.attestationReachable = true;
        break;
      }
    } catch {
      /* try the next path */
    }
  }

  // /health and /v1/health — pass Check 3 if the body mentions attestation/vane.
  for (const path of ['/health', '/v1/health']) {
    try {
      const r = await httpRequest(`${root}${path}`, { method: 'GET' });
      ctx.reachable = true;
      const body = r.bodyText.toLowerCase();
      if (r.status !== 404 && r.status !== 500 && (body.includes('attestation') || body.includes('vane'))) {
        ctx.healthMentionsVane = true;
        break;
      }
    } catch {
      /* try the next path */
    }
  }

  return ctx;
}

// Shared failure used by every check when the server never answered.
function unreachable(
  id: string,
  label: string,
  auditQuestion: string,
  url: string,
): CheckResult {
  return {
    id,
    label,
    passed: false,
    detail: `Could not connect to ${url}. Is the server running?`,
    auditQuestion,
    fixUrl: FIX_URL,
  };
}

// ── Check 1 — Agent identity headers ─────────────────────────────────────────

export async function checkAgentIdentity(ctx: ProbeContext): Promise<CheckResult> {
  const id = 'agent-identity';
  const label = 'Agent identity on tool calls';
  const auditQuestion = 'Which agent made this request, and who authorized it?';
  try {
    if (!ctx.reachable) return unreachable(id, label, auditQuestion, ctx.url);

    const headerSets = [ctx.mcpHeaders, ctx.baseHeaders];
    // Spec list + x-vane-receipt (the real middleware downstream header).
    const identityHeaders = [
      'x-vane-passport',
      'x-agent-identity',
      'x-vane-agent-id',
      'x-vane-receipt',
    ];

    let found = false;
    for (const headers of headerSets) {
      for (const name of identityHeaders) {
        if (nonEmptyHeader(headers, name)) {
          found = true;
          break;
        }
      }
      if (found) break;
    }

    // authorization header carrying "Agent", or a Bearer JWT with agent claims.
    if (!found && ctx.authHeader) {
      const lower = ctx.authHeader.toLowerCase();
      if (lower.includes('agent')) {
        found = true;
      } else if (lower.startsWith('bearer ') && ctx.jwtPayload) {
        // Agent claims: Vane's "vane"/"vane_xorg" objects, or a generic agent id.
        found = hasKeyDeep(ctx.jwtPayload, ['vane', 'vane_xorg', 'agentid', 'agent_id']);
      }
    }

    // A decoded receipt with an agentId is definitive.
    if (!found && ctx.receipt && hasKeyDeep(ctx.receipt, ['agentid'])) {
      found = true;
    }

    return {
      id,
      label,
      passed: found,
      detail: found
        ? 'Agent identity is present on tool calls — requests are attributable to a specific agent.'
        : 'No agent identity headers detected on MCP tool calls. Any action taken by your agents is unattributable.',
      auditQuestion,
      fixUrl: FIX_URL,
    };
  } catch {
    return {
      id,
      label,
      passed: false,
      detail: 'No agent identity headers detected on MCP tool calls. Any action taken by your agents is unattributable.',
      auditQuestion,
      fixUrl: FIX_URL,
    };
  }
}

// ── Check 2 — Cryptographic action signatures ────────────────────────────────

export async function checkActionSignatures(ctx: ProbeContext): Promise<CheckResult> {
  const id = 'action-signatures';
  const label = 'Cryptographic signatures on responses';
  const auditQuestion = 'Can you prove this tool call response was not tampered with?';
  try {
    if (!ctx.reachable) return unreachable(id, label, auditQuestion, ctx.url);

    // x-vane-signature header on either response.
    const sigHeader =
      nonEmptyHeader(ctx.mcpHeaders, 'x-vane-signature') ??
      nonEmptyHeader(ctx.baseHeaders, 'x-vane-signature');

    let found = Boolean(sigHeader);

    // signature / attestation field anywhere in the parsed JSON body.
    if (!found && ctx.mcpJson) {
      found = hasKeyDeep(ctx.mcpJson, ['signature', 'attestation', 'sig']);
    }

    // A decoded x-vane-receipt is itself the attestation proof of the call.
    if (!found && ctx.receipt) {
      found = true;
    }

    let detail: string;
    if (found) {
      detail = 'Tool call responses carry a cryptographic signature or attestation — response integrity is provable.';
    } else if (ctx.mcpJsonParseFailed && !sigHeader) {
      detail = 'Response was not JSON — could not inspect payload. No signature header present either.';
    } else {
      detail = 'Tool call responses carry no cryptographic signature. You cannot prove response integrity to an auditor.';
    }

    return { id, label, passed: found, detail, auditQuestion, fixUrl: FIX_URL };
  } catch {
    return {
      id,
      label,
      passed: false,
      detail: 'Tool call responses carry no cryptographic signature. You cannot prove response integrity to an auditor.',
      auditQuestion,
      fixUrl: FIX_URL,
    };
  }
}

// ── Check 3 — Attestation endpoint ───────────────────────────────────────────

export async function checkAttestationEndpoint(ctx: ProbeContext): Promise<CheckResult> {
  const id = 'attestation-endpoint';
  const label = 'Attestation log reachable';
  const auditQuestion = 'Where is your immutable audit trail of agent actions?';
  try {
    if (!ctx.reachable) return unreachable(id, label, auditQuestion, ctx.url);

    const found = ctx.attestationReachable || ctx.healthMentionsVane;

    return {
      id,
      label,
      passed: found,
      detail: found
        ? 'An attestation endpoint is reachable — agent actions are being written to an audit trail.'
        : 'No attestation endpoint detected. Your agent actions are not being logged to an immutable audit trail.',
      auditQuestion,
      fixUrl: FIX_URL,
    };
  } catch {
    return {
      id,
      label,
      passed: false,
      detail: 'No attestation endpoint detected. Your agent actions are not being logged to an immutable audit trail.',
      auditQuestion,
      fixUrl: FIX_URL,
    };
  }
}

// ── Check 4 — Delegation chain ───────────────────────────────────────────────

export async function checkDelegationChain(ctx: ProbeContext): Promise<CheckResult> {
  const id = 'delegation-chain';
  const label = 'Delegation chain on agent calls';
  const auditQuestion = 'Can you prove which human authorized this agent to act?';
  try {
    if (!ctx.reachable) return unreachable(id, label, auditQuestion, ctx.url);

    // Delegation response headers.
    const delegationHeader =
      nonEmptyHeader(ctx.mcpHeaders, 'x-vane-delegation') ??
      nonEmptyHeader(ctx.mcpHeaders, 'x-delegation-chain') ??
      nonEmptyHeader(ctx.baseHeaders, 'x-vane-delegation') ??
      nonEmptyHeader(ctx.baseHeaders, 'x-delegation-chain');

    let found = Boolean(delegationHeader);

    // Spec claims + Vane's real delegation claim keys, searched at any depth.
    const delegationKeys = [
      'act',
      'may_act',
      'delegation_chain',
      'delegationchain',
      'actor',
      'azp',
    ];

    if (!found && ctx.jwtPayload) {
      if (ctx.jwtPayload['azp']) {
        // azp counts only when accompanied by a subject claim.
        found = Boolean(ctx.jwtPayload['sub']);
      }
      if (!found) found = hasKeyDeep(ctx.jwtPayload, delegationKeys);
    }

    // Decoded receipt carries delegationChain directly.
    if (!found && ctx.receipt) {
      found = hasKeyDeep(ctx.receipt, ['delegationchain', 'delegation_chain']);
    }

    let detail: string;
    if (found) {
      detail = 'A delegation chain is present — the human or system that authorized this agent is provable.';
    } else if (ctx.mcpJsonParseFailed && !ctx.jwtPayload && !delegationHeader) {
      detail = 'Response was not JSON — could not inspect payload. No delegation header present either.';
    } else {
      detail = 'No delegation chain detected. You cannot prove which human or system authorized this agent to act on their behalf.';
    }

    return { id, label, passed: found, detail, auditQuestion, fixUrl: FIX_URL };
  } catch {
    return {
      id,
      label,
      passed: false,
      detail: 'No delegation chain detected. You cannot prove which human or system authorized this agent to act on their behalf.',
      auditQuestion,
      fixUrl: FIX_URL,
    };
  }
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

/**
 * Probe the target once, run all four checks against the gathered evidence, and
 * return a complete AuditReport. Never throws.
 */
export async function runAudit(url: string): Promise<AuditReport> {
  const startedAt = new Date().toISOString();
  const ctx = await buildProbe(url);

  const results: CheckResult[] = [
    await checkAgentIdentity(ctx),
    await checkActionSignatures(ctx),
    await checkAttestationEndpoint(ctx),
    await checkDelegationChain(ctx),
  ];

  const passedCount = results.filter((r) => r.passed).length;

  return {
    url,
    reachable: ctx.reachable,
    startedAt,
    results,
    passedCount,
    totalCount: results.length,
  };
}
