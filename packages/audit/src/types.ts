// ── Public result types ─────────────────────────────────────────────────────

/**
 * The outcome of a single audit check. One of these is produced by every check
 * function in checks.ts. Checks never throw — a failure (including a network or
 * parse error) is always returned as a CheckResult with `passed: false`.
 */
export interface CheckResult {
  /** Stable machine id, e.g. "agent-identity". */
  id: string;
  /** Human-readable label printed in the report. */
  label: string;
  /** Whether the MCP server demonstrated this property. */
  passed: boolean;
  /** One-line explanation of the result — the brutal honest part. */
  detail: string;
  /** The question an auditor will ask that this check maps to. */
  auditQuestion: string;
  /** Where to go to fix a failing check. */
  fixUrl: string;
}

/** The full report returned by runAudit() and rendered by report.ts. */
export interface AuditReport {
  /** The normalized target URL that was probed. */
  url: string;
  /** Whether the server answered at least one request. */
  reachable: boolean;
  /** ISO 8601 timestamp of when the audit started. */
  startedAt: string;
  /** One entry per check, in display order. */
  results: CheckResult[];
  /** Number of checks that passed. */
  passedCount: number;
  /** Total number of checks run (always results.length). */
  totalCount: number;
}

// ── Internal probe context ──────────────────────────────────────────────────
//
// The network is touched once, up front, by buildProbe() in checks.ts. The
// gathered evidence is stored here and handed to each check function so the
// four checks do not each re-hammer the server. Every field is nullable so a
// partial or failed probe still produces a well-formed context.

export interface ProbeContext {
  /** Normalized target URL. */
  url: string;
  /** True if any request to the server completed (any status code). */
  reachable: boolean;

  // GET <url>
  baseStatus: number | null;
  baseHeaders: Record<string, string> | null;
  baseBodyText: string | null;

  // POST <url>/mcp  { jsonrpc, method: "tools/list" }
  mcpStatus: number | null;
  mcpHeaders: Record<string, string> | null;
  mcpBodyText: string | null;
  /** Parsed JSON body of the tools/list response, or null. */
  mcpJson: unknown;
  /** True when a body was returned but could not be parsed as JSON. */
  mcpJsonParseFailed: boolean;

  /**
   * The value of any `authorization` response header observed (base or mcp),
   * and the decoded JWT payload if that value carried a parseable JWT.
   */
  authHeader: string | null;
  jwtPayload: Record<string, unknown> | null;

  /**
   * Decoded `x-vane-receipt` header if present — this is the exact header the
   * @vane.build/mcp-middleware attaches downstream on a verified call. Its
   * presence is the strongest possible signal that Vane is wired in correctly.
   */
  receipt: Record<string, unknown> | null;

  // Attestation surface
  /** True if any attestation endpoint returned a non-404/non-500 response. */
  attestationReachable: boolean;
  /** True if a /health (or /v1/health) body mentioned "attestation" or "vane". */
  healthMentionsVane: boolean;
}
