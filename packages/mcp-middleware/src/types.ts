// ── Credential types ──────────────────────────────────────────────────────────
//
// These are intentionally duplicated from the Vane server source so this
// package has zero dependencies and can be embedded in any MCP server.

export interface VanePassportClaims {
  iss: string;
  sub: string;
  aud: string[];
  jti: string;
  iat: number;
  exp: number;
  nbf: number;
  vane: {
    v: 1;
    agentId: string;
    org: string;
    orgSpiffeId: string;
    scopes: string[];
    delegationChain: string[];
    delegationId?: string;
  };
}

// ── Attestation receipt ───────────────────────────────────────────────────────
//
// Open format. Attached to every verified tool call. Any system can parse and
// verify this independently.

export interface AttestationReceipt {
  v: 1;
  type: 'VaneAttestationReceipt';
  passportId: string;
  agentId: string;
  agentSpiffeId: string;
  org: string;
  orgSpiffeId: string;
  tool: string;
  scopeGranted: string;
  delegationChain: string[];
  issuedBy: string;
  passportIssuedAt: string;  // ISO 8601
  passportExpiresAt: string; // ISO 8601
  verifiedAt: string;        // ISO 8601
  verifier: string;          // "@vane.build/mcp-middleware@<version>"
}

// ── Verification result ───────────────────────────────────────────────────────

export type PassportVerificationResult =
  | { valid: true; claims: VanePassportClaims; scopeGranted: string }
  | { valid: false; error: string; code: PassportErrorCode };

export type PassportErrorCode =
  | 'MALFORMED_TOKEN'
  | 'ALGORITHM_MISMATCH'
  | 'WRONG_TOKEN_TYPE'
  | 'SIGNATURE_INVALID'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_NOT_YET_VALID'
  | 'AUDIENCE_MISMATCH'
  | 'INVALID_ISSUER'
  | 'INVALID_SUBJECT'
  | 'UNSUPPORTED_VERSION'
  | 'MALFORMED_CLAIMS'
  | 'CHAIN_INCOHERENT'
  | 'SCOPE_DENIED';

// ── Middleware options ────────────────────────────────────────────────────────

export interface VaneMiddlewareOptions {
  // Ed25519 SPKI PEM of the Vane CA root key.
  // Obtain this once from your Vane instance (GET /v1/ca/public-key?companyId=<id>).
  // Pin it in your deployment; the only rotation path is a planned key rollover.
  vanePublicKey: string;

  // If true (default), 401 responses include the error code and message.
  // Set to false to return generic 401s without leaking reason strings.
  exposeErrors?: boolean;
}

export interface VerifyOptions {
  // Name of the tool being called. If provided, the passport must grant
  // a scope that covers "tool:<tool>".
  tool?: string;

  // Override current time for testing. Unix seconds.
  now?: number;
}
