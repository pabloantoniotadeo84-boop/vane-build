// ── Credential types ──────────────────────────────────────────────────────────
//
// These are intentionally duplicated from the Counsel server source so this
// package has zero dependencies and can be embedded in any MCP server.

export interface CounselPassportClaims {
  iss: string;
  sub: string;
  aud: string[];
  jti: string;
  iat: number;
  exp: number;
  nbf: number;
  counsel: {
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
// verify this independently — it references the passport by jti so an auditor
// can retrieve and re-verify the original credential.

export interface AttestationReceipt {
  v: 1;
  type: 'CounselAttestationReceipt';
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
  | { valid: true; claims: CounselPassportClaims; scopeGranted: string }
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

export interface CounselMiddlewareOptions {
  // Ed25519 SPKI PEM of the Counsel CA root key.
  // Obtain this once from your Counsel instance (GET /v1/keys/ca or from your
  // admin). Pin it in your deployment; the only rotation path is a planned key
  // rollover published by Counsel with advance notice.
  counselPublicKey: string;

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
