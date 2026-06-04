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

// Cross-org delegation token claims (typ: "XORG+JWT").
// Verified using the *originating* org's CA public key, not the host org's key.
export interface CrossOrgDelegationClaims {
  iss: string;
  sub: string;
  aud: string[];
  jti: string;
  iat: number;
  exp: number;
  nbf: number;
  vane_xorg: {
    v: 1;
    agentId: string;
    originOrg: string;
    originOrgSpiffeId: string;
    targetOrg: string;
    targetOrgSpiffeId: string;
    scopes: string[];
    delegationChain: string[];
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
  passportIssuedAt: string;   // ISO 8601
  passportExpiresAt: string;  // ISO 8601
  verifiedAt: string;         // ISO 8601
  verifier: string;           // "@vane.build/mcp-middleware@<version>"
  // Present when the verified token was a cross-org delegation token.
  crossOrg?: {
    targetOrg: string;
    targetOrgSpiffeId: string;
  };
}

// ── Verification result ───────────────────────────────────────────────────────

export type PassportVerificationResult =
  | { valid: true; claims: VanePassportClaims; scopeGranted: string; tokenType: 'passport' }
  | { valid: true; claims: CrossOrgDelegationClaims; scopeGranted: string; tokenType: 'cross-org' }
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
  | 'SCOPE_DENIED'
  | 'PASSPORT_REVOKED'
  // Catch-all for any unexpected error during verification. Emitted by the
  // fail-closed wrapper so that an exception anywhere in the pipeline always
  // resolves to a deny rather than escaping the verifier.
  | 'VERIFICATION_ERROR'
  // Cross-org specific
  | 'CROSS_ORG_NOT_ACCEPTED'
  | 'CROSS_ORG_UNKNOWN_ORIGIN'
  | 'TARGET_MISMATCH';

// ── Middleware options ────────────────────────────────────────────────────────

export interface VaneMiddlewareOptions {
  // Ed25519 SPKI PEM of the Vane CA root key.
  // Obtain this once from your Vane instance (GET /v1/ca/public-key?companyId=<id>).
  // Pin it in your deployment; the only rotation path is a planned key rollover.
  vanePublicKey: string;

  // If true (default), 401 responses include the error code and message.
  // Set to false to return generic 401s without leaking reason strings.
  exposeErrors?: boolean;

  // Optional revocation list fetcher. If provided, this function is called on
  // every request after signature verification succeeds. The returned array of
  // JTIs is checked against the passport's jti claim.
  //
  // Trade-off: fetching this list requires a network call to the Vane server
  // (GET /v1/passports/revoked), which breaks the "offline" property of
  // passport verification. Short passport TTLs (≤ 1 hour, the enforced max)
  // are therefore the *primary* defense against key or credential compromise —
  // an expired passport is always rejected. This option adds defense-in-depth
  // for scenarios where immediate revocation is required before the TTL lapses.
  //
  // Implementation guidance: cache the revocation list with a TTL matched to
  // your risk tolerance (e.g., 60 s) rather than fetching it on every request.
  fetchRevocationList?: () => Promise<string[]>;

  // ── Cross-org support ─────────────────────────────────────────────────────
  //
  // To accept cross-org delegation tokens (XORG+JWT) from agents belonging to
  // external organizations, provide both options below.
  //
  // Cross-org tokens are signed with the *originating* org's private key, not
  // the host org's key. The middleware resolves the originating org's public key
  // via resolveCrossOrgPublicKey, then verifies the token offline.
  //
  // Recommended implementation: call GET /v1/ca/public-key?companyId=<originOrg>
  // on the Vane server and cache the result (e.g., 1-hour TTL keyed by org ID).
  // The public key is stable until the originating org rotates their key.

  // Called with the originOrg name extracted from an XORG+JWT token. Return
  // the SPKI PEM public key for that org, or null to reject the token.
  resolveCrossOrgPublicKey?: (originOrg: string) => Promise<string | null>;

  // This MCP server's organization ID. When set, cross-org tokens whose
  // vane_xorg.targetOrg does not match this value are rejected.
  expectedTargetOrg?: string;
}

export interface VerifyOptions {
  // Name of the tool being called. If provided, the passport must grant
  // a scope that covers "tool:<tool>".
  tool?: string;

  // Override current time for testing. Unix seconds.
  now?: number;
}
