// Counsel Agent Passport (CAP) — credential schema version 1.
//
// A CAP+JWT credential is a standard EdDSA JWT with typ "CAP+JWT" and
// a versioned "counsel" claim object. Any JWT library that supports EdDSA
// can parse it; the only Counsel-specific logic is in the "counsel" object
// and the scope matching rules below.

// ── Credential claims ─────────────────────────────────────────────────────────

export interface CounselPassportClaims {
  // Standard JWT claims (RFC 7519)
  iss: string;    // SPIFFE ID of the issuing Counsel instance
  sub: string;    // Agent's SPIFFE ID — the credential subject
  aud: string[];  // Must include PASSPORT_AUDIENCE = "counsel:passport:v1"
  jti: string;    // Unique passport ID (UUID v4) — for future revocation support
  iat: number;    // Issued-at (Unix seconds)
  exp: number;    // Expiry (Unix seconds)
  nbf: number;    // Not-before (Unix seconds, equals iat at issuance)

  // Counsel-specific claims — namespaced to avoid collision with JWT extensions
  counsel: {
    v: 1;                     // Schema version — verifiers MUST reject unknown versions
    agentId: string;          // Human-readable agent identifier
    org: string;              // Issuing organization name
    orgSpiffeId: string;      // Organization's SPIFFE ID
    scopes: string[];         // Authorization scopes — see scope rules below
    delegationChain: string[]; // [orgSpiffeId, ..., agentSpiffeId] — full authorization path
    delegationId?: string;    // jti of the RFC 8693 token this passport was derived from
  };
}

// ── Scope format ──────────────────────────────────────────────────────────────
//
// Scopes use "category:name" format. Matching rules (evaluated in order):
//   "*"         — covers any scope
//   "cat:*"     — covers any scope in category "cat"
//   "cat:name"  — covers exactly "cat:name"
//
// Examples:
//   "tool:*"         allows calling any MCP tool
//   "tool:search"    allows calling only the "search" tool
//   "attest:write"   allows writing attestation records
//   "resource:read"  allows reading resources

// ── Attestation receipt ───────────────────────────────────────────────────────
//
// The open, documented format attached to every verified tool call.
// Any system can parse and verify this format independently.
// It is not a signature — it is a transparency record produced by the verifier.

export interface AttestationReceipt {
  v: 1;
  type: 'CounselAttestationReceipt';
  passportId: string;       // jti of the verified passport
  agentId: string;
  agentSpiffeId: string;
  org: string;
  orgSpiffeId: string;
  tool: string;             // tool that was called
  scopeGranted: string;     // which scope in the passport authorized this call
  delegationChain: string[];
  issuedBy: string;         // iss — which Counsel instance signed this passport
  passportIssuedAt: string; // ISO 8601
  passportExpiresAt: string; // ISO 8601
  verifiedAt: string;       // ISO 8601 — when this receipt was produced
  verifier: string;         // package name + version that produced this receipt
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
