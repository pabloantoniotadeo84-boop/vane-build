// Vane Agent Passport (CAP) — credential schema version 1.
//
// A CAP+JWT credential is a standard EdDSA JWT with typ "CAP+JWT" and
// a versioned "vane" claim object. Any JWT library that supports EdDSA
// can parse it; the only Vane-specific logic is in the "vane" object
// and the scope matching rules below.

// ── Credential claims ─────────────────────────────────────────────────────────

export interface VanePassportClaims {
  // Standard JWT claims (RFC 7519)
  iss: string;    // SPIFFE ID of the issuing Vane instance
  sub: string;    // Agent's SPIFFE ID — the credential subject
  aud: string[];  // Must include PASSPORT_AUDIENCE = "vane:passport:v1"
  jti: string;    // Unique passport ID (UUID v4) — for revocation
  iat: number;    // Issued-at (Unix seconds)
  exp: number;    // Expiry (Unix seconds)
  nbf: number;    // Not-before (Unix seconds, equals iat at issuance)

  // Vane-specific claims — namespaced to avoid collision with JWT extensions
  vane: {
    v: 1;                     // Schema version — verifiers MUST reject unknown versions
    agentId: string;          // Human-readable agent identifier
    org: string;              // Issuing organization name
    orgSpiffeId: string;      // Organization's SPIFFE ID
    scopes: string[];         // Authorization scopes — see scope rules below
    delegationChain: string[]; // [orgSpiffeId, ..., agentSpiffeId] — full authorization path
    delegationId?: string;    // jti of the RFC 8693 token this passport was derived from

    // ── Sender-constraint claims (all optional, all caller-supplied) ──────────
    // These bind a passport to a single use and defeat bearer-token replay.
    // A passport that omits them is a plain bearer credential (backward
    // compatible); a verifier only enforces a constraint when it asks for it.

    nonce?: string;           // 128-bit caller-supplied random value, hex-encoded.
                              //   Enforced when the verifier passes expectedNonce.
    aud?: string;             // Per-deployment recipient audience — a single string
                              //   identifying the intended server (e.g.
                              //   "https://api.example.com"). Distinct from the
                              //   top-level protocol `aud` (PASSPORT_AUDIENCE).
                              //   Enforced when the verifier passes expectedAudience.
    requestHash?: string;     // SHA-256 hex of the canonical request
                              //   (METHOD|url|sha256(body)). When present, the
                              //   verifier MUST validate it against the live request.
  };
}

// ── Scope format ──────────────────────────────────────────────────────────────
//
// Scopes use "category:name" format. Matching rules (evaluated in order):
//   "*"         — covers any scope
//   "cat:*"     — covers any scope in category "cat"
//   "cat:name"  — covers exactly "cat:name"

// ── Attestation receipt ───────────────────────────────────────────────────────
//
// The open, documented format attached to every verified tool call.
// Any system can parse and verify this format independently.

export interface AttestationReceipt {
  v: 1;
  type: 'VaneAttestationReceipt';
  passportId: string;       // jti of the verified passport
  agentId: string;
  agentSpiffeId: string;
  org: string;
  orgSpiffeId: string;
  tool: string;             // tool that was called
  scopeGranted: string;     // which scope in the passport authorized this call
  delegationChain: string[];
  issuedBy: string;         // iss — which Vane instance signed this passport
  passportIssuedAt: string; // ISO 8601
  passportExpiresAt: string; // ISO 8601
  verifiedAt: string;       // ISO 8601 — when this receipt was produced
  verifier: string;         // package name + version that produced this receipt
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
  // Sender-constraint failures (nonce binding / recipient audience / request binding).
  | 'MISSING_NONCE'
  | 'NONCE_MISMATCH'
  | 'MISSING_AUDIENCE'
  | 'REQUEST_MISMATCH'
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
  | 'VERIFICATION_ERROR';
