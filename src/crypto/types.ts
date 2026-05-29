export interface KeyPair {
  publicKey: string;  // SPKI PEM
  privateKey: string; // PKCS8 PEM
}

export interface AttestationRecord {
  index: number;
  timestamp: string;          // ISO 8601
  payload: unknown;
  delegation?: DelegationInfo; // present when attested under a delegation token
  hash: string;               // SHA-256 hex of canonical(index|timestamp|payload[|delegation])
  signature: string;          // Ed25519 over hash, base64url-encoded
}

export interface VerificationResult {
  valid: boolean;
  merkleRoot?: string; // present on success
  failedAtIndex?: number;
  error?: string;
}

export interface AgentRegistration {
  agentId: string;
  spiffeId: string;
  companyId?: string;
  registeredAt: string;
  metadata?: Record<string, unknown>;
}

// RFC 8693 §4.4 — recursive act claim for delegation chains.
export interface ActClaim {
  sub: string;
  act?: ActClaim;
}

// Claims present in a verified SPIFFE JWT-SVID.
export interface JwtSvidClaims {
  sub: string;      // SPIFFE ID
  aud: string[];
  iat: number;
  exp: number;
  jti: string;
  act?: ActClaim;   // present on delegation tokens
  scope?: string;   // present on delegation tokens issued via /v1/token-exchange
}

// RFC 8693 §2.2.1 successful token exchange response.
export interface TokenExchangeResponse {
  access_token: string;
  issued_token_type: string;
  token_type: 'N_A';
  expires_in: number;
}

// Delegation metadata extracted from a verified RFC 8693 token and stored
// as a first-class signed field on every attested record that carries one.
export interface DelegationInfo {
  subject: string;           // sub — entity being acted on behalf of
  delegationChain: string[]; // ordered [subject, proximate-actor, ..., origin]
  act: ActClaim | null;      // raw act claim for deep traversal
  tokenId: string;           // jti — ties this record to the exchange event
}
