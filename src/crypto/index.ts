export { generateKeyPair } from './keypair.js';
export { signPayload, verifyPayload, canonicalize } from './signer.js';
export { AttestationChain } from './chain.js';
export { computeRoot, buildProof, verifyProof } from './merkle.js';
export type { MerkleProof, ProofNode } from './merkle.js';
export type { InclusionProof } from './chain.js';
export type { KeyPair, AttestationRecord, DelegationInfo, VerificationResult, AgentRegistration, ActClaim, JwtSvidClaims, TokenExchangeResponse } from './types.js';

export { agentSpiffeId, companySpiffeId, parseSpiffeId, validateSpiffeId, TRUST_DOMAIN } from './spiffe.js';
export type { ParsedSpiffeId } from './spiffe.js';

export { issueJwtSvid, verifyJwtSvid, deriveKeyId, SVID_AUDIENCE } from './svid.js';
export { exchangeToken, extractDelegationChain, GRANT_TYPE, TOKEN_TYPE_JWT } from './token-exchange.js';
