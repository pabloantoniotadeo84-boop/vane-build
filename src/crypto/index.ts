export { generateKeyPair } from './keypair.js';
export { signPayload, verifyPayload, canonicalize } from './signer.js';
export { AttestationChain } from './chain.js';
export { computeRoot, buildProof, verifyProof } from './merkle.js';
export type { MerkleProof, ProofNode } from './merkle.js';
export type { InclusionProof } from './chain.js';

export { rfc6962RootHex, consistencyProofHex, verifyConsistencyHex } from './rfc6962.js';
export { signSTH, verifySTH } from './sth.js';
export type { SignedTreeHead, STHFields } from './sth.js';
export type { KeyPair, AttestationRecord, DelegationInfo, VerificationResult, AgentRegistration, ActClaim, JwtSvidClaims, TokenExchangeResponse, CrossOrgDelegationClaims } from './types.js';

export { agentSpiffeId, companySpiffeId, parseSpiffeId, validateSpiffeId, TRUST_DOMAIN } from './spiffe.js';
export type { ParsedSpiffeId } from './spiffe.js';

export { issueJwtSvid, verifyJwtSvid, deriveKeyId, SVID_AUDIENCE } from './svid.js';
export { exchangeToken, extractDelegationChain, GRANT_TYPE, TOKEN_TYPE_JWT } from './token-exchange.js';

export {
  issueCrossOrgToken,
  verifyCrossOrgToken,
  CROSS_ORG_TOKEN_TYPE,
  CROSS_ORG_AUDIENCE,
  CROSS_ORG_MAX_TTL,
} from './cross-org.js';
export type {
  IssueCrossOrgTokenOptions,
  CrossOrgVerifyOptions,
  CrossOrgVerificationResult,
  CrossOrgErrorCode,
} from './cross-org.js';
