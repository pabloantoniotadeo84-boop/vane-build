export { createVaneMiddleware, decodeReceipt, McpAuthError, RECEIPT_HEADER } from './middleware.js';
export { verifyPassport, verifyCrossOrgToken, matchScope, CROSS_ORG_TOKEN_TYPE } from './verify.js';
export type {
  VanePassportClaims,
  CrossOrgDelegationClaims,
  AttestationReceipt,
  PassportVerificationResult,
  PassportErrorCode,
  VaneMiddlewareOptions,
  VerifyOptions,
} from './types.js';
export type { CrossOrgVerifyOptions } from './verify.js';
