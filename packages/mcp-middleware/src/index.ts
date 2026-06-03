export { createVaneMiddleware, decodeReceipt, McpAuthError, RECEIPT_HEADER } from './middleware.js';
export { verifyPassport, matchScope } from './verify.js';
export type {
  VanePassportClaims,
  AttestationReceipt,
  PassportVerificationResult,
  PassportErrorCode,
  VaneMiddlewareOptions,
  VerifyOptions,
} from './types.js';
