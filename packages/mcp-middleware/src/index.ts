export { createCounselMiddleware, decodeReceipt, McpAuthError, RECEIPT_HEADER } from './middleware.js';
export { verifyPassport, matchScope } from './verify.js';
export type {
  CounselPassportClaims,
  AttestationReceipt,
  PassportVerificationResult,
  PassportErrorCode,
  CounselMiddlewareOptions,
  VerifyOptions,
} from './types.js';
