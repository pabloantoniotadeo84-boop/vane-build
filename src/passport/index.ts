export {
  issuePassport,
  generateNonce,
  computeRequestHash,
  PASSPORT_AUDIENCE,
  PASSPORT_TTL_DEFAULT,
  PASSPORT_TTL_MIN,
  PASSPORT_TTL_MAX,
} from './credential.js';
export type { IssuePassportOptions, CanonicalRequest } from './credential.js';
export { verifyPassport, matchScope } from './verify.js';
export type { VerifyPassportOptions } from './verify.js';
export type {
  VanePassportClaims,
  AttestationReceipt,
  PassportVerificationResult,
  PassportErrorCode,
} from './types.js';
