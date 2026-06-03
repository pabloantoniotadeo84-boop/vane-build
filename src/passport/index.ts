export { issuePassport, PASSPORT_AUDIENCE, PASSPORT_TTL_DEFAULT } from './credential.js';
export type { IssuePassportOptions } from './credential.js';
export { verifyPassport, matchScope } from './verify.js';
export type { VerifyPassportOptions } from './verify.js';
export type {
  VanePassportClaims,
  AttestationReceipt,
  PassportVerificationResult,
  PassportErrorCode,
} from './types.js';
