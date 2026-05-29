import { sign as cryptoSign, createPrivateKey, randomUUID } from 'node:crypto';
import { deriveKeyId } from '../crypto/svid.js';
import { validateSpiffeId, TRUST_DOMAIN } from '../crypto/spiffe.js';
import type { CounselPassportClaims } from './types.js';

export const PASSPORT_AUDIENCE = 'counsel:passport:v1';
export const PASSPORT_TTL_DEFAULT = 3600; // 1 hour

function b64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

export interface IssuePassportOptions {
  agentId: string;
  agentSpiffeId: string;
  org: string;
  orgSpiffeId: string;
  scopes: string[];
  delegationChain: string[];
  delegationId?: string;
  ttl?: number;          // seconds, defaults to PASSPORT_TTL_DEFAULT
  privateKeyPem: string;
  publicKeyPem: string;
}

/**
 * Issues a Counsel Agent Passport (CAP+JWT).
 *
 * The resulting token is a standard EdDSA JWT verifiable by any party that
 * holds the CA public key — no network call to Counsel is required.
 *
 * Security invariants:
 *   - alg is hard-coded to EdDSA; no algorithm confusion is possible
 *   - typ is "CAP+JWT" — distinct from SVID tokens (typ "JWT")
 *   - aud is "counsel:passport:v1" — prevents replay across token types
 *   - nbf equals iat — no pre-dating
 *   - delegationChain tail MUST equal agentSpiffeId before signing
 */
export function issuePassport(opts: IssuePassportOptions): string {
  if (!validateSpiffeId(opts.agentSpiffeId)) {
    throw new Error(`Invalid agent SPIFFE ID: ${opts.agentSpiffeId}`);
  }
  if (!validateSpiffeId(opts.orgSpiffeId)) {
    throw new Error(`Invalid org SPIFFE ID: ${opts.orgSpiffeId}`);
  }
  if (opts.scopes.length === 0) {
    throw new Error('Passport must include at least one scope');
  }
  if (opts.delegationChain.length === 0) {
    throw new Error('Passport must include a delegation chain');
  }
  const chainTail = opts.delegationChain[opts.delegationChain.length - 1];
  if (chainTail !== opts.agentSpiffeId) {
    throw new Error(
      `delegationChain tail (${chainTail}) must equal agentSpiffeId (${opts.agentSpiffeId})`,
    );
  }

  const ttl = opts.ttl ?? PASSPORT_TTL_DEFAULT;
  const now = Math.floor(Date.now() / 1000);
  const kid = deriveKeyId(opts.publicKeyPem);

  const header = b64url(JSON.stringify({ alg: 'EdDSA', typ: 'CAP+JWT', kid }));

  const claims: CounselPassportClaims = {
    iss: `spiffe://${TRUST_DOMAIN}/ca`,
    sub: opts.agentSpiffeId,
    aud: [PASSPORT_AUDIENCE],
    jti: randomUUID(),
    iat: now,
    exp: now + ttl,
    nbf: now,
    counsel: {
      v: 1,
      agentId: opts.agentId,
      org: opts.org,
      orgSpiffeId: opts.orgSpiffeId,
      scopes: opts.scopes,
      delegationChain: opts.delegationChain,
      ...(opts.delegationId !== undefined && { delegationId: opts.delegationId }),
    },
  };

  const payload = b64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const sig = cryptoSign(null, Buffer.from(signingInput), createPrivateKey(opts.privateKeyPem))
    .toString('base64url');

  return `${signingInput}.${sig}`;
}
