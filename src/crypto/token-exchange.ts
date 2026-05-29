import { issueJwtSvid, verifyJwtSvid } from './svid.js';
import type { ActClaim, JwtSvidClaims, TokenExchangeResponse } from './types.js';

export const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';

const DELEGATION_TTL = 3600;

/**
 * RFC 8693 §2 token exchange.
 *
 * Issues a delegation token where:
 *   sub  = subject's SPIFFE ID (the entity being acted upon)
 *   act  = { sub: actor's SPIFFE ID, act: <prior chain from subject token> }
 *
 * This preserves the full delegation chain when exchanges are chained:
 *   round 1: agent-A acts as company → { sub: company, act: { sub: agent-A } }
 *   round 2: sub-agent-B (via the round-1 token) acts as company →
 *             { sub: company, act: { sub: sub-agent-B, act: { sub: agent-A } } }
 */
export function exchangeToken(
  subjectToken: string,
  actorToken: string,
  privateKeyPem: string,
  publicKeyPem: string,
): TokenExchangeResponse {
  const subjectClaims = verifyJwtSvid(subjectToken, publicKeyPem);
  const actorClaims = verifyJwtSvid(actorToken, publicKeyPem);

  // New actor wraps the existing act chain carried by the subject token.
  const actChain: ActClaim = { sub: actorClaims.sub };
  if (subjectClaims.act) actChain.act = subjectClaims.act;

  const delegationToken = issueJwtSvid(
    subjectClaims.sub,
    privateKeyPem,
    publicKeyPem,
    DELEGATION_TTL,
    { act: actChain },
  );

  return {
    access_token: delegationToken,
    issued_token_type: TOKEN_TYPE_JWT,
    token_type: 'N_A',
    expires_in: DELEGATION_TTL,
  };
}

/**
 * Extracts the delegation chain from a token's claims as an ordered array.
 * Index 0 = subject (entity being acted upon).
 * Index 1 = most proximate actor.
 * Index n = original delegating actor (innermost act).
 */
export function extractDelegationChain(claims: JwtSvidClaims): string[] {
  const chain: string[] = [claims.sub];
  let act: ActClaim | undefined = claims.act;
  while (act) {
    chain.push(act.sub);
    act = act.act;
  }
  return chain;
}
