# Vane — Handoff

**Date:** 2026-06-04  
**Status:** Alpha. Core cryptographic stack is production-ready. Persistence, auth, and delivery layers need operational hardening before production deployment.

---

## What Vane Is

Vane is a trust and attestation layer for AI agents. It solves three problems:

1. **Action integrity** — tamper-evident, append-only log of everything an agent does
2. **Identity** — SPIFFE workload identities tied to every record
3. **Delegation** — cryptographic proof of who authorized what, bound into each attestation record

The key design choice: every verification is offline. MCP servers, tools, and auditors verify passports and attestation records using a CA public key they fetch once — no round-trips to Vane on the hot path.

---

## Architecture State

### Runtime
- Node.js 22+ (required for `node:crypto` Ed25519 and `node:sqlite`)
- TypeScript strict + NodeNext ESM
- Hono HTTP framework, `@hono/node-server` adapter
- PostgreSQL (migrated from `node:sqlite`; `DATABASE_URL` env var required)

### Source layout
```
src/
  api/
    app.ts           All route handlers (~1750 lines, the full HTTP surface)
    server.ts        Port binding only
    rate-limit.ts    Sliding window rate limiting per API key
    ws.ts            WebSocket broadcast for real-time chain updates
  crypto/
    keypair.ts       Ed25519 key pair generation
    signer.ts        signPayload / verifyPayload + canonicalize()
    chain.ts         AttestationChain — append-only log
    merkle.ts        Merkle tree: computeRoot, buildProof, verifyProof
    spiffe.ts        SPIFFE ID construction, parsing, validation
    svid.ts          JWT-SVID issuance and verification (EdDSA)
    token-exchange.ts RFC 8693 delegation chain logic
    cross-org.ts     Cross-org delegation tokens (XORG+JWT)
    types.ts         All shared TypeScript interfaces
    index.ts         Barrel re-export
  passport/
    credential.ts    issuePassport — CAP+JWT issuance
    verify.ts        verifyPassport — offline verification, 13-step
    types.ts         VanePassportClaims, PassportVerificationResult
    index.ts         Barrel re-export
  db/
    store.ts         PostgreSQL via pg Pool; AES-256-GCM envelope encryption
  logger.ts          Pino structured logging
  sentry.ts          Sentry error capture
  webhooks/          Webhook delivery, retry scheduler, HMAC-SHA256 signatures

packages/
  sdk/               @vane.build/sdk — VaneClient (CJS + ESM)
  mcp-middleware/    Hono + fetch middleware for MCP servers
  integrations/
    langchain/       LangChain callback handler
    crewai/          CrewAI observer (Python)
```

---

## Token Types

There are three distinct JWT token types in flight, each with a different `typ` header and `aud` claim to prevent replay:

| Token | `typ` | `aud` | Use |
|---|---|---|---|
| JWT-SVID | `JWT` | `vane` | SPIFFE identity assertion; used in RFC 8693 exchanges |
| Agent Passport (CAP) | `CAP+JWT` | `vane:passport:v1` | Primary bearer credential for MCP tool calls |
| Cross-org delegation | `XORG+JWT` | `vane:xorg:v1` | Agent from org A acting on org B's MCP server |

All three are Ed25519 (EdDSA), signed with the company's CA key pair. The `verifyJwtSvid`, `verifyPassport`, and `verifyCrossOrgToken` functions are the three verification entry points.

---

## Security Posture

### What was hardened (last few commits)
- **Algorithm confusion** — all three verifiers reject `alg:none`, unknown `alg` values, and non-Ed25519 public keys before calling `cryptoVerify`. The key-type guard runs _before_ the signature check.
- **Fail-closed** — `verifyPayload` wraps its crypto call in `try/catch` and returns `{ valid: false }` on any error. `verifyPassport` and `verifyCrossOrgToken` return structured failure objects; they never throw on bad input. `verifyJwtSvid` throws on all failures (callers handle).
- **Auth middleware** — the Hono auth middleware (`app.use('/v1/*', ...)`) falls through to 401 on any uncaught exception from the mTLS path; the API key path returns 401 explicitly.
- **Delegation binding** — the delegation JWT is verified and its contents are embedded in the attestation record hash. You cannot strip or swap a delegation token without invalidating the record signature.
- **Key rotation grace period** — `verifyPassportMultiKey` in `app.ts` tries the current key first, then retired keys within the configurable grace window (`VANE_KEY_ROTATION_GRACE_PERIOD_HOURS`, default 24). Non-signature failures short-circuit immediately (expired passport fails fast regardless of key).

### What is NOT hardened (known gaps)
1. **No workload attestation on agent registration** — `POST /v1/agents/register` requires only the company's API key. Any key holder can register any `agentId`. Production requires TPM, projected service account tokens, or SPIRE before this is safe.
2. **Company creation is open** — `POST /v1/companies` has no admin gate. Namespace squatting is possible.
3. **Private keys in PostgreSQL** — AES-256-GCM envelope encryption is implemented and used when `VANE_MASTER_KEY` is set, but `MASTER_KEY` is derived from a plain env var, not an HSM or KMS. A compromised `MASTER_KEY` decrypts all private keys.
4. **No JWT revocation for SVIDs** — `verifyJwtSvid` has no revocation check. Only passports have revocation (via `store.isPassportRevoked`). Delegation tokens expire but can't be revoked early.
5. **Single trust domain** — `SPIFFE_TRUST_DOMAIN` is a global env var. All companies share `vane.local`.

---

## Authentication Layers

The auth middleware resolves a `companyId` from any of three mechanisms, in priority order:

1. **mTLS client certificate CN** — only attempted when `VANE_MTLS_CA_CERT` is set
2. **Bearer API key** (`vane_<hex>`) — looked up in `api_keys` table
3. **Bearer OAuth token** (`oauth_<...>`) — looked up in `oauth_tokens` table; short-lived (3600s)

OAuth clients are created via `POST /v1/oauth/clients` and exchange credentials for tokens via `POST /v1/oauth/token` (RFC 6749 §4.4 client credentials flow).

Public endpoints (no auth required):
- `GET /v1/health`
- `GET /v1/ca/public-key`, `GET /v1/ca/public-keys`, `GET /v1/ca/well-known`
- `POST /v1/companies`, `POST /v1/setup`
- `POST /v1/recover-key` (localhost only)
- `POST /v1/oauth/token`
- `GET /v1/agents/:agentId/timeline/view` (handles own auth via query param)

---

## Agent Passport Flow

The intended production flow for MCP tool authorization:

```
1. POST /v1/agents/register        → agent registered, SVID issued
2. POST /v1/agents/:id/passport    → CAP+JWT issued (5min–1hr TTL)
3. Agent presents passport as Bearer token to MCP server
4. MCP server calls verifyPassport(token, { caPublicKey }) offline
   OR calls POST /v1/passport/verify for server-side check + receipt
5. POST /v1/passports/:jti/revoke  → immediate revocation if needed
6. GET  /v1/ocsp/:jti              → signed revocation status (cacheable 5min)
```

The `mcp-middleware` package implements steps 4–5 as Hono middleware and a `fetch`-compatible handler. Cross-org passports use `verifyCrossOrgToken` with the originating org's CA public key fetched from `GET /v1/ca/public-key?companyId=<originOrg>`.

---

## Test Suite

`tests/crypto.test.ts` — run with `npm test` (vitest).

Coverage:
- Ed25519 sign/verify golden vector and tamper rejection
- Passport expiry, delegation chain coherence, TTL bounds (5min–1hr)
- Algorithm confusion hardening (alg:none, RS256, HS256, missing alg, RSA key with EdDSA header) — tested against both `verifyJwtSvid` and `verifyPassport`
- Attestation chain hash and signature tampering detection
- Merkle inclusion proof construction and verification
- JWT-SVID issuance and RFC 8693 delegation chain extraction
- Revocation: JTI in list → denied; prefix match → allowed; no list → allowed
- OCSP signed response integrity
- Key rotation: new key verifies new passports; old key rejected; grace period multi-key fallback
- Cross-org token issuance, expiry, wrong key, wrong target org, scope denial
- MCP middleware cross-org flow: accept, reject (not configured, null key, wrong target), receipt shape
- Server and middleware `verifyCrossOrgToken` consistency

**What is NOT tested:**
- HTTP route handlers (no integration/e2e test layer)
- Store/database operations
- Webhook delivery and retry
- OAuth token flow
- Rate limiting
- mTLS path

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `PORT` | `3000` | HTTP listen port |
| `SPIFFE_TRUST_DOMAIN` | `vane.local` | SPIFFE trust domain for all IDs |
| `VANE_MASTER_KEY` | (unset) | AES-256-GCM envelope encryption key for private keys in DB |
| `VANE_MTLS_CA_CERT` | (unset) | Path to CA cert; enables mTLS auth path |
| `VANE_KEY_ROTATION_GRACE_PERIOD_HOURS` | `24` | How long a retired key remains valid for passport verification |
| `VANE_BASE_URL` | (inferred) | Base URL for OIDC discovery documents |
| `SENTRY_DSN` | (unset) | Sentry DSN for error capture |

---

## Running

```bash
# Dev (tsx, no build step)
DATABASE_URL=postgres://... npm run dev

# Run tests
npm test

# Build
npm run build && npm start
```

---

## Open Work

**Operational**
- Integration/e2e test layer for HTTP routes (Hono test client or supertest)
- `DATABASE_URL` must be set; no fallback to SQLite in dev — consider restoring SQLite for local dev
- `node_modules` is committed to `.gitignore`-ignore; the `packages/integrations/crewai/__pycache__` should also be ignored
- No `package.json` `engines` field for the integrations packages

**Security**
- Agent registration needs workload attestation before production
- `POST /v1/companies` needs an admin gate
- `VANE_MASTER_KEY` derivation should use HKDF or a KMS, not raw SHA-256
- `verifyJwtSvid` is the only verifier that throws instead of returning a result type — consider making it consistent with `verifyPassport`'s return-type pattern so callers can't accidentally swallow the error

**Features**
- Terraform provider (`549b8bd`) — read the commit; it exists but its state relative to the current API is unknown
- `packages/sdk` — `VaneClient.attest()` passes `companyId` in the body (redundant; server ignores it for auth but embeds it in the payload)
- Webhook retry scheduler uses an in-process timer; needs an external job runner for multi-instance deployments
- OCSP responses are signed with `signPayload` over the response JSON; caching headers are set but there's no ETagger or conditional-GET support

**Documentation**
- `docs/cross-org-trust.md` and `docs/disaster-recovery.md` exist; `CLAUDE.md` is the most complete reference but is not user-facing
- The marketing site is in `vane-site/` and is served at `/` from `public/index.html`; the two may be out of sync
