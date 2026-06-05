# Vane — Handoff

**Date:** 2026-06-05  
**Status:** Alpha. The cryptographic and protocol stack is well-hardened. Persistence and delivery layers need operational hardening before production deployment.

---

## What Vane Is

Vane is a trust and attestation layer for AI agents. It solves three problems:

1. **Action integrity** — tamper-evident, append-only log of everything an agent does
2. **Identity** — SPIFFE workload identities tied to every record
3. **Delegation** — cryptographic proof of who authorized what, bound into each attestation record

The key design choice: every verification is offline. MCP servers, tools, and auditors verify passports and attestation records using a CA public key fetched once — no round-trips to Vane on the hot path.

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
    app.ts             All route handlers (~1750 lines, the full HTTP surface)
    server.ts          Port binding only
    rate-limit.ts      Sliding window rate limiting per API key
    ws.ts              WebSocket broadcast for real-time chain updates
  crypto/
    keypair.ts         Ed25519 key pair generation
    signer.ts          signPayload / verifyPayload + JCS canonicalize()
    chain.ts           AttestationChain — append-only log
    merkle.ts          Merkle tree: computeRoot, buildProof, verifyProof
    spiffe.ts          SPIFFE ID construction, parsing, validation
    svid.ts            JWT-SVID issuance and verification (EdDSA)
    token-exchange.ts  RFC 8693 delegation chain logic
    cross-org.ts       Cross-org delegation tokens (XORG+JWT)
    types.ts           All shared TypeScript interfaces
    index.ts           Barrel re-export
  passport/
    credential.ts      issuePassport — CAP+JWT issuance
    verify.ts          verifyPassport — offline verification, 18-step (see conformance/)
    types.ts           VanePassportClaims, PassportVerificationResult
    index.ts           Barrel re-export
  db/
    store.ts           PostgreSQL via pg Pool; AES-256-GCM envelope encryption
  logger.ts            Pino structured logging
  sentry.ts            Sentry error capture
  webhooks/            Webhook delivery, retry scheduler, HMAC-SHA256 signatures

packages/
  sdk/                 @vane.build/sdk — VaneClient (CJS + ESM)
  mcp-middleware/      Hono + fetch middleware for MCP servers
  integrations/
    langchain/         LangChain callback handler
    crewai/            CrewAI observer (Python)

scripts/
  backup-db.ts         Dump all 14 tables to timestamped JSON + SHA-256 checksum
  restore-db.ts        Verify checksum, drop/recreate tables, restore rows
  verify-proof.ts      Offline CLI: verify a Merkle inclusion proof (no network)

conformance/
  README.md            Normative passport verification spec (protocol + error codes)
  reference-verifier.ts Self-contained reference verifier (Node built-ins only)
  vectors.json         22 test vectors; every scenario pinned to a fixed epoch
  generate-vectors.ts  Regenerates vectors.json (maintainers only)

public/
  index.html           Marketing site (single-file HTML + CSS + JS)
  passport-crypto.js   In-browser Ed25519 module, independently testable
  favicon.svg          Terracotta weathervane mark
  og.svg               Open Graph share card
```

---

## Token Types

Three distinct JWT token types are in flight, each with a different `typ` header and `aud` to prevent replay:

| Token | `typ` | `aud` | Use |
|---|---|---|---|
| JWT-SVID | `JWT` | `vane` | SPIFFE identity assertion; used in RFC 8693 exchanges |
| Agent Passport (CAP) | `CAP+JWT` | `vane:passport:v1` | Primary bearer credential for MCP tool calls |
| Cross-org delegation | `XORG+JWT` | `vane:xorg:v1` | Agent from org A acting on org B's MCP server |

All three are Ed25519 (EdDSA), signed with the company's CA key pair.

---

## What Was Hardened (This Batch — 2026-06-05)

Eight commits landed since the previous handoff, all security or protocol work:

### Sender-constrained passports (`b371353`)
Passports can now carry three optional binding fields in the `vane` claim object:

- **`nonce`** (32 hex) — caller-gated; enforced only when the verifier supplies `expectedNonce`. Absent or mismatched → `MISSING_NONCE` / `NONCE_MISMATCH`.
- **`aud`** (string) — caller-gated; enforced only when verifier supplies `expectedAudience`. → `MISSING_AUDIENCE` / `AUDIENCE_MISMATCH`.
- **`requestHash`** (64 hex) — **claim-gated / fail-closed**. When the claim is present, any verifier that lacks `expectedRequestHash` OR whose hash mismatches → `REQUEST_MISMATCH`. Prevents bearer replay for request-bound passports.

The asymmetry is intentional: nonce/audience are opt-in enforcement at the verifier; request binding is mandatory once the issuer asserts it.

Request hash formula: `SHA-256_hex(METHOD + "|" + url + "|" + SHA-256_hex(body))`.

### JCS RFC 8785 canonical serialization (`9f063c3`)
`canonicalize()` in `signer.ts` was updated to full JCS (RFC 8785) compliance — recursive key sort, deterministic number encoding. **Attestation record hashes and signatures now cover JCS bytes.** Passports remain exempt (signatures cover raw base64url bytes, not re-serialized JSON — see conformance/README.md §3 for why).

### Clock-skew leeway + `nbf` enforcement (`80b1450`)
All three verifiers (`verifyJwtSvid`, `verifyPassport`, `verifyCrossOrgToken`) now apply a configurable clock-skew leeway (default 30 s) to both `exp` and `nbf` checks. A negative leeway is a configuration error that throws before any token is inspected.

### CI gate + supply chain scan (`eda5198`)
`.github/workflows/` now runs `npm test` on every push and PR, plus a GitHub dependency review action that blocks PRs introducing known-vulnerable or license-restricted packages.

### Inclusion proof API + offline CLI (`f9dbfe6`)
`GET /v1/agents/:agentId/attestations/:index/proof` returns a Merkle inclusion proof bound to the agent's attestation sub-chain. `scripts/verify-proof.ts` is an offline CLI that verifies a saved proof JSON against a pinned CA public key — no network, no database. Exit codes: 0 = valid, 1 = invalid, 2 = usage/parse error.

### Conformance suite + reference verifier (`10aaa20`)
`conformance/` is the normative specification of the passport verification protocol — written for third-party implementers who need to port the verifier to another language. `conformance/reference-verifier.ts` is a self-contained, zero-external-dependency implementation. `conformance/vectors.json` has 22 test vectors covering every error code plus cross-org, sender constraints, revocation, and scope matching. `tests/conformance.test.ts` cross-runs every vector through both the production verifier and the reference verifier; they must agree on every result or the suite fails, preventing spec/implementation drift.

### Rate limiting on passport issuance (`b80be21`)
The passport issuance endpoint now enforces a per-company sliding window rate limit. Config is in `src/api/rate-limit.ts`.

### Backup and restore (`7ad15bd`)
`scripts/backup-db.ts` dumps all 14 PostgreSQL tables to a timestamped JSON file alongside a SHA-256 checksum. `scripts/restore-db.ts` verifies the checksum, drops and recreates tables in FK-safe order, restores every row, then verifies row counts match the backup. Both export pure functions used by `tests/backup-restore.test.ts` — no Postgres connection needed for tests.

---

## Security Posture

### What was hardened (cumulative)
- **Algorithm confusion** — all three verifiers reject `alg:none`, unknown `alg` values, and non-Ed25519 public keys before calling `cryptoVerify`. Key-type guard runs before the signature check.
- **Fail-closed** — `verifyPayload` returns `{ valid: false }` on any error; `verifyPassport` and `verifyCrossOrgToken` return structured failure objects and never throw on bad input; unexpected errors in either path resolve to `VERIFICATION_ERROR`.
- **Auth middleware** — falls through to 401 on any uncaught exception; API key path returns 401 explicitly.
- **Delegation binding** — delegation JWT is verified and its contents embedded in the attestation record hash. Cannot strip or swap without invalidating the record signature.
- **Key rotation grace period** — `verifyPassportMultiKey` tries the current key first, then retired keys within `VANE_KEY_ROTATION_GRACE_PERIOD_HOURS` (default 24). Non-signature failures (expired passport) short-circuit immediately.
- **JCS canonical serialization** — attestation hashes cover JCS bytes; no insertion-order ambiguity.
- **Sender constraints** — bearer replay defeated via nonce, audience, and request binding.
- **Signed tree heads + consistency proofs** — `GET /v1/checkpoint` returns a signed snapshot; `GET /v1/consistency` proves append-only growth between two roots.

### Known gaps (not hardened)
1. **No workload attestation on agent registration** — `POST /v1/agents/register` requires only the company's API key. Production requires TPM, projected service account tokens, or SPIRE.
2. **Company creation is open** — `POST /v1/companies` has no admin gate. Namespace squatting is possible.
3. **Private keys in PostgreSQL** — AES-256-GCM envelope encryption via `VANE_MASTER_KEY`, but the master key is a plain env var (not an HSM/KMS). A leaked `VANE_MASTER_KEY` decrypts all private keys.
4. **No JWT revocation for SVIDs** — `verifyJwtSvid` has no revocation check. Only passports have revocation via `store.isPassportRevoked`.
5. **Single trust domain** — `SPIFFE_TRUST_DOMAIN` is a global env var shared by all companies.

---

## Authentication Layers

The auth middleware resolves a `companyId` from any of three mechanisms, in priority order:

1. **mTLS client certificate CN** — only attempted when `VANE_MTLS_CA_CERT` is set
2. **Bearer API key** (`vane_<hex>`) — looked up in `api_keys` table
3. **Bearer OAuth token** (`oauth_<...>`) — looked up in `oauth_tokens` table; short-lived (3600 s)

OAuth clients are created via `POST /v1/oauth/clients` and exchange credentials for tokens via `POST /v1/oauth/token` (RFC 6749 §4.4 client credentials flow).

**Public endpoints** (no auth required):
- `GET /v1/health`
- `GET /v1/ca/public-key`, `GET /v1/ca/public-keys`, `GET /v1/ca/well-known`
- `POST /v1/companies`, `POST /v1/setup`
- `POST /v1/recover-key` (localhost only)
- `POST /v1/oauth/token`
- `GET /v1/agents/:agentId/timeline/view` (handles own auth via query param)
- `GET /v1/checkpoint`, `GET /v1/consistency` (signed tree heads; public by design)

---

## Agent Passport Flow

```
1. POST /v1/agents/register        → agent registered, SVID issued
2. POST /v1/agents/:id/passport    → CAP+JWT issued (5 min–1 hr TTL)
3. Agent presents passport as Bearer token to MCP server
4. MCP server calls verifyPassport(token, { caPublicKey }) offline
   OR calls POST /v1/passport/verify for server-side check + receipt
5. POST /v1/passports/:jti/revoke  → immediate revocation if needed
6. GET  /v1/ocsp/:jti              → signed revocation status (cacheable 5 min)
```

`mcp-middleware` implements steps 4–5 as Hono middleware and a `fetch`-compatible handler. Cross-org passports use `verifyCrossOrgToken` with the originating org's CA public key fetched from `GET /v1/ca/public-key?companyId=<originOrg>`.

---

## Test Suite

Run with `npm test` (vitest).

| File | What it covers |
|---|---|
| `tests/crypto.test.ts` | Ed25519 sign/verify, algorithm confusion (alg:none, RS256, HS256, RSA key), chain tamper, Merkle proofs, JWT-SVID, RFC 8693, revocation, OCSP, key rotation, cross-org tokens, MCP middleware |
| `tests/conformance.test.ts` | Runs all 22 vectors in `conformance/vectors.json` through both the production verifier and the reference verifier; fails if they disagree |
| `tests/sender-constrained.test.ts` | Nonce, recipient audience, request binding — all three constraints, good and bad paths |
| `tests/clock-skew.test.ts` | `exp` and `nbf` with leeway, negative leeway config error |
| `tests/canonicalize.test.ts` | JCS RFC 8785 compliance: key sort, number encoding, round-trip |
| `tests/inclusion-proof.test.ts` | Per-agent attestation sub-chain, proof construction and offline verification |
| `tests/fail-closed.test.ts` | Verifiers return structured failures (never throw) on corrupt/unexpected input |
| `tests/issuance-rate-limit.test.ts` | Per-company sliding window rate limit on passport issuance |
| `tests/backup-restore.test.ts` | Backup serialization, checksum, restore round-trip, row count verification (in-memory fakes, no Postgres) |
| `tests/checkpoint.test.ts` | Signed tree head issuance and consistency proof |
| `tests/ci-workflow.test.ts` | CI gate smoke tests |
| `tests/passport-crypto.test.ts` | In-browser `passport-crypto.js` module (Node crypto/subtle compat) |

**What is NOT tested:**
- HTTP route handlers end-to-end (no integration/e2e test layer)
- Store/database operations against a live Postgres instance
- Webhook delivery and retry
- OAuth token flow
- mTLS path

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *required* | PostgreSQL connection string |
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

# Build and start
npm run build && npm start

# Backup the database
tsx scripts/backup-db.ts [output-dir]

# Restore from backup
tsx scripts/restore-db.ts <backup-file.json>

# Offline proof verification
tsx scripts/verify-proof.ts <proof.json> <ca-public-key.pem>
tsx scripts/verify-proof.ts <proof.json> --ca-from-proof   # local demo only
```

---

## Marketing Site

The marketing site lives entirely in `public/`. No build step, no bundler.

```
public/index.html        All HTML + CSS + JS (~600 lines each section)
public/passport-crypto.js  Pure ES module: Ed25519 sign/verify for the playground
public/favicon.svg       Terracotta weathervane mark
public/og.svg            Open Graph share card (1200×630)
```

Serve it with any static file server (`npx serve public` or `python3 -m http.server 8080 --directory public`). The `index.html` references Three.js from cdnjs, lazy-loaded when the *How It Works* section scrolls into view. `passport-crypto.js` is loaded as `<script type="module">` — requires HTTP, not `file://`.

`docs/website.md` documents the site architecture and the `passport-crypto.js` module API.

---

## Open Work

**Operational**
- Integration/e2e test layer for HTTP routes (Hono test client or supertest)
- `DATABASE_URL` must be set; no fallback to SQLite in dev — consider restoring SQLite for local dev iteration
- Webhook retry scheduler uses an in-process timer; needs an external job runner for multi-instance deployments
- OCSP responses have no ETagger or conditional-GET support

**Security**
- Agent registration needs workload attestation before production (TPM, k8s projected tokens, SPIRE)
- `POST /v1/companies` needs an admin gate
- `VANE_MASTER_KEY` derivation should use HKDF or a KMS, not a raw env var
- `verifyJwtSvid` is the only verifier that throws instead of returning a result type — consider aligning it with `verifyPassport`'s return-type pattern

**SDK / packages**
- `VaneClient.attest()` still passes `companyId` in the body (redundant; server ignores it for auth but embeds it in the payload)
- No `package.json` `engines` field for the integration packages (`langchain`, `crewai`)

**Features**
- Conformance vectors cover the passport verifier; no equivalent vectors for the `XORG+JWT` cross-org verifier or the RFC 8693 delegation chain verifier
- `verifyProof` CLI (`scripts/verify-proof.ts`) has no companion test; it's exercised manually
- The Terraform provider (see git log) exists but its state relative to the current API is unknown
