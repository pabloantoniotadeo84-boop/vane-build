# Counsel — Architecture Reference

## What This Is

Counsel is a trust and attestation layer for AI agents. Its core job is to produce a tamper-evident, cryptographically signed log of every action an agent takes, along with proof of *who* authorized that action and under what delegation. The log is auditable by third parties without trusting the server.

The three problems it solves:

1. **Action integrity** — a record of what an agent did cannot be silently altered after the fact.
2. **Identity** — agents and companies have SPIFFE workload identities tied to every record.
3. **Delegation** — an agent acting on behalf of a company carries a cryptographic proof of that authorization (who delegated to whom, through what chain) bound into the attestation record itself.

---

## File Map

```
src/
  api/
    server.ts          HTTP server entry point (port binding, nothing else)
    app.ts             All route handlers — the entire HTTP surface lives here

  crypto/
    keypair.ts         Ed25519 key pair generation (wraps node:crypto)
    signer.ts          signPayload / verifyPayload + canonicalize()
    chain.ts           AttestationChain class — the append-only log
    merkle.ts          Merkle tree: computeRoot, buildProof, verifyProof
    spiffe.ts          SPIFFE ID construction, parsing, and validation
    svid.ts            JWT-SVID issuance and verification (EdDSA)
    token-exchange.ts  RFC 8693 delegation token logic + chain extraction
    types.ts           All shared TypeScript interfaces
    index.ts           Barrel re-export of the entire crypto module

  db/
    store.ts           SQLite persistence via node:sqlite DatabaseSync

  example.ts           Standalone script demonstrating the crypto primitives

packages/
  sdk/
    src/index.ts       TypeScript client SDK (CounselClient)
    test.ts            Manual integration test for the SDK
```

---

## Tech Stack and Why

| Technology | Why it was chosen |
|---|---|
| **Node.js `node:crypto`** | Ed25519 built in since Node 12. Zero external crypto dependencies — critical for the most security-sensitive part of the system. No supply-chain risk. |
| **`node:sqlite` (DatabaseSync)** | Built into Node.js 22+. Synchronous API fits the single-process model cleanly — no async/await ceremony for DB calls. Zero external database dependency. |
| **Hono** | Lightweight, TypeScript-native HTTP framework. Fast handler dispatch, clean middleware API, works across runtimes. Much less overhead than Express. |
| **`@hono/node-server`** | Thin adapter to run a Hono `fetch`-based app on Node.js's `http.Server`. Lets Hono stay runtime-agnostic. |
| **TypeScript strict + NodeNext** | `NodeNext` module resolution enforces explicit `.js` extensions in imports, which is correct for ESM. `strict: true` catches nullability bugs. |
| **tsx** | Zero-config TypeScript execution in dev mode. No build step while iterating, no ts-node config complexity. |

---

## Database Schema

Three tables, managed by `src/db/store.ts`. The constructor runs `CREATE TABLE IF NOT EXISTS` on every startup, so the schema is self-bootstrapping.

### `keys`
```sql
CREATE TABLE keys (
  id      INTEGER PRIMARY KEY CHECK (id = 1),  -- enforces singleton
  public  TEXT NOT NULL,                        -- SPKI PEM
  private TEXT NOT NULL                         -- PKCS8 PEM
);
```
Stores the single Ed25519 key pair for this server instance. The `CHECK (id = 1)` constraint makes it physically impossible to have more than one row. Generated on first boot if absent.

### `records`
```sql
CREATE TABLE records (
  idx        INTEGER PRIMARY KEY,  -- attestation index (0-based, sequential)
  timestamp  TEXT    NOT NULL,     -- ISO 8601
  payload    TEXT    NOT NULL,     -- JSON-serialized
  delegation TEXT,                 -- JSON-serialized DelegationInfo, nullable
  hash       TEXT    NOT NULL,     -- SHA-256 hex of canonical preimage
  signature  TEXT    NOT NULL      -- Ed25519 over hash, base64url
);
```
The attestation log. `idx` is the position in the chain and is included in each record's hash preimage to prevent reordering attacks.

**Migration note**: `store.ts` runs a migration on startup that (a) drops the old `previous_hash` column if present (prior linked-list schema), and (b) adds the `delegation` column if absent (added after initial schema). This handles DBs created at any point in the project's history.

### `agents`
```sql
CREATE TABLE agents (
  agent_id      TEXT PRIMARY KEY,
  spiffe_id     TEXT NOT NULL UNIQUE,
  company_id    TEXT,               -- nullable, optional association
  registered_at TEXT NOT NULL,
  metadata      TEXT                -- JSON-serialized object, nullable
);
```
Registry of known agent workloads. `spiffe_id` uniqueness is enforced at the DB level. Registration is currently unauthenticated (see Limitations).

---

## API Endpoints

All requests and responses use `Content-Type: application/json`. The server binds to `localhost:3000` by default; override with `PORT` env var.

---

### `GET /v1/health`

Health check. Always returns 200.

```json
{ "status": "ok" }
```

---

### `POST /v1/agents/register`

Registers an agent workload and issues its initial JWT-SVID.

**Request body**
```json
{
  "agentId":   "string (required)",
  "companyId": "string (optional)",
  "metadata":  "object (optional)"
}
```

**Response 201**
```json
{
  "agentId":      "agent-1",
  "spiffeId":     "spiffe://counsel.local/agent/agent-1",
  "svid":         "<jwt>",
  "registeredAt": "2026-01-01T00:00:00.000Z"
}
```

The `spiffeId` is always `spiffe://${TRUST_DOMAIN}/agent/${encodeURIComponent(agentId)}`. `TRUST_DOMAIN` defaults to `counsel.local`; override with `SPIFFE_TRUST_DOMAIN` env var.

Uses `INSERT OR REPLACE` — re-registering an existing `agentId` overwrites the row.

---

### `GET /v1/agents/:agentId/svid`

Issues a fresh JWT-SVID for an already-registered agent. Useful for token refresh.

**Response 200**
```json
{
  "agentId":  "agent-1",
  "spiffeId": "spiffe://counsel.local/agent/agent-1",
  "svid":     "<jwt>"
}
```

Returns 404 if the agent is not registered.

---

### `POST /v1/companies/svid`

Issues a JWT-SVID for a company identity. Companies are not persisted to the DB — only agents are registered. This endpoint constructs the SPIFFE ID on the fly and issues a token.

**Request body**
```json
{ "companyId": "acme" }
```

**Response 200**
```json
{
  "companyId": "acme",
  "spiffeId":  "spiffe://counsel.local/company/acme",
  "svid":      "<jwt>"
}
```

The company SVID is the `subject_token` for the RFC 8693 exchange endpoint below.

---

### `POST /v1/token/exchange`

RFC 8693 §2 token exchange. Takes two pre-issued JWT-SVIDs and produces a delegation token encoding the full `sub`/`act` chain.

**Request body** (RFC 8693 form parameters as JSON)
```json
{
  "grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token":      "<jwt — entity being acted upon>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "actor_token":        "<jwt — the acting agent>",
  "actor_token_type":   "urn:ietf:params:oauth:token-type:jwt"
}
```

**Response 200**
```json
{
  "access_token":       "<delegation jwt>",
  "issued_token_type":  "urn:ietf:params:oauth:token-type:jwt",
  "token_type":         "N_A",
  "expires_in":         3600,
  "delegation_chain":   ["spiffe://counsel.local/company/acme", "spiffe://counsel.local/agent/agent-1"]
}
```

The issued token's claims:
- `sub` — subject's SPIFFE ID (from `subject_token`)
- `act.sub` — actor's SPIFFE ID (from `actor_token`)
- `act.act` — prior delegation chain from the subject token, if any (chain extension)
- `jti` — unique token ID

The `delegation_chain` array is ordered `[subject, proximate-actor, ..., original-actor]`.

**Chain extension** — if `subject_token` already contains an `act` claim (i.e., the subject is itself a delegation token), that chain is preserved as the inner `act.act`. This allows multi-hop delegation to be recorded faithfully.

---

### `POST /v1/token-exchange`

Simplified delegation token issuance. Instead of requiring pre-issued JWTs as inputs, this endpoint accepts raw IDs and builds the SPIFFE identities internally. Use this when you control both the agent and the company context.

**Request body**
```json
{
  "agentId":   "agent-1",
  "companyId": "acme",
  "actingOn":  "acme",
  "scope":     "attest:write"
}
```

- `agentId` — must be a registered agent; becomes `act.sub` as `spiffe://.../agent/{agentId}`
- `companyId` — validated against the agent's registered `companyId` if set; returns 403 on mismatch
- `actingOn` — the entity being acted upon; becomes `sub` as `spiffe://.../company/{actingOn}`
- `scope` — arbitrary space-separated permission string, embedded as a `scope` claim

**Response 201**
```json
{
  "token": "<signed jwt>",
  "sub":   "spiffe://counsel.local/company/acme",
  "act":   { "sub": "spiffe://counsel.local/agent/agent-1" },
  "jti":   "cb6a2a5e-21ad-4d2c-80c9-d37516f276ab",
  "scope": "attest:write"
}
```

Pass `token` as the `delegation` field in `POST /v1/attest`.

---

### `POST /v1/attest`

The core endpoint. Appends a signed, indexed record to the attestation chain.

**Request body**
```json
{
  "agentId":    "agent-1",
  "companyId":  "acme",
  "actionType": "data-query",
  "payload":    { "arbitrary": "action data" },
  "delegation": "<jwt from /v1/token-exchange or /v1/token/exchange — optional>"
}
```

All of `agentId`, `companyId`, `actionType`, and `payload` are required. `delegation` is optional.

If `delegation` is present, the server verifies the JWT (signature + expiry + audience + SPIFFE ID format), extracts the `DelegationInfo`, and includes it in the record. A tampered or expired delegation JWT returns 400.

**Response 201** — an `AttestationRecord`
```json
{
  "index":      7,
  "timestamp":  "2026-01-01T00:00:00.000Z",
  "payload":    { "agentId": "agent-1", "companyId": "acme", "actionType": "data-query", "payload": { ... } },
  "delegation": {
    "subject":         "spiffe://counsel.local/company/acme",
    "delegationChain": ["spiffe://counsel.local/company/acme", "spiffe://counsel.local/agent/agent-1"],
    "act":             { "sub": "spiffe://counsel.local/agent/agent-1" },
    "tokenId":         "cb6a2a5e-21ad-4d2c-80c9-d37516f276ab"
  },
  "hash":       "f651...",
  "signature":  "vdv-nC..."
}
```

The `delegation` field is only present when a delegation token was supplied.

---

### `GET /v1/chain`

Returns the full attestation chain in insertion order.

```json
{ "records": [ ...AttestationRecord ] }
```

---

### `GET /v1/verify`

Verifies every record's hash and signature, then computes and returns the Merkle root. O(n) over the chain length.

**Success**
```json
{ "valid": true, "merkleRoot": "a3f9..." }
```

**Failure**
```json
{ "valid": false, "failedAtIndex": 3, "error": "record 3: hash mismatch" }
```

---

### `GET /v1/proof/:index`

Returns a Merkle inclusion proof for a single record. An external auditor can verify this proof in O(log n) without possessing the full chain.

**Response 200**
```json
{
  "record": { ...AttestationRecord },
  "proof":  [
    { "sibling": "a1b2...", "position": "right" },
    { "sibling": "c3d4...", "position": "left" }
  ],
  "root": "e5f6..."
}
```

`position` is the position of the *sibling* in its pair. To re-derive the root: start from `record.hash`, hash it with each sibling in order (sibling-left means `hash(sibling + current)`, sibling-right means `hash(current + sibling)`). If the final value equals `root`, the record is included.

---

## Cryptographic Design

### Algorithm choice: Ed25519

Everything uses Ed25519 (EdDSA). Reasons:

- **No parameter choices** — unlike ECDSA, Ed25519 has no per-signature random nonce; a nonce collision in ECDSA leaks the private key. Ed25519 signatures are deterministic.
- **Compact** — 32-byte public keys, 64-byte signatures.
- **No SHA-256 ASN.1 wrapper confusion** — `cryptoSign(null, data, privateKey)` works because the algorithm is implied by the key type; there is no way to accidentally use the wrong digest.
- **Built into Node.js** — no external library.

### Key management

One Ed25519 key pair per server instance, generated on first boot and stored in the `keys` table. The key ID (`kid` in JWT headers) is derived as `SHA-256(SPKI DER)[0:16]` — stable and deterministic from the public key, suitable for use in JWT headers without storing it separately.

### Attestation record integrity

Each record's `hash` is:

```
SHA-256( index + "|" + timestamp + "|" + canonicalize(payload) [+ "|" + canonicalize(delegation)] )
```

The `index` is included to prevent an attacker from taking two authentic records and swapping their positions. The `delegation` blob is included when present, binding the authorization proof to this specific record — it cannot be stripped or swapped with a different delegation without invalidating the hash.

The `signature` field is Ed25519 over the `hash` (not over the raw preimage). Signing the hash rather than the full preimage keeps signature verification fast regardless of payload size.

### Canonical serialization

`canonicalize()` in `signer.ts` serializes any JSON-compatible value by recursively sorting object keys before encoding. This ensures the same logical object always produces the same byte string regardless of property insertion order — necessary for deterministic hashing across language runtimes or JSON parsers.

### Merkle tree

Built over all record hashes. Construction:

1. Pad leaf list to the next power of two by repeating the last leaf (standard binary Merkle padding).
2. Hash pairs bottom-up: `SHA-256(leftHash + rightHash)`.
3. The single remaining hash is the root.

This supports O(log n) inclusion proofs. The root returned by `GET /v1/verify` and `GET /v1/proof/:index` is the same value — an external auditor can verify any proof against a trusted root snapshot without downloading the full chain.

### SPIFFE JWT-SVID format

All JWTs issued by Counsel follow the SPIFFE JWT-SVID spec:

**Header**: `{ "alg": "EdDSA", "typ": "JWT", "kid": "<16-hex-char key ID>" }`

**Claims**:
```json
{
  "sub": "spiffe://counsel.local/agent/agent-1",
  "aud": ["counsel"],
  "iat": 1700000000,
  "exp": 1700003600,
  "jti": "uuid-v4",
  "act": { "sub": "spiffe://...", "act": { ... } },  // delegation tokens only
  "scope": "attest:write"                             // /v1/token-exchange tokens only
}
```

`verifyJwtSvid` checks: valid EdDSA signature, not expired, audience contains `"counsel"`, `sub` matches the SPIFFE ID pattern `^spiffe://[^/]+/.+$`.

### RFC 8693 delegation chain

The `act` claim structure (from RFC 8693 §4.4) is a recursive nested object. Index 0 of `delegationChain` is always the subject (entity being acted upon); each subsequent entry is an actor closer to the original issuer. The `exchangeToken` function in `token-exchange.ts` preserves the chain when exchanges are stacked:

```
round 1: agent-A acts on behalf of company
  → { sub: company, act: { sub: agent-A } }

round 2: sub-agent-B presents the round-1 token to act on behalf of company
  → { sub: company, act: { sub: sub-agent-B, act: { sub: agent-A } } }
```

---

## What Has Been Built

- **Crypto primitives** — Ed25519 key generation, payload signing/verification, canonical serialization
- **Attestation chain** — append-only log with indexed, hash-chained records; full-chain verification; Merkle inclusion proofs
- **SPIFFE identity** — SPIFFE ID construction for agents and companies; JWT-SVID issuance and verification
- **Delegation** — RFC 8693 token exchange (`/v1/token/exchange`) and simplified delegation issuance (`/v1/token-exchange`); delegation chain preservation across multi-hop exchanges; delegation bound cryptographically to attestation records
- **Persistence** — SQLite via `node:sqlite` DatabaseSync; schema migration for backward compatibility with older DB files
- **HTTP API** — all endpoints described above, built on Hono
- **TypeScript SDK** — `@counsel/sdk` in `packages/sdk`; ships both CJS and ESM builds; `CounselClient` with `attest()` and `getProof()` methods

---

## Known Limitations

**Security**

1. **No workload attestation on registration** — `POST /v1/agents/register` requires no proof of identity. Any caller can register as any `agentId`. Production would require node attestation (TPM measurement, k8s projected service account tokens, SPIRE agent, etc.) before issuing an SVID.

2. **API keys are ignored server-side** — The SDK sends `Authorization: Bearer <key>` on every request. The server has no auth middleware; the header is silently discarded. All endpoints are open.

3. **Private key in plaintext SQLite** — The Ed25519 private key is stored in the `keys` table as a PEM string. No HSM, no envelope encryption, no key escrow.

4. **No JWT revocation** — Issued SVIDs and delegation tokens are valid until their `exp`. There is no revocation list, no short-lived rotation, no introspection endpoint.

5. **Single trust domain** — `SPIFFE_TRUST_DOMAIN` is a single global env var. Multi-tenant deployments serving multiple trust domains are not supported.

**SDK bug** — `CounselClient.attest()` sends `delegation_token` in the request body (`packages/sdk/src/index.ts:70`), but `POST /v1/attest` expects the field to be named `delegation`. Delegation tokens sent via the SDK are silently dropped server-side.

**Operational**

6. **In-memory chain** — `AttestationChain` hydrates the full record set into memory on startup. This is fine for development but will not scale to millions of records.

7. **Merkle root is recomputed from scratch on every verify** — `chain.verify()` iterates all records O(n) and does not cache intermediate nodes. For a chain of N records, `GET /v1/verify` costs O(N).

8. **Node.js 22+ required** — `node:sqlite` with `DatabaseSync` is only available in Node.js 22 and later. This is not documented in `package.json` engines field.

9. **No key rotation** — Replacing the key pair invalidates all existing signatures. There is no mechanism to sign new records with a new key while keeping old records verifiable under the old key.

10. **No request ID or structured logging** — All errors surface as JSON `{ error: "..." }` responses. There is no correlation ID or log output from the request handlers, making it hard to trace failures in production.
