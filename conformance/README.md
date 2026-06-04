# Vane Agent Passport — Conformance Suite

This directory is the **normative specification** of the Vane Agent Passport
verification protocol. It is written so that a developer at a third-party
company can implement a byte-for-byte compatible verifier **without reading any
Vane server source code**.

It contains:

| File | Purpose |
|---|---|
| `README.md` | This document — the protocol specification. |
| `reference-verifier.ts` | A self-contained reference verifier (Node built-ins only). Read this as executable spec; port it to your language. |
| `vectors.json` | ≥ 10 conformance test vectors. Run your verifier against these; it conforms if it produces the recorded result for every vector. |
| `generate-vectors.ts` | The generator that produced `vectors.json`. For maintainers. |

The Vane test suite (`tests/conformance.test.ts`) runs every vector through
**both** the production verifier (`src/passport/verify.ts`) and the reference
verifier here, and fails if they disagree on any vector — so this spec and the
implementation cannot silently drift apart.

---

## 1. What a Vane passport is

A **Vane Agent Passport** is a short-lived, offline-verifiable credential that
proves an AI agent is authorized — by an organization, through an explicit
delegation chain — to perform actions. It is a standard **EdDSA JWT** with a
Vane-specific token type (`CAP+JWT`) and a namespaced `vane` claim object.

The defining property is **offline verification**: a recipient (e.g. an MCP
server) needs only

1. the raw passport string, and
2. the Vane CA's Ed25519 **public** key (published once, pinned),

to fully verify the credential. No network call to Vane is required on the hot
path. (Revocation is the one optional online add-on — see §6.)

---

## 2. Token structure

A passport is JWS compact serialization — three base64url segments joined by `.`:

```
base64url(header) "." base64url(payload) "." base64url(signature)
```

### 2.1 Header

```json
{ "alg": "EdDSA", "typ": "CAP+JWT", "kid": "<16 hex chars>" }
```

| field | rule |
|---|---|
| `alg` | MUST be `"EdDSA"`. `"none"`, missing, or any other value MUST be rejected. |
| `typ` | MUST be `"CAP+JWT"`. This separates passports from SVIDs (`"JWT"`) and cross-org tokens (`"XORG+JWT"`). |
| `kid` | First 16 hex chars of `SHA-256(SPKI-DER(publicKey))`. Informational — used to select among rotated keys. Verifiers are not required to check it. |

### 2.2 Payload (claims)

```json
{
  "iss": "spiffe://vane.local/ca",
  "sub": "spiffe://vane.local/company/acme/agent/agent-7",
  "aud": ["vane:passport:v1"],
  "jti": "89925f4a-ef5a-48dd-a0e4-4d81f0568559",
  "iat": 1750000000,
  "exp": 1750003600,
  "nbf": 1750000000,
  "vane": {
    "v": 1,
    "agentId": "agent-7",
    "org": "acme",
    "orgSpiffeId": "spiffe://vane.local/company/acme",
    "scopes": ["tool:search", "data:read"],
    "delegationChain": [
      "spiffe://vane.local/company/acme",
      "spiffe://vane.local/company/acme/agent/agent-7"
    ]
  }
}
```

#### Standard JWT claims

| claim | type | required | meaning / rule |
|---|---|---|---|
| `iss` | string | **yes** | Issuing Vane CA, a SPIFFE ID. MUST match `^spiffe://[^/]+/.+$`. |
| `sub` | string | **yes** | Subject agent's SPIFFE ID. Same regex. |
| `aud` | string[] | **yes** | MUST contain the protocol audience `"vane:passport:v1"`. |
| `exp` | number | **yes** | Expiry, Unix seconds. |
| `nbf` | number | optional | Not-before, Unix seconds. Checked only when present. |
| `iat` | number | issued | Issued-at. Not checked by verifiers. |
| `jti` | string | **yes** | Unique passport ID (UUIDv4). The **revocation key**. |

#### `vane` object

| field | type | required | meaning / rule |
|---|---|---|---|
| `v` | number | **yes** | Schema version. This spec defines `1`. Unknown versions MUST be rejected. |
| `scopes` | string[] | **yes** | Non-empty. Authorization scopes (see §4). |
| `delegationChain` | string[] | **yes** | Non-empty. `[orgSpiffeId, …, agentSpiffeId]`. The **tail MUST equal `sub`**. |
| `agentId` | string | issued | Human-readable agent id. Informational — not validated by verifiers. |
| `org` | string | issued | Issuing org name. Informational. |
| `orgSpiffeId` | string | issued | Issuing org SPIFFE ID. Informational. |
| `delegationId` | string | optional | `jti` of the RFC 8693 token this passport derived from. Informational. |
| `nonce` | string (32 hex) | optional | Sender constraint — see §5. |
| `aud` | string | optional | Per-deployment recipient audience — see §5. **Distinct from the top-level `aud` array.** |
| `requestHash` | string (64 hex) | optional | Request binding — see §5. |

> The fields marked *informational* are carried for auditing and copied into the
> attestation receipt, but a conforming verifier does **not** reject a passport
> based on their contents.

---

## 3. The signing algorithm (read this carefully)

The signature is **Ed25519** (PureEdDSA, no pre-hash) over the **ASCII bytes**
of the first two token segments, exactly as transmitted:

```
signingInput = base64url(header) + "." + base64url(payload)
signature    = Ed25519_Sign(privateKey, ASCII(signingInput))
token        = signingInput + "." + base64url(signature)
```

Issuance produces each segment as `base64url(JSON.stringify(object))`.

> ### ⚠️ Passports are NOT canonicalized (no JCS / RFC 8785)
>
> Vane uses JCS canonicalization for **attestation record hashing**, but **not**
> for passports. A passport signature covers the **literal transmitted
> base64url text** of the header and payload. Therefore a verifier MUST:
>
> - split the received token on `.`,
> - verify the signature over the substring `headerB64 + "." + payloadB64`
>   **exactly as received**, and
> - **never** re-serialize or re-canonicalize the decoded JSON before verifying.
>
> Re-serializing (e.g. sorting keys) will change the bytes and break otherwise
> valid signatures. Decode the JSON only to *read* claim values after the
> signature has been verified.

---

## 4. Scope format and matching

Scopes are `category:name` strings. A granted scope `g` covers a requested
scope `r` when:

| granted | covers |
|---|---|
| `*` | any `r` |
| `cat:*` | any `r` that starts with `cat:` |
| `cat:x` | exactly `cat:x` |

When a verifier is asked to authorize a tool call for tool `T`, it forms the
requested scope `tool:T` and requires that **some** granted scope covers it;
otherwise `SCOPE_DENIED`. When no tool is requested, verification returns the
first (broadest) granted scope as `scopeGranted`.

---

## 5. Sender constraints (optional, defeat bearer replay)

A passport may bind itself to a single use. Each constraint is independent.

| constraint | claim | gating | failure |
|---|---|---|---|
| Nonce | `vane.nonce` (32 hex) | **caller-gated** — enforced only when the verifier supplies `expectedNonce` | absent → `MISSING_NONCE`; differs → `NONCE_MISMATCH` |
| Recipient audience | `vane.aud` (string) | **caller-gated** — enforced only when the verifier supplies `expectedAudience` | absent → `MISSING_AUDIENCE`; differs → `AUDIENCE_MISMATCH` |
| Request binding | `vane.requestHash` (64 hex) | **claim-gated** — enforced whenever the claim is present | present but verifier has no `expectedRequestHash`, or mismatch → `REQUEST_MISMATCH` (fail closed) |

The asymmetry matters: a missing nonce/audience is only a problem if the
verifier *asked* for it, but a request-bound passport asserts it is valid for
exactly one request, so any verifier MUST honor `requestHash` or reject.

The request hash is computed as:

```
requestHash = SHA-256_hex( METHOD + "|" + url + "|" + SHA-256_hex(body) )
```

with `METHOD` upper-cased and `body` the empty string when there is none.

---

## 6. Revocation (separate from cryptographic verification)

**The cryptographic + claims verification never consults a revocation list.**
Revocation is a distinct step layered on top, performed **after** a passport is
otherwise valid (i.e. after the scope check):

1. Run the offline verification (§7). If it fails, return that failure.
2. If it succeeds, test the passport's `jti` against the set of revoked IDs.
   If present, the final result is `PASSPORT_REVOKED`.

Vane exposes the revoked set at `GET /v1/passports/revoked` (returns `{ revoked:
[{ jti, revokedAt, reason? }] }`) and per-passport status at `GET /v1/ocsp/:jti`.
Because fetching this list requires a network call, it is a **defense-in-depth**
measure: the *primary* containment is short TTLs (passports are capped at 1 hour),
so an expired passport is always rejected regardless of list availability. Cache
the list with a short TTL (e.g. 60 s) matched to your risk tolerance.

The reference verifier accepts the revoked set directly via `revokedJtis` and
performs the check as its final step, so the vectors can exercise it offline.

---

## 7. Verification algorithm (normative, in order)

Let `leeway` be the clock-skew leeway in seconds. Default **30**. A negative
value is a configuration error and MUST throw (not return a DENY). Let `now` be
the current Unix time (overridable for testing).

1. **Parse.** Split the token on `.`. Exactly 3 segments, else `MALFORMED_TOKEN`.
   base64url-decode segments 1 and 2 and `JSON.parse` them, else `MALFORMED_TOKEN`.
2. **Algorithm.** `header.alg` MUST be `"EdDSA"` (reject missing / `"none"` /
   other) → `ALGORITHM_MISMATCH`.
3. **Token type.** `header.typ` MUST be `"CAP+JWT"` → `WRONG_TOKEN_TYPE`.
4. **Signature.** The CA key MUST be Ed25519. Verify the signature over the
   ASCII bytes `seg1 + "." + seg2` (as received). Failure → `SIGNATURE_INVALID`.
5. **Expiry.** `exp` MUST be a number and `exp + leeway ≥ now` → else `TOKEN_EXPIRED`.
6. **Not-before.** If `nbf` is a number and `nbf − leeway > now` → `TOKEN_NOT_YET_VALID`.
7. **Protocol audience.** `aud` MUST be an array containing `"vane:passport:v1"`
   → else `AUDIENCE_MISMATCH`.
8. **Issuer.** `iss` MUST match `^spiffe://[^/]+/.+$` → else `INVALID_ISSUER`.
9. **Subject.** `sub` MUST match the same pattern → else `INVALID_SUBJECT`.
10. **Vane claims.** `vane` MUST be a non-array object → else `MALFORMED_CLAIMS`.
11. **Version.** `vane.v` MUST be in `{1}` → else `UNSUPPORTED_VERSION`.
12. **Shape.** `vane.scopes` and `vane.delegationChain` MUST be non-empty arrays
    → else `MALFORMED_CLAIMS`.
13. **Chain coherence.** `delegationChain.at(-1)` MUST equal `sub`
    → else `CHAIN_INCOHERENT`.
14. **Nonce** (if `expectedNonce` supplied) → `MISSING_NONCE` / `NONCE_MISMATCH`.
15. **Recipient audience** (if `expectedAudience` supplied) → `MISSING_AUDIENCE`
    / `AUDIENCE_MISMATCH`.
16. **Request binding** (if `vane.requestHash` present) → `REQUEST_MISMATCH`.
17. **Scope** (if a tool was requested) → `SCOPE_DENIED`; otherwise `scopeGranted`
    is the first granted scope.
18. **Revocation** (if a revoked set is available; §6) → `PASSPORT_REVOKED`.

Any unexpected exception during steps 1–18 MUST resolve to a single fail-closed
result with code `VERIFICATION_ERROR` — it must never escape as an undefined or
throw to the caller (except the negative-leeway configuration error above).

### Error codes

```
MALFORMED_TOKEN  ALGORITHM_MISMATCH  WRONG_TOKEN_TYPE  SIGNATURE_INVALID
TOKEN_EXPIRED    TOKEN_NOT_YET_VALID AUDIENCE_MISMATCH MISSING_NONCE
NONCE_MISMATCH   MISSING_AUDIENCE    REQUEST_MISMATCH  INVALID_ISSUER
INVALID_SUBJECT  UNSUPPORTED_VERSION MALFORMED_CLAIMS  CHAIN_INCOHERENT
SCOPE_DENIED     PASSPORT_REVOKED    VERIFICATION_ERROR
```

A successful verification returns `{ valid: true, claims, scopeGranted }`.
A failure returns `{ valid: false, code, error }` where `code` is one of the above.

---

## 8. The test vectors

`vectors.json` has the shape:

```jsonc
{
  "description": "...",
  "protocol": { "tokenType": "CAP+JWT", "algorithm": "EdDSA …", … },
  "vectorCount": 22,
  "vectors": [
    {
      "name": "valid-passport",
      "description": "A well-formed, in-window passport that must verify.",
      "token": "<raw CAP+JWT string>",
      "inputs": {
        "caPublicKey": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
        "now": 1750000060,
        "tool": "search",                 // optional
        "expectedNonce": "…",             // optional
        "expectedAudience": "…",          // optional
        "expectedRequestHash": "…",       // optional
        "clockSkewSeconds": 30,           // optional
        "revokedJtis": ["…"]              // optional
      },
      "expected": { "valid": true, "scopeGranted": "tool:search" }
      // or, on failure:
      // "expected": { "valid": false, "code": "TOKEN_EXPIRED" }
    }
  ]
}
```

Notes for implementers:

- **Every time claim is pinned** to a fixed reference epoch and **every vector
  carries an explicit `now`**. Feed `inputs.now` to your verifier so results are
  reproducible forever; the vectors never expire.
- `caPublicKey` is the trust anchor for that vector. For the `bad-signature`
  vector it is the genuine CA key (the token was signed with a different key on
  purpose).
- `revokedJtis`, when present, is the revoked set your verifier should apply in
  the revocation step (§6).
- A vector with `expected.valid === true` records the `scopeGranted` your
  verifier must return; a failing vector records the exact `code`.

### Required scenarios (all present)

| vector | result |
|---|---|
| `valid-passport` | verifies |
| `expired-passport` | `TOKEN_EXPIRED` |
| `bad-signature` | `SIGNATURE_INVALID` |
| `tampered-payload` | `SIGNATURE_INVALID` |
| `wrong-audience` | `AUDIENCE_MISMATCH` |
| `nonce-correct` / `nonce-mismatch` | verifies / `NONCE_MISMATCH` |
| `nbf-in-future` | `TOKEN_NOT_YET_VALID` |
| `invalid-delegation-chain` | `CHAIN_INCOHERENT` |
| `cross-org-valid` | verifies |
| `revoked-passport` | `PASSPORT_REVOKED` |

Plus extra coverage: `valid-with-tool`, `valid-wildcard-scope`,
`wrong-protocol-audience`, `missing-nonce`, `unsupported-version`, `alg-none`,
`wrong-token-type`, `malformed-token`, `scope-denied`, `request-bound-match`,
`request-bound-unbound-verifier`.

> **About `cross-org-valid`:** a cross-org delegation is expressed as an ordinary
> `CAP+JWT` passport whose `delegationChain` originates in a different
> organization than the subject (`[globex, acme, acme-agent]`). It is coherent
> (tail == `sub`) and verifies under the standard rules. (Vane also has a
> separate `XORG+JWT` token type for tokens signed by the *originating* org's
> key; that is out of scope for the passport verifier specified here.)

---

## 9. Running it

```bash
# Verify the reference verifier and production verifier agree on every vector:
npx vitest run tests/conformance.test.ts

# Regenerate vectors.json (maintainers; produces fresh keys + signatures):
npx tsx conformance/generate-vectors.ts
```

To validate **your own** verifier: load `vectors.json`, and for each vector call
your verifier with `inputs` and compare against `expected`. You conform when you
produce the recorded `valid`/`code`/`scopeGranted` for all of them.
