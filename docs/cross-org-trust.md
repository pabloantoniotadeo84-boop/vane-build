# Cross-Org Trust: How Vane Handles Agents Calling Across Organizational Boundaries

## The Problem

SPIFFE was designed for workloads running inside one organization's infrastructure.
Every SPIFFE workload identity (SVID) is issued and verified within a single
*trust domain* — `spiffe://acme.vane.build/...` for Acme, `spiffe://exa.vane.build/...`
for Exa. That model works well when all participants trust the same root CA.

But modern AI systems don't stay inside one organization's boundary. A billing agent
running on Acme's infrastructure may need to call Exa's web search MCP server to do
its job. At that point the trust model breaks:

- **Exa's MCP server has no way to know if an agent legitimately represents Acme.**
  Any program can claim to be `spiffe://acme.vane.build/company/acme/agent/billing-agent`.
- **Exa cannot call Acme's identity provider** to verify the claim at request time —
  it would add latency, require network access, and tightly couple Exa's uptime to
  Acme's infrastructure.
- **A standard SPIFFE SVID won't work** because it is signed by Acme's CA, and Exa
  has no standing relationship with that CA.

The SPIFFE specification defines a *federation* protocol for this (SPIFFE Federation),
but it requires Exa to formally federate with every organization whose agents it wants
to accept — impractical at scale where hundreds of different companies' agents might
call your MCP server.

---

## How Vane Solves It: Cross-Org Delegation Tokens

Vane introduces a second token type, `XORG+JWT`, that carries all the information
needed to cross an organizational boundary while staying offline-verifiable.

A cross-org delegation token is a standard EdDSA JWT signed by **Company A's
private key** (the originating organization) that contains:

| Claim | What it says |
|---|---|
| `sub` | The agent's SPIFFE ID — who is calling |
| `vane_xorg.originOrg` | Company A — who authorized this call |
| `vane_xorg.originOrgSpiffeId` | Company A's SPIFFE identity |
| `vane_xorg.targetOrg` | Company B — the only org this token is valid at |
| `vane_xorg.targetOrgSpiffeId` | Company B's SPIFFE identity |
| `vane_xorg.scopes` | What the agent is allowed to do at Company B's server |
| `vane_xorg.delegationChain` | Full chain: `[orgSpiffeId, agentSpiffeId]` |
| `exp` | Expiry — maximum 15 minutes after issuance |

The token is signed by Company A's private key and can be verified by **anyone who
holds Company A's CA public key**. That key is published openly at:

```
GET /v1/ca/public-key?companyId=<companyId>
```

No federation setup. No runtime callbacks to Vane. Exa fetches Acme's public key
once, caches it, and verifies any `XORG+JWT` from Acme's agents entirely offline.

---

## Worked Example: Acme's Billing Agent Calls Exa's Search MCP Server

### Cast

- **Acme**: company using Vane for agent attestation. Trust domain: `vane.local` (or `acme.vane.build` in production).
- **Exa**: MCP server provider. Exa's server has `@vane.build/mcp-middleware` installed.
- **billing-agent**: Acme's AI agent that needs to search the web.

### Step 1 — Acme registers their agent (one time)

```bash
# Acme creates their company and a billing-agent
POST /v1/companies         { "companyId": "acme" }
POST /v1/agents/register   { "agentId": "billing-agent" }
# → agent's SPIFFE ID: spiffe://vane.local/company/acme/agent/billing-agent
```

### Step 2 — Exa configures their middleware (one time)

Exa installs `@vane.build/mcp-middleware` and configures it to accept cross-org tokens:

```typescript
const vane = createVaneMiddleware({
  vanePublicKey: exaPublicKey,  // Exa's own key, for regular Exa-issued passports

  // Accept XORG+JWT tokens from external organizations:
  expectedTargetOrg: 'exa',   // Reject tokens targeting any other org
  resolveCrossOrgPublicKey: async (originOrg) => {
    // Fetch and cache the originating org's CA public key.
    // In production: cache with a ~1h TTL keyed by originOrg.
    const res = await fetch(`https://api.vane.build/v1/ca/public-key?companyId=${originOrg}`);
    const { pem } = await res.json();
    return pem;
  },
});
```

This is the only configuration change Exa needs. They never need to call Acme's
servers at request time.

### Step 3 — Acme's billing-agent gets a cross-org token before calling Exa

When the billing-agent is about to call Exa's search tool, it first requests a
cross-org delegation token from Vane:

```bash
POST /v1/token/cross-org
Authorization: Bearer <acme-api-key>

{
  "agentId":   "billing-agent",
  "targetOrg": "exa",
  "scopes":    ["tool:search"],
  "ttl":       300
}
```

Vane responds with a signed `XORG+JWT` token:

```json
{
  "token":              "<signed XORG+JWT>",
  "originOrg":          "acme",
  "targetOrg":          "exa",
  "agentSpiffeId":      "spiffe://vane.local/company/acme/agent/billing-agent",
  "delegationChain":    ["spiffe://vane.local/company/acme", "spiffe://vane.local/company/acme/agent/billing-agent"],
  "scopes":             ["tool:search"],
  "expiresIn":          300
}
```

The token is signed with Acme's Ed25519 private key.

### Step 4 — The agent presents the token to Exa's MCP server

The billing-agent calls Exa's MCP server, passing the `XORG+JWT` as a Bearer token:

```bash
POST https://mcp.exa.ai/
Authorization: Bearer <XORG+JWT>
Content-Type: application/json

{
  "method": "tools/call",
  "params": { "name": "search", "arguments": { "query": "..." } }
}
```

### Step 5 — Exa's middleware verifies the token entirely offline

When the middleware receives the request:

1. **Peek at the token header** — sees `"typ": "XORG+JWT"`. This is a cross-org token.
2. **Read `vane_xorg.originOrg`** from the unverified payload — `"acme"`.
3. **Call `resolveCrossOrgPublicKey("acme")`** — returns Acme's SPKI PEM (from cache or a fresh fetch).
4. **Verify the Ed25519 signature** using Acme's public key. Tampered or forged tokens fail here.
5. **Check `exp`** — token was issued ≤ 5 minutes ago. Expired tokens fail here.
6. **Check `vane_xorg.targetOrg === "exa"`** — token was scoped to this server. Tokens issued for Stripe won't work here.
7. **Check `vane_xorg.scopes` covers `"tool:search"`** — the specific tool being called.
8. **Attach the `AttestationReceipt`** and forward the request to the search handler.

No network calls to Vane. No round-trip to Acme. Total added latency: ~0 ms after key cache warms.

### What Exa's handler receives

After the middleware passes, the request's `x-vane-receipt` header contains a
base64url-encoded `AttestationReceipt`:

```json
{
  "v": 1,
  "type": "VaneAttestationReceipt",
  "passportId": "uuid-of-this-token",
  "agentId": "billing-agent",
  "agentSpiffeId": "spiffe://vane.local/company/acme/agent/billing-agent",
  "org": "acme",
  "orgSpiffeId": "spiffe://vane.local/company/acme",
  "tool": "search",
  "scopeGranted": "tool:search",
  "delegationChain": [
    "spiffe://vane.local/company/acme",
    "spiffe://vane.local/company/acme/agent/billing-agent"
  ],
  "crossOrg": {
    "targetOrg": "exa",
    "targetOrgSpiffeId": "spiffe://vane.local/company/exa"
  },
  "verifiedAt": "2026-06-03T19:00:00.000Z"
}
```

The `crossOrg` field distinguishes this from a regular same-org passport.

---

## Security Properties

### What an attacker cannot do even if they intercept a cross-org token

| Attacker capability | Why it fails |
|---|---|
| Replay the same token at a different MCP server | `targetOrg` is bound into the signature; `expectedTargetOrg` check rejects mismatches |
| Replay the token after 15 minutes | `exp` is enforced; tokens older than `CROSS_ORG_MAX_TTL` (900 s) are always rejected |
| Forge a token claiming to be from Acme | Requires Acme's private key, which never leaves Vane's database |
| Strip the scope constraint and call any tool | `scopes` is signed; middleware verifies each tool call against them |
| Extend the delegation chain to add extra actors | `delegationChain` is signed; verification checks `chain.at(-1) === sub` |
| Present an `XORG+JWT` as a regular passport | `typ: "XORG+JWT"` fails `verifyPassport`'s `WRONG_TOKEN_TYPE` check |
| Present a regular passport as a cross-org token | `typ: "CAP+JWT"` fails `verifyCrossOrgToken`'s `WRONG_TOKEN_TYPE` check |

### What the 15-minute TTL cap achieves

Cross-org tokens have a much shorter maximum TTL than regular passports (15 minutes
vs. 1 hour). The reasoning:

- **Interception risk is higher** for tokens that cross network boundaries between
  organizations. A shorter window limits the damage window.
- **Revocation is harder cross-org** — Exa has no real-time visibility into Acme's
  revocation list. Short TTLs make revocation less critical.
- **Agents can re-request tokens cheaply** — the `POST /v1/token/cross-org` call is
  fast and happens at most once every 15 minutes per agent-to-org pair.

---

## The Trust Model: Why Exa Doesn't Need to Call Vane's Servers

The cross-org trust model has three layers:

### Layer 1 — Vane is the root of trust for key publication

Exa trusts that `GET /v1/ca/public-key?companyId=acme` returns the legitimate public
key for Acme. This is the only connection to Vane, and it can be:
- Cached for hours (the key only changes on key rotation)
- Pre-loaded at startup
- Fetched lazily and cached per org

If Vane's key endpoint is compromised, an attacker could serve a different key and
issue fraudulent tokens for Acme. This is the same trust model as HTTPS certificate
authorities — the CA is trusted to serve correct public keys.

### Layer 2 — Ed25519 signatures are unforgeable without the private key

Once Exa has Acme's public key (from Layer 1), it can verify any token Acme signed
without calling anything. The math is:

```
valid = Ed25519.verify(
  key   = acme_public_key,
  msg   = base64url(header) + "." + base64url(payload),
  sig   = base64url(token.signature),
)
```

An attacker who does not have Acme's private key cannot produce a valid signature.
Node.js's `node:crypto` module implements this using libssl.

### Layer 3 — Claims are bound into the signature

Every field in the token — `targetOrg`, `scopes`, `exp`, `delegationChain` — is
part of the signed payload. Changing any field after issuance invalidates the
signature. There is no way to extend a scope or retarget a token without
re-signing it, which requires the private key.

### What Exa can assert after verification

When the middleware succeeds, Exa's handler can assert with cryptographic confidence:

1. **This token was issued by Vane on behalf of Acme.** (Ed25519 signature over Acme's key)
2. **The agent is `billing-agent` in Acme's organization.** (delegationChain)
3. **This token was issued specifically to be presented to Exa.** (targetOrg check)
4. **The token is not older than 15 minutes.** (exp check)
5. **The agent was authorized to call `tool:search`.** (scope check)

Exa does not need to trust anything Acme says in-band — all trust flows from the
cryptographic proof in the token itself.

---

## `SPIFFE_TRUST_DOMAIN` and Multi-Trust-Domain Deployments

By default, all SPIFFE IDs in Vane use `vane.local` as the trust domain:
```
spiffe://vane.local/company/acme/agent/billing-agent
```

In production, set `SPIFFE_TRUST_DOMAIN` to your own domain:
```bash
SPIFFE_TRUST_DOMAIN=acme.vane.build
```

Vane now issues:
```
spiffe://acme.vane.build/company/acme/agent/billing-agent
```

For cross-org tokens between organizations with different trust domains
(e.g., Acme uses `acme.vane.build` and Exa uses `exa.vane.build`), the
verification path is identical — Exa fetches Acme's public key from Vane's
discovery endpoint regardless of which trust domain Acme uses.

Full SPIFFE federation (where trust domains federate at the control-plane level)
is out of scope for this implementation. Cross-org delegation tokens provide
the same practical result — an agent from one org can be cryptographically
verified by another org — without the operational overhead of federation.

---

## API Reference

### `POST /v1/token/cross-org`

Issues a cross-org delegation token for an agent in the authenticated company.

**Request**
```json
{
  "agentId":           "billing-agent",
  "targetOrg":         "exa",
  "targetOrgSpiffeId": "spiffe://exa.vane.build/company/exa",
  "scopes":            ["tool:search"],
  "ttl":               300
}
```

- `agentId` — required; must be a registered agent in the authenticated company
- `targetOrg` — required; the organization whose MCP server will receive this token
- `targetOrgSpiffeId` — optional; defaults to `spiffe://<TRUST_DOMAIN>/company/<targetOrg>`
- `scopes` — required; non-empty array of scope strings
- `ttl` — optional; defaults to 900 (15 minutes); cannot exceed 900

**Response `201`**
```json
{
  "token":              "<XORG+JWT>",
  "originOrg":          "acme",
  "originOrgSpiffeId":  "spiffe://vane.local/company/acme",
  "targetOrg":          "exa",
  "targetOrgSpiffeId":  "spiffe://vane.local/company/exa",
  "agentId":            "billing-agent",
  "agentSpiffeId":      "spiffe://vane.local/company/acme/agent/billing-agent",
  "delegationChain":    [...],
  "scopes":             ["tool:search"],
  "caPublicKey":        "<SPKI PEM>",
  "expiresIn":          300
}
```

The `caPublicKey` field is Acme's current CA public key — include it in your
cache pre-warming logic so Exa doesn't need a round-trip to discover it.

### `createVaneMiddleware` — cross-org options

```typescript
const vane = createVaneMiddleware({
  vanePublicKey: exaOwnPublicKey,

  // Cross-org support
  expectedTargetOrg: 'exa',
  resolveCrossOrgPublicKey: async (originOrg: string) => {
    // Return the SPKI PEM for the originating org's CA key, or null to reject.
    // Cache this aggressively — the key only changes on key rotation.
    return keyCache.get(originOrg) ?? fetchFromVane(originOrg);
  },
});
```

`verifyAsync(token, { tool })` — the async verify method handles both `CAP+JWT`
passports and `XORG+JWT` cross-org tokens. Use this when you need to verify a
token outside of a request context and the token type might be either.
