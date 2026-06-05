# VANE

**Cryptographic identity for AI agents.**

[![npm version](https://img.shields.io/npm/v/@vane.build/sdk)](https://www.npmjs.com/package/@vane.build/sdk)
[![npm downloads](https://img.shields.io/npm/dw/@vane.build/sdk)](https://www.npmjs.com/package/@vane.build/sdk)
[![CI](https://github.com/vane-build/vane/actions/workflows/ci.yml/badge.svg)](https://github.com/vane-build/vane/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Vane issues signed **Agent Passports** — Ed25519 credentials that prove which agent took an action, who authorized it, and what it was allowed to do. Every action is appended to a Merkle-backed attestation chain. Passports verify offline with only a public key: no call to Vane on the hot path.

---

## Installation

```bash
npm install @vane.build/sdk
```

---

## Quick start

```typescript
import { VaneClient } from '@vane.build/sdk';

const vane = new VaneClient({
  baseUrl: 'https://api.vane.build',
  apiKey: process.env.VANE_API_KEY!,
});

// Attest an action — returns a signed, indexed record
const record = await vane.attest(
  'agent-1',          // agentId
  'acme',             // companyId
  'data-query',       // actionType
  {
    query: 'SELECT * FROM contracts WHERE status = ?',
    params: ['pending'],
    database: 'contracts-prod',
  },
);

console.log(record);
// {
//   index: 42,
//   timestamp: "2026-06-05T14:23:11.000Z",
//   payload: { agentId: "agent-1", companyId: "acme", actionType: "data-query", payload: { ... } },
//   hash: "f651a3b2...",
//   signature: "vdv-nC4rY..."
// }

// Retrieve a Merkle inclusion proof for any record
const proof = await vane.getProof(42);

console.log(proof.root);
// "a3f9e2c1..."  — verifiable against any saved root snapshot
```

### Issuing and verifying a passport

Passports are issued server-side and verified offline at the tool boundary. The verifier needs only the CA public key — no network call.

```typescript
import { verifyPassport } from '@vane.build/mcp-middleware';

// Issued by POST /v1/agents/:id/passport on your Vane instance.
// The agent presents this token as a Bearer credential to MCP tools.
const passport = '<CAP+JWT from your Vane instance>';

// Fetch the CA public key once: GET /v1/ca/public-key
const caPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----`;

const result = verifyPassport(passport, { caPublicKey, tool: 'query-contracts' });

if (result.valid) {
  console.log(result.claims.vane);
  // {
  //   v: 1,
  //   agentId: "agent-1",
  //   org: "acme",
  //   orgSpiffeId: "spiffe://vane.local/company/acme",
  //   scopes: ["tool:query-contracts"],
  //   delegationChain: [
  //     "spiffe://vane.local/company/acme",
  //     "spiffe://vane.local/company/acme/agent/agent-1"
  //   ]
  // }
} else {
  console.error(result.code, result.error);
  // e.g. "TOKEN_EXPIRED", "Passport has expired"
}
```

---

## What a passport proves

A Vane Agent Passport (type `CAP+JWT`) is a standard EdDSA JWT. Every verifier checks these claims in order:

| Claim | What it proves |
|---|---|
| `sub` | The agent's SPIFFE workload identity (`spiffe://trust-domain/company/org/agent/id`) |
| `iss` | Which Vane CA instance signed this passport |
| `exp` / `nbf` | Passport is time-bounded (5 min – 1 hour TTL) |
| `vane.org` | The organization that authorized this agent |
| `vane.delegationChain` | The full authorization path from org root to this agent |
| `vane.scopes` | What the agent is allowed to do (`tool:*`, `tool:query-contracts`, etc.) |
| `vane.delegationId` | Links this passport to the RFC 8693 token that authorized it |
| `vane.nonce` | Optional: caller-bound 128-bit value — defeats bearer replay |
| `vane.aud` | Optional: recipient-bound audience — enforces which server accepts this token |
| `vane.requestHash` | Optional: SHA-256 of `METHOD\|url\|sha256(body)` — fail-closed request binding |

Verification is a 16-step deterministic procedure. The reference implementation and conformance test vectors are in [`conformance/`](conformance/).

---

## Framework integrations

### LangChain

```bash
npm install @vane.build/langchain
```

```typescript
import { VaneCallbackHandler } from '@vane.build/langchain';
import { ChatOpenAI } from '@langchain/openai';

const handler = new VaneCallbackHandler({ baseUrl, apiKey, agentId: 'agent-1' });
const llm = new ChatOpenAI({ callbacks: [handler] });

await llm.invoke('Summarise this contract.');
// Every LLM call and tool invocation is attested automatically.
```

### OpenAI Agents SDK

```bash
npm install @vane.build/openai-agents
```

```typescript
import { createVaneHooks } from '@vane.build/openai-agents';
import { run } from '@openai/agents';

const hooks = createVaneHooks({ baseUrl, apiKey, agentId: 'agent-1' });
await run(agent, 'Review this contract.', { hooks });
// Tool calls, agent starts/ends, and handoffs are all attested.
```

### MCP middleware

```bash
npm install @vane.build/mcp-middleware
```

```typescript
import { createVaneMiddleware } from '@vane.build/mcp-middleware';

const vane = createVaneMiddleware({ vanePublicKey: caPublicKey });

// Fetch-compatible (Hono, Next.js Edge, Cloudflare Workers)
const handler = vane.fetchMiddleware();

// Express / Connect
app.use(express.json());
app.use(vane.expressMiddleware());

// MCP SDK handler wrapper
server.setRequestHandler(CallToolRequestSchema, vane.mcpHandler(async (req, receipt) => {
  console.log(receipt.agentId, receipt.scopeGranted);
  return { content: [{ type: 'text', text: 'ok' }] };
}));
```

---

## Security

The cryptographic guarantees Vane provides:

- **Ed25519 signatures** — deterministic, no per-signature nonce; key-type guard runs before every `cryptoVerify` call; `alg:none` is explicitly rejected.
- **Merkle attestation** — every attestation record is hash-chained and included in a binary Merkle tree. `GET /v1/proof/:index` returns an O(log n) inclusion proof verifiable offline.
- **Signed tree heads** — `GET /v1/checkpoint` returns a signed snapshot of the current root; `GET /v1/consistency` proves append-only growth between two roots (RFC 6962 consistency proofs).
- **AES-256-GCM at rest** — company private keys are envelope-encrypted in PostgreSQL via `VANE_MASTER_KEY`.
- **Fail-closed verification** — `verifyPassport` and `verifyCrossOrgToken` never throw on bad input; every unexpected error path returns a structured `DENY` result. A thrown exception can never fall through to a grant.
- **Sender-constrained passports** — nonce, recipient audience, and request binding defeat bearer-token replay. Request binding (`vane.requestHash`) is fail-closed when asserted: a verifier that cannot prove the request hash matches is denied.
- **Key rotation grace period** — `verifyPassportMultiKey` tries the current key first, then retired keys within a configurable grace window. Passports signed before rotation remain valid; verification short-circuits on non-signature failures.
- **JCS canonical serialization** — attestation hashes cover RFC 8785 JCS bytes; no insertion-order ambiguity across implementations.

Full cryptographic specification: [docs.vane.build/security](https://docs.vane.build/security)

---

## EU AI Act compliance

Vane's append-only attestation chain and signed agent credentials address the **Article 9 risk management** and **Article 12 logging** obligations in the EU AI Act — every high-risk AI system action is recorded with a verifiable, tamper-evident audit trail tied to a named agent and authorization chain.

More detail: [docs.vane.build/eu-ai-act](https://docs.vane.build/eu-ai-act)

---

## Pricing

| Plan | Price | What's included |
|---|---|---|
| **Developer** | Free | 10k attestations/mo, 1 company, community support |
| **Startup** | $99 / month | 500k attestations/mo, 10 companies, email support, SLA |
| **Enterprise** | Custom | Unlimited, dedicated instance, mTLS, on-prem, SLA |

[vane.build#pricing](https://vane.build#pricing)

---

## Links

- [Documentation](https://docs.vane.build)
- [API Reference](https://docs.vane.build/api)
- [npm — @vane.build/sdk](https://www.npmjs.com/package/@vane.build/sdk)
- [GitHub](https://github.com/vane-build/vane)
- [vane.build](https://vane.build)
- hello@vane.build
- [Book a demo](https://cal.com/pablo-gonzalez-gl12ly2/vane-demo)

---

Built in Puerto Rico. MIT License.
