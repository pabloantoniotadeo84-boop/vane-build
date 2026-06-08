# Vane

**Cryptographic identity infrastructure for AI agents.**

Give your agents a passport. Every action signed, attested, and independently verifiable.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![npm](https://img.shields.io/npm/dw/@vane.build/mcp-middleware?label=weekly%20downloads)](https://npmjs.com/package/@vane.build/mcp-middleware)
[![docs](https://img.shields.io/badge/docs-docs.vane.build-b5451b)](https://docs.vane.build)

---

## What is Vane?

AI agents call APIs, move money, read databases, and take real-world actions. An API key proves nothing — it tells you nothing about which agent acted, who authorized it, what it was permitted to do, or whether the record can be trusted.

Vane issues **Agent Passports** — Ed25519-signed credentials that prove an agent's identity, authorization chain, and permission scope. Every action is attested to an append-only Merkle tree. Passports verify offline with only a public key. No trust in Vane's servers required.

## Three lines of code

```typescript
import { VaneClient } from '@vane.build/sdk'

const vane = new VaneClient({ baseUrl, apiKey, agentId })
await vane.attest('financial_transfer', payload)
```

Works with LangChain, OpenAI Agents SDK, MCP, and any HTTP framework via middleware or sidecar.

## How it works

1. **Register** your agent and receive an API key
2. **Issue** a passport — a signed JWT containing the agent's identity, delegation chain, and permission scopes
3. **Attest** every action to an append-only Merkle tree with RFC 6962 signed tree heads
4. **Verify** any passport or inclusion proof offline, with only Vane's CA public key — no network call, no trust in Vane's infrastructure

Any third party holding the CA public key can verify any action, at any time, without trusting Vane.

## This repository

This is Vane's API server — the infrastructure that issues passports and maintains the global attestation log. It is not the SDK.

**Stack:** Node.js + TypeScript · Hono · PostgreSQL · Ed25519 · RFC 6962 Merkle tree · Railway

## npm packages

| Package | Description |
|---|---|
| [`@vane.build/sdk`](https://npmjs.com/package/@vane.build/sdk) | Core client |
| [`@vane.build/mcp-middleware`](https://npmjs.com/package/@vane.build/mcp-middleware) | Hono / Express / MCP passport validation middleware |
| [`@vane.build/langchain`](https://npmjs.com/package/@vane.build/langchain) | LangChain integration |
| [`@vane.build/openai-agents`](https://npmjs.com/package/@vane.build/openai-agents) | OpenAI Agents SDK integration |
| [`@vane.build/sidecar`](https://npmjs.com/package/@vane.build/sidecar) | Zero-SDK-change sidecar proxy |

## Getting started

```bash
git clone https://github.com/vane-build/vane.git
cd vane
npm install
cp .env.example .env    # fill in DATABASE_URL and signing key config
npm run dev
```

Full setup, environment variables, and API reference at **[docs.vane.build](https://docs.vane.build)**.

## Security

- Fail-closed verification across all authentication and authorization paths
- Sender-constrained passports — nonce binding, audience enforcement, optional request binding
- JCS (RFC 8785) canonical serialization for all signed bytes
- Clock-skew leeway and `nbf` enforcement across all five verifiers
- Rate limiting on issuance endpoints (PostgreSQL-backed sliding windows)
- RFC 6962 consistency proofs on all signed tree heads
- GitHub Actions CI with dependency review and supply chain scanning

Security documentation available on request — [security@vane.build](mailto:security@vane.build)

## Documentation

Full documentation at [docs.vane.build](https://docs.vane.build), including the passport specification, attestation protocol, inclusion proof API, and offline CLI verifier.

## License

[AGPL-3.0](./LICENSE). The Vane API server is free to use and inspect. If you run it as a network service, your modifications must be open-sourced under the same license.

For commercial licensing inquiries: [pablo@vane.build](mailto:pablo@vane.build)
