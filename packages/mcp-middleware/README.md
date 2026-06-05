# @vane.build/mcp-middleware

Offline [Vane](https://vane.build) Agent Passport verification for MCP servers, Hono, and Express. Zero runtime dependencies beyond `node:crypto`.

## Installation

```bash
npm install @vane.build/mcp-middleware
```

## How it works

An agent presents its `CAP+JWT` passport as an `Authorization: Bearer` header. The middleware verifies the EdDSA signature offline using your Vane CA public key — no network call to Vane on the hot path. On success it attaches an `AttestationReceipt` to the request so downstream handlers know which agent made the call and under what scope. On failure it returns 401.

Fetch the CA public key once from your Vane instance and pin it in your deployment:

```bash
curl https://api.vane.build/v1/ca/public-key?companyId=acme
```

## Hono example

```typescript
import { Hono } from 'hono';
import { createVaneMiddleware, decodeReceipt, RECEIPT_HEADER } from '@vane.build/mcp-middleware';

const vane = createVaneMiddleware({
  vanePublicKey: process.env.VANE_CA_PUBLIC_KEY!,
});

const app = new Hono();

// fetchMiddleware() is Hono/Next.js Edge/Cloudflare Workers compatible.
app.use('/mcp', async (c, next) => {
  const handle = vane.fetchMiddleware();
  return handle(c.req.raw, () => next());
});

app.post('/mcp', (c) => {
  const receipt = decodeReceipt(c.req.raw.headers.get(RECEIPT_HEADER)!);
  // receipt.agentId, receipt.org, receipt.scopeGranted, receipt.tool, ...
  return c.json({ ok: true });
});
```

## Express example

```typescript
import express from 'express';
import { createVaneMiddleware } from '@vane.build/mcp-middleware';

// Extend the Express Request type to include vaneReceipt.
declare module 'express-serve-static-core' {
  interface Request { vaneReceipt?: import('@vane.build/mcp-middleware').AttestationReceipt; }
}

const vane = createVaneMiddleware({
  vanePublicKey: process.env.VANE_CA_PUBLIC_KEY!,
});

const app = express();
app.use(express.json());
app.use(vane.expressMiddleware()); // attaches req.vaneReceipt on success

app.post('/mcp', (req, res) => {
  const { agentId, org, tool, scopeGranted } = req.vaneReceipt!;
  res.json({ ok: true, agentId, org, tool, scopeGranted });
});
```

## MCP SDK handler example

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createVaneMiddleware } from '@vane.build/mcp-middleware';

const vane = createVaneMiddleware({
  vanePublicKey: process.env.VANE_CA_PUBLIC_KEY!,
});

const server = new Server({ name: 'my-server', version: '1.0.0' });

// The passport must be set in request.params._meta.authorization by the MCP client.
server.setRequestHandler(
  CallToolRequestSchema,
  vane.mcpHandler(async (request, receipt) => {
    // receipt is a verified AttestationReceipt — agent identity is confirmed.
    return { content: [{ type: 'text', text: `Hello, ${receipt.agentId}` }] };
  }),
);
```

## Options

```typescript
createVaneMiddleware({
  // Ed25519 SPKI PEM of your Vane CA root key. Required.
  // Obtain from GET /v1/ca/public-key?companyId=<id>
  vanePublicKey: string;

  // When true (default), 401 responses include the error code and message.
  // Set to false to return plain {"error":"Unauthorized"} without leaking reason strings.
  exposeErrors?: boolean;

  // Revocation check. If provided, called after signature verification passes.
  // The returned array of JTIs is checked against the passport's jti claim.
  // Fail-closed: if this throws or returns a non-array, the request is denied.
  // Cache the list (e.g. 60 s TTL) — calling Vane on every request breaks the
  // offline property. Short passport TTLs are the primary revocation defence.
  fetchRevocationList?: () => Promise<string[]>;

  // Cross-org support. If provided, XORG+JWT tokens are accepted.
  // Called with the originOrg extracted from the token; return its SPKI PEM key.
  resolveCrossOrgPublicKey?: (originOrg: string) => Promise<string | null>;

  // If set, cross-org tokens whose vane_xorg.targetOrg doesn't match are rejected.
  expectedTargetOrg?: string;
})
```

## AttestationReceipt shape

```typescript
interface AttestationReceipt {
  v: 1;
  type: 'VaneAttestationReceipt';
  passportId: string;       // JWT ID (jti)
  agentId: string;
  agentSpiffeId: string;    // spiffe://vane.local/company/acme/agent/agent-1
  org: string;
  orgSpiffeId: string;
  tool: string;             // MCP tool name, or "(not an MCP tool call)"
  scopeGranted: string;     // matched scope, e.g. "tool:*"
  delegationChain: string[];
  passportIssuedAt: string; // ISO 8601
  passportExpiresAt: string;
  verifiedAt: string;
  verifier: string;         // "@vane.build/mcp-middleware@<version>"
  crossOrg?: { targetOrg: string; targetOrgSpiffeId: string };
}
```

## Error codes

`MALFORMED_TOKEN` · `ALGORITHM_MISMATCH` · `WRONG_TOKEN_TYPE` · `SIGNATURE_INVALID` · `TOKEN_EXPIRED` · `TOKEN_NOT_YET_VALID` · `AUDIENCE_MISMATCH` · `INVALID_ISSUER` · `INVALID_SUBJECT` · `UNSUPPORTED_VERSION` · `MALFORMED_CLAIMS` · `CHAIN_INCOHERENT` · `SCOPE_DENIED` · `PASSPORT_REVOKED` · `CROSS_ORG_NOT_ACCEPTED` · `CROSS_ORG_UNKNOWN_ORIGIN` · `TARGET_MISMATCH` · `VERIFICATION_ERROR`

All verifiers are fail-closed: any unexpected exception resolves to `VERIFICATION_ERROR` and denies the request — it never escapes as an uncaught throw.

---

[Vane main repo](https://github.com/vane-build/vane) · [docs.vane.build/mcp-middleware](https://docs.vane.build/mcp-middleware)
