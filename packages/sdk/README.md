# @vane.build/sdk

TypeScript client for the [Vane](https://vane.build) attestation API. Ships both CJS and ESM builds. Node 18+.

## Installation

```bash
npm install @vane.build/sdk
```

## Quick start

```typescript
import { VaneClient } from '@vane.build/sdk';

const vane = new VaneClient({
  baseUrl: 'https://api.vane.build',
  apiKey: process.env.VANE_API_KEY!,
});

// Attest an action — appends a signed, indexed record to the chain
const record = await vane.attest(
  'agent-1',       // agentId
  'acme',          // companyId
  'data-query',    // actionType
  { query: 'SELECT * FROM contracts', params: [] },
);

// record.hash and record.signature are Ed25519-backed
console.log(record.index, record.hash, record.signature);

// Fetch a Merkle inclusion proof for any record
const proof = await vane.getProof(record.index);
console.log(proof.root);   // verifiable offline against a saved root snapshot
```

## API reference

### `new VaneClient(options)`

```typescript
new VaneClient({ baseUrl: string; apiKey: string })
// or the positional form:
new VaneClient(baseUrl: string, apiKey: string)
```

### `client.attest(agentId, companyId, actionType, payload, delegationToken?)`

Appends a record to the company's attestation chain. Returns an `AttestationRecord`.

| Parameter | Type | Notes |
|---|---|---|
| `agentId` | `string` | Agent registered under the company |
| `companyId` | `string` | Your company identifier |
| `actionType` | `string` | Arbitrary action label (`"data-query"`, `"llm-call"`, etc.) |
| `payload` | `unknown` | JSON-serializable action data |
| `delegationToken` | `string?` | RFC 8693 delegation JWT (optional) |

### `client.getProof(index)`

Returns an `InclusionProof` for the record at `index`. The proof is an O(log n) Merkle path verifiable offline against any saved root.

### Types

```typescript
interface AttestationRecord {
  index:      number;
  timestamp:  string;        // ISO 8601
  payload:    unknown;
  delegation?: DelegationInfo;
  hash:       string;        // SHA-256 hex
  signature:  string;        // Ed25519, base64url
}

interface InclusionProof {
  record: AttestationRecord;
  proof:  ProofNode[];       // { sibling: string; position: 'left' | 'right' }[]
  root:   string;            // Merkle root, SHA-256 hex
}
```

## More

Full documentation, framework integrations (LangChain, OpenAI Agents, MCP middleware), security details, and EU AI Act compliance notes: [github.com/vane-build/vane](https://github.com/vane-build/vane)
