# @vane.build/audit

Audit your MCP server for cryptographic agent accountability.

## Usage

```bash
npx @vane.build/audit <your-mcp-server-url>
```

## What it checks

1. **Agent identity** — do your tool calls carry a verifiable agent identity?
2. **Cryptographic signatures** — are responses signed and tamper-evident?
3. **Attestation log** — are agent actions anchored in an immutable audit trail?
4. **Delegation chain** — can you prove who authorized your agents to act?

## Fix failed checks

Install [@vane.build/mcp-middleware](https://vane.build/docs) to pass all four checks in under 10 minutes.

## License

MIT
