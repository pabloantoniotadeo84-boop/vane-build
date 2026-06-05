# @vane.build/sidecar

A proxy process that intercepts outbound HTTP/HTTPS calls from any AI agent, attaches a valid [Vane](https://vane.build) Agent Passport as a header, and records every call in the Vane attestation chain — without changing a line of agent code. Node 22+.

## How it works

Run the sidecar alongside your agent and point the agent's HTTP proxy at it:

```
agent process → HTTP_PROXY=http://127.0.0.1:8080 → sidecar → upstream
```

On every outbound call the sidecar:

1. Fetches (and caches) a Vane Agent Passport from your Vane instance
2. Injects `Vane-Passport: <cap-jwt>` into the request headers
3. Also sets `Authorization: Bearer <cap-jwt>` if the request has no existing Authorization header
4. Records the call in the Vane attestation chain (fire-and-forget, never blocks)

For HTTPS, the sidecar uses transparent MITM via a locally-generated CA. The agent process must trust that CA certificate.

## Installation

```bash
npm install @vane.build/sidecar
npm run build   # compiles TypeScript to dist/
```

## Running

Set the required environment variables, then start the sidecar:

```bash
VANE_API_URL=https://api.vane.build \
VANE_API_KEY=vane_... \
VANE_AGENT_ID=my-agent \
VANE_COMPANY_ID=acme \
node dist/index.js
```

The sidecar prints startup instructions including the proxy address and CA certificate path:

```
[vane-sidecar] Proxy listening on http://127.0.0.1:8080
[vane-sidecar] Agent: my-agent  Company: acme

[vane-sidecar] ── MITM CA certificate ───────────────────────────────────
[vane-sidecar] Written to: ./vane-ca.pem
[vane-sidecar] Fetch via:  GET http://127.0.0.1:8080/vane-ca-cert.pem

[vane-sidecar] Set on your agent process:
[vane-sidecar]   HTTP_PROXY=http://127.0.0.1:8080
[vane-sidecar]   HTTPS_PROXY=http://127.0.0.1:8080
[vane-sidecar]   NODE_EXTRA_CA_CERTS=./vane-ca.pem
```

Then start your agent:

```bash
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
NODE_EXTRA_CA_CERTS=./vane-ca.pem \
node my-agent.js
```

For Python agents use `REQUESTS_CA_BUNDLE=./vane-ca.pem` instead of `NODE_EXTRA_CA_CERTS`.

## Headers injected

| Header | Value | When |
|---|---|---|
| `Vane-Passport` | `<cap-jwt>` | Every proxied outbound request |
| `Authorization` | `Bearer <cap-jwt>` | Only when no Authorization header is already present |

## Inbound verification (optional)

If `SIDECAR_AGENT_TARGET` is set, the sidecar also operates as a reverse proxy. Incoming requests to `http://127.0.0.1:<port>/...` are verified against the Vane CA public key before being forwarded to the target:

```bash
SIDECAR_AGENT_TARGET=http://localhost:3001 \
node dist/index.js
```

A request with a missing or invalid `Vane-Passport` header (or `Authorization: Bearer <cap-jwt>`) is rejected with 401. Verified requests are forwarded as-is.

## Environment variables

| Variable | Default | Required |
|---|---|---|
| `VANE_API_URL` | — | yes |
| `VANE_API_KEY` | — | yes |
| `VANE_AGENT_ID` | — | yes |
| `VANE_COMPANY_ID` | — | yes |
| `SIDECAR_PORT` | `8080` | no |
| `SIDECAR_AGENT_TARGET` | — | no (inbound reverse proxy only) |
| `SIDECAR_CA_CERT_FILE` | `./vane-ca.pem` | no |

## CA certificate

The MITM root CA is ephemeral — generated fresh on each startup. You can fetch it at any time from:

```
GET http://127.0.0.1:<SIDECAR_PORT>/vane-ca-cert.pem
```

No authentication required. The path is also written to disk at `SIDECAR_CA_CERT_FILE` on startup.

---

[Vane main repo](https://github.com/vane-build/vane) · [docs.vane.build/sidecar](https://docs.vane.build/sidecar)
