/**
 * Counsel Sidecar Proxy
 *
 * A zero-config sidecar that runs alongside any AI agent. It intercepts
 * outbound HTTP/HTTPS calls (via HTTP_PROXY / HTTPS_PROXY), attaches the
 * agent's Counsel passport, attests every outbound tool call, and verifies
 * incoming Counsel credentials on inbound calls — all without changing agent
 * code.
 *
 * For HTTPS, the sidecar performs transparent MITM using a locally-generated
 * root CA. Agents must trust that CA certificate (see startup output).
 *
 * Configuration (all via environment variables):
 *
 *   COUNSEL_API_URL       Base URL of the Counsel server  (required)
 *   COUNSEL_API_KEY       Company-scoped API key          (required)
 *   COUNSEL_AGENT_ID      Agent ID pre-registered on the server (required)
 *   COUNSEL_COMPANY_ID    Company ID                      (required)
 *   SIDECAR_PORT          Proxy listen port               (default: 8080)
 *   SIDECAR_AGENT_TARGET  Where to forward verified inbound calls
 *                         e.g. http://localhost:3001      (optional)
 *   SIDECAR_CA_CERT_FILE  Path to write the MITM CA cert  (default: ./counsel-ca.pem)
 *
 * Usage — outbound (forward proxy):
 *
 *   HTTP_PROXY=http://localhost:8080  your-agent-command
 *   HTTPS_PROXY=http://localhost:8080 your-agent-command
 *
 *   Every outbound HTTP/HTTPS request made by the agent will have
 *   "Counsel-Passport" and (if no Authorization is already set)
 *   "Authorization: Bearer <passport>" injected automatically.
 *
 *   The agent process must trust the MITM CA certificate. Set:
 *     NODE_EXTRA_CA_CERTS=./counsel-ca.pem
 *   or fetch it at runtime from http://localhost:<SIDECAR_PORT>/counsel-ca-cert.pem
 *
 * Usage — inbound (reverse proxy):
 *
 *   Point callers at http://localhost:<SIDECAR_PORT>/...
 *   The sidecar verifies "Counsel-Passport" (or "Authorization: Bearer")
 *   on every request before forwarding to SIDECAR_AGENT_TARGET.
 */

import { writeFileSync } from 'node:fs';
import { CounselClient } from './counsel.js';
import { createProxyServer } from './proxy.js';
import { createMitmCA } from './ca.js';

function require_env(name: string): string {
  const val = process.env[name];
  if (!val) {
    console.error(`[counsel-sidecar] Fatal: ${name} is required but not set`);
    process.exit(1);
  }
  return val;
}

const config = {
  apiUrl:    require_env('COUNSEL_API_URL'),
  apiKey:    require_env('COUNSEL_API_KEY'),
  agentId:   require_env('COUNSEL_AGENT_ID'),
  companyId: require_env('COUNSEL_COMPANY_ID'),
};

const port        = parseInt(process.env.SIDECAR_PORT ?? '8080', 10);
const agentTarget = process.env.SIDECAR_AGENT_TARGET;
const caCertFile  = process.env.SIDECAR_CA_CERT_FILE ?? './counsel-ca.pem';

const client = new CounselClient(config);

// Initialize MITM CA and Counsel passport in parallel
let ca: Awaited<ReturnType<typeof createMitmCA>>;

try {
  [ca] = await Promise.all([
    createMitmCA(),
    client.initialize(),
  ]);
} catch (err) {
  console.error('[counsel-sidecar] Startup failed:', err);
  process.exit(1);
}

// Persist the CA cert so agents can import it into their trust store
try {
  writeFileSync(caCertFile, ca.certPem, 'utf8');
} catch (err) {
  console.error(`[counsel-sidecar] Warning: could not write CA cert to ${caCertFile}:`, err);
}

const server = createProxyServer(client, agentTarget, ca);

server.listen(port, '127.0.0.1', () => {
  console.log(`[counsel-sidecar] Proxy listening on http://127.0.0.1:${port}`);
  console.log(`[counsel-sidecar] Agent: ${config.agentId}  Company: ${config.companyId}`);
  if (agentTarget) {
    console.log(`[counsel-sidecar] Inbound calls forwarded to ${agentTarget}`);
  }
  console.log('');
  console.log('[counsel-sidecar] ── MITM CA certificate ───────────────────────────────────');
  console.log(`[counsel-sidecar] Written to: ${caCertFile}`);
  console.log(`[counsel-sidecar] Fetch via:  GET http://127.0.0.1:${port}/counsel-ca-cert.pem`);
  console.log('[counsel-sidecar] Trust it with one of:');
  console.log(`[counsel-sidecar]   NODE_EXTRA_CA_CERTS=${caCertFile}          (Node.js)`);
  console.log(`[counsel-sidecar]   REQUESTS_CA_BUNDLE=${caCertFile}           (Python/requests)`);
  console.log(`[counsel-sidecar]   SSL_CERT_FILE=${caCertFile}                (OpenSSL-linked tools)`);
  console.log('[counsel-sidecar] ─────────────────────────────────────────────────────────');
  console.log('');
  console.log('[counsel-sidecar] Set on your agent process:');
  console.log(`[counsel-sidecar]   HTTP_PROXY=http://127.0.0.1:${port}`);
  console.log(`[counsel-sidecar]   HTTPS_PROXY=http://127.0.0.1:${port}`);
  console.log(`[counsel-sidecar]   NODE_EXTRA_CA_CERTS=${caCertFile}`);
});

server.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[counsel-sidecar] Port ${port} is already in use. Set SIDECAR_PORT to a different port.`);
  } else {
    console.error('[counsel-sidecar] Fatal server error:', err);
  }
  process.exit(1);
});
