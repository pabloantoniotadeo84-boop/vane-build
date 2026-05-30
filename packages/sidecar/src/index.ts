/**
 * Counsel Sidecar Proxy
 *
 * A zero-config sidecar that runs alongside any AI agent. It intercepts
 * outbound HTTP calls (via HTTP_PROXY / HTTPS_PROXY), attaches the agent's
 * Counsel passport, attests every outbound tool call, and verifies incoming
 * Counsel credentials on inbound calls — all without changing agent code.
 *
 * Configuration (all via environment variables):
 *
 *   COUNSEL_API_URL     Base URL of the Counsel server  (required)
 *   COUNSEL_API_KEY     Company-scoped API key          (required)
 *   COUNSEL_AGENT_ID    Agent ID pre-registered on the server (required)
 *   COUNSEL_COMPANY_ID  Company ID                      (required)
 *   SIDECAR_PORT        Proxy listen port               (default: 8080)
 *   SIDECAR_AGENT_TARGET  Where to forward verified inbound calls
 *                         e.g. http://localhost:3001   (optional)
 *
 * Usage — outbound (forward proxy):
 *
 *   HTTP_PROXY=http://localhost:8080  your-agent-command
 *   HTTPS_PROXY=http://localhost:8080 your-agent-command
 *
 *   Every outbound HTTP/HTTPS request made by the agent will have
 *   "Counsel-Passport" and (if no Authorization is already set)
 *   "Authorization: Bearer <passport>" injected automatically.
 *   Note: for HTTPS, the sidecar tunnels via CONNECT — headers cannot be
 *   injected inside the encrypted stream without a MITM CA setup.
 *
 * Usage — inbound (reverse proxy):
 *
 *   Point callers at http://localhost:<SIDECAR_PORT>/...
 *   The sidecar verifies "Counsel-Passport" (or "Authorization: Bearer")
 *   on every request before forwarding to SIDECAR_AGENT_TARGET.
 */

import { CounselClient } from './counsel.js';
import { createProxyServer } from './proxy.js';

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

const client = new CounselClient(config);

try {
  await client.initialize();
} catch (err) {
  console.error('[counsel-sidecar] Failed to initialize passport:', err);
  process.exit(1);
}

const server = createProxyServer(client, agentTarget);

server.listen(port, '127.0.0.1', () => {
  console.log(`[counsel-sidecar] Proxy listening on http://127.0.0.1:${port}`);
  if (agentTarget) {
    console.log(`[counsel-sidecar] Inbound calls will be forwarded to ${agentTarget}`);
  } else {
    console.log('[counsel-sidecar] Inbound forwarding disabled (set SIDECAR_AGENT_TARGET to enable)');
  }
  console.log(`[counsel-sidecar] Set HTTP_PROXY=http://127.0.0.1:${port} on your agent process`);
});

server.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[counsel-sidecar] Port ${port} is already in use. Set SIDECAR_PORT to a different port.`);
  } else {
    console.error('[counsel-sidecar] Fatal server error:', err);
  }
  process.exit(1);
});
