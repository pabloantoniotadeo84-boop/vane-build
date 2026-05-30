import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import type { CounselClient } from './counsel.js';

/**
 * Creates the sidecar HTTP server. It handles three request patterns:
 *
 *   1. CONNECT <host>:<port>  — HTTPS tunnel (outbound). Passes through as-is;
 *      passport injection is not possible inside an encrypted tunnel.
 *
 *   2. GET/POST http://...    — HTTP forward proxy (outbound). Attaches the
 *      agent's Counsel passport as "Counsel-Passport" header, attests the call
 *      to Counsel (fire-and-forget), and forwards the request.
 *
 *   3. GET/POST /path         — Inbound request. Verifies the "Counsel-Passport"
 *      header (or falls back to "Authorization: Bearer <cap-jwt>"), then
 *      reverse-proxies to SIDECAR_AGENT_TARGET. Returns 401 on missing/invalid
 *      passport, 502 if SIDECAR_AGENT_TARGET is not configured.
 */
export function createProxyServer(client: CounselClient, agentTarget?: string): http.Server {
  const server = http.createServer(async (req, res) => {
    const url = req.url ?? '/';

    if (url.startsWith('http://') || url.startsWith('https://')) {
      await handleOutbound(req, res, client);
    } else {
      await handleInbound(req, res, client, agentTarget);
    }
  });

  server.on('connect', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    handleConnect(req, socket, head);
  });

  // Prevent uncaught errors from crashing the process
  server.on('error', (err) => {
    console.error('[counsel-sidecar] Server error:', err);
  });

  return server;
}

// ── Outbound forward proxy ────────────────────────────────────────────────────

async function handleOutbound(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  client: CounselClient,
): Promise<void> {
  let target: URL;
  try {
    target = new URL(req.url!);
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Malformed proxy request URL' }));
    return;
  }

  // Attest before the request goes out — fire-and-forget so latency is unaffected
  client.attest(req.method ?? 'GET', req.url!, {
    host: target.hostname,
    path: target.pathname + target.search,
  });

  let passport: string;
  try {
    passport = await client.getPassport();
  } catch (err) {
    console.error('[counsel-sidecar] Could not obtain passport:', err);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Counsel passport unavailable' }));
    return;
  }

  // Clone headers, add passport, strip hop-by-hop proxy headers
  const headers: http.OutgoingHttpHeaders = Object.fromEntries(
    Object.entries(req.headers).filter(([k]) => k !== 'proxy-connection' && k !== 'proxy-authorization'),
  );
  headers['counsel-passport'] = passport;
  // Set Authorization only when the outbound request carries none of its own
  if (!headers['authorization']) {
    headers['authorization'] = `Bearer ${passport}`;
  }

  const isHttps = target.protocol === 'https:';
  const defaultPort = isHttps ? 443 : 80;
  const options: http.RequestOptions = {
    hostname: target.hostname,
    port: target.port ? parseInt(target.port, 10) : defaultPort,
    path: target.pathname + target.search,
    method: req.method,
    headers,
  };

  const transport = isHttps ? https : http;
  const proxyReq = transport.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode ?? 200, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad Gateway' }));
    }
  });

  req.pipe(proxyReq);
}

// ── HTTPS CONNECT tunnel ──────────────────────────────────────────────────────

function handleConnect(req: http.IncomingMessage, socket: net.Socket, head: Buffer): void {
  const [host, portStr] = (req.url ?? '').split(':');
  const port = parseInt(portStr ?? '443', 10);

  if (!host || isNaN(port)) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  const upstream = net.connect(port, host, () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });

  upstream.on('error', () => {
    socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    socket.destroy();
  });

  socket.on('error', () => upstream.destroy());
}

// ── Inbound verification + reverse proxy ─────────────────────────────────────

async function handleInbound(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  client: CounselClient,
  agentTarget?: string,
): Promise<void> {
  // Extract the Counsel passport from the request headers.
  // Prefer the dedicated "Counsel-Passport" header; fall back to
  // "Authorization: Bearer <token>" when that token looks like a CAP+JWT.
  const passportHeader = req.headers['counsel-passport'];
  const authHeader = req.headers['authorization'];

  let incomingPassport: string | undefined;

  if (typeof passportHeader === 'string' && passportHeader) {
    incomingPassport = passportHeader;
  } else if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    incomingPassport = authHeader.slice(7);
  }

  if (!incomingPassport) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'Missing Counsel passport',
      hint: 'Set "Counsel-Passport: <token>" header or "Authorization: Bearer <cap-jwt>"',
    }));
    return;
  }

  if (!client.verifyPassportLocal(incomingPassport)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Counsel passport is invalid or has expired' }));
    return;
  }

  if (!agentTarget) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'Inbound routing not configured',
      hint: 'Set SIDECAR_AGENT_TARGET to the local agent address (e.g. http://localhost:3001)',
    }));
    return;
  }

  // Forward to the local agent
  let targetUrl: URL;
  try {
    targetUrl = new URL(req.url ?? '/', agentTarget);
  } catch {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid SIDECAR_AGENT_TARGET' }));
    return;
  }

  const options: http.RequestOptions = {
    hostname: targetUrl.hostname,
    port: targetUrl.port ? parseInt(targetUrl.port, 10) : 80,
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers: req.headers,
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode ?? 200, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent target unavailable' }));
    }
  });

  req.pipe(proxyReq);
}
