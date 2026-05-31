import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';
import type { CounselClient } from './counsel.js';
import type { MitmCA } from './ca.js';
import { getCert } from './ca.js';

/**
 * Creates the sidecar HTTP server. It handles three request patterns:
 *
 *   1. CONNECT <host>:<port>  — HTTPS tunnel. The sidecar terminates TLS using
 *      a dynamically-issued leaf certificate signed by the MITM CA, injects
 *      the agent's Counsel passport, attests the call, then re-encrypts to
 *      the real destination.
 *
 *   2. GET/POST http://...    — HTTP forward proxy (outbound). Attaches the
 *      agent's Counsel passport as "Counsel-Passport" header, attests the call
 *      to Counsel (fire-and-forget), and forwards the request.
 *
 *   3. GET/POST /path         — Inbound request. Verifies the "Counsel-Passport"
 *      header (or falls back to "Authorization: Bearer <cap-jwt>"), then
 *      reverse-proxies to SIDECAR_AGENT_TARGET. Returns 401 on missing/invalid
 *      passport, 502 if SIDECAR_AGENT_TARGET is not configured.
 *
 *      Special case: GET /counsel-ca-cert.pem returns the MITM CA certificate
 *      (no auth required) so agents can install it into their trust store.
 */
export function createProxyServer(
  client: CounselClient,
  agentTarget: string | undefined,
  ca: MitmCA,
): http.Server {
  // Associates each MITM TLS socket with its upstream target.
  // WeakMap ensures the entries are GC'd automatically when sockets close.
  const socketTargets = new WeakMap<net.Socket, { host: string; port: number }>();

  // Internal HTTP server used purely for parsing decrypted MITM traffic.
  // Never bound to a port — connections are injected via emit('connection').
  const mitmServer = http.createServer(async (req, res) => {
    const target = socketTargets.get(req.socket);
    if (!target) {
      res.writeHead(500).end();
      return;
    }
    await handleMitmRequest(req, res, target.host, target.port, client).catch((err) => {
      console.error('[counsel-sidecar] MITM request error:', err);
      if (!res.headersSent) res.writeHead(502).end();
    });
  });

  mitmServer.on('clientError', (_err, socket) => {
    socket.destroy();
  });

  const server = http.createServer(async (req, res) => {
    const url = req.url ?? '/';
    if (url.startsWith('http://') || url.startsWith('https://')) {
      await handleOutbound(req, res, client).catch((err) => {
        console.error('[counsel-sidecar] Outbound error:', err);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad Gateway' }));
        }
      });
    } else {
      await handleInbound(req, res, client, agentTarget, ca.certPem).catch((err) => {
        console.error('[counsel-sidecar] Inbound error:', err);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad Gateway' }));
        }
      });
    }
  });

  server.on('connect', (req, socket, head) => {
    handleConnect(req, socket as net.Socket, head, ca, client, mitmServer, socketTargets).catch(
      (err) => {
        console.error('[counsel-sidecar] CONNECT handler error:', err);
        (socket as net.Socket).destroy();
      },
    );
  });

  server.on('error', (err) => {
    console.error('[counsel-sidecar] Server error:', err);
  });

  return server;
}

// ── HTTPS CONNECT — MITM ─────────────────────────────────────────────────────

async function handleConnect(
  req: http.IncomingMessage,
  socket: net.Socket,
  head: Buffer,
  ca: MitmCA,
  client: CounselClient,
  mitmServer: http.Server,
  socketTargets: WeakMap<net.Socket, { host: string; port: number }>,
): Promise<void> {
  const target = req.url ?? '';
  const lastColon = target.lastIndexOf(':');
  const host = lastColon > 0 ? target.slice(0, lastColon) : target;
  const portStr = lastColon > 0 ? target.slice(lastColon + 1) : '443';
  const port = parseInt(portStr, 10);

  if (!host || isNaN(port)) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  let leaf: { certPem: string; keyPem: string };
  try {
    leaf = await getCert(ca, host);
  } catch (err) {
    console.error(`[counsel-sidecar] Failed to issue leaf cert for ${host}:`, err);
    socket.write('HTTP/1.1 500 MITM Setup Failed\r\n\r\n');
    socket.destroy();
    return;
  }

  // Tell the client the TCP tunnel is established.
  // After this write the client will immediately start a TLS ClientHello.
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  // If any bytes arrived before we set up TLS, push them back to the read
  // queue so the TLSSocket sees them as the start of the TLS stream.
  if (head.length > 0) {
    socket.unshift(head);
  }

  // Wrap the raw socket in TLS server-side, presenting our signed leaf cert.
  // Only advertise HTTP/1.1 — we do not implement HTTP/2 MITM.
  const tlsSocket = new tls.TLSSocket(socket, {
    isServer: true,
    cert: leaf.certPem,
    key: leaf.keyPem,
    ALPNProtocols: ['http/1.1'],
    requestCert: false,
  });

  tlsSocket.on('error', (err) => {
    // Suppress TLS errors (e.g. client rejected our cert, connection reset)
    // at debug level — these are expected when the agent hasn't yet installed the CA.
    if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
      console.error(`[counsel-sidecar] MITM TLS error for ${host}: ${err.message}`);
    }
    tlsSocket.destroy();
  });

  // Record the upstream target before handing the socket to the HTTP parser.
  socketTargets.set(tlsSocket, { host, port });

  // Feed the decrypted socket to the internal HTTP server.
  // Node's HTTP parser will fire 'request' events with cleartext headers,
  // letting handleMitmRequest inject passports and forward to the real upstream.
  mitmServer.emit('connection', tlsSocket);
}

// ── MITM request forwarding ──────────────────────────────────────────────────

async function handleMitmRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  host: string,
  port: number,
  client: CounselClient,
): Promise<void> {
  const path = req.url ?? '/';

  // Fire-and-forget attestation
  client.attest(req.method ?? 'GET', `https://${host}:${port}${path}`, {
    host,
    path,
    via: 'mitm',
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

  // Clone headers, inject passport, strip hop-by-hop proxy headers
  const headers: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (k !== 'proxy-connection' && k !== 'proxy-authorization') {
      headers[k] = v;
    }
  }
  headers['counsel-passport'] = passport;
  if (!headers['authorization']) {
    headers['authorization'] = `Bearer ${passport}`;
  }
  // Ensure the Host header matches the actual upstream
  headers['host'] = port === 443 ? host : `${host}:${port}`;

  const options: https.RequestOptions = {
    hostname: host,
    port,
    path,
    method: req.method,
    headers,
  };

  const proxyReq = https.request(options, (proxyRes) => {
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

  const headers: http.OutgoingHttpHeaders = Object.fromEntries(
    Object.entries(req.headers).filter(
      ([k]) => k !== 'proxy-connection' && k !== 'proxy-authorization',
    ),
  );
  headers['counsel-passport'] = passport;
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

// ── Inbound verification + reverse proxy ─────────────────────────────────────

async function handleInbound(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  client: CounselClient,
  agentTarget: string | undefined,
  caCertPem: string,
): Promise<void> {
  // Unauthenticated CA cert download — agents use this to bootstrap trust.
  if (req.method === 'GET' && req.url === '/counsel-ca-cert.pem') {
    res.writeHead(200, {
      'Content-Type': 'application/x-pem-file',
      'Content-Disposition': 'attachment; filename="counsel-ca.pem"',
    });
    res.end(caCertPem);
    return;
  }

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
