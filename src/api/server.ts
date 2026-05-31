import { createAdaptorServer } from '@hono/node-server';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { app } from './app.js';
import { attachWebSocketServer } from './ws.js';
import type { Server } from 'node:http';
import { logger } from '../logger.js';
import { initSentry } from '../sentry.js';

initSentry();

const PORT = Number(process.env.PORT ?? 3000);

// ── mTLS mode ─────────────────────────────────────────────────────────────────
// When COUNSEL_MTLS_CA_CERT is set the server switches to HTTPS and requests
// (but does not require) a client certificate on every connection.
//
// Accepted environment variables:
//   COUNSEL_MTLS_CA_CERT  PEM-encoded CA cert, or a file path to one.
//                         Used to verify client certificates.
//   COUNSEL_TLS_CERT      PEM-encoded server certificate, or a file path.
//   COUNSEL_TLS_KEY       PEM-encoded server private key, or a file path.
//
// When a client presents a certificate whose CN matches a known company ID, the
// auth middleware in app.ts uses that CN as the company identity without
// requiring a Bearer token. Clients without certificates fall back to API key /
// OAuth token authentication, so existing callers continue to work unmodified.

function readPemOrFile(value: string): string {
  return value.trimStart().startsWith('-----') ? value : readFileSync(value, 'utf8');
}

const mTlsCaCert = process.env.COUNSEL_MTLS_CA_CERT;

if (mTlsCaCert) {
  const serverCert = process.env.COUNSEL_TLS_CERT;
  const serverKey  = process.env.COUNSEL_TLS_KEY;

  if (!serverCert || !serverKey) {
    logger.fatal('COUNSEL_MTLS_CA_CERT is set but COUNSEL_TLS_CERT and COUNSEL_TLS_KEY are also required');
    process.exit(1);
  }

  const server = createAdaptorServer({
    fetch: app.fetch,
    createServer: createHttpsServer,
    serverOptions: {
      ca:   readPemOrFile(mTlsCaCert),
      cert: readPemOrFile(serverCert),
      key:  readPemOrFile(serverKey),
      // Ask for a client cert but do not reject connections that omit one;
      // those fall through to the normal Bearer token auth path.
      requestCert: true,
      rejectUnauthorized: false,
    },
  });

  attachWebSocketServer(server as unknown as Server);
  server.listen(PORT, () => {
    logger.info({ port: PORT, tls: 'mtls' }, 'Counsel API listening');
  });
  registerShutdown(server as unknown as Server);
} else {
  const server = createAdaptorServer({ fetch: app.fetch });
  attachWebSocketServer(server as unknown as Server);
  server.listen(PORT, () => {
    logger.info({ port: PORT, tls: false }, 'Counsel API listening');
  });
  registerShutdown(server as unknown as Server);
}

function registerShutdown(server: Server): void {
  function shutdown(signal: string): void {
    logger.info({ signal }, 'Received shutdown signal, closing server');
    server.close(() => {
      logger.info('Server closed, exiting');
      process.exit(0);
    });
  }
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT',  () => shutdown('SIGINT'));
}
