import { WebSocketServer, WebSocket } from 'ws';
import type { Server } from 'node:http';

const clients = new Set<WebSocket>();

export function broadcast(data: unknown): void {
  if (clients.size === 0) return;
  const msg = JSON.stringify(data);
  for (const client of clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  }
}

export function attachWebSocketServer(server: Server): void {
  const wss = new WebSocketServer({ server, path: '/v1/ws' });
  wss.on('connection', (ws) => {
    clients.add(ws);
    ws.on('close', () => clients.delete(ws));
    ws.on('error', () => clients.delete(ws));
  });
}
