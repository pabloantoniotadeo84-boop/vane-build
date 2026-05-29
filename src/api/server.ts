import { serve } from '@hono/node-server';
import { app } from './app.js';

const PORT = 3000;

serve({ fetch: app.fetch, port: PORT }, () => {
  console.log(`Counsel API  →  http://localhost:${PORT}`);
});
