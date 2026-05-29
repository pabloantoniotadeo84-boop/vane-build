import { Hono } from 'hono';
import { generateKeyPair, AttestationChain } from '../crypto/index.js';
import { Store } from '../db/store.js';

const store = new Store();

const keys = store.getKeys() ?? (() => {
  const fresh = generateKeyPair();
  store.saveKeys(fresh);
  return fresh;
})();

const chain = new AttestationChain();
chain.hydrate(store.getAllRecords());

export const app = new Hono();

app.get('/v1/health', (c) => {
  return c.json({ status: 'ok' });
});

app.post('/v1/attest', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Request body must be valid JSON' }, 400);
  }

  const { agentId, companyId, actionType, payload } = body;

  if (
    typeof agentId !== 'string' || !agentId ||
    typeof companyId !== 'string' || !companyId ||
    typeof actionType !== 'string' || !actionType ||
    payload === undefined
  ) {
    return c.json(
      { error: 'Missing or invalid fields: agentId, companyId, actionType, payload are required' },
      400,
    );
  }

  const record = chain.append({ agentId, companyId, actionType, payload }, keys.privateKey);
  store.insertRecord(record);

  return c.json(record, 201);
});

app.get('/v1/chain', (c) => {
  return c.json({ records: chain.getRecords() });
});

app.get('/v1/verify', (c) => {
  const result = chain.verify(keys.publicKey);
  if (result.valid) {
    return c.json({ valid: true });
  }
  return c.json({ valid: false, failedAtIndex: result.failedAtIndex });
});
