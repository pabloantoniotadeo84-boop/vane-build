import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import {
  createIssuanceRateLimitMiddleware,
  InMemoryRateLimitStore,
} from '../src/api/issuance-rate-limit.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildApp(store: InMemoryRateLimitStore, handlerSpy?: { called: boolean }) {
  const app = new Hono<{ Variables: { companyId: string } }>();
  const limiter = createIssuanceRateLimitMiddleware(store);

  // Simulate the auth middleware setting companyId before the limiter runs.
  app.use('*', async (c, next) => {
    const auth = c.req.header('Authorization') ?? '';
    // Map "Bearer <key>" to a stable companyId for tests.
    c.set('companyId', auth.startsWith('Bearer company-b') ? 'company-b' : 'company-a');
    return next();
  });

  app.on('POST', '/v1/agents/:agentId/passport', limiter, (c) => {
    if (handlerSpy) handlerSpy.called = true;
    return c.json({ passport: 'issued' }, 201);
  });

  return app;
}

async function post(app: Hono, path: string, apiKey: string) {
  return app.request(path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}` },
  });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('issuance rate limiter', () => {
  let store: InMemoryRateLimitStore;

  beforeEach(() => {
    store = new InMemoryRateLimitStore();
  });

  it('a single request passes', async () => {
    const app = buildApp(store);
    const res = await post(app, '/v1/agents/agent-1/passport', 'key-a');
    expect(res.status).toBe(201);
  });

  it('the 61st request in a minute returns 429', async () => {
    const app = buildApp(store);

    // 60 allowed requests.
    for (let i = 0; i < 60; i++) {
      const r = await post(app, '/v1/agents/agent-1/passport', 'key-a');
      expect(r.status).toBe(201);
    }

    // 61st hits the per-key minute limit.
    const res = await post(app, '/v1/agents/agent-1/passport', 'key-a');
    expect(res.status).toBe(429);
  });

  it('the 429 response body contains error, limit, remaining, and retryAfter', async () => {
    const app = buildApp(store);

    for (let i = 0; i < 60; i++) {
      await post(app, '/v1/agents/agent-1/passport', 'key-a');
    }

    const res = await post(app, '/v1/agents/agent-1/passport', 'key-a');
    expect(res.status).toBe(429);

    const body = await res.json() as Record<string, unknown>;
    expect(typeof body['error']).toBe('string');
    expect(typeof body['limit']).toBe('number');
    expect(typeof body['remaining']).toBe('number');
    expect(typeof body['retryAfter']).toBe('number');

    expect(body['limit']).toBe(60);
    expect(body['remaining']).toBe(0);
    expect((body['retryAfter'] as number)).toBeGreaterThan(0);
  });

  it('requests from different API keys do not share a limit', async () => {
    const app = buildApp(store);

    // Exhaust the limit for key-a.
    for (let i = 0; i < 60; i++) {
      await post(app, '/v1/agents/agent-1/passport', 'key-a');
    }
    const blockedRes = await post(app, '/v1/agents/agent-1/passport', 'key-a');
    expect(blockedRes.status).toBe(429);

    // key-b has a fresh limit — first request must succeed.
    const freshRes = await post(app, '/v1/agents/agent-1/passport', 'key-b');
    expect(freshRes.status).toBe(201);
  });

  it('rate limiter middleware can be applied to any route', async () => {
    const app = new Hono<{ Variables: { companyId: string } }>();
    const limiter = createIssuanceRateLimitMiddleware(store);

    app.use('*', async (c, next) => {
      c.set('companyId', 'test-company');
      return next();
    });

    // Apply the same middleware instance to an unrelated route.
    app.get('/arbitrary-route', limiter, (c) => c.json({ ok: true }));
    app.post('/another-route', limiter, (c) => c.json({ ok: true }));

    const res1 = await app.request('/arbitrary-route', {
      headers: { Authorization: 'Bearer arb-key' },
    });
    expect(res1.status).toBe(200);

    const res2 = await app.request('/another-route', {
      method: 'POST',
      headers: { Authorization: 'Bearer post-key' },
    });
    expect(res2.status).toBe(200);
  });

  it('a 429 response never invokes the passport handler', async () => {
    const spy = { called: false };
    const app = buildApp(store, spy);

    // Exhaust the rate limit.
    for (let i = 0; i < 60; i++) {
      await post(app, '/v1/agents/agent-1/passport', 'key-a');
    }
    spy.called = false; // reset after the allowed requests

    // 61st request — handler must not be called.
    const res = await post(app, '/v1/agents/agent-1/passport', 'key-a');
    expect(res.status).toBe(429);
    expect(spy.called).toBe(false);
  });
});
