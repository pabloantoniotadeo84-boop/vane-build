import type { MiddlewareHandler } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';

const WINDOW_MS = 60_000;

const LIMITS = {
  sensitive: 10,   // POST /v1/setup, POST /v1/oauth/token
  attest:    100,  // POST /v1/attest
  standard:  1000, // everything else
} as const;

type Tier = keyof typeof LIMITS;

interface Bucket {
  timestamps: number[];
}

const buckets = new Map<string, Bucket>();

// Purge empty buckets once per window to prevent unbounded Map growth.
setInterval(() => {
  const cutoff = Date.now() - WINDOW_MS;
  for (const [key, bucket] of buckets.entries()) {
    bucket.timestamps = bucket.timestamps.filter(t => t > cutoff);
    if (bucket.timestamps.length === 0) buckets.delete(key);
  }
}, WINDOW_MS).unref();

function getTier(method: string, path: string): Tier {
  if (method === 'POST' && path === '/v1/attest') return 'attest';
  if (
    (method === 'POST' && path === '/v1/setup') ||
    (method === 'POST' && path === '/v1/oauth/token')
  ) return 'sensitive';
  return 'standard';
}

function getRateLimitKey(c: Parameters<MiddlewareHandler>[0]): string {
  const auth = c.req.header('Authorization');
  if (auth?.startsWith('Bearer ')) return `token:${auth.slice(7)}`;
  try {
    const info = getConnInfo(c);
    return `ip:${info.remote.address ?? 'unknown'}`;
  } catch {
    return 'ip:unknown';
  }
}

export function rateLimitMiddleware(): MiddlewareHandler {
  return async (c, next) => {
    const tier = getTier(c.req.method, c.req.path);
    const limit = LIMITS[tier];
    const key = `${tier}:${getRateLimitKey(c)}`;
    const now = Date.now();
    const cutoff = now - WINDOW_MS;

    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { timestamps: [] };
      buckets.set(key, bucket);
    }

    // Drop timestamps outside the sliding window.
    bucket.timestamps = bucket.timestamps.filter(t => t > cutoff);

    const count = bucket.timestamps.length;

    // Reset = when the oldest entry in the window expires (or now+window if empty).
    const resetMs = count > 0 ? bucket.timestamps[0] + WINDOW_MS : now + WINDOW_MS;
    const resetSec = Math.ceil(resetMs / 1000);

    c.header('X-RateLimit-Limit', String(limit));
    c.header('X-RateLimit-Reset', String(resetSec));

    if (count >= limit) {
      c.header('X-RateLimit-Remaining', '0');
      c.header('Retry-After', String(Math.ceil((resetMs - now) / 1000)));
      return c.json({ error: 'Too Many Requests' }, 429);
    }

    bucket.timestamps.push(now);
    // Remaining = how many more requests are allowed after this one.
    c.header('X-RateLimit-Remaining', String(limit - count - 1));

    await next();
  };
}
