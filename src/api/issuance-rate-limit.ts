import type { MiddlewareHandler } from 'hono';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Absolute Unix timestamp (ms) when the oldest event in the window expires. */
  resetMs: number;
}

/**
 * Persistence contract for the issuance rate limiter.
 * Implemented by Store (PostgreSQL) and InMemoryRateLimitStore (tests).
 */
export interface IssuanceRateLimitStore {
  checkAndIncrement(
    key: string,
    windowMs: number,
    limit: number,
    nowMs: number,
  ): Promise<RateLimitResult>;
}

/**
 * In-memory implementation for unit tests.
 * Not safe for multi-instance production use — counters are lost on restart.
 */
export class InMemoryRateLimitStore implements IssuanceRateLimitStore {
  private readonly events = new Map<string, number[]>();

  async checkAndIncrement(
    key: string,
    windowMs: number,
    limit: number,
    nowMs: number,
  ): Promise<RateLimitResult> {
    const cutoff = nowMs - windowMs;
    const existing = this.events.get(key) ?? [];
    // Prune events outside the window.
    const inWindow = existing.filter((t) => t > cutoff);
    const count = inWindow.length;
    const allowed = count < limit;
    const oldestTs = inWindow[0] ?? null;
    const resetMs = oldestTs !== null ? oldestTs + windowMs : nowMs + windowMs;

    if (allowed) {
      inWindow.push(nowMs);
      this.events.set(key, inWindow);
    }

    return {
      allowed,
      limit,
      remaining: allowed ? limit - count - 1 : 0,
      resetMs,
    };
  }

  reset(): void {
    this.events.clear();
  }
}

const MINUTE_MS = 60_000;
const HOUR_MS   = 3_600_000;
const DAY_MS    = 86_400_000;

/**
 * Sliding-window rate limiter for credential issuance endpoints.
 *
 * Enforces three independent windows per request:
 *   - 60  requests / minute  per API key
 *   - 1000 requests / hour   per API key
 *   - 10000 requests / day   per company
 *
 * Returns 429 with JSON body { error, limit, remaining, retryAfter } when any
 * window is exceeded. Designed to be applied to specific routes, not globally.
 *
 * Usage:
 *   const limiter = createIssuanceRateLimitMiddleware(store);
 *   app.on('POST', '/v1/agents/:id/passport', limiter);
 */
export function createIssuanceRateLimitMiddleware(
  rlStore: IssuanceRateLimitStore,
): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.req.header('Authorization');
    const apiKey = auth?.startsWith('Bearer ') ? auth.slice(7) : '';
    // companyId is set by the auth middleware, which runs before this one.
    const companyId = (c.get as (key: string) => string | undefined)('companyId') ?? '';
    const nowMs = Date.now();

    const windows: Array<{ key: string; windowMs: number; limit: number }> = [
      { key: `rl:min:${apiKey}`,        windowMs: MINUTE_MS, limit: 60 },
      { key: `rl:hr:${apiKey}`,         windowMs: HOUR_MS,   limit: 1000 },
      { key: `rl:day:cmp:${companyId}`, windowMs: DAY_MS,    limit: 10000 },
    ];

    for (const { key, windowMs, limit } of windows) {
      const result = await rlStore.checkAndIncrement(key, windowMs, limit, nowMs);
      if (!result.allowed) {
        const retryAfter = Math.max(1, Math.ceil((result.resetMs - nowMs) / 1000));
        return c.json({ error: 'Too Many Requests', limit, remaining: 0, retryAfter }, 429);
      }
    }

    return next();
  };
}
