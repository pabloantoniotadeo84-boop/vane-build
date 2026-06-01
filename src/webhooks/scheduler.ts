import type { Store } from '../db/store.js';
import { attemptDelivery } from './delivery.js';
import { BACKOFF_DELAYS_MS, MAX_DELIVERY_ATTEMPTS, RETRY_INTERVAL_MS } from './types.js';
import { logger } from '../logger.js';

export function startWebhookScheduler(store: Store): NodeJS.Timeout {
  return setInterval(() => void runRetries(store), RETRY_INTERVAL_MS);
}

async function runRetries(store: Store): Promise<void> {
  let due: Awaited<ReturnType<Store['getPendingRetries']>>;
  try {
    due = await store.getPendingRetries(new Date().toISOString());
  } catch (err) {
    logger.error({ err }, 'webhook scheduler: failed to fetch pending retries');
    return;
  }

  for (const item of due) {
    void processRetry(store, item).catch(err =>
      logger.error({ err, deliveryId: item.deliveryId }, 'webhook scheduler: retry error'),
    );
  }
}

async function processRetry(
  store: Store,
  item: Awaited<ReturnType<Store['getPendingRetries']>>[number],
): Promise<void> {
  const result = await attemptDelivery(item.url, item.rawSecret, item.event, item.payload);
  const newAttempts = item.attempts + 1;

  if (result.success) {
    await store.markDeliveryDelivered(item.deliveryId, newAttempts);
  } else if (newAttempts >= MAX_DELIVERY_ATTEMPTS) {
    await store.markDeliveryFailed(item.deliveryId, newAttempts, result.error ?? 'delivery failed');
    logger.warn({ deliveryId: item.deliveryId, webhookId: item.webhookId }, 'webhook delivery permanently failed');
  } else {
    const nextRetryAt = new Date(Date.now() + BACKOFF_DELAYS_MS[item.attempts]).toISOString();
    await store.scheduleDeliveryRetry(item.deliveryId, newAttempts, nextRetryAt, result.error ?? null);
  }
}
