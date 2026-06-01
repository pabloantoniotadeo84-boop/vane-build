import type { Store } from '../db/store.js';
import { attemptDelivery } from './delivery.js';
import { BACKOFF_DELAYS_MS, MAX_DELIVERY_ATTEMPTS } from './types.js';
import { logger } from '../logger.js';

export { startWebhookScheduler } from './scheduler.js';

export async function fireWebhookEvent(
  store: Store,
  companyId: string,
  event: string,
  payload: Record<string, unknown>,
): Promise<void> {
  console.log('webhook firing for event:', event);
  let webhooks: Awaited<ReturnType<Store['getActiveWebhooksForEvent']>>;
  try {
    webhooks = await store.getActiveWebhooksForEvent(companyId, event);
    logger.info({ companyId, event, count: webhooks.length }, 'fireWebhookEvent: webhooks loaded');
  } catch (err) {
    logger.error({ err, companyId, event }, 'fireWebhookEvent: failed to load webhooks');
    return;
  }

  for (const wh of webhooks) {
    logger.info({ webhookId: wh.id, url: wh.url, event }, 'fireWebhookEvent: attempting delivery');
    void deliverToWebhook(store, wh, event, payload).catch(err =>
      logger.error({ err, webhookId: wh.id, url: wh.url, event }, 'fireWebhookEvent: delivery error'),
    );
  }
}

async function deliverToWebhook(
  store: Store,
  wh: { id: string; url: string; rawSecret: string },
  event: string,
  payload: Record<string, unknown>,
): Promise<void> {
  const delivery = await store.createDelivery(wh.id, event, payload);
  const result = await attemptDelivery(wh.url, wh.rawSecret, event, payload);
  const newAttempts = 1;

  if (result.success) {
    await store.markDeliveryDelivered(delivery.id, newAttempts);
  } else if (newAttempts >= MAX_DELIVERY_ATTEMPTS) {
    await store.markDeliveryFailed(delivery.id, newAttempts, result.error ?? 'delivery failed');
  } else {
    // BACKOFF_DELAYS_MS[0] = 30s for the first retry
    const nextRetryAt = new Date(Date.now() + BACKOFF_DELAYS_MS[0]).toISOString();
    await store.scheduleDeliveryRetry(delivery.id, newAttempts, nextRetryAt, result.error ?? null);
  }
}
