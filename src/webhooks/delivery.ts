import { createHmac, randomUUID } from 'node:crypto';
import { DELIVERY_TIMEOUT_MS } from './types.js';

export interface DeliveryResult {
  success: boolean;
  statusCode?: number;
  error?: string;
}

export async function attemptDelivery(
  url: string,
  rawSecret: string,
  event: string,
  payload: Record<string, unknown>,
): Promise<DeliveryResult> {
  const body = JSON.stringify(payload);
  const sig = 'sha256=' + createHmac('sha256', rawSecret).update(body).digest('hex');
  const deliveryId = randomUUID();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vane-Event': event,
        'X-Vane-Signature': sig,
        'X-Vane-Delivery': deliveryId,
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return res.ok
      ? { success: true, statusCode: res.status }
      : { success: false, statusCode: res.status, error: `HTTP ${res.status}` };
  } catch (err) {
    clearTimeout(timeout);
    return { success: false, error: err instanceof Error ? err.message : String(err) };
  }
}
