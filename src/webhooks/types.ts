export interface WebhookRow {
  id: string;
  companyId: string;
  url: string;
  events: string[];
  active: boolean;
  createdAt: string;
}

export interface DeliveryRow {
  id: string;
  webhookId: string;
  event: string;
  payload: Record<string, unknown>;
  status: 'pending' | 'delivered' | 'failed';
  attempts: number;
  nextRetryAt: string | null;
  lastError: string | null;
  createdAt: string;
}

// Delays used after each failed attempt (index = current attempts count before increment)
export const BACKOFF_DELAYS_MS = [
  30_000,      // 30 seconds  (after 1st attempt)
  300_000,     // 5 minutes   (after 2nd attempt)
  1_800_000,   // 30 minutes  (after 3rd attempt)
];

// Total attempts allowed: 1 initial + 3 retries = 4
export const MAX_DELIVERY_ATTEMPTS = BACKOFF_DELAYS_MS.length + 1;
export const DELIVERY_TIMEOUT_MS = 10_000;
export const RETRY_INTERVAL_MS = 10_000;
