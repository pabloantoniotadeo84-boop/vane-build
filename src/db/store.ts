import { Pool } from 'pg';
import { randomBytes, randomUUID, createCipheriv, createDecipheriv, createHash, timingSafeEqual } from 'node:crypto';
import type { AttestationRecord, KeyPair, AgentRegistration } from '../crypto/types.js';
import type { WebhookRow, DeliveryRow } from '../webhooks/types.js';
import { logger } from '../logger.js';

// ── Envelope encryption ───────────────────────────────────────────────────────

function deriveMasterKey(): Buffer | null {
  const env = process.env.VANE_MASTER_KEY;
  if (!env) return null;
  return createHash('sha256').update(env, 'utf8').digest();
}

const MASTER_KEY: Buffer | null = deriveMasterKey();

if (!MASTER_KEY) {
  logger.warn('VANE_MASTER_KEY is not set — private keys are stored in plaintext in the database');
}

// Stored format: "enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>"
function encryptPrivateKey(pem: string): string {
  if (!MASTER_KEY) return pem;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const ct = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('hex')}:${tag.toString('hex')}:${ct.toString('hex')}`;
}

function decryptPrivateKey(stored: string): string {
  if (!stored.startsWith('enc:v1:')) {
    if (MASTER_KEY) {
      console.warn('[VANE] WARNING: Plaintext private key found in database. Re-save keys to encrypt.');
    }
    return stored;
  }
  if (!MASTER_KEY) {
    throw new Error('Encrypted private key found in database but VANE_MASTER_KEY is not set');
  }
  const parts = stored.split(':');
  if (parts.length < 5) throw new Error('Malformed encrypted key record');
  const iv  = Buffer.from(parts[2], 'hex');
  const tag = Buffer.from(parts[3], 'hex');
  const ct  = Buffer.from(parts[4], 'hex');
  const decipher = createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ct).toString('utf8') + decipher.final('utf8');
}

export interface CompanyRecord {
  companyId: string;
  spiffeId: string;
  registeredAt: string;
  metadata?: Record<string, unknown>;
}

export class Store {
  private readonly pool: Pool;

  constructor() {
    this.pool = new Pool({ connectionString: process.env.DATABASE_URL });
  }

  async init(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS companies (
        company_id    TEXT PRIMARY KEY,
        spiffe_id     TEXT NOT NULL UNIQUE,
        registered_at TEXT NOT NULL,
        metadata      TEXT
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS keys (
        company_id  TEXT PRIMARY KEY REFERENCES companies(company_id),
        public_key  TEXT NOT NULL,
        private_key TEXT NOT NULL
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        key        TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(company_id),
        label      TEXT,
        created_at TEXT NOT NULL
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS agents (
        agent_id      TEXT NOT NULL,
        company_id    TEXT NOT NULL REFERENCES companies(company_id),
        spiffe_id     TEXT NOT NULL UNIQUE,
        registered_at TEXT NOT NULL,
        metadata      TEXT,
        PRIMARY KEY (agent_id, company_id)
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS records (
        company_id TEXT    NOT NULL REFERENCES companies(company_id),
        idx        INTEGER NOT NULL,
        timestamp  TEXT    NOT NULL,
        payload    TEXT    NOT NULL,
        delegation TEXT,
        hash       TEXT    NOT NULL,
        signature  TEXT    NOT NULL,
        PRIMARY KEY (company_id, idx)
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS keys_history (
        id          TEXT PRIMARY KEY,
        company_id  TEXT NOT NULL REFERENCES companies(company_id),
        public_key  TEXT NOT NULL,
        private_key TEXT NOT NULL,
        retired_at  TEXT NOT NULL
      )
    `);
    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS keys_history_company_retired_idx ON keys_history (company_id, retired_at)
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS revoked_passports (
        jti        TEXT NOT NULL,
        company_id TEXT NOT NULL REFERENCES companies(company_id),
        revoked_at TEXT NOT NULL,
        reason     TEXT,
        PRIMARY KEY (jti, company_id)
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id     TEXT PRIMARY KEY,
        client_secret TEXT NOT NULL,
        company_id    TEXT NOT NULL REFERENCES companies(company_id),
        created_at    TEXT NOT NULL
      )
    `);
    // expires_at stored as Unix epoch milliseconds (BIGINT)
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        token      TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(company_id),
        expires_at BIGINT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS webhooks (
        id          TEXT PRIMARY KEY,
        company_id  TEXT NOT NULL REFERENCES companies(company_id),
        url         TEXT NOT NULL,
        events      TEXT[] NOT NULL,
        secret_hash TEXT NOT NULL,
        active      BOOLEAN NOT NULL DEFAULT true,
        created_at  TEXT NOT NULL
      )
    `);
    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS webhooks_company_id_idx ON webhooks (company_id)
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS webhook_deliveries (
        id            TEXT PRIMARY KEY,
        webhook_id    TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
        event         TEXT NOT NULL,
        payload       JSONB NOT NULL,
        status        TEXT NOT NULL DEFAULT 'pending',
        attempts      INTEGER NOT NULL DEFAULT 0,
        next_retry_at TEXT,
        last_error    TEXT,
        created_at    TEXT NOT NULL
      )
    `);
    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS webhook_deliveries_retry_idx
        ON webhook_deliveries (status, next_retry_at)
        WHERE status = 'pending' AND next_retry_at IS NOT NULL
    `);

    // ── Append-only enforcement on records ────────────────────────────────────
    // Trigger function: reject any UPDATE or DELETE on the records table.
    // CREATE OR REPLACE makes this idempotent across restarts.
    await this.pool.query(`
      CREATE OR REPLACE FUNCTION records_append_only()
      RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'records table is append-only: % is not permitted', TG_OP;
      END;
      $$
    `);

    // DROP + CREATE is the only idempotent way to install triggers on PostgreSQL < 14.
    await this.pool.query(`DROP TRIGGER IF EXISTS records_no_update ON records`);
    await this.pool.query(`
      CREATE TRIGGER records_no_update
        BEFORE UPDATE ON records
        FOR EACH ROW EXECUTE FUNCTION records_append_only()
    `);
    await this.pool.query(`DROP TRIGGER IF EXISTS records_no_delete ON records`);
    await this.pool.query(`
      CREATE TRIGGER records_no_delete
        BEFORE DELETE ON records
        FOR EACH ROW EXECUTE FUNCTION records_append_only()
    `);
  }

  // ── Companies ────────────────────────────────────────────────────────────────

  async createCompany(companyId: string, spiffeId: string, metadata?: Record<string, unknown>): Promise<CompanyRecord> {
    const registeredAt = new Date().toISOString();
    await this.pool.query(
      `INSERT INTO companies (company_id, spiffe_id, registered_at, metadata) VALUES ($1, $2, $3, $4)`,
      [companyId, spiffeId, registeredAt, metadata ? JSON.stringify(metadata) : null],
    );
    return { companyId, spiffeId, registeredAt, metadata };
  }

  async getCompany(companyId: string): Promise<CompanyRecord | null> {
    const { rows } = await this.pool.query<{
      company_id: string; spiffe_id: string; registered_at: string; metadata: string | null;
    }>(
      `SELECT company_id, spiffe_id, registered_at, metadata FROM companies WHERE company_id = $1`,
      [companyId],
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      companyId: r.company_id,
      spiffeId: r.spiffe_id,
      registeredAt: r.registered_at,
      metadata: r.metadata ? JSON.parse(r.metadata) : undefined,
    };
  }

  async listCompanies(): Promise<CompanyRecord[]> {
    const { rows } = await this.pool.query<{
      company_id: string; spiffe_id: string; registered_at: string; metadata: string | null;
    }>(`SELECT company_id, spiffe_id, registered_at, metadata FROM companies`);
    return rows.map((r) => ({
      companyId: r.company_id,
      spiffeId: r.spiffe_id,
      registeredAt: r.registered_at,
      metadata: r.metadata ? JSON.parse(r.metadata) : undefined,
    }));
  }

  // ── Keys ─────────────────────────────────────────────────────────────────────

  async getKeys(companyId: string): Promise<KeyPair | null> {
    const { rows } = await this.pool.query<{ public_key: string; private_key: string }>(
      `SELECT public_key, private_key FROM keys WHERE company_id = $1`,
      [companyId],
    );
    if (!rows[0]) return null;
    return { publicKey: rows[0].public_key, privateKey: decryptPrivateKey(rows[0].private_key) };
  }

  async saveKeys(companyId: string, keys: KeyPair): Promise<void> {
    await this.pool.query(
      `INSERT INTO keys (company_id, public_key, private_key) VALUES ($1, $2, $3)
       ON CONFLICT (company_id) DO UPDATE SET public_key = EXCLUDED.public_key, private_key = EXCLUDED.private_key`,
      [companyId, keys.publicKey, encryptPrivateKey(keys.privateKey)],
    );
  }

  // Copies the current active key into keys_history before rotation.
  async retireCurrentKey(companyId: string): Promise<void> {
    const { rows } = await this.pool.query<{ public_key: string; private_key: string }>(
      `SELECT public_key, private_key FROM keys WHERE company_id = $1`,
      [companyId],
    );
    if (!rows[0]) return;
    const id = randomUUID();
    const retiredAt = new Date().toISOString();
    await this.pool.query(
      `INSERT INTO keys_history (id, company_id, public_key, private_key, retired_at) VALUES ($1, $2, $3, $4, $5)`,
      [id, companyId, rows[0].public_key, rows[0].private_key, retiredAt],
    );
  }

  // Returns retired keys with retired_at >= the supplied ISO cutoff timestamp.
  async getRetiredKeys(
    companyId: string,
    since: string,
  ): Promise<Array<{ id: string; publicKey: string; retiredAt: string }>> {
    const { rows } = await this.pool.query<{ id: string; public_key: string; retired_at: string }>(
      `SELECT id, public_key, retired_at FROM keys_history
       WHERE company_id = $1 AND retired_at >= $2
       ORDER BY retired_at DESC`,
      [companyId, since],
    );
    return rows.map(r => ({ id: r.id, publicKey: r.public_key, retiredAt: r.retired_at }));
  }

  // ── API Keys ─────────────────────────────────────────────────────────────────

  async createApiKey(companyId: string, label?: string): Promise<string> {
    const key = 'vane_' + randomBytes(32).toString('hex');
    await this.pool.query(
      `INSERT INTO api_keys (key, company_id, label, created_at) VALUES ($1, $2, $3, $4)`,
      [key, companyId, label ?? null, new Date().toISOString()],
    );
    return key;
  }

  async validateApiKey(key: string): Promise<{ companyId: string } | null> {
    const { rows } = await this.pool.query<{ company_id: string }>(
      `SELECT company_id FROM api_keys WHERE key = $1`,
      [key],
    );
    if (!rows[0]) return null;
    return { companyId: rows[0].company_id };
  }

  async getFirstApiKey(companyId: string): Promise<{ key: string; label: string | null; createdAt: string } | null> {
    const { rows } = await this.pool.query<{ key: string; label: string | null; created_at: string }>(
      `SELECT key, label, created_at FROM api_keys WHERE company_id = $1 ORDER BY created_at ASC LIMIT 1`,
      [companyId],
    );
    if (!rows[0]) return null;
    return { key: rows[0].key, label: rows[0].label, createdAt: rows[0].created_at };
  }

  async listApiKeys(companyId: string): Promise<Array<{ key: string; label: string | null; createdAt: string }>> {
    const { rows } = await this.pool.query<{ key: string; label: string | null; created_at: string }>(
      `SELECT key, label, created_at FROM api_keys WHERE company_id = $1 ORDER BY created_at ASC`,
      [companyId],
    );
    return rows.map((r) => ({ key: r.key, label: r.label, createdAt: r.created_at }));
  }

  async deleteApiKey(companyId: string, key: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM api_keys WHERE key = $1 AND company_id = $2`,
      [key, companyId],
    );
    return (rowCount ?? 0) > 0;
  }

  // ── Agents ───────────────────────────────────────────────────────────────────

  async registerAgent(reg: AgentRegistration): Promise<void> {
    if (!reg.companyId) throw new Error('companyId is required');
    await this.pool.query(
      `INSERT INTO agents (agent_id, company_id, spiffe_id, registered_at, metadata)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (agent_id, company_id) DO UPDATE SET
         spiffe_id = EXCLUDED.spiffe_id,
         registered_at = EXCLUDED.registered_at,
         metadata = EXCLUDED.metadata`,
      [reg.agentId, reg.companyId, reg.spiffeId, reg.registeredAt, reg.metadata ? JSON.stringify(reg.metadata) : null],
    );
  }

  async getAgent(agentId: string, companyId: string): Promise<AgentRegistration | null> {
    const { rows } = await this.pool.query<{
      agent_id: string; company_id: string; spiffe_id: string; registered_at: string; metadata: string | null;
    }>(
      `SELECT agent_id, company_id, spiffe_id, registered_at, metadata
       FROM agents WHERE agent_id = $1 AND company_id = $2`,
      [agentId, companyId],
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      agentId: r.agent_id,
      spiffeId: r.spiffe_id,
      companyId: r.company_id,
      registeredAt: r.registered_at,
      metadata: r.metadata ? JSON.parse(r.metadata) : undefined,
    };
  }

  // ── Records ──────────────────────────────────────────────────────────────────

  async getAllRecords(companyId: string): Promise<AttestationRecord[]> {
    const { rows } = await this.pool.query<{
      idx: number; timestamp: string; payload: string; delegation: string | null; hash: string; signature: string;
    }>(
      `SELECT idx, timestamp, payload, delegation, hash, signature
       FROM records WHERE company_id = $1 ORDER BY idx ASC`,
      [companyId],
    );
    return rows.map((r) => ({
      index: r.idx,
      timestamp: r.timestamp,
      payload: JSON.parse(r.payload),
      ...(r.delegation && { delegation: JSON.parse(r.delegation) }),
      hash: r.hash,
      signature: r.signature,
    }));
  }

  async insertRecord(companyId: string, record: AttestationRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO records (company_id, idx, timestamp, payload, delegation, hash, signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        companyId,
        record.index,
        record.timestamp,
        JSON.stringify(record.payload),
        record.delegation ? JSON.stringify(record.delegation) : null,
        record.hash,
        record.signature,
      ],
    );
  }

  // ── Passport revocation ───────────────────────────────────────────────────────

  async revokePassport(companyId: string, jti: string, reason?: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO revoked_passports (jti, company_id, revoked_at, reason) VALUES ($1, $2, $3, $4)`,
      [jti, companyId, new Date().toISOString(), reason ?? null],
    );
  }

  async isPassportRevoked(companyId: string, jti: string): Promise<boolean> {
    const { rows } = await this.pool.query(
      `SELECT 1 FROM revoked_passports WHERE jti = $1 AND company_id = $2`,
      [jti, companyId],
    );
    return rows.length > 0;
  }

  async getPassportRevocationDetails(
    companyId: string,
    jti: string,
  ): Promise<{ jti: string; revokedAt: string; reason?: string } | null> {
    const { rows } = await this.pool.query<{ jti: string; revoked_at: string; reason: string | null }>(
      `SELECT jti, revoked_at, reason FROM revoked_passports WHERE jti = $1 AND company_id = $2`,
      [jti, companyId],
    );
    if (!rows[0]) return null;
    return {
      jti: rows[0].jti,
      revokedAt: rows[0].revoked_at,
      ...(rows[0].reason !== null && { reason: rows[0].reason }),
    };
  }

  async getRevokedPassports(companyId: string): Promise<Array<{ jti: string; revokedAt: string; reason?: string }>> {
    const { rows } = await this.pool.query<{ jti: string; revoked_at: string; reason: string | null }>(
      `SELECT jti, revoked_at, reason FROM revoked_passports WHERE company_id = $1 ORDER BY revoked_at ASC`,
      [companyId],
    );
    return rows.map((r) => ({
      jti: r.jti,
      revokedAt: r.revoked_at,
      ...(r.reason !== null && { reason: r.reason }),
    }));
  }

  // ── OAuth clients ─────────────────────────────────────────────────────────────

  async createOAuthClient(companyId: string): Promise<{ clientId: string; clientSecret: string }> {
    const clientId = 'cc_' + randomBytes(16).toString('hex');
    const clientSecret = randomBytes(32).toString('hex');
    const secretHash = createHash('sha256').update(clientSecret, 'hex').digest('hex');
    await this.pool.query(
      `INSERT INTO oauth_clients (client_id, client_secret, company_id, created_at) VALUES ($1, $2, $3, $4)`,
      [clientId, secretHash, companyId, new Date().toISOString()],
    );
    return { clientId, clientSecret };
  }

  async validateOAuthCredentials(clientId: string, clientSecret: string): Promise<{ companyId: string } | null> {
    const { rows } = await this.pool.query<{ client_secret: string; company_id: string }>(
      `SELECT client_secret, company_id FROM oauth_clients WHERE client_id = $1`,
      [clientId],
    );
    if (!rows[0]) return null;
    const candidate = createHash('sha256').update(clientSecret, 'hex').digest('hex');
    // Constant-time comparison to prevent timing attacks.
    if (!timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(rows[0].client_secret, 'hex'))) return null;
    return { companyId: rows[0].company_id };
  }

  async listOAuthClients(companyId: string): Promise<Array<{ clientId: string; createdAt: string }>> {
    const { rows } = await this.pool.query<{ client_id: string; created_at: string }>(
      `SELECT client_id, created_at FROM oauth_clients WHERE company_id = $1 ORDER BY created_at ASC`,
      [companyId],
    );
    return rows.map((r) => ({ clientId: r.client_id, createdAt: r.created_at }));
  }

  // ── OAuth tokens ──────────────────────────────────────────────────────────────

  async createOAuthToken(companyId: string, ttlSeconds = 3600): Promise<string> {
    const token = 'oauth_' + randomBytes(32).toString('hex');
    const expiresAt = Date.now() + ttlSeconds * 1000;
    await this.pool.query(
      `INSERT INTO oauth_tokens (token, company_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
      [token, companyId, expiresAt, new Date().toISOString()],
    );
    return token;
  }

  async validateOAuthToken(token: string): Promise<{ companyId: string } | null> {
    const { rows } = await this.pool.query<{ company_id: string; expires_at: string }>(
      `SELECT company_id, expires_at FROM oauth_tokens WHERE token = $1`,
      [token],
    );
    if (!rows[0]) return null;
    if (Date.now() > Number(rows[0].expires_at)) return null;
    return { companyId: rows[0].company_id };
  }

  // Purge tokens that expired more than one hour ago. Call periodically.
  async purgeExpiredOAuthTokens(): Promise<void> {
    const cutoff = Date.now() - 3600 * 1000;
    await this.pool.query(`DELETE FROM oauth_tokens WHERE expires_at < $1`, [cutoff]);
  }

  // ── Webhooks ──────────────────────────────────────────────────────────────────

  async createWebhook(
    companyId: string,
    url: string,
    events: string[],
  ): Promise<{ webhook: WebhookRow; rawSecret: string }> {
    const id = randomUUID();
    const rawSecret = randomBytes(32).toString('hex');
    const encryptedSecret = encryptPrivateKey(rawSecret);
    const createdAt = new Date().toISOString();

    await this.pool.query(
      `INSERT INTO webhooks (id, company_id, url, events, secret_hash, active, created_at)
       VALUES ($1, $2, $3, $4, $5, true, $6)`,
      [id, companyId, url, events, encryptedSecret, createdAt],
    );

    return {
      webhook: { id, companyId, url, events, active: true, createdAt },
      rawSecret,
    };
  }

  async listWebhooks(companyId: string): Promise<WebhookRow[]> {
    const { rows } = await this.pool.query<{
      id: string; company_id: string; url: string; events: string[]; active: boolean; created_at: string;
    }>(
      `SELECT id, company_id, url, events, active, created_at
       FROM webhooks WHERE company_id = $1 ORDER BY created_at ASC`,
      [companyId],
    );
    return rows.map(r => ({
      id: r.id,
      companyId: r.company_id,
      url: r.url,
      events: r.events,
      active: r.active,
      createdAt: r.created_at,
    }));
  }

  async getWebhookById(id: string, companyId: string): Promise<WebhookRow | null> {
    const { rows } = await this.pool.query<{
      id: string; company_id: string; url: string; events: string[]; active: boolean; created_at: string;
    }>(
      `SELECT id, company_id, url, events, active, created_at
       FROM webhooks WHERE id = $1 AND company_id = $2`,
      [id, companyId],
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return { id: r.id, companyId: r.company_id, url: r.url, events: r.events, active: r.active, createdAt: r.created_at };
  }

  async deleteWebhook(id: string, companyId: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM webhooks WHERE id = $1 AND company_id = $2`,
      [id, companyId],
    );
    return (rowCount ?? 0) > 0;
  }

  // Returns active webhooks subscribed to the given event, with decrypted secrets for HMAC signing.
  async getActiveWebhooksForEvent(
    companyId: string,
    event: string,
  ): Promise<Array<{ id: string; url: string; rawSecret: string }>> {
    const { rows } = await this.pool.query<{ id: string; url: string; secret_hash: string }>(
      `SELECT id, url, secret_hash FROM webhooks
       WHERE company_id = $1 AND active = true AND $2 = ANY(events)`,
      [companyId, event],
    );
    return rows.map(r => ({ id: r.id, url: r.url, rawSecret: decryptPrivateKey(r.secret_hash) }));
  }

  // Returns the webhook URL and decrypted secret for a delivery attempt.
  async getWebhookForDelivery(
    webhookId: string,
  ): Promise<{ url: string; rawSecret: string } | null> {
    const { rows } = await this.pool.query<{ url: string; secret_hash: string }>(
      `SELECT url, secret_hash FROM webhooks WHERE id = $1 AND active = true`,
      [webhookId],
    );
    if (!rows[0]) return null;
    return { url: rows[0].url, rawSecret: decryptPrivateKey(rows[0].secret_hash) };
  }

  // ── Webhook deliveries ────────────────────────────────────────────────────────

  async createDelivery(
    webhookId: string,
    event: string,
    payload: Record<string, unknown>,
  ): Promise<DeliveryRow> {
    const id = randomUUID();
    const createdAt = new Date().toISOString();

    await this.pool.query(
      `INSERT INTO webhook_deliveries (id, webhook_id, event, payload, status, attempts, created_at)
       VALUES ($1, $2, $3, $4, 'pending', 0, $5)`,
      [id, webhookId, event, payload, createdAt],
    );

    return { id, webhookId, event, payload, status: 'pending', attempts: 0, nextRetryAt: null, lastError: null, createdAt };
  }

  async markDeliveryDelivered(id: string, attempts: number): Promise<void> {
    await this.pool.query(
      `UPDATE webhook_deliveries SET status = 'delivered', attempts = $2, next_retry_at = NULL WHERE id = $1`,
      [id, attempts],
    );
  }

  async markDeliveryFailed(id: string, attempts: number, lastError: string): Promise<void> {
    await this.pool.query(
      `UPDATE webhook_deliveries SET status = 'failed', attempts = $2, last_error = $3, next_retry_at = NULL WHERE id = $1`,
      [id, attempts, lastError],
    );
  }

  async scheduleDeliveryRetry(
    id: string,
    attempts: number,
    nextRetryAt: string,
    lastError: string | null,
  ): Promise<void> {
    await this.pool.query(
      `UPDATE webhook_deliveries SET attempts = $2, next_retry_at = $3, last_error = $4 WHERE id = $1`,
      [id, attempts, nextRetryAt, lastError],
    );
  }

  // Returns all pending deliveries whose next_retry_at is <= now (due for retry).
  async getPendingRetries(now: string): Promise<Array<{
    deliveryId: string;
    webhookId: string;
    event: string;
    payload: Record<string, unknown>;
    attempts: number;
    url: string;
    rawSecret: string;
  }>> {
    const { rows } = await this.pool.query<{
      id: string; webhook_id: string; event: string; payload: Record<string, unknown>;
      attempts: number; url: string; secret_hash: string;
    }>(
      `SELECT d.id, d.webhook_id, d.event, d.payload, d.attempts, w.url, w.secret_hash
       FROM webhook_deliveries d
       JOIN webhooks w ON d.webhook_id = w.id
       WHERE d.status = 'pending'
         AND d.next_retry_at IS NOT NULL
         AND d.next_retry_at <= $1`,
      [now],
    );
    return rows.map(r => ({
      deliveryId: r.id,
      webhookId: r.webhook_id,
      event: r.event,
      payload: r.payload,
      attempts: r.attempts,
      url: r.url,
      rawSecret: decryptPrivateKey(r.secret_hash),
    }));
  }
}
