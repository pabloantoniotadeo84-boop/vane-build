import { Pool } from 'pg';
import { randomBytes, createCipheriv, createDecipheriv, createHash, timingSafeEqual } from 'node:crypto';
import type { AttestationRecord, KeyPair, AgentRegistration } from '../crypto/types.js';
import { logger } from '../logger.js';

// ── Envelope encryption ───────────────────────────────────────────────────────

function deriveMasterKey(): Buffer | null {
  const env = process.env.COUNSEL_MASTER_KEY;
  if (!env) return null;
  return createHash('sha256').update(env, 'utf8').digest();
}

const MASTER_KEY: Buffer | null = deriveMasterKey();

if (!MASTER_KEY) {
  logger.warn('COUNSEL_MASTER_KEY is not set — private keys are stored in plaintext in the database');
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
      console.warn('[COUNSEL] WARNING: Plaintext private key found in database. Re-save keys to encrypt.');
    }
    return stored;
  }
  if (!MASTER_KEY) {
    throw new Error('Encrypted private key found in database but COUNSEL_MASTER_KEY is not set');
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

  // ── API Keys ─────────────────────────────────────────────────────────────────

  async createApiKey(companyId: string, label?: string): Promise<string> {
    const key = 'counsel_' + randomBytes(32).toString('hex');
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
}
