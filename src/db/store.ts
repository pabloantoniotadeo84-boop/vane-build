import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { AttestationRecord, KeyPair, AgentRegistration } from '../crypto/types.js';

const DB_PATH = process.env.DB_PATH ?? join(process.cwd(), 'counsel.db');

export interface CompanyRecord {
  companyId: string;
  spiffeId: string;
  registeredAt: string;
  metadata?: Record<string, unknown>;
}

export class Store {
  private readonly db: DatabaseSync;

  constructor(path = DB_PATH) {
    this.db = new DatabaseSync(path);
    this.ensureSchema();
  }

  private ensureSchema(): void {
    // Detect old single-tenant schema by the presence of keys.id (the singleton constraint).
    // If found, drop all old tables and start fresh with the multi-tenant schema.
    const keysInfo = this.db
      .prepare('PRAGMA table_info(keys)')
      .all() as Array<{ name: string }>;
    if (keysInfo.some((c) => c.name === 'id')) {
      this.db.exec(`
        DROP TABLE IF EXISTS records;
        DROP TABLE IF EXISTS agents;
        DROP TABLE IF EXISTS api_keys;
        DROP TABLE IF EXISTS keys;
      `);
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS companies (
        company_id    TEXT PRIMARY KEY,
        spiffe_id     TEXT NOT NULL UNIQUE,
        registered_at TEXT NOT NULL,
        metadata      TEXT
      );
      CREATE TABLE IF NOT EXISTS keys (
        company_id TEXT PRIMARY KEY REFERENCES companies(company_id),
        public     TEXT NOT NULL,
        private    TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS api_keys (
        key        TEXT PRIMARY KEY,
        company_id TEXT NOT NULL REFERENCES companies(company_id),
        label      TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS agents (
        agent_id      TEXT NOT NULL,
        company_id    TEXT NOT NULL REFERENCES companies(company_id),
        spiffe_id     TEXT NOT NULL UNIQUE,
        registered_at TEXT NOT NULL,
        metadata      TEXT,
        PRIMARY KEY (agent_id, company_id)
      );
      CREATE TABLE IF NOT EXISTS records (
        company_id TEXT    NOT NULL REFERENCES companies(company_id),
        idx        INTEGER NOT NULL,
        timestamp  TEXT    NOT NULL,
        payload    TEXT    NOT NULL,
        delegation TEXT,
        hash       TEXT    NOT NULL,
        signature  TEXT    NOT NULL,
        PRIMARY KEY (company_id, idx)
      );
      CREATE TABLE IF NOT EXISTS revoked_passports (
        jti        TEXT NOT NULL,
        company_id TEXT NOT NULL REFERENCES companies(company_id),
        revoked_at TEXT NOT NULL,
        reason     TEXT,
        PRIMARY KEY (jti, company_id)
      );
    `);
  }

  // ── Companies ────────────────────────────────────────────────────────────────

  createCompany(companyId: string, spiffeId: string, metadata?: Record<string, unknown>): CompanyRecord {
    const registeredAt = new Date().toISOString();
    this.db
      .prepare(`INSERT INTO companies (company_id, spiffe_id, registered_at, metadata) VALUES (?, ?, ?, ?)`)
      .run(companyId, spiffeId, registeredAt, metadata ? JSON.stringify(metadata) : null);
    return { companyId, spiffeId, registeredAt, metadata };
  }

  getCompany(companyId: string): CompanyRecord | null {
    const row = this.db
      .prepare(`SELECT company_id, spiffe_id, registered_at, metadata FROM companies WHERE company_id = ?`)
      .get(companyId) as { company_id: string; spiffe_id: string; registered_at: string; metadata: string | null } | undefined;
    if (!row) return null;
    return {
      companyId: row.company_id,
      spiffeId: row.spiffe_id,
      registeredAt: row.registered_at,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }

  listCompanies(): CompanyRecord[] {
    const rows = this.db
      .prepare(`SELECT company_id, spiffe_id, registered_at, metadata FROM companies`)
      .all() as Array<{ company_id: string; spiffe_id: string; registered_at: string; metadata: string | null }>;
    return rows.map((r) => ({
      companyId: r.company_id,
      spiffeId: r.spiffe_id,
      registeredAt: r.registered_at,
      metadata: r.metadata ? JSON.parse(r.metadata) : undefined,
    }));
  }

  // ── Keys ─────────────────────────────────────────────────────────────────────

  getKeys(companyId: string): KeyPair | null {
    const row = this.db
      .prepare(`SELECT public, private FROM keys WHERE company_id = ?`)
      .get(companyId) as { public: string; private: string } | undefined;
    if (!row) return null;
    return { publicKey: row.public, privateKey: row.private };
  }

  saveKeys(companyId: string, keys: KeyPair): void {
    this.db
      .prepare(`INSERT OR REPLACE INTO keys (company_id, public, private) VALUES (?, ?, ?)`)
      .run(companyId, keys.publicKey, keys.privateKey);
  }

  // ── API Keys ─────────────────────────────────────────────────────────────────

  createApiKey(companyId: string, label?: string): string {
    const key = 'counsel_' + randomBytes(32).toString('hex');
    this.db
      .prepare(`INSERT INTO api_keys (key, company_id, label, created_at) VALUES (?, ?, ?, ?)`)
      .run(key, companyId, label ?? null, new Date().toISOString());
    return key;
  }

  // Returns the companyId if the key is valid, null otherwise.
  validateApiKey(key: string): { companyId: string } | null {
    const row = this.db
      .prepare(`SELECT company_id FROM api_keys WHERE key = ?`)
      .get(key) as { company_id: string } | undefined;
    if (!row) return null;
    return { companyId: row.company_id };
  }

  getFirstApiKey(companyId: string): { key: string; label: string | null; createdAt: string } | null {
    const row = this.db
      .prepare(`SELECT key, label, created_at FROM api_keys WHERE company_id = ? ORDER BY rowid ASC LIMIT 1`)
      .get(companyId) as { key: string; label: string | null; created_at: string } | undefined;
    if (!row) return null;
    return { key: row.key, label: row.label, createdAt: row.created_at };
  }

  // ── Agents ───────────────────────────────────────────────────────────────────

  registerAgent(reg: AgentRegistration): void {
    if (!reg.companyId) throw new Error('companyId is required');
    this.db
      .prepare(
        `INSERT OR REPLACE INTO agents (agent_id, company_id, spiffe_id, registered_at, metadata)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        reg.agentId,
        reg.companyId,
        reg.spiffeId,
        reg.registeredAt,
        reg.metadata ? JSON.stringify(reg.metadata) : null,
      );
  }

  getAgent(agentId: string, companyId: string): AgentRegistration | null {
    const row = this.db
      .prepare(
        `SELECT agent_id, company_id, spiffe_id, registered_at, metadata
         FROM agents WHERE agent_id = ? AND company_id = ?`,
      )
      .get(agentId, companyId) as
      | { agent_id: string; company_id: string; spiffe_id: string; registered_at: string; metadata: string | null }
      | undefined;
    if (!row) return null;
    return {
      agentId: row.agent_id,
      spiffeId: row.spiffe_id,
      companyId: row.company_id,
      registeredAt: row.registered_at,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }

  // ── Records ──────────────────────────────────────────────────────────────────

  getAllRecords(companyId: string): AttestationRecord[] {
    const rows = this.db
      .prepare(
        `SELECT idx, timestamp, payload, delegation, hash, signature
         FROM records WHERE company_id = ? ORDER BY idx ASC`,
      )
      .all(companyId) as Array<{
        idx: number;
        timestamp: string;
        payload: string;
        delegation: string | null;
        hash: string;
        signature: string;
      }>;
    return rows.map((r) => ({
      index: r.idx,
      timestamp: r.timestamp,
      payload: JSON.parse(r.payload),
      ...(r.delegation && { delegation: JSON.parse(r.delegation) }),
      hash: r.hash,
      signature: r.signature,
    }));
  }

  insertRecord(companyId: string, record: AttestationRecord): void {
    this.db
      .prepare(
        `INSERT INTO records (company_id, idx, timestamp, payload, delegation, hash, signature)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        companyId,
        record.index,
        record.timestamp,
        JSON.stringify(record.payload),
        record.delegation ? JSON.stringify(record.delegation) : null,
        record.hash,
        record.signature,
      );
  }

  // ── Passport revocation ───────────────────────────────────────────────────────

  revokePassport(companyId: string, jti: string, reason?: string): void {
    this.db
      .prepare(
        `INSERT INTO revoked_passports (jti, company_id, revoked_at, reason) VALUES (?, ?, ?, ?)`,
      )
      .run(jti, companyId, new Date().toISOString(), reason ?? null);
  }

  isPassportRevoked(companyId: string, jti: string): boolean {
    const row = this.db
      .prepare(`SELECT 1 FROM revoked_passports WHERE jti = ? AND company_id = ?`)
      .get(jti, companyId);
    return row !== undefined;
  }

  getRevokedPassports(companyId: string): Array<{ jti: string; revokedAt: string; reason?: string }> {
    const rows = this.db
      .prepare(
        `SELECT jti, revoked_at, reason FROM revoked_passports WHERE company_id = ? ORDER BY revoked_at ASC`,
      )
      .all(companyId) as Array<{ jti: string; revoked_at: string; reason: string | null }>;
    return rows.map((r) => ({
      jti: r.jti,
      revokedAt: r.revoked_at,
      ...(r.reason !== null && { reason: r.reason }),
    }));
  }
}
