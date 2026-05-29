import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { AttestationRecord, KeyPair, AgentRegistration } from '../crypto/types.js';

const DB_PATH = process.env.DB_PATH ?? join(process.cwd(), 'counsel.db');

export class Store {
  private readonly db: DatabaseSync;

  constructor(path = DB_PATH) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS keys (
        id      INTEGER PRIMARY KEY CHECK (id = 1),
        public  TEXT NOT NULL,
        private TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS records (
        idx        INTEGER PRIMARY KEY,
        timestamp  TEXT    NOT NULL,
        payload    TEXT    NOT NULL,
        delegation TEXT,
        hash       TEXT    NOT NULL,
        signature  TEXT    NOT NULL
      );
      CREATE TABLE IF NOT EXISTS agents (
        agent_id      TEXT PRIMARY KEY,
        spiffe_id     TEXT NOT NULL UNIQUE,
        company_id    TEXT,
        registered_at TEXT NOT NULL,
        metadata      TEXT
      );
      CREATE TABLE IF NOT EXISTS api_keys (
        key        TEXT PRIMARY KEY,
        label      TEXT,
        created_at TEXT NOT NULL
      );
    `);
    this.migrate();
  }

  private migrate(): void {
    const cols = this.db
      .prepare('PRAGMA table_info(records)')
      .all() as Array<{ name: string }>;

    // Drop previous_hash column if this DB was created under the old linked-list schema.
    if (cols.some((c) => c.name === 'previous_hash')) {
      this.db.exec(`
        CREATE TABLE records_new (
          idx        INTEGER PRIMARY KEY,
          timestamp  TEXT    NOT NULL,
          payload    TEXT    NOT NULL,
          delegation TEXT,
          hash       TEXT    NOT NULL,
          signature  TEXT    NOT NULL
        );
        INSERT INTO records_new (idx, timestamp, payload, hash, signature)
          SELECT idx, timestamp, payload, hash, signature FROM records;
        DROP TABLE records;
        ALTER TABLE records_new RENAME TO records;
      `);
      return;
    }

    // Add delegation column to databases that pre-date the field.
    if (!cols.some((c) => c.name === 'delegation')) {
      this.db.exec(`ALTER TABLE records ADD COLUMN delegation TEXT`);
    }
  }

  getKeys(): KeyPair | null {
    const row = this.db.prepare('SELECT public, private FROM keys WHERE id = 1').get() as
      | { public: string; private: string }
      | undefined;
    if (!row) return null;
    return { publicKey: row.public, privateKey: row.private };
  }

  saveKeys(keys: KeyPair): void {
    this.db
      .prepare('INSERT OR REPLACE INTO keys (id, public, private) VALUES (1, ?, ?)')
      .run(keys.publicKey, keys.privateKey);
  }

  getAllRecords(): AttestationRecord[] {
    const rows = this.db
      .prepare('SELECT idx, timestamp, payload, delegation, hash, signature FROM records ORDER BY idx ASC')
      .all() as Array<{
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

  insertRecord(record: AttestationRecord): void {
    this.db
      .prepare(
        `INSERT INTO records (idx, timestamp, payload, delegation, hash, signature) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.index,
        record.timestamp,
        JSON.stringify(record.payload),
        record.delegation ? JSON.stringify(record.delegation) : null,
        record.hash,
        record.signature,
      );
  }

  registerAgent(reg: AgentRegistration): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO agents (agent_id, spiffe_id, company_id, registered_at, metadata)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        reg.agentId,
        reg.spiffeId,
        reg.companyId ?? null,
        reg.registeredAt,
        reg.metadata ? JSON.stringify(reg.metadata) : null,
      );
  }

  hasApiKeys(): boolean {
    const row = this.db.prepare('SELECT 1 FROM api_keys LIMIT 1').get();
    return row !== undefined;
  }

  createApiKey(label?: string): string {
    const key = 'counsel_' + randomBytes(32).toString('hex');
    this.db
      .prepare('INSERT INTO api_keys (key, label, created_at) VALUES (?, ?, ?)')
      .run(key, label ?? null, new Date().toISOString());
    return key;
  }

  validateApiKey(key: string): boolean {
    const row = this.db.prepare('SELECT 1 FROM api_keys WHERE key = ?').get(key);
    return row !== undefined;
  }

  getAgent(agentId: string): AgentRegistration | null {
    const row = this.db
      .prepare('SELECT agent_id, spiffe_id, company_id, registered_at, metadata FROM agents WHERE agent_id = ?')
      .get(agentId) as
      | { agent_id: string; spiffe_id: string; company_id: string | null; registered_at: string; metadata: string | null }
      | undefined;
    if (!row) return null;
    return {
      agentId: row.agent_id,
      spiffeId: row.spiffe_id,
      companyId: row.company_id ?? undefined,
      registeredAt: row.registered_at,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }
}
