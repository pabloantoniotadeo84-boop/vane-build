#!/usr/bin/env -S npx tsx
/**
 * Vane database restore tool.
 *
 *   tsx scripts/restore-db.ts <backup-file.json>
 *
 * Reads a backup produced by backup-db.ts, verifies the SHA-256 checksum
 * before touching the database, drops and recreates all tables in FK-safe
 * order, restores every row, then verifies row counts match the backup.
 *
 * The exported pure function applyBackup is used by the test suite via
 * injected in-memory fakes — no Postgres connection required for tests.
 */
import { readFileSync, existsSync } from 'node:fs';
import type { Pool } from 'pg';
import {
  computeChecksum,
  INSERT_ORDER,
  ALL_TABLES,
  type BackupData,
  type TableName,
} from './backup-db.js';

// ── Read + verify backup file ─────────────────────────────────────────────────

/** Reads a backup JSON file, verifies its checksum, and returns the parsed data. */
export function readAndVerifyBackup(backupPath: string): BackupData {
  if (!existsSync(backupPath)) {
    throw new Error(`backup file not found: ${backupPath}`);
  }
  const checksumPath = `${backupPath}.sha256`;
  if (!existsSync(checksumPath)) {
    throw new Error(`checksum file not found: ${checksumPath}`);
  }
  const content = readFileSync(backupPath, 'utf8');
  const stored = readFileSync(checksumPath, 'utf8').trim();
  if (stored !== computeChecksum(content)) {
    throw new Error('checksum mismatch — backup file may be corrupted or tampered');
  }
  return JSON.parse(content) as BackupData;
}

// ── Injectable restore primitives ─────────────────────────────────────────────

/** Clears all data in FK-safe reverse order before restoring. */
export type TableTruncator = () => Promise<void>;

/** Inserts a batch of rows into a table. Column names are taken from row keys. */
export type RowWriter = (table: TableName, rows: Record<string, unknown>[]) => Promise<void>;

/** Returns the row count for a table. */
export type RowCounter = (table: TableName) => Promise<number>;

export interface RestoreOptions {
  truncateAll: TableTruncator;
  writeRows: RowWriter;
  countRows: RowCounter;
}

/**
 * Core restore logic — fully injectable, no Postgres dependency.
 *
 * Sequence:
 *   1. Truncate all tables (caller decides how).
 *   2. Insert rows from the backup in FK-safe order.
 *   3. Count rows in every table and return the map.
 *
 * Throws if any table's restored count does not match the backup count.
 */
export async function applyBackup(
  data: BackupData,
  { truncateAll, writeRows, countRows }: RestoreOptions,
): Promise<Record<TableName, number>> {
  await truncateAll();

  for (const table of INSERT_ORDER) {
    const rows = data.tables[table] ?? [];
    if (rows.length > 0) {
      await writeRows(table, rows);
    }
  }

  const counts = {} as Record<TableName, number>;
  for (const table of ALL_TABLES) {
    const actual = await countRows(table);
    const expected = (data.tables[table] ?? []).length;
    if (actual !== expected) {
      throw new Error(
        `row count mismatch for table "${table}": expected ${expected}, got ${actual}`,
      );
    }
    counts[table] = actual;
  }
  return counts;
}

// ── Full Postgres schema DDL (used by restoreDatabase) ───────────────────────
// This is an intentional duplication of the DDL from src/db/store.ts so the
// restore script is fully self-contained and can recreate the schema without
// importing application code.

async function recreateSchema(pool: Pool): Promise<void> {
  // Base tables — no FK deps
  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies (
      company_id    TEXT PRIMARY KEY,
      spiffe_id     TEXT NOT NULL UNIQUE,
      registered_at TEXT NOT NULL,
      metadata      TEXT
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      company_id  TEXT PRIMARY KEY REFERENCES companies(company_id),
      public_key  TEXT NOT NULL,
      private_key TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      key        TEXT PRIMARY KEY,
      company_id TEXT NOT NULL REFERENCES companies(company_id),
      label      TEXT,
      created_at TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agents (
      agent_id      TEXT NOT NULL,
      company_id    TEXT NOT NULL REFERENCES companies(company_id),
      spiffe_id     TEXT NOT NULL UNIQUE,
      registered_at TEXT NOT NULL,
      metadata      TEXT,
      PRIMARY KEY (agent_id, company_id)
    )
  `);
  await pool.query(`
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys_history (
      id          TEXT PRIMARY KEY,
      company_id  TEXT NOT NULL REFERENCES companies(company_id),
      public_key  TEXT NOT NULL,
      private_key TEXT NOT NULL,
      retired_at  TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS keys_history_company_retired_idx
      ON keys_history (company_id, retired_at)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS revoked_passports (
      jti        TEXT NOT NULL,
      company_id TEXT NOT NULL REFERENCES companies(company_id),
      revoked_at TEXT NOT NULL,
      reason     TEXT,
      PRIMARY KEY (jti, company_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id     TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      company_id    TEXT NOT NULL REFERENCES companies(company_id),
      created_at    TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      token      TEXT PRIMARY KEY,
      company_id TEXT NOT NULL REFERENCES companies(company_id),
      expires_at BIGINT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  await pool.query(`
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
  await pool.query(`
    CREATE INDEX IF NOT EXISTS webhooks_company_id_idx ON webhooks (company_id)
  `);
  await pool.query(`
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
  await pool.query(`
    CREATE INDEX IF NOT EXISTS webhook_deliveries_retry_idx
      ON webhook_deliveries (status, next_retry_at)
      WHERE status = 'pending' AND next_retry_at IS NOT NULL
  `);
  // Append-only enforcement on records
  await pool.query(`
    CREATE OR REPLACE FUNCTION records_append_only()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'records table is append-only: % is not permitted', TG_OP;
    END;
    $$
  `);
  await pool.query(`DROP TRIGGER IF EXISTS records_no_update ON records`);
  await pool.query(`
    CREATE TRIGGER records_no_update
      BEFORE UPDATE ON records
      FOR EACH ROW EXECUTE FUNCTION records_append_only()
  `);
  await pool.query(`DROP TRIGGER IF EXISTS records_no_delete ON records`);
  await pool.query(`
    CREATE TRIGGER records_no_delete
      BEFORE DELETE ON records
      FOR EACH ROW EXECUTE FUNCTION records_append_only()
  `);
  // Global CA key (single row)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ca_key (
      id          INTEGER PRIMARY KEY,
      public_key  TEXT NOT NULL,
      private_key TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      CHECK (id = 1)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS issuance_rate_limit_events (
      rate_key TEXT   NOT NULL,
      ts       BIGINT NOT NULL
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS issuance_rl_events_idx
      ON issuance_rate_limit_events (rate_key, ts)
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS signed_tree_heads (
      company_id TEXT    NOT NULL REFERENCES companies(company_id),
      tree_size  INTEGER NOT NULL,
      root_hash  TEXT    NOT NULL,
      timestamp  BIGINT  NOT NULL,
      signature  TEXT    NOT NULL,
      PRIMARY KEY (company_id, tree_size)
    )
  `);
  // Append-only enforcement on signed_tree_heads
  await pool.query(`
    CREATE OR REPLACE FUNCTION sth_append_only()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'signed_tree_heads table is append-only: % is not permitted', TG_OP;
    END;
    $$
  `);
  await pool.query(`DROP TRIGGER IF EXISTS sth_no_update ON signed_tree_heads`);
  await pool.query(`
    CREATE TRIGGER sth_no_update
      BEFORE UPDATE ON signed_tree_heads
      FOR EACH ROW EXECUTE FUNCTION sth_append_only()
  `);
  await pool.query(`DROP TRIGGER IF EXISTS sth_no_delete ON signed_tree_heads`);
  await pool.query(`
    CREATE TRIGGER sth_no_delete
      BEFORE DELETE ON signed_tree_heads
      FOR EACH ROW EXECUTE FUNCTION sth_append_only()
  `);
}

// ── Postgres wrapper ──────────────────────────────────────────────────────────

/**
 * Full restore against a live Postgres database:
 *
 *   1. Read backup file and verify SHA-256 checksum — fails fast before any DB change.
 *   2. Drop all tables in reverse FK order with CASCADE.
 *   3. Recreate the full schema (all 14 tables, indexes, triggers).
 *   4. Insert rows in FK-safe order using parameterised INSERT.
 *   5. Verify every table's row count matches the backup and return the counts.
 *
 * Note: TRUNCATE (not DROP) cannot be used here because we need a clean schema
 * state. DROP CASCADE handles FK constraints automatically.
 */
export async function restoreDatabase(
  pool: Pool,
  backupPath: string,
): Promise<Record<TableName, number>> {
  const data = readAndVerifyBackup(backupPath);

  const truncateAll: TableTruncator = async () => {
    // Drop all 14 tables at once with CASCADE to respect FK constraints cleanly.
    await pool.query(`
      DROP TABLE IF EXISTS
        webhook_deliveries, webhooks,
        records, signed_tree_heads,
        keys_history, revoked_passports,
        oauth_clients, oauth_tokens,
        api_keys, agents, keys, companies,
        ca_key, issuance_rate_limit_events
      CASCADE
    `);
    await pool.query(`DROP FUNCTION IF EXISTS records_append_only() CASCADE`);
    await pool.query(`DROP FUNCTION IF EXISTS sth_append_only() CASCADE`);
    await recreateSchema(pool);
  };

  const writeRows: RowWriter = async (table, rows) => {
    for (const row of rows) {
      const cols = Object.keys(row);
      const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
      const quoted = cols.map((c) => `"${c}"`).join(', ');
      const values = cols.map((c) => row[c]);
      await pool.query(
        `INSERT INTO "${table}" (${quoted}) VALUES (${placeholders})`,
        values,
      );
    }
  };

  const countRows: RowCounter = async (table) => {
    const { rows } = await pool.query<{ count: string }>(`SELECT COUNT(*) FROM "${table}"`);
    return Number(rows[0].count);
  };

  return applyBackup(data, { truncateAll, writeRows, countRows });
}

// ── CLI entrypoint ────────────────────────────────────────────────────────────

if (process.env.NODE_ENV !== 'test' && (import.meta.url.endsWith('restore-db.ts') || import.meta.url.endsWith('restore-db.js'))) {
  (async () => {
    const { Pool: PgPool } = await import('pg');
    const [, , backupPath] = process.argv;
    if (!backupPath) {
      console.error('Usage: tsx scripts/restore-db.ts <backup-file.json>');
      process.exit(2);
    }
    if (!process.env.DATABASE_URL) {
      console.error('error: DATABASE_URL is not set');
      process.exit(1);
    }
    const pool = new PgPool({ connectionString: process.env.DATABASE_URL });
    try {
      console.log(`Restoring database from ${backupPath} ...`);
      const counts = await restoreDatabase(pool, backupPath);
      const totalRows = Object.values(counts).reduce((s, n) => s + n, 0);
      for (const [table, count] of Object.entries(counts)) {
        console.log(`  ${table.padEnd(30)} ${count} rows`);
      }
      console.log(`Restore complete — ${totalRows} total rows restored.`);
    } finally {
      await pool.end();
    }
  })().catch((err) => {
    console.error('restore failed:', err);
    process.exit(1);
  });
}
