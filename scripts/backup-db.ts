#!/usr/bin/env -S npx tsx
/**
 * Vane database backup tool.
 *
 *   tsx scripts/backup-db.ts [output-dir]
 *
 * Dumps all 14 tables to a timestamped JSON file and writes a SHA-256
 * checksum alongside it. Output is human-readable and database-version-
 * independent — no pg_dump format, no binary blobs.
 *
 * The exported pure functions (dumpTables, writeBackupFiles, verifyBackup,
 * computeChecksum) are used directly by the test suite without touching Postgres.
 */
import { createHash } from 'node:crypto';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Pool } from 'pg';

// ── Schema constants ──────────────────────────────────────────────────────────

export const SCHEMA_VERSION = '1';

/** Every table that exists in the Vane schema, for backup purposes. */
export const ALL_TABLES = [
  'companies',
  'keys',
  'api_keys',
  'agents',
  'records',
  'keys_history',
  'revoked_passports',
  'oauth_clients',
  'oauth_tokens',
  'webhooks',
  'webhook_deliveries',
  'ca_key',
  'issuance_rate_limit_events',
  'signed_tree_heads',
] as const;

export type TableName = (typeof ALL_TABLES)[number];

/**
 * FK-safe INSERT order: parent tables before child tables.
 * ca_key and issuance_rate_limit_events have no FK dependencies.
 * companies is the root for all tenant tables.
 * webhook_deliveries depends on webhooks.
 */
export const INSERT_ORDER: readonly TableName[] = [
  'ca_key',
  'issuance_rate_limit_events',
  'companies',
  'keys',
  'api_keys',
  'agents',
  'records',
  'keys_history',
  'revoked_passports',
  'oauth_clients',
  'oauth_tokens',
  'webhooks',
  'webhook_deliveries',
  'signed_tree_heads',
];

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BackupData {
  schemaVersion: string;
  exportedAt: string;
  tables: Partial<Record<TableName, Record<string, unknown>[]>>;
}

export interface VerifyResult {
  valid: boolean;
  schemaVersion?: string;
  tables?: Record<TableName, number>;
  error?: string;
}

/** Injectable fetcher — accepts any table name, returns rows. */
export type RowFetcher = (table: TableName) => Promise<Record<string, unknown>[]>;

// ── Pure functions ─────────────────────────────────────────────────────────────

/** SHA-256 of a UTF-8 string, returned as lowercase hex. */
export function computeChecksum(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Fetches every table via the injected fetcher and assembles BackupData.
 * No I/O, no Postgres dependency — fully testable with a fake fetcher.
 */
export async function dumpTables(fetchRows: RowFetcher): Promise<BackupData> {
  const tables: BackupData['tables'] = {};
  for (const table of ALL_TABLES) {
    tables[table] = await fetchRows(table);
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    tables,
  };
}

/**
 * Writes the backup JSON and a companion `.sha256` file.
 * Returns the paths of both files.
 */
export function writeBackupFiles(
  data: BackupData,
  outputDir: string,
): { backupPath: string; checksumPath: string } {
  const timestamp = data.exportedAt.replace(/[:.]/g, '-');
  const backupPath = join(outputDir, `vane-backup-${timestamp}.json`);
  const checksumPath = `${backupPath}.sha256`;
  const content = JSON.stringify(data, null, 2);
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(backupPath, content, 'utf8');
  writeFileSync(checksumPath, computeChecksum(content), 'utf8');
  return { backupPath, checksumPath };
}

/**
 * Health-check function: reads a backup file, verifies its SHA-256 checksum,
 * and confirms every expected table is present. Returns per-table row counts
 * so a caller can assert non-zero counts.
 */
export function verifyBackup(filePath: string): VerifyResult {
  const checksumPath = `${filePath}.sha256`;

  if (!existsSync(filePath)) {
    return { valid: false, error: `backup file not found: ${filePath}` };
  }
  if (!existsSync(checksumPath)) {
    return { valid: false, error: `checksum file not found: ${checksumPath}` };
  }

  const content = readFileSync(filePath, 'utf8');
  const storedChecksum = readFileSync(checksumPath, 'utf8').trim();
  if (storedChecksum !== computeChecksum(content)) {
    return { valid: false, error: 'checksum mismatch — backup file may be corrupted' };
  }

  let data: BackupData;
  try {
    data = JSON.parse(content) as BackupData;
  } catch (err) {
    return { valid: false, error: `invalid JSON: ${(err as Error).message}` };
  }

  const missing = ALL_TABLES.filter((t) => !(t in data.tables));
  if (missing.length > 0) {
    return { valid: false, error: `missing tables: ${missing.join(', ')}` };
  }

  const tables = {} as Record<TableName, number>;
  for (const t of ALL_TABLES) {
    tables[t] = (data.tables[t] ?? []).length;
  }
  return { valid: true, schemaVersion: data.schemaVersion, tables };
}

// ── Postgres wrapper ──────────────────────────────────────────────────────────

/**
 * Backs up the live Postgres database to a timestamped JSON + checksum pair.
 * The `pool` is used only for SELECT queries — no schema changes.
 */
export async function backupDatabase(
  pool: Pool,
  outputDir: string,
): Promise<{ backupPath: string; checksumPath: string }> {
  const fetchRows: RowFetcher = async (table) => {
    const { rows } = await pool.query(`SELECT * FROM "${table}"`);
    return rows;
  };
  const data = await dumpTables(fetchRows);
  return writeBackupFiles(data, outputDir);
}

// ── CLI entrypoint ────────────────────────────────────────────────────────────

if (process.env.NODE_ENV !== 'test' && import.meta.url.endsWith('backup-db.ts') || import.meta.url.endsWith('backup-db.js')) {
  // Only run when executed directly, not when imported.
  (async () => {
    const { Pool: PgPool } = await import('pg');
    const outputDir = process.argv[2] ?? './backups';
    if (!process.env.DATABASE_URL) {
      console.error('error: DATABASE_URL is not set');
      process.exit(1);
    }
    const pool = new PgPool({ connectionString: process.env.DATABASE_URL });
    try {
      console.log(`Backing up database to ${outputDir} ...`);
      const { backupPath, checksumPath } = await backupDatabase(pool, outputDir);
      console.log(`  backup  : ${backupPath}`);
      console.log(`  sha256  : ${checksumPath}`);
      const result = verifyBackup(backupPath);
      if (!result.valid) {
        console.error(`  verification FAILED: ${result.error}`);
        process.exit(1);
      }
      const totalRows = Object.values(result.tables ?? {}).reduce((s, n) => s + n, 0);
      console.log(`  verified: ${totalRows} total rows across ${ALL_TABLES.length} tables`);
    } finally {
      await pool.end();
    }
  })().catch((err) => {
    console.error('backup failed:', err);
    process.exit(1);
  });
}
