import { describe, it, expect, beforeEach } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

import {
  dumpTables,
  writeBackupFiles,
  verifyBackup,
  computeChecksum,
  INSERT_ORDER,
  ALL_TABLES,
  SCHEMA_VERSION,
  type BackupData,
  type TableName,
  type RowFetcher,
} from '../scripts/backup-db.js';
import {
  readAndVerifyBackup,
  applyBackup,
  type RestoreOptions,
} from '../scripts/restore-db.js';

// ── In-memory fake database ───────────────────────────────────────────────────
//
// Stores rows in a Map and implements the RowFetcher / RestoreOptions interfaces
// that the backup/restore functions expect. No Postgres dependency.

class FakeDB {
  private store = new Map<string, Record<string, unknown>[]>();

  set(table: string, rows: Record<string, unknown>[]): void {
    this.store.set(table, rows.map((r) => ({ ...r })));
  }

  get(table: string): Record<string, unknown>[] {
    return this.store.get(table) ?? [];
  }

  clearAll(): void {
    for (const table of ALL_TABLES) {
      this.store.set(table, []);
    }
  }

  fetcher(): RowFetcher {
    return async (table) => this.get(table);
  }

  restoreOptions(): RestoreOptions {
    return {
      truncateAll: async () => this.clearAll(),
      writeRows: async (table: TableName, rows: Record<string, unknown>[]) => {
        const existing = this.get(table);
        this.store.set(table, [...existing, ...rows.map((r) => ({ ...r }))]);
      },
      countRows: async (table: TableName) => this.get(table).length,
    };
  }
}

// ── Representative fixtures ───────────────────────────────────────────────────
//
// At least one row per table, with realistic column values. The signed_tree_heads
// timestamp is a string because Postgres returns BIGINT as a string in Node.js.

function makeFixtures(): Record<string, Record<string, unknown>[]> {
  const companyId = 'acme';
  const agentId = 'agent-1';
  const webhookId = randomUUID();
  const retiredKeyId = randomUUID();
  const revokedJti = randomUUID();
  const deliveryId = randomUUID();
  const caKeyTimestamp = new Date().toISOString();

  return {
    companies: [
      {
        company_id: companyId,
        spiffe_id: `spiffe://vane.local/company/${companyId}`,
        registered_at: '2026-01-01T00:00:00.000Z',
        metadata: null,
      },
    ],
    keys: [
      {
        company_id: companyId,
        public_key: '-----BEGIN PUBLIC KEY-----\nfakePub==\n-----END PUBLIC KEY-----',
        private_key: '-----BEGIN PRIVATE KEY-----\nfakePriv==\n-----END PRIVATE KEY-----',
      },
    ],
    api_keys: [
      {
        key: 'vane_abc123def456',
        company_id: companyId,
        label: 'default',
        created_at: '2026-01-01T00:00:00.000Z',
      },
    ],
    agents: [
      {
        agent_id: agentId,
        company_id: companyId,
        spiffe_id: `spiffe://vane.local/company/${companyId}/agent/${agentId}`,
        registered_at: '2026-01-01T00:00:00.000Z',
        metadata: null,
      },
    ],
    records: [
      {
        company_id: companyId,
        idx: 0,
        timestamp: '2026-01-01T00:00:00.000Z',
        payload: JSON.stringify({ agentId, actionType: 'data-query', payload: { q: 'select 1' } }),
        delegation: null,
        hash: 'a'.repeat(64),
        signature: 'b'.repeat(64),
      },
      {
        company_id: companyId,
        idx: 1,
        timestamp: '2026-01-01T00:01:00.000Z',
        payload: JSON.stringify({ agentId, actionType: 'tool-call', payload: { tool: 'search' } }),
        delegation: JSON.stringify({ subject: `spiffe://vane.local/company/${companyId}`, delegationChain: [] }),
        hash: 'c'.repeat(64),
        signature: 'd'.repeat(64),
      },
    ],
    signed_tree_heads: [
      {
        company_id: companyId,
        tree_size: 1,
        root_hash: 'e'.repeat(64),
        timestamp: '1700000000000', // BIGINT comes back as string from pg
        signature: 'f'.repeat(64),
      },
      {
        company_id: companyId,
        tree_size: 2,
        root_hash: 'g'.repeat(64),
        timestamp: '1700000001000',
        signature: 'h'.repeat(64),
      },
    ],
    ca_key: [
      {
        id: 1,
        public_key: '-----BEGIN PUBLIC KEY-----\ncaPub==\n-----END PUBLIC KEY-----',
        private_key: '-----BEGIN PRIVATE KEY-----\ncaPriv==\n-----END PRIVATE KEY-----',
        created_at: caKeyTimestamp,
      },
    ],
    issuance_rate_limit_events: [
      { rate_key: `${companyId}:passport`, ts: 1700000000000 },
    ],
    keys_history: [
      {
        id: retiredKeyId,
        company_id: companyId,
        public_key: '-----BEGIN PUBLIC KEY-----\noldPub==\n-----END PUBLIC KEY-----',
        private_key: '-----BEGIN PRIVATE KEY-----\noldPriv==\n-----END PRIVATE KEY-----',
        retired_at: '2026-01-01T00:00:00.000Z',
      },
    ],
    revoked_passports: [
      {
        jti: revokedJti,
        company_id: companyId,
        revoked_at: '2026-01-01T00:00:00.000Z',
        reason: 'key rotation',
      },
    ],
    oauth_clients: [
      {
        client_id: 'cc_abc',
        client_secret: 'e'.repeat(64),
        company_id: companyId,
        created_at: '2026-01-01T00:00:00.000Z',
      },
    ],
    oauth_tokens: [
      {
        token: 'oauth_xyz',
        company_id: companyId,
        expires_at: 9999999999999,
        created_at: '2026-01-01T00:00:00.000Z',
      },
    ],
    webhooks: [
      {
        id: webhookId,
        company_id: companyId,
        url: 'https://example.com/hook',
        events: ['attest.created', 'attest.deleted'],
        secret_hash: 'enc:v1:fakesecret',
        active: true,
        created_at: '2026-01-01T00:00:00.000Z',
      },
    ],
    webhook_deliveries: [
      {
        id: deliveryId,
        webhook_id: webhookId,
        event: 'attest.created',
        payload: { type: 'attest.created', data: { companyId } },
        status: 'delivered',
        attempts: 1,
        next_retry_at: null,
        last_error: null,
        created_at: '2026-01-01T00:00:00.000Z',
      },
    ],
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function tempDir(): string {
  return join(tmpdir(), `vane-backup-test-${randomUUID()}`);
}

// ── Backup: JSON format and checksum ─────────────────────────────────────────

describe('dumpTables', () => {
  it('includes every expected table in the backup', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) {
      db.set(table, rows);
    }

    const data = await dumpTables(db.fetcher());

    expect(data.schemaVersion).toBe(SCHEMA_VERSION);
    expect(typeof data.exportedAt).toBe('string');
    for (const table of ALL_TABLES) {
      expect(data.tables).toHaveProperty(table);
    }
  });

  it('captures the exact row count per table', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) {
      db.set(table, rows);
    }

    const data = await dumpTables(db.fetcher());

    expect(data.tables.companies).toHaveLength(1);
    expect(data.tables.records).toHaveLength(2);
    expect(data.tables.signed_tree_heads).toHaveLength(2);
    expect(data.tables.webhooks).toHaveLength(1);
    expect(data.tables.webhook_deliveries).toHaveLength(1);
    expect(data.tables.ca_key).toHaveLength(1);
  });

  it('preserves all column values for an attestation record', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) {
      db.set(table, rows);
    }

    const data = await dumpTables(db.fetcher());
    const record = data.tables.records?.[0];

    expect(record?.company_id).toBe('acme');
    expect(record?.idx).toBe(0);
    expect(record?.hash).toBe('a'.repeat(64));
    expect(record?.signature).toBe('b'.repeat(64));
  });

  it('preserves all column values for signed tree heads', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) {
      db.set(table, rows);
    }

    const data = await dumpTables(db.fetcher());
    const sths = data.tables.signed_tree_heads ?? [];

    expect(sths).toHaveLength(2);
    expect(sths[0].tree_size).toBe(1);
    expect(sths[1].tree_size).toBe(2);
    expect(sths[0].root_hash).toBe('e'.repeat(64));
  });
});

// ── computeChecksum ───────────────────────────────────────────────────────────

describe('computeChecksum', () => {
  it('returns a 64-character hex string (SHA-256)', () => {
    const cs = computeChecksum('hello world');
    expect(cs).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(cs)).toBe(true);
  });

  it('produces a stable known-answer vector', () => {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    expect(computeChecksum('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('is sensitive to a single character change', () => {
    const a = computeChecksum('hello');
    const b = computeChecksum('Hello');
    expect(a).not.toBe(b);
  });
});

// ── writeBackupFiles ──────────────────────────────────────────────────────────

describe('writeBackupFiles', () => {
  it('writes a JSON file and a companion .sha256 file', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath, checksumPath } = writeBackupFiles(data, tempDir());

    expect(existsSync(backupPath)).toBe(true);
    expect(existsSync(checksumPath)).toBe(true);
    expect(backupPath.endsWith('.json')).toBe(true);
    expect(checksumPath.endsWith('.sha256')).toBe(true);
  });

  it('checksum file contains exactly the SHA-256 of the JSON file', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath, checksumPath } = writeBackupFiles(data, tempDir());

    const { readFileSync: rf } = await import('node:fs');
    const content = rf(backupPath, 'utf8');
    const storedChecksum = rf(checksumPath, 'utf8').trim();

    expect(storedChecksum).toBe(computeChecksum(content));
  });
});

// ── verifyBackup ──────────────────────────────────────────────────────────────

describe('verifyBackup', () => {
  it('returns valid=true and per-table counts for a good backup', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());

    const result = verifyBackup(backupPath);

    expect(result.valid).toBe(true);
    expect(result.schemaVersion).toBe(SCHEMA_VERSION);
    expect(result.error).toBeUndefined();
    expect(result.tables?.companies).toBe(1);
    expect(result.tables?.records).toBe(2);
    expect(result.tables?.signed_tree_heads).toBe(2);
    expect(result.tables?.ca_key).toBe(1);
    expect(result.tables?.agents).toBe(1);
    expect(result.tables?.api_keys).toBe(1);
  });

  it('returns valid=false when the backup file does not exist', () => {
    const result = verifyBackup('/nonexistent/path/backup.json');
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/not found/);
  });

  it('returns valid=false when the checksum file is missing', async () => {
    const { writeFileSync: wf } = await import('node:fs');
    const dir = tempDir();
    const { mkdirSync } = await import('node:fs');
    mkdirSync(dir, { recursive: true });
    const backupPath = join(dir, 'backup.json');
    wf(backupPath, JSON.stringify({ schemaVersion: '1', exportedAt: '', tables: {} }), 'utf8');
    // No .sha256 file written

    const result = verifyBackup(backupPath);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/checksum file not found/);
  });

  it('returns valid=false when the checksum does not match', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath, checksumPath } = writeBackupFiles(data, tempDir());

    // Corrupt the checksum file
    writeFileSync(checksumPath, 'a'.repeat(64), 'utf8');

    const result = verifyBackup(backupPath);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/checksum mismatch/);
  });

  it('returns valid=false when the backup JSON is missing a table', async () => {
    const dir = tempDir();
    const { mkdirSync } = await import('node:fs');
    mkdirSync(dir, { recursive: true });

    // Build a backup with only some tables
    const partial: BackupData = {
      schemaVersion: SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      tables: { companies: [] }, // all other tables missing
    };
    const content = JSON.stringify(partial, null, 2);
    const backupPath = join(dir, 'partial.json');
    const checksumPath = `${backupPath}.sha256`;
    writeFileSync(backupPath, content, 'utf8');
    writeFileSync(checksumPath, computeChecksum(content), 'utf8');

    const result = verifyBackup(backupPath);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/missing tables/);
  });

  it('verifyBackup row counts are non-zero for every populated table', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    const result = verifyBackup(backupPath);

    expect(result.valid).toBe(true);
    const tables = result.tables!;
    // Every table in fixtures has at least one row
    for (const table of Object.keys(fixtures)) {
      expect(tables[table as TableName]).toBeGreaterThan(0);
    }
  });
});

// ── readAndVerifyBackup ───────────────────────────────────────────────────────

describe('readAndVerifyBackup', () => {
  it('reads and parses a valid backup file', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());

    const read = readAndVerifyBackup(backupPath);
    expect(read.schemaVersion).toBe(SCHEMA_VERSION);
    expect((read.tables.companies ?? []).length).toBe(1);
  });

  it('throws when the backup file does not exist', () => {
    expect(() => readAndVerifyBackup('/no/such/file.json')).toThrow(/not found/);
  });

  it('throws when the checksum does not match', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath, checksumPath } = writeBackupFiles(data, tempDir());

    writeFileSync(checksumPath, 'b'.repeat(64), 'utf8');
    expect(() => readAndVerifyBackup(backupPath)).toThrow(/checksum mismatch/);
  });
});

// ── applyBackup: full backup → wipe → restore cycle ──────────────────────────

describe('applyBackup — full cycle', () => {
  it('restores every row correctly after a wipe', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    // 1. Backup
    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());

    // 2. Wipe the database (simulates a disaster)
    db.clearAll();
    for (const table of ALL_TABLES) {
      expect(db.get(table)).toHaveLength(0);
    }

    // 3. Read back from disk and restore
    const read = readAndVerifyBackup(backupPath);
    const counts = await applyBackup(read, db.restoreOptions());

    // 4. Verify every table was restored to its original row count
    expect(counts.companies).toBe(1);
    expect(counts.keys).toBe(1);
    expect(counts.api_keys).toBe(1);
    expect(counts.agents).toBe(1);
    expect(counts.records).toBe(2);
    expect(counts.signed_tree_heads).toBe(2);
    expect(counts.ca_key).toBe(1);
    expect(counts.issuance_rate_limit_events).toBe(1);
    expect(counts.keys_history).toBe(1);
    expect(counts.revoked_passports).toBe(1);
    expect(counts.oauth_clients).toBe(1);
    expect(counts.oauth_tokens).toBe(1);
    expect(counts.webhooks).toBe(1);
    expect(counts.webhook_deliveries).toBe(1);
  });

  it('restores attestation record field values faithfully', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    db.clearAll();

    const read = readAndVerifyBackup(backupPath);
    await applyBackup(read, db.restoreOptions());

    const records = db.get('records');
    expect(records).toHaveLength(2);
    expect(records[0].company_id).toBe('acme');
    expect(records[0].idx).toBe(0);
    expect(records[0].hash).toBe('a'.repeat(64));
    expect(records[1].idx).toBe(1);
    expect(records[1].delegation).not.toBeNull();
  });

  it('restores signed tree heads faithfully', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    db.clearAll();

    const read = readAndVerifyBackup(backupPath);
    await applyBackup(read, db.restoreOptions());

    const sths = db.get('signed_tree_heads');
    expect(sths).toHaveLength(2);
    expect(sths[0].tree_size).toBe(1);
    expect(sths[0].root_hash).toBe('e'.repeat(64));
    expect(sths[1].tree_size).toBe(2);
  });

  it('restores company data faithfully', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    db.clearAll();

    const read = readAndVerifyBackup(backupPath);
    await applyBackup(read, db.restoreOptions());

    const companies = db.get('companies');
    expect(companies).toHaveLength(1);
    expect(companies[0].company_id).toBe('acme');
    expect(companies[0].spiffe_id).toBe('spiffe://vane.local/company/acme');
  });

  it('restores agents faithfully', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    db.clearAll();

    const read = readAndVerifyBackup(backupPath);
    await applyBackup(read, db.restoreOptions());

    const agents = db.get('agents');
    expect(agents).toHaveLength(1);
    expect(agents[0].agent_id).toBe('agent-1');
    expect(agents[0].spiffe_id).toContain('agent-1');
  });

  it('restores API keys faithfully', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    db.clearAll();

    const read = readAndVerifyBackup(backupPath);
    await applyBackup(read, db.restoreOptions());

    const keys = db.get('api_keys');
    expect(keys).toHaveLength(1);
    expect(keys[0].key).toBe('vane_abc123def456');
    expect(keys[0].company_id).toBe('acme');
  });

  it('INSERT_ORDER respects FK dependencies (companies before keys, webhooks before deliveries)', () => {
    const companiesIdx = INSERT_ORDER.indexOf('companies');
    const keysIdx = INSERT_ORDER.indexOf('keys');
    const webhooksIdx = INSERT_ORDER.indexOf('webhooks');
    const deliveriesIdx = INSERT_ORDER.indexOf('webhook_deliveries');
    const caKeyIdx = INSERT_ORDER.indexOf('ca_key');
    const recordsIdx = INSERT_ORDER.indexOf('records');
    const sthIdx = INSERT_ORDER.indexOf('signed_tree_heads');

    expect(companiesIdx).toBeLessThan(keysIdx);
    expect(companiesIdx).toBeLessThan(recordsIdx);
    expect(webhooksIdx).toBeLessThan(deliveriesIdx);
    expect(caKeyIdx).toBeLessThan(companiesIdx); // ca_key has no FK deps — must come first
    expect(companiesIdx).toBeLessThan(sthIdx);
  });

  it('throws when a row count mismatch occurs during restore', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());
    const read = readAndVerifyBackup(backupPath);
    db.clearAll();

    // Sabotage the restore: countRows for 'records' always returns 0
    const opts = db.restoreOptions();
    const sabotaged: RestoreOptions = {
      ...opts,
      countRows: async (table: TableName) =>
        table === 'records' ? 0 : opts.countRows(table),
    };

    await expect(applyBackup(read, sabotaged)).rejects.toThrow(
      /row count mismatch.*records/i,
    );
  });
});

// ── verifyBackup as health check ──────────────────────────────────────────────

describe('verifyBackup health-check', () => {
  it('passes on a freshly-written backup with all tables populated', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());

    const result = verifyBackup(backupPath);
    expect(result.valid).toBe(true);
    expect(result.schemaVersion).toBe('1');
    // All tables present
    expect(Object.keys(result.tables ?? {})).toHaveLength(ALL_TABLES.length);
  });

  it('passes when some tables are empty (valid schema, just no data)', async () => {
    const db = new FakeDB();
    // Only populate companies — all other tables empty but present
    db.set('companies', [{ company_id: 'test', spiffe_id: 'spiffe://test', registered_at: '', metadata: null }]);
    // Other tables default to []

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());

    const result = verifyBackup(backupPath);
    // verifyBackup only checks presence of tables, not non-zero counts
    expect(result.valid).toBe(true);
    expect(result.tables?.companies).toBe(1);
    expect(result.tables?.records).toBe(0);
  });

  it('fails when the backup file has been tampered after writing', async () => {
    const db = new FakeDB();
    const fixtures = makeFixtures();
    for (const [table, rows] of Object.entries(fixtures)) db.set(table, rows);

    const data = await dumpTables(db.fetcher());
    const { backupPath } = writeBackupFiles(data, tempDir());

    // Tamper with the backup file without updating the checksum
    const content = readFileSync(backupPath, 'utf8');
    writeFileSync(backupPath, content.replace('"acme"', '"evil-corp"'), 'utf8');

    const result = verifyBackup(backupPath);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/checksum mismatch/);
  });
});
