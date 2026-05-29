import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import type { AttestationRecord, KeyPair } from '../crypto/types.js';

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
        idx           INTEGER PRIMARY KEY,
        timestamp     TEXT    NOT NULL,
        payload       TEXT    NOT NULL,
        previous_hash TEXT    NOT NULL,
        hash          TEXT    NOT NULL,
        signature     TEXT    NOT NULL
      );
    `);
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
      .prepare(
        'INSERT OR REPLACE INTO keys (id, public, private) VALUES (1, ?, ?)',
      )
      .run(keys.publicKey, keys.privateKey);
  }

  getAllRecords(): AttestationRecord[] {
    const rows = this.db
      .prepare('SELECT * FROM records ORDER BY idx ASC')
      .all() as Array<{
        idx: number;
        timestamp: string;
        payload: string;
        previous_hash: string;
        hash: string;
        signature: string;
      }>;
    return rows.map((r) => ({
      index: r.idx,
      timestamp: r.timestamp,
      payload: JSON.parse(r.payload),
      previousHash: r.previous_hash,
      hash: r.hash,
      signature: r.signature,
    }));
  }

  insertRecord(record: AttestationRecord): void {
    this.db
      .prepare(
        `INSERT INTO records (idx, timestamp, payload, previous_hash, hash, signature)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.index,
        record.timestamp,
        JSON.stringify(record.payload),
        record.previousHash,
        record.hash,
        record.signature,
      );
  }
}
