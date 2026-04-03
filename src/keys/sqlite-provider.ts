import { ed25519 } from '@noble/curves/ed25519';
import { deriveDidKey } from './did-key.js';
import type { KeyCategory, KeyProvider, KeyRecord } from '../types.js';

export interface SqliteKeyProviderConfig {
  dbPath: string;
}

interface SqliteDatabaseLike {
  exec(sql: string): unknown;
  prepare(sql: string): {
    run(...params: unknown[]): { changes: number };
    get(...params: unknown[]): Record<string, unknown> | undefined;
  };
  close(): void;
}

interface BetterSqlite3Like {
  new (path: string): SqliteDatabaseLike;
}

export async function loadBetterSqlite3(): Promise<BetterSqlite3Like> {
  try {
    const mod = await import('better-sqlite3');
    return (mod.default ?? mod) as BetterSqlite3Like;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      'SqliteKeyProvider requires the optional peer dependency better-sqlite3. ' +
      'Install it with: npm install better-sqlite3\n' +
      `Original error: ${message}`
    );
  }
}

export class SqliteKeyProvider implements KeyProvider {
  private readonly dbPath: string;
  private dbPromise?: Promise<SqliteDatabaseLike>;

  constructor(config: SqliteKeyProviderConfig) {
    this.dbPath = config.dbPath;
  }

  async generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord> {
    const db = await this.getDb();
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const did = deriveDidKey(publicKey);
    const createdAt = new Date().toISOString();

    try {
      db.prepare(
        `INSERT INTO pdtf_keys (key_id, category, secret_key, public_key, did, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).run(
        keyId,
        category,
        Buffer.from(privateKey),
        Buffer.from(publicKey),
        did,
        createdAt
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.toLowerCase().includes('unique')) {
        throw new Error(`Key already exists: ${keyId}`);
      }
      throw error;
    }

    return {
      keyId,
      did,
      publicKey,
      category,
      createdAt,
    };
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const row = await this.getKeyRow(keyId);
    return ed25519.sign(data, toUint8Array(row['secret_key']));
  }

  async getPublicKey(keyId: string): Promise<Uint8Array> {
    const row = await this.getKeyRow(keyId);
    return toUint8Array(row['public_key']);
  }

  async resolveDidKey(keyId: string): Promise<string> {
    const row = await this.getKeyRow(keyId);
    return String(row['did']);
  }

  private async getKeyRow(keyId: string): Promise<Record<string, unknown>> {
    const db = await this.getDb();
    const row = db.prepare(
      'SELECT key_id, category, secret_key, public_key, did, created_at FROM pdtf_keys WHERE key_id = ?'
    ).get(keyId);

    if (!row) {
      throw new Error(`Key not found: ${keyId}`);
    }

    return row;
  }

  protected async loadBetterSqlite3(): Promise<BetterSqlite3Like> {
    return loadBetterSqlite3();
  }

  private async getDb(): Promise<SqliteDatabaseLike> {
    if (!this.dbPromise) {
      this.dbPromise = this.loadBetterSqlite3().then((Database) => {
        const db = new Database(this.dbPath);
        db.exec(`
          CREATE TABLE IF NOT EXISTS pdtf_keys (
            key_id TEXT PRIMARY KEY,
            category TEXT,
            secret_key BLOB,
            public_key BLOB,
            did TEXT,
            created_at TEXT
          )
        `);
        return db;
      });
    }

    return this.dbPromise;
  }
}

function toUint8Array(value: unknown): Uint8Array {
  if (Buffer.isBuffer(value)) {
    return new Uint8Array(value);
  }

  if (value instanceof Uint8Array) {
    return value;
  }

  throw new Error('Invalid binary key material in SQLite');
}
