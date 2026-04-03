import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { SqliteKeyProvider, loadBetterSqlite3 } from '../sqlite-provider.js';

class MissingSqliteKeyProvider extends SqliteKeyProvider {
  protected override async loadBetterSqlite3() {
    throw new Error(
      'SqliteKeyProvider requires the optional peer dependency better-sqlite3. Install it with: npm install better-sqlite3'
    );
  }
}

describe('SqliteKeyProvider', () => {
  it('supports full lifecycle: generate, sign, verify, resolve did:key', async () => {
    const provider = new SqliteKeyProvider({ dbPath: ':memory:' });
    const record = await provider.generateKey('test-key', 'adapter');
    const data = new TextEncoder().encode('hello world');

    const signature = await provider.sign('test-key', data);
    const publicKey = await provider.getPublicKey('test-key');
    const did = await provider.resolveDidKey('test-key');

    expect(publicKey).toEqual(new Uint8Array(record.publicKey));
    expect(did).toBe(record.did);
    expect(ed25519.verify(signature, data, publicKey)).toBe(true);
  });

  it('throws clear errors for missing keys', async () => {
    const provider = new SqliteKeyProvider({ dbPath: ':memory:' });

    await expect(provider.getPublicKey('missing')).rejects.toThrow('Key not found: missing');
    await expect(provider.sign('missing', new Uint8Array([1]))).rejects.toThrow(
      'Key not found: missing'
    );
    await expect(provider.resolveDidKey('missing')).rejects.toThrow('Key not found: missing');
  });

  it('throws clear errors for duplicate keys', async () => {
    const provider = new SqliteKeyProvider({ dbPath: ':memory:' });

    await provider.generateKey('duplicate', 'adapter');
    await expect(provider.generateKey('duplicate', 'adapter')).rejects.toThrow(
      'Key already exists: duplicate'
    );
  });

  it('throws a helpful error when better-sqlite3 is not installed', async () => {
    const provider = new MissingSqliteKeyProvider({ dbPath: ':memory:' });

    await expect(provider.getPublicKey('test-key')).rejects.toThrow('better-sqlite3');
  });

  it('loadBetterSqlite3 resolves when dependency is installed', async () => {
    await expect(loadBetterSqlite3()).resolves.toBeTypeOf('function');
  });
});
