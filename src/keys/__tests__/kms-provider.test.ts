import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { deriveDidKey } from '../did-key.js';
import { KmsKeyProvider, extractEd25519PublicKeyFromPem } from '../kms-provider.js';

class TestKmsKeyProvider extends KmsKeyProvider {
  constructor(
    private readonly kmsModule: {
      KeyManagementServiceClient: new () => {
        createCryptoKey: (...args: any[]) => Promise<any[]>;
        asymmetricSign: (...args: any[]) => Promise<any[]>;
        getPublicKey: (...args: any[]) => Promise<any[]>;
      };
    }
  ) {
    super({ projectId: 'proj', locationId: 'global', keyRingId: 'ring' });
  }

  protected override async loadKmsModule() {
    return this.kmsModule;
  }
}

class MissingKmsKeyProvider extends KmsKeyProvider {
  constructor() {
    super({ projectId: 'proj', locationId: 'global', keyRingId: 'ring' });
  }

  protected override async loadKmsModule() {
    throw new Error(
      'KmsKeyProvider requires the optional peer dependency @google-cloud/kms. Install it with: npm install @google-cloud/kms'
    );
  }
}

describe('KmsKeyProvider', () => {
  it('generates a key record using KMS', async () => {
    const keyPair = generateKeyPairSync('ed25519');
    const pem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const publicKey = extractEd25519PublicKeyFromPem(pem);

    const createCryptoKey = async (request: unknown) => {
      expect(request).toEqual({
        parent: 'projects/proj/locations/global/keyRings/ring',
        cryptoKeyId: 'test-key',
        cryptoKey: {
          purpose: 'ASYMMETRIC_SIGN',
          versionTemplate: {
            algorithm: 'EC_SIGN_ED25519',
          },
        },
      });
      return [{ createTime: '2026-04-03T00:00:00.000Z' }];
    };

    const provider = new TestKmsKeyProvider({
      KeyManagementServiceClient: class {
        createCryptoKey = createCryptoKey;
        asymmetricSign = async () => [{}];
        getPublicKey = async () => [{ pem }];
      },
    });

    const record = await provider.generateKey('test-key', 'adapter');

    expect(record.publicKey).toEqual(publicKey);
    expect(record.did).toBe(deriveDidKey(publicKey));
    expect(record.createdAt).toBe('2026-04-03T00:00:00.000Z');
  });

  it('signs with the first crypto key version and returns raw signature bytes', async () => {
    const keyPair = generateKeyPairSync('ed25519');
    const data = new TextEncoder().encode('hello');
    const signature = new Uint8Array(nodeSign(null, data, keyPair.privateKey));

    const provider = new TestKmsKeyProvider({
      KeyManagementServiceClient: class {
        createCryptoKey = async () => [{}];
        asymmetricSign = async (request: unknown) => {
          expect(request).toEqual({
            name: 'projects/proj/locations/global/keyRings/ring/cryptoKeys/test-key/cryptoKeyVersions/1',
            data,
          });
          return [{ signature }];
        };
        getPublicKey = async () => [{}];
      },
    });

    await expect(provider.sign('test-key', data)).resolves.toEqual(signature);
  });

  it('gets and caches public keys', async () => {
    const keyPair = generateKeyPairSync('ed25519');
    const pem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    let calls = 0;

    const provider = new TestKmsKeyProvider({
      KeyManagementServiceClient: class {
        createCryptoKey = async () => [{}];
        asymmetricSign = async () => [{}];
        getPublicKey = async () => {
          calls += 1;
          return [{ pem }];
        };
      },
    });

    const first = await provider.getPublicKey('test-key');
    const second = await provider.getPublicKey('test-key');

    expect(first).toEqual(second);
    expect(calls).toBe(1);
  });

  it('resolves a did:key from the public key', async () => {
    const keyPair = generateKeyPairSync('ed25519');
    const pem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const publicKey = extractEd25519PublicKeyFromPem(pem);

    const provider = new TestKmsKeyProvider({
      KeyManagementServiceClient: class {
        createCryptoKey = async () => [{}];
        asymmetricSign = async () => [{}];
        getPublicKey = async () => [{ pem }];
      },
    });

    await expect(provider.resolveDidKey('test-key')).resolves.toBe(deriveDidKey(publicKey));
  });

  it('throws if KMS returns a non-raw Ed25519 signature', async () => {
    const provider = new TestKmsKeyProvider({
      KeyManagementServiceClient: class {
        createCryptoKey = async () => [{}];
        asymmetricSign = async () => [{ signature: new Uint8Array([1, 2, 3]) }];
        getPublicKey = async () => [{}];
      },
    });

    await expect(provider.sign('test-key', new Uint8Array([1]))).rejects.toThrow(
      'Expected raw 64-byte Ed25519 signature'
    );
  });

  it('throws if KMS does not return a public key', async () => {
    const provider = new TestKmsKeyProvider({
      KeyManagementServiceClient: class {
        createCryptoKey = async () => [{}];
        asymmetricSign = async () => [{}];
        getPublicKey = async () => [{}];
      },
    });

    await expect(provider.getPublicKey('test-key')).rejects.toThrow(
      'KMS did not return a public key for key: test-key'
    );
  });

  it('throws a helpful error when @google-cloud/kms is not installed', async () => {
    const provider = new MissingKmsKeyProvider();

    await expect(provider.getPublicKey('test-key')).rejects.toThrow('@google-cloud/kms');
  });
});
