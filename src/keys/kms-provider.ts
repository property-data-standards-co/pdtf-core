import { createPublicKey } from 'node:crypto';
import { deriveDidKey } from './did-key.js';
import type { KeyCategory, KeyProvider, KeyRecord } from '../types.js';

export interface KmsKeyProviderConfig {
  projectId: string;
  locationId: string;
  keyRingId: string;
  fetchFn?: typeof fetch;
}

interface KmsClientLike {
  createCryptoKey(request: {
    parent: string;
    cryptoKeyId: string;
    cryptoKey: {
      purpose: 'ASYMMETRIC_SIGN';
      versionTemplate: {
        algorithm: 'EC_SIGN_ED25519';
      };
    };
  }): Promise<unknown[]>;
  asymmetricSign(request: {
    name: string;
    data: Uint8Array;
  }): Promise<unknown[]>;
  getPublicKey(request: {
    name: string;
  }): Promise<unknown[]>;
}

interface KmsModuleLike {
  KeyManagementServiceClient: new (...args: any[]) => KmsClientLike;
}

export async function loadKmsModule(): Promise<KmsModuleLike> {
  try {
    return (await import('@google-cloud/kms')) as KmsModuleLike;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      'KmsKeyProvider requires the optional peer dependency @google-cloud/kms. ' +
      'Install it with: npm install @google-cloud/kms\n' +
      `Original error: ${message}`
    );
  }
}

export class KmsKeyProvider implements KeyProvider {
  private readonly projectId: string;
  private readonly locationId: string;
  private readonly keyRingId: string;
  private readonly fetchFn?: typeof fetch;
  private clientPromise?: Promise<KmsClientLike>;
  private readonly publicKeyCache = new Map<string, Uint8Array>();

  constructor(config: KmsKeyProviderConfig) {
    this.projectId = config.projectId;
    this.locationId = config.locationId;
    this.keyRingId = config.keyRingId;
    this.fetchFn = config.fetchFn;
  }

  async generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord> {
    const client = await this.getClient();
    const now = new Date().toISOString();
    const [cryptoKey] = await client.createCryptoKey({
      parent: this.keyRingName(),
      cryptoKeyId: keyId,
      cryptoKey: {
        purpose: 'ASYMMETRIC_SIGN',
        versionTemplate: {
          algorithm: 'EC_SIGN_ED25519',
        },
      },
    });

    const publicKey = await this.getPublicKey(keyId);
    const createdAt: string =
      typeof (cryptoKey as { createTime?: unknown } | undefined)?.createTime === 'string'
        ? ((cryptoKey as { createTime?: string }).createTime ?? now)
        : now;

    return {
      keyId,
      did: deriveDidKey(publicKey),
      publicKey,
      category,
      createdAt,
    };
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const client = await this.getClient();
    const [response] = await client.asymmetricSign({
      name: this.cryptoKeyVersionName(keyId),
      data,
    });

    const signatureValue = (response as { signature?: Uint8Array | Buffer } | undefined)?.signature;
    if (!signatureValue) {
      throw new Error(`KMS did not return a signature for key: ${keyId}`);
    }

    const signature = new Uint8Array(signatureValue);
    if (signature.length !== 64) {
      throw new Error(
        `Expected raw 64-byte Ed25519 signature from KMS, got ${signature.length} bytes`
      );
    }

    return signature;
  }

  async getPublicKey(keyId: string): Promise<Uint8Array> {
    const cached = this.publicKeyCache.get(keyId);
    if (cached) {
      return cached;
    }

    const client = await this.getClient();
    const [response] = await client.getPublicKey({
      name: this.cryptoKeyVersionName(keyId),
    });

    const pem = (response as { pem?: string } | undefined)?.pem;
    if (!pem) {
      throw new Error(`KMS did not return a public key for key: ${keyId}`);
    }

    const publicKey = extractEd25519PublicKeyFromPem(pem);
    this.publicKeyCache.set(keyId, publicKey);
    return publicKey;
  }

  async resolveDidKey(keyId: string): Promise<string> {
    const publicKey = await this.getPublicKey(keyId);
    return deriveDidKey(publicKey);
  }

  private keyRingName(): string {
    return [
      'projects',
      this.projectId,
      'locations',
      this.locationId,
      'keyRings',
      this.keyRingId,
    ].join('/');
  }

  private cryptoKeyName(keyId: string): string {
    return `${this.keyRingName()}/cryptoKeys/${keyId}`;
  }

  private cryptoKeyVersionName(keyId: string): string {
    return `${this.cryptoKeyName(keyId)}/cryptoKeyVersions/1`;
  }

  protected async loadKmsModule(): Promise<KmsModuleLike> {
    return loadKmsModule();
  }

  private async getClient(): Promise<KmsClientLike> {
    this.fetchFn;
    if (!this.clientPromise) {
      this.clientPromise = this.loadKmsModule().then(
        (kms) => new kms.KeyManagementServiceClient()
      );
    }
    return this.clientPromise;
  }
}

function extractEd25519PublicKeyFromPem(pem: string): Uint8Array {
  const keyObject = createPublicKey(pem);
  const der = keyObject.export({ format: 'der', type: 'spki' });
  const derBytes = new Uint8Array(der);

  if (derBytes.length < 32) {
    throw new Error('Invalid Ed25519 public key returned by KMS');
  }

  const publicKey = derBytes.slice(-32);
  if (publicKey.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
  }

  return publicKey;
}

export { extractEd25519PublicKeyFromPem };
