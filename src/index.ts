/**
 * @pdtf/core — PDTF 2.0 core utilities
 *
 * Subpath imports:
 *   import { VcSigner } from '@pdtf/core/signer'
 *   import { DidResolver } from '@pdtf/core/did'
 *   import { checkStatus } from '@pdtf/core/status'
 *   import { FederationRegistryResolver, OpenIdFederationResolver } from '@pdtf/core/federation'
 *   import { FirestoreKeyProvider } from '@pdtf/core/keys'
 *   import { VcValidator } from '@pdtf/core/validator'
 *
 * Or import everything from the root:
 *   import { VcSigner, DidResolver, FederationRegistryResolver } from '@pdtf/core'
 */

// Re-export all public APIs
export * from './types.js';
export * from './keys/index.js';
export * from './signer/index.js';
export * from './validator/index.js';
export * from './did/index.js';
export * from './status/index.js';
export * from './federation/index.js';
export * from './assembly/index.js';
