# @pdtf/core

PDTF 2.0 core utilities — cryptographic signing, verification, DIDs, status lists, and trust registry.

## Install

```bash
npm install @pdtf/core
```

## Modules

| Import | Description |
|--------|-------------|
| `@pdtf/core/keys` | Ed25519 key management (Firestore dev provider, KMS prod provider) |
| `@pdtf/core/signer` | Build and sign Verifiable Credentials with DataIntegrityProof |
| `@pdtf/core/validator` | 4-stage VC verification pipeline (structure → signature → TIR → status) |
| `@pdtf/core/did` | DID resolution (did:key, did:web), PDTF URN validation |
| `@pdtf/core/status` | W3C Bitstring Status List — create, encode, check |
| `@pdtf/core/tir` | Trusted Issuer Registry client with caching |

## Quick Start

### Sign a credential

```typescript
import { VcSigner, FirestoreKeyProvider } from '@pdtf/core';

const keyProvider = new FirestoreKeyProvider({ firestore: db });
const keyRecord = await keyProvider.generateKey('epc-adapter/signing-key-1', 'adapter');
const signer = new VcSigner(keyProvider, 'epc-adapter/signing-key-1', keyRecord.did);

const vc = await signer.sign({
  type: 'PropertyCredential',
  credentialSubject: {
    id: 'urn:pdtf:uprn:100023336956',
    energyEfficiency: { rating: 'B', score: 85 },
  },
  credentialStatus: {
    id: 'https://adapters.propdata.org.uk/status/epc/1#42',
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '42',
    statusListCredential: 'https://adapters.propdata.org.uk/status/epc/1',
  },
});
```

### Verify a credential

```typescript
import { VcValidator, DidResolver, TirClient } from '@pdtf/core';

const validator = new VcValidator();
const result = await validator.validate(vc, {
  didResolver: new DidResolver(),
  tirClient: new TirClient(),
  credentialPaths: ['Property:/energyEfficiency/*'],
});

console.log(result.valid); // true
console.log(result.stages.signature.passed); // true
```

### Resolve a DID

```typescript
import { DidResolver } from '@pdtf/core/did';

const resolver = new DidResolver();
const doc = await resolver.resolve('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
```

### Check revocation status

```typescript
import { checkStatus } from '@pdtf/core/status';

const revoked = await checkStatus(
  'https://adapters.propdata.org.uk/status/epc/1',
  42
);
```

## Architecture

This package implements the consensus-free infrastructure layer of PDTF 2.0:

- **Cryptography**: Ed25519 signing with `eddsa-jcs-2022` cryptosuite (D4, D6)
- **Identity**: `did:key` for persons, `did:web` for organisations/transactions (D7)
- **Revocation**: W3C Bitstring Status List v1.0 (D18)
- **Trust**: Trusted Issuer Registry with entity:path authorisation (D8, D20)

Decision references (D1–D32) are documented in the [PDTF 2.0 Architecture Overview](https://property-data-standards-co.github.io/webv2/specs/00/).

## CLI

The `pdtf` CLI provides command-line access to core PDTF operations. Install globally or use via `npx`:

```bash
npm install -g @pdtf/core
# or
npx @pdtf/core <command>
```

### `pdtf did resolve <did>`

Resolve a DID and print the DID Document as JSON.

```bash
$ pdtf did resolve did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
{
  "@context": ["https://www.w3.org/ns/did/v1", ...],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{ ... }],
  "authentication": ["did:key:z6Mkh...#z6Mkh..."],
  "assertionMethod": ["did:key:z6Mkh...#z6Mkh..."]
}
```

Supports both `did:key` (local resolution) and `did:web` (fetches `/.well-known/did.json`).

### `pdtf vc inspect <file>`

Pretty-print a Verifiable Credential — shows type, issuer, subject, dates, proof details, evidence, and terms of use.

```bash
$ pdtf vc inspect credential.json

Verifiable Credential

  Type: VerifiableCredential, PropertyDataCredential
  Issuer: did:key:z6Mkh...
  Subject: urn:pdtf:uprn:100023336956
  Valid From: 2025-01-15T09:00:00Z
  Valid Until: (none)

Proof

  Type: DataIntegrityProof
  Cryptosuite: eddsa-jcs-2022
  Verification Method: did:key:z6Mkh...#z6Mkh...
  Proof Value: z3FbQ7c...  (88 chars)
```

### `pdtf vc verify <file> [--tir <registry.json>]`

Run the 4-stage verification pipeline on a signed VC:

1. **Structure** — valid VC shape, required fields present
2. **Signature** — Ed25519 proof verification via DID resolution
3. **TIR** — issuer authorisation check (requires `--tir`)
4. **Status** — revocation check (skipped in CLI mode)

```bash
$ pdtf vc verify signed-credential.json --tir registry.json

  ✓ Structure
  ✓ Signature
  ✓ TIR
  ○ Status (skipped)

  Credential is valid
```

Without `--tir`, the TIR stage is skipped:

```bash
$ pdtf vc verify signed-credential.json

  ✓ Structure
  ✓ Signature
  ○ TIR (skipped)
  ○ Status (skipped)

  Credential is valid
```

### `pdtf tir validate [file]`

Validate a Trusted Issuer Registry file against the expected schema. Checks required fields, valid trust levels, valid statuses, and uniqueness of DIDs/slugs.

```bash
$ pdtf tir validate registry.json
✓ 3 issuers, 2 account providers — all valid
```

Defaults to `registry.json` in the current directory if no file is specified.

### `pdtf org init --domain <domain> [--output <dir>]`

Scaffold a new organisation `did:web` identity — generates an Ed25519 keypair and DID Document.

```bash
$ pdtf org init --domain propdata.org.uk --output ./my-org

✓ Organisation DID initialised

  DID:                 did:web:propdata.org.uk
  Verification Method: did:web:propdata.org.uk#key-1
  DID Document:        ./my-org/did.json
  Private Key (JWK):   ./my-org/private-key.jwk

⚠ WARNING: Secure the private key file!

Next steps:
  1. Host did.json at https://propdata.org.uk/.well-known/did.json
  2. Register the DID in your Trusted Issuer Registry
```

**Flags:**
- `--domain <domain>` — the domain for the `did:web` identifier (required)
- `--output <dir>` — output directory for generated files (defaults to `.`)

## Cross-Language Compatibility

PDTF 2.0 has implementations in four languages:

| Language | Package | Repository |
|----------|---------|------------|
| **TypeScript** | `@pdtf/core` | This repo |
| **Rust** | `pdtf-core` | [core-rs](https://github.com/property-data-standards-co/core-rs) |
| **Python** | `pdtf_core` | [core-rs/bindings/python](https://github.com/property-data-standards-co/core-rs/tree/main/bindings/python) |
| **C#/.NET** | `Pdtf.Core` | [core-rs/bindings/dotnet](https://github.com/property-data-standards-co/core-rs/tree/main/bindings/dotnet) |

All implementations use the same underlying algorithms:

- **Ed25519** for signing (EdDSA over Curve25519)
- **JCS (RFC 8785)** for JSON canonicalization before signing
- **`did:key`** with Ed25519 multicodec prefix (`0xed01`)
- **`eddsa-jcs-2022`** cryptosuite for DataIntegrityProof

**VCs signed in any language verify correctly in any other.** A credential signed with the Python bindings will pass verification in the TypeScript validator, and vice versa. This is enforced by the shared cryptographic primitives and W3C-compliant canonicalization.

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT — Ed Molyneux / Moverly
