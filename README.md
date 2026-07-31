![EveryCRED Logo](src/assets/images/image.png)

# EveryCRED Verifier JS

[![Made by EveryCRED](https://img.shields.io/badge/Made%20by-EveryCRED-blue)](https://everycred.com)
![Version](https://img.shields.io/badge/Version-3.0.0--beta.1-blue)

[EveryCRED Verifier JS](https://www.npmjs.com/package/@viitorcloudtechnologies/everycred-verifier-js) is a custom verifier designed to verify EveryCRED credentials according to the W3C credentials standard.

## Installation

You can install the library using npm:

```shell
npm i @viitorcloudtechnologies/everycred-verifier-js
```

## Supported Algorithm Formats

The EveryCRED Verifier JS supports two credential formats:

1. **JsonWebSignature** (`vc+ld+sd_jwt`): 
   - Selective Disclosure JSON Web Token format
   - Uses JWT with RS256 signature verification
   - Supports selective disclosure of credential claims

2. **Ed25519 Format**: 
   - Traditional Ed25519 signature format
   - Uses Ed25519Signature2020 proof type

## Usage

## Configuration Options

The `EveryCredVerifier` constructor accepts a `VerificationConfig` object with the following options:

- `offChainVerification` (boolean, default: `false`): Perform verification without requiring internet connection or external API calls 
- `isBlockchainVerificationEnabled` (boolean, default: `true`): Enable blockchain-based verification checks. Note: for SD JWT credentials this value is overridden automatically based on the presence of an `evidence` field (see [SD JWT Credential Format](#sd-jwt-credential-format)).
- `logDiagnosticStep` (boolean, default: `false`): Enable detailed diagnostic logging in the console
- `blockchainApiKeys` (object, default: `{}`): Blockchain explorer API keys supplied by **you** at runtime — required for on-chain verification. The library no longer bundles any keys.
  - `ethereum` (string): [Etherscan](https://etherscan.io/myapikey) API key. Used for any network reached through the Etherscan v2 multichain API — currently Ethereum Mainnet, Ethereum Sepolia, Polygon Mainnet, and Polygon Amoy.
  - `polygon` (string): [Polygonscan](https://polygonscan.com/myapikey) API key. Used for Polygon Testnet.

  Each network entry declares which key it needs, so you only have to provide the keys for the networks your credentials actually use. Networks reached over the Etherscan v2 endpoint are distinguished by their `chainId`.

  > **Breaking change (v3.0.0):** API keys are no longer shipped with the package. On-chain verification will fail with a clear error (`Failed to retrieve URL or API key from the matched API.`) unless you provide your own keys via `blockchainApiKeys`. Off-chain verification is unaffected. **Never hardcode these keys** — load them from environment variables or a secrets manager.
- `offlinePublicKey` (object or array, optional): A caller-pinned Ed25519 public key (or keys) used to verify the signature when the issuer profile cannot be fetched (e.g. `offChainVerification` with no network access). Applies to **Ed25519-format** credentials and to **EdDSA-signed SD JWT** credentials. See [Offline signature verification](#offline-signature-verification-offlinepublickey) below.

## On-Chain Verification

The EveryCRED Verifier JS performs on-chain verification to validate the credentials against the blockchain. This process involves fetching and comparing blockchain data to ensure the credential's integrity and authenticity.

### Steps

1. **Blockchain Hash Fetch**: Fetch the blockchain hash of the credential.
2. **Generate Credential Hash**: Generate a hash of the credential.
3. **Checksum Integrity**: Compare the generated hash with the blockchain hash.
4. **Revocation Check**: Check if the credential has been revoked.
5. **Expiration Check**: Verify if the credential has expired.

### Usage

```typescript
import { EveryCredVerifier } from '@viitorcloudtechnologies/everycred-verifier-js';

// Define a progress callback function to receive updates
const progressCallback = (step: string, title: string, status: boolean, reason: string) => {
    console.log(`Step: ${step}, Title: ${title}, Status: ${status}, Reason: ${reason}`);
};

// Create a certificate object for verification
const certificate = {
    // Define your certificate properties here
    // For SD JWT format, include: format, credential, disclosures, issuer, issued_at
    // For Ed25519 format, include standard W3C credential fields
};

// Create an instance of EveryCredVerifier with configuration.
// Supply your own blockchain explorer API keys at runtime — never hardcode them.
const verifier = new EveryCredVerifier(progressCallback, {
    isBlockchainVerificationEnabled: true,
    blockchainApiKeys: {
        ethereum: process.env.ETHERSCAN_API_KEY,
        polygon: process.env.POLYGONSCAN_API_KEY,
    },
});

// Perform on-chain verification
const verificationResult = await verifier.verify(certificate);

// Handle the verification result
console.log("Verification message:", verificationResult.message);
console.log("Verification status:", verificationResult.status);
console.log("Network name:", verificationResult.networkName);
```

This code demonstrates how to use the EveryCredVerifier package for on-chain verification. First, a progress callback function is defined to receive updates during the verification process. Then, a certificate object is created with the relevant properties.

Next, an instance of EveryCredVerifier is created with the progress callback function and configuration options. The `verify` method is called with the certificate object, triggering the on-chain verification process. Finally, the verification result is handled, displaying the verification message, status, and network name.

## Off-Chain Verification

The EveryCRED Verifier JS offers off-chain verification capabilities in addition to its on-chain verification functionality. This feature comprises two main components:

### Steps

1. **Proof Value Verification**:
    - Verify the existence and correctness of the proof value within the credential.
    - Ensure that the credential's proof adheres to the expected format and contains all necessary information.
    - For SD JWT format: Verify JWT signature using RS256 algorithm.
    - For Ed25519 format: Verify Ed25519 signature.

2. **Revocation Verification:**
    - **Online Mode**:
        - If the verifier is online, it will attempt to fetch the issuer profile and the revocation list from the provided URLs.
        - The fetched data is then used to check if the credential ID is listed in the revocation list.
        - **Every issuer profile is expected to publish a `revocationList` URL.** If the URL is missing, or the list cannot be fetched (network error, non-JSON, empty response), verification **fails**. An empty `revokedAssertions: []` array is a valid response and is treated as "nothing revoked" — verification proceeds normally in that case. See [Migrating from v2.x to v3.0.0](#migrating-from-v2x-to-v300) below for details on this breaking change.
    - **Offline Mode**:
        - When the verifier is offline, it does not perform revocation checking.
        - Only the expiration dates (valid from and valid until) are verified against the local data.
        - Revocation checking is skipped in offline mode to ensure that the verification process remains lightweight and does not rely on external resources when offline.

### Usage

```typescript
// Create an instance of EveryCredVerifier with off-chain verification enabled
const verifier = new EveryCredVerifier(progressCallback, {
    offChainVerification: true,
    logDiagnosticStep: true
});

// Perform off-chain verification
const verificationResult = await verifier.verify(certificate);
```

This code snippet creates an instance of EveryCredVerifier with the `offChainVerification` flag set to `true` in the configuration object. It then calls the verify method with the certificate object. By default, `offChainVerification` is set to `false` for on-chain verification.

### Offline Signature Verification (`offlinePublicKey`)

For credentials whose issuer uses a DID-document profile (`verificationMethod[].publicKeyJwk`), signature verification normally resolves the public key from that profile — which requires fetching it over the network. In a genuinely offline scenario (no network access at all, e.g. a QR-code scan with no connectivity), that fetch isn't possible, so the key must be supplied up front.

`offlinePublicKey` lets you pin the raw Ed25519 public key(s) you trust, instead of the whole issuer profile — kept intentionally minimal (a 32-byte key rather than a full JSON/DID document) so it's cheap to carry in size-constrained transports such as a CBOR-encoded payload:

```typescript
const verifier = new EveryCredVerifier(progressCallback, {
    offChainVerification: true,
    offlinePublicKey: {
        // Optional: matches proof.verificationMethod (or its '#fragment').
        // Omit when the issuer has a single key.
        id: 'did:web:issuer.example#key-1',
        // Raw Ed25519 public key (32 bytes), base64 or base64url encoded.
        publicKey: 'MCowBQYDK2VwAyEA...', // example only
    },
});

const verificationResult = await verifier.verify(certificate, true);
```

Multiple keys (e.g. an issuer with several active signing keys) can be supplied as an array; the matching `id` (or its `#fragment`) is used to pick the right one. When `offlinePublicKey` is not supplied, the verifier falls back to resolving the key from the issuer profile (if reachable) or the legacy embedded-key format.

For **SD JWT** credentials the same option applies, matched against the JWT header's `kid`. Because the pinned key is always Ed25519, the token must be `EdDSA`-signed — an `RS256` token with a pinned key is rejected as an algorithm mismatch rather than silently verified. RS256 SD JWTs carry their PEM key inside the `kid` itself, so they already verify without any network access and need no pinned key.

> **What `offChainVerification` does and does not skip:** it skips **blockchain anchor lookups only**. The issuer-profile and revocation-list fetches are ordinary HTTP requests, so they are attempted whenever the environment reports connectivity, independent of this flag. When the environment reports being offline, those fetches are skipped and revocation falls back to validity-date checks only — supply `offlinePublicKey` so signature verification still succeeds in that case.

## SD JWT Credential Format

### Structure

SD JWT credentials must have the following structure:

```typescript
{
  format: 'vc+ld+sd_jwt',
  credential: string,      // JWT token string
  disclosures: string[],   // Array of disclosure strings
  issuer: string,          // Issuer identifier
  issued_at: string        // ISO 8601 timestamp
}
```

### Example

```typescript
const sdCredential = {
  format: 'vc+ld+sd_jwt',
  credential: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiY2RlZiMxMjM0NTY3ODkwIn0...',
  disclosures: ['WyIxMjM0NTY3ODkwIiwibmFtZSIsIkpvaG4gRG9lIl0', 'WyIxMjM0NTY3ODkwIiwiaWF0IiwxNjAwMDAwMDAwXQ'],
  issuer: 'did:example:issuer',
  issued_at: '2024-01-01T00:00:00Z'
};

const verifier = new EveryCredVerifier(progressCallback);
const result = await verifier.verify(sdCredential);
```

### Special Notes

- **Evidence Field**: For SD JWT credentials, blockchain verification is decided automatically by the presence of an `evidence` field — if `evidence` is present, on-chain verification runs; if it is absent, on-chain verification is skipped. This auto-detection overrides any `isBlockchainVerificationEnabled` value passed in the configuration for this format.
- **Signature Algorithm**: SD JWT credentials use RS256 algorithm for signature verification.

## Issuer Profile Key Resolution (DID Documents)

Starting in `3.0.0-beta.0`, the issuer's signing key is resolved from the issuer's **published profile**
instead of being trusted directly from the credential/JWT:

- If the issuer profile exposes a DID-document-style `verificationMethod[]` array (each entry carrying a
  `publicKeyJwk`), the verifier resolves the correct entry using the credential's key reference (the SD-JWT
  header `kid`, or the Ed25519 `proof.verificationMethod`) and uses **that** key to verify the signature.
- The resolved key's `controller`/`id` DID is checked against the DID named in the credential's key
  reference, so a credential cannot be verified against a key belonging to a different issuer DID.
- The JWT `alg` header is cross-checked against the resolved key's type (EdDSA ↔ OKP/Ed25519, RS256 ↔ RSA);
  a mismatch fails verification instead of trusting the header's declared algorithm.
- Legacy issuer profiles (the `@context`/`type`/`publicKey[]` shape, or an embedded key on the credential
  itself) remain supported as a fallback for issuers that have not migrated to DID documents.

This closes a class of key-confusion issues where a credential's own header/proof could point at an
arbitrary key rather than one actually published by the issuer.

## Migrating from v2.x to v3.0.0

v3.0.0 introduces **two breaking changes**. Review both before upgrading.

### 1. Blockchain explorer API keys are no longer bundled

v3.0.0 removes the blockchain explorer API keys that were previously bundled with the package. To upgrade:

1. **Obtain your own keys** from [Etherscan](https://etherscan.io/myapikey) and, if you verify Polygon Testnet credentials, [Polygonscan](https://polygonscan.com/myapikey).
2. **Pass them via `blockchainApiKeys`** when constructing the verifier (see [Configuration Options](#configuration-options)). Load them from environment variables or a secrets manager — never hardcode them.

```typescript
// v2.x — keys were bundled, nothing to pass
const verifier = new EveryCredVerifier(progressCallback, { isBlockchainVerificationEnabled: true });

// v3.x — supply your own keys
const verifier = new EveryCredVerifier(progressCallback, {
  isBlockchainVerificationEnabled: true,
  blockchainApiKeys: {
    ethereum: process.env.ETHERSCAN_API_KEY,
    polygon: process.env.POLYGONSCAN_API_KEY,
  },
});
```

No change is required for off-chain verification, or for SD JWT credentials without an `evidence` field (on-chain verification is skipped in those cases).

### 2. Issuer profiles must publish a revocation list

Previously, an issuer profile with no `revocationList` URL (or one that failed to fetch) was treated as
"nothing to revoke against" and verification passed. **This leniency has been removed.**

> **⚠️ Known consequence:** any issuer profile that does not publish a `revocationList` URL will now
> **fail verification** until the issuer publishes one. This is an intentional product decision, but it is
> a real behavioral change from `2.0.0` — if you verify credentials from issuers you do not control, confirm
> they have published a revocation list (an empty `revokedAssertions: []` list is fine) before upgrading.

| Scenario | v2.0.0 | v3.0.0-beta.0 |
|---|---|---|
| `revocationList` URL missing from issuer profile | Pass (nothing to check) | **Fail** |
| `revocationList` URL present but unfetchable (network error, non-JSON, empty) | Pass | **Fail** (`REVOCATION_LIST_FETCH_ERROR`) |
| `revocationList` fetched with `revokedAssertions: []` | Pass | Pass (unchanged) |
| Credential ID present in `revokedAssertions` | Fail | Fail (unchanged) |

No configuration change is required to adopt this — it is enforced automatically during revocation
verification (see [Off-Chain Verification](#off-chain-verification) above).

## Package Notes

Version 3.0.0-beta.1 of the EveryCRED Verifier JS verifies EveryCRED credentials according to the W3C credentials standard. The package supports both SD JWT format and traditional Ed25519 format credentials, with automatic format detection and routing. Blockchain explorer API keys are supplied by the consumer at runtime via `blockchainApiKeys` and are never bundled with the package. Issuer signing keys are resolved from the issuer's published profile (DID document `verificationMethod`, with legacy formats supported as a fallback), and issuer profiles are now required to publish a revocation list for verification to succeed.

> **Pre-release notice:** `3.0.0-beta.1` is a pre-release of the 3.0.0 line, published to the npm `beta` dist-tag. It has not been merged into `main` and is not the `latest` stable release. See the [GitHub Releases page](https://github.com/EveryCRED/everycred-verifier-js/releases) for full details on each pre-release.