![EveryCRED Logo](src/assets/images/image.png)

# EveryCRED Verifier JS

[![Made by EveryCRED](https://img.shields.io/badge/Made%20by-EveryCRED-blue)](https://everycred.com)
![Version](https://img.shields.io/badge/Version-2.0.0-blue)

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

## Migrating from v2.x to v3.0.0

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

## Package Notes

Version 3.0.0 of the EveryCRED Verifier JS verifies EveryCRED credentials according to the W3C credentials standard. The package supports both SD JWT format and traditional Ed25519 format credentials, with automatic format detection and routing. Blockchain explorer API keys are supplied by the consumer at runtime via `blockchainApiKeys` and are never bundled with the package. 