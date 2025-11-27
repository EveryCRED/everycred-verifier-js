![EveryCRED Logo](src/assets/images/image.png)

# EveryCRED Verifier JS

[![Made by EveryCRED](https://img.shields.io/badge/Made%20by-EveryCRED-blue)](https://everycred.com)
![Version](https://img.shields.io/badge/Version-2.0.0--beta.0-blue)

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
- `isBlockchainVerificationEnabled` (boolean, default: `false`): Enable blockchain-based verification checks
- `logDiagnosticStep` (boolean, default: `false`): Enable detailed diagnostic logging in the console

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

// Create an instance of EveryCredVerifier with configuration
const verifier = new EveryCredVerifier(progressCallback, {
    isBlockchainVerificationEnabled: true
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

- **Evidence Field**: If the credential contains an `evidence` field, blockchain verification is automatically disabled, even if `isBlockchainVerificationEnabled` is set to `true`.
- **Signature Algorithm**: SD JWT credentials use RS256 algorithm for signature verification.

## Package Notes

Version 2.0.0-beta.0 of the EveryCRED Verifier JS to verify EveryCRED credentials according to the W3C credentials standard. The package now supports both SD JWT format and traditional Ed25519 format credentials, with automatic format detection and routing. 