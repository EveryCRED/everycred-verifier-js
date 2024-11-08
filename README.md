![EveryCRED Logo](src/assets/images/image.png)

# EveryCRED Verifier JS :lock:

Version: 1.1.2 :bookmark_tabs:

[EveryCRED Verifier JS](https://www.npmjs.com/package/@viitorcloudtechnologies/everycred-verifier-js) is a custom verifier designed to verify EveryCRED credentials according to the W3C credentials standard.

## Installation

You can install the library using npm:

```shell
npm i @viitorcloudtechnologies/everycred-verifier-js
```

## Verifier Steps :clipboard:

The EveryCRED Verifier JS follows the following steps to validate credentials:

1. **Validators** :white_check_mark:: Check the authenticity and integrity of the credential.
   - **Authenticity checks** :closed_lock_with_key:: Verify the authenticity of the credential.
   - **Integrity Checks** :closed_lock_with_key:: Check the integrity of the credential.
   - **Issuer check** :passport_control:: Validate the issuer of the credential.
   - **Data Validation** :abacus:: Perform validation on the credential data.
   - **Checksum Match (Hash Comparison)** :arrows_clockwise:: Compare hashes to ensure the integrity of the credential.
     - **Blockchain Hash Fetch** :link:: Fetch the blockchain hash of the credential.
     - **Generate Credential Hash** :1234:: Generate a hash of the credential.
     - **Checksum Integrity** :heavy_check_mark:: Compare the generated hash with the blockchain hash.

2. **Status Check** :vertical_traffic_light:: Perform checks related to the status of the credential.
   - **Credential Revocation check** :no_entry_sign:: Check if the credential has been revoked.
   - **Credential Expiration check** :alarm_clock:: Verify if the credential has expired.

## Package Verification Steps :package:

The verifier performs detailed verification steps on the package:

1. **Validator** :white_check_mark:: Check the validity of the credential fields.
   - **type** :heavy_check_mark:: Verify if the "type" field exists and supports the "VerifiableCredential" type.
   - **@context** :heavy_check_mark:: Check the existence and validity of the "@context" field.
   - **ID (Identifier)** :heavy_check_mark:: Verify the existence of the "id" field.
   - **credentialSubject** :heavy_check_mark:: Check the existence of the "credentialSubject" field and validate its information.
   - **Issuer** :heavy_check_mark:: Verify the existence and validity of the "issuer" field.
     - Fetch Issuer profile information from the issuer link.
     - Check the validity of the "@context" field in the Issuer profile.
     - Validate the Issuer profile type against the supported types.
     - Check if the "id" matches the issuer link fetched from the credential.
     - Verify the existence of the Issuer's name and email.
     - Check if the revocation list exists.
     - Check the existence and format of the public key.
     - Fetch the Revocation List from the issuer profile.
   - **ValidUntil (Optional)** :heavy_check_mark:: Check the existence and format of the "validUntil" field.
   - **Proof** :heavy_check_mark:: Check the existence and validity of the "proof" field.
     - Validate the fields within the proof.
     - Verify the support for the current proof type ("MerkleProof2019").
   - **IssuanceDate** :heavy_check_mark:: Check the existence of the "issuanceDate" field.

2. **Checksum Match (Hash Comparison)** :arrows_clockwise:: Compare hashes to ensure the integrity of the credential.
   - **Note**: For the first version, only "MerkleProof2019" is supported.
   - Decode "proofValue" and extract signature details.
      - We use **MerkleProof2019** algorithm to decode the "proofValue" and extract the signature details. This will be used for the previously issued credentials.
      - We use **ED25519** algorithm to decode the "proofValue" and extract the signature details. This will be used for the newly issued credentials.

   - Validate the existence of the "anchors" keyword with valid data.
   - Ensure that the following key fields exist in your credentials:
     - "path"
     - "merkleRoot"
     - "targetHash"
     - "anchors"
   - Separate the transaction ID and blink value.
   - Apply chain condition and call the corresponding API:
     - EthereumMainnet
     - EthereumSepolia
     - PolygonMainnet
     - PolygonAmoy

   - Handle API responses:
     - Success: Retrieve the data and get the hash of the credentials from the transaction data.
     - Error: Return the error from the API or indicate transaction lookup errors or transaction not found errors.

3. **Status Check** :vertical_traffic_light::
   - **Revocation** :no_entry_sign:: Check if the "revocationList" exists in the credential and fetch the revocation list details.
     - Validate the "@context" field in the revocation list.
     - Check the validity of the revocation list type against the supported types.
     - Verify the "id" key against the revocation link fetched from the credential.
     - Check if the issuer list exists and match the issuer link from the issuer profile.
     - Verify the existence of "revokedAssertions".
     - Find the credential ID in the revocation list and return a message if revoked.
     - If the ID matches, retrieve the revocation message and indicate that the credential is revoked with the given message.
     - If not matched, consider the credential valid and not revoked.
   - **Expiration (ValidFrom & ValidUntil)** :date:: Validate today's date with the "validFrom" & "validUntil" dates.

## Usage :hammer_and_wrench:

## On-Chain Verification :chains:

The EveryCRED Verifier JS performs on-chain verification to validate the credentials against the blockchain. This process involves fetching and comparing blockchain data to ensure the credential's integrity and authenticity.

### Steps

1. **Blockchain Hash Fetch** :link:: Fetch the blockchain hash of the credential.
2. **Generate Credential Hash** :1234:: Generate a hash of the credential.
3. **Checksum Integrity** :heavy_check_mark:: Compare the generated hash with the blockchain hash.
4. **Revocation Check** :no_entry_sign:: Check if the credential has been revoked.
5. **Expiration Check** :alarm_clock:: Verify if the credential has expired.

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
};

// Create an instance of EveryCredVerifier
const verifier = new EveryCredVerifier(progressCallback);

// Perform on-chain verification
const verificationResult = await verifier.verify(certificate);

// Handle the verification result
console.log("Verification message:", verificationResult.message);
console.log("Verification status:", verificationResult.status);
console.log("Network name:", verificationResult.networkName);
```

This code demonstrates how to use the EveryCredVerifier package for on-chain verification. First, a progress callback function is defined to receive updates during the verification process. Then, a certificate object is created with the relevant properties.

Next, an instance of EveryCredVerifier is created with the progress callback function. The `verify` method is called with the certificate object, triggering the on-chain verification process. Finally, the verification result is handled, displaying the verification message, status, and network name.

## Off-Chain Verification :unlock:

The EveryCRED Verifier JS offers off-chain verification capabilities in addition to its on-chain verification functionality. This feature comprises two main components:

### Steps

1. **Proof Value Verification** :white_check_mark::
    - Verify the existence and correctness of the proof value within the credential.
    - Ensure that the credential's proof adheres to the expected format and contains all necessary information.

2. **Revocation Verification:**
    - **Online Mode** :globe_with_meridians::
        - If the verifier is online, it will attempt to fetch the issuer profile and the revocation list from the provided URLs.
        - The fetched data is then used to check if the credential ID is listed in the revocation list.
    - **Offline Mode** :mobile_phone_off::
        - When the verifier is offline, it does not perform revocation checking.
        - Only the expiration dates (valid from and valid until) are verified against the local data.
        - Revocation checking is skipped in offline mode to ensure that the verification process remains lightweight and does not rely on external resources when offline.

### Usage

```typescript
// Create an instance of EveryCredVerifier
const verifier = new EveryCredVerifier(progressCallback);

// Perform off-chain verification by calling the verify method with the certificate and offChainVerification flag set to true
const verificationResult = await verifier.verify(certificate, true);
```

This code snippet creates an instance of EveryCredVerifier with the offChainVerification flag set to true. It then calls the verify method with the certificate object and the true flag, indicating that off-chain verification should be performed. By default, offChainVerification is set to false for on-chain verification.

## Package Notes :memo:

Version 1.1.2 of the EveryCRED Verifier JS to verify EveryCRED credentials according to the W3C credentials standard.
