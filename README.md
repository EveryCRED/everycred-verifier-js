![EveryCRED Logo](src/assets/images/image.png)

# EveryCRED Verifier JS :lock:

Version: 1.0.11 :bookmark_tabs:

EveryCRED Verifier JS is a custom verifier designed to verify EveryCRED credentials according to the W3C credentials standard.

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
   - **DisplayHtml (Optional)** :heavy_check_mark:: Check the existence of the "displayHtml" field.
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
     - EthereumRopsten
     - EthereumSepolia
     - PolygonMainnet
     - PolygonTestnet

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

## Package Notes :memo:

Version 1.0.11 of the EveryCRED Verifier JS to verify EveryCRED credentials according to the W3C credentials standard.
