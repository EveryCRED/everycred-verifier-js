/* Defining a constant object called `CREDENTIALS_CONSTANTS` which contains various properties related
to verifiable credentials. These properties include the type of verifiable credential, the context
values, the required keys for the credential subject and proof, the supported proof type, the
context values for the issuer profile, the supported issuer profile type, and the required public
key fields for the issuer profile. This object can be exported and used in other parts of the code
to ensure consistency in the values used for verifiable credentials. */
export const CREDENTIALS_CONSTANTS = {
  verifiable_credential: "VerifiableCredential",
  context_values: [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/v2",
  ],
  credentialSubjectRequiredKeys: ["id", "name", "image"],
  proofRequiredKeys: [
    "type",
    "created",
    "proofPurpose",
    "proofValue",
    "verificationMethod",
  ],
  proofTypeSupported: ["MerkleProof2019"],
  issuer_profile_context_values: [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/v2",
    "https://w3id.org/openbadges/v2",
  ],
  issuerProfileTypeSupported: ["Profile"],
  issuerProfilePublicKeyFields: ["id", "created"],
  revocation_list_context_values: [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/v2",
    "https://w3id.org/openbadges/v2",
  ],
  revocation_list_type_supported: "RevocationList",
};

/* Defining an enum called `CREDENTIALS_VALIDATORS_KEYS` which contains keys used for validating the
properties of a verifiable credential. Each key is assigned a string value. This enum can be
exported and used in other parts of the code to ensure consistency in the keys used for validation. */
export enum CREDENTIALS_VALIDATORS_KEYS {
  type = "type",
  context = "@context",
  id = "id",
  credentialSubject = "credentialSubject",
  proof = "proof",
  issuanceDate = "issuanceDate",
  validUntilDate = "validUntil"
}

/* Defining an enum called `CREDENTIALS_ISSUER_VALIDATORS_KEYS` which contains keys used for validating
the properties of a verifiable credential issuer. Each key is assigned a string value. This enum can
be exported and used in other parts of the code to ensure consistency in the keys used for
validation. */
export enum CREDENTIALS_ISSUER_VALIDATORS_KEYS {
  issuer = "issuer",
  context = "@context",
  type = "type",
  id = "id",
  name = "name",
  email = "email",
  revocationList = "revocationList",
  publicKey = "publicKey",
}

/* Defining an enum called `STATUS_REVOCATION_CHECK` which contains keys used for checking the status
of a revocation check. Each key is assigned a string value. This enum can be exported and used in
other parts of the code to ensure consistency in the keys used for revocation check. */
export enum REVOCATION_STATUS_CHECK_KEYS {
  context = "@context",
  type = "type",
  id = "id",
  issuer = "issuer",
  revokedAssertions = "revokedAssertions",
}
