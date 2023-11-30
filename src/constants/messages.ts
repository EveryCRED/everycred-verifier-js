export enum Messages {
  VERIFICATION_SUCCESS = "Verification Successful",
  VERIFICATION_FAILED = "Verification Failed",

  TYPE_KEY_VALIDATE = "Validate Credential type",
  TYPE_KEY_SUCCESS = "Credential type key is present in the credential with valid data.",
  TYPE_KEY_ERROR = "Credential type key is not present or having invalid data in the credential.",

  CONTEXT_KEY_VALIDATE = "Validate Credential @context",
  CONTEXT_KEY_SUCCESS = "Credential @context key is present in the credential with valid data.",
  CONTEXT_KEY_ERROR = "Credential @context key is not present or having invalid data in the credential.",

  ID_KEY_VALIDATE = "Validate Credential id",
  ID_KEY_SUCCESS = "Credential id key is present in the credential with valid data.",
  ID_KEY_ERROR = "Credential id key is not present or having invalid data in the credential.",

  CREDENTIAL_SUBJECT_KEY_VALIDATE = "Validate Credential credentialSubject",
  CREDENTIAL_SUBJECT_KEY_SUCCESS = "Credential credential subject key is present in the certificate with valid data.",
  CREDENTIAL_SUBJECT_KEY_ERROR = "Credential credentialSubject key is not present or having invalid data in the credential.",

  CREDENTIALS_VALIDATION = "Credentials validation",
  CREDENTIALS_VALIDATION_SUCCESS = "Credentials validation succeeded",
  CREDENTIALS_VALIDATION_FAILED = "Credentials validation failed",

  CREDENTIAL_VALIDATION = "Credential validation",
  CREDENTIAL_VALIDATION_SUCCESS = "Credential validation succeeded",
  CREDENTIAL_VALIDATION_FAILED = "Credential validation failed",

  PROOF_KEY_VALIDATE = "Validate Credential proof",
  PROOF_KEY_SUCCESS = "Credential proof key is present in the credential with valid data.",
  PROOF_KEY_ERROR = "Credential proof key is not present or having invalid data in the credential.",

  ISSUANCE_DATE_KEY_VALIDATE = "Validate issuance date",
  ISSUANCE_DATE_KEY_SUCCESS = "Credential issuance date key is present in the credential with valid data.",
  ISSUANCE_DATE_KEY_ERROR = "Credential issuance date key is not present or having invalid data in the credential.",

  ISSUER_VALIDATION = 'Issuer validation',
  ISSUER_VALIDATION_SUCCESS = 'Issuer validation succeeded',
  ISSUER_VALIDATION_FAILED = 'Issuer validation failed',

  ISSUER_KEY_SUCCESS = "Credential issuer validation successful.",
  ISSUER_KEY_ERROR = "Credential issuer key is not present or having invalid data in the credential.",

  FETCHING_ISSUER_PROFILE = "Fetching issuer validation started",
  FETCHING_ISSUER_PROFILE_SUCCESS = "Issuer profile details fetched successfully.",
  FETCHING_ISSUER_PROFILE_ERROR = "Error while fetching issuer profile details",

  CONTEXT_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information @context",
  CONTEXT_ISSUER_PROFILE_KEY_SUCCESS = "@context key is present in the issuer profile information with valid data.",
  CONTEXT_ISSUER_PROFILE_KEY_ERROR = "Credential @context key is not present or having invalid data in the issuer profile information.",

  TYPE_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information type",
  TYPE_ISSUER_PROFILE_KEY_SUCCESS = "type key is present in the issuer profile information with valid data.",
  TYPE_ISSUER_PROFILE_KEY_ERROR = "type key is not present or having invalid data in the issuer profile information.",

  ID_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information id",
  ID_ISSUER_PROFILE_KEY_SUCCESS = "id key is present in the issuer profile information with valid data.",
  ID_ISSUER_PROFILE_KEY_ERROR = "id key is not present or having invalid data in the issuer profile information.",

  NAME_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information name",
  NAME_ISSUER_PROFILE_KEY_SUCCESS = "name key is present in the issuer profile information with valid data.",
  NAME_ISSUER_PROFILE_KEY_ERROR = "name key is not present or having invalid data in the issuer profile information.",

  EMAIL_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information email",
  EMAIL_ISSUER_PROFILE_KEY_SUCCESS = "email key is present in the issuer profile information with valid data.",
  EMAIL_ISSUER_PROFILE_KEY_ERROR = "email key is not present or having invalid data in the issuer profile information.",

  REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information revocationList",
  REVOCATION_LIST_ISSUER_PROFILE_KEY_SUCCESS = "revocationList key is present in the issuer profile information with valid data.",
  REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR = "revocationList key is not present or having invalid data in the issuer profile information.",

  PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE = "Validate issuer profile information publicKey",
  PUBLIC_KEY_ISSUER_PROFILE_KEY_SUCCESS = "publicKey key is present in the issuer profile information with valid data.",
  PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR = "publicKey key is not present or having invalid data in the issuer profile information.",

  FETCHING_REVOCATION_LIST_ISSUER_PROFILE = "Fetching revocation list started",
  FETCHING_REVOCATION_LIST_ISSUER_PROFILE_SUCCESS = "Fetching revocation list details successfully.",
  FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR = "Error while fetching revocation list",

  REVOCATION_STATUS_VALIDATION = 'Revocation status validation',

  CONTEXT_REVOCATION_LIST_KEY_VALIDATE = "Validate revocation list @context",
  CONTEXT_REVOCATION_LIST_KEY_SUCCESS = "@context key is present in the revocation list with valid data.",
  CONTEXT_REVOCATION_LIST_KEY_ERROR = "@context key is not present or having invalid data in the revocation list.",

  TYPE_REVOCATION_LIST_KEY_VALIDATE = "Validate revocation list type",
  TYPE_REVOCATION_LIST_KEY_SUCCESS = "type key is present in the revocation list with valid data.",
  TYPE_REVOCATION_LIST_KEY_ERROR = "type key is not present or having invalid data in the revocation list.",

  ID_REVOCATION_LIST_KEY_VALIDATE = "Validate revocation list id",
  ID_REVOCATION_LIST_KEY_SUCCESS = "id key is present in the revocation list with valid data.",
  ID_REVOCATION_LIST_KEY_ERROR = "id key is not present or having invalid data in the revocation list.",

  ISSUER_REVOCATION_LIST_KEY_VALIDATE = "Validate revocation list issuer",
  ISSUER_REVOCATION_LIST_KEY_SUCCESS = "issuer key is present in the revocation list with valid data.",
  ISSUER_REVOCATION_LIST_KEY_ERROR = "issuer key is not present or having invalid data in the revocation list.",

  REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE = "Validate revocation list revokedAssertions",
  REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_SUCCESS = "revokedAssertions key is present in the revocation list with valid data.",
  REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR = "revokedAssertions key is not present or having invalid data in the revocation list.",

  VALID_UNTIL_DATE_KEY_VALIDATE = "Validate Credential validUntil",
  VALID_UNTIL_DATE_KEY_SUCCESS = "validUntil key is present in the credential with valid data.",
  VALID_UNTIL_DATE_KEY_ERROR = "credential is expired.",

  VALID_FROM_DATE_KEY_VALIDATE = "Validate Credential validFrom",
  VALID_FROM_DATE_KEY_SUCCESS = "validFrom key is present in the credential with valid data.",
  VALID_FROM_DATE_KEY_ERROR = "credential is not yet validated.",

  REVOCATION_STATUS_CHECK_SUCCESS = "Credential is valid and not revoked.",
  REVOCATION_STATUS_CHECK_FAILED = "Revocation status check failed",

  FETCHING_NORMALIZED_DECODED_DATA = "Fetching normalized and decoded data started",
  FETCHING_NORMALIZED_DECODED_DATA_SUCCESS = "Fetched normalized and decoded data successfully.",
  FETCHING_NORMALIZED_DECODED_DATA_ERROR = "Error while fetching normalized and decoded data",

  FETCHING_AES_NORMALIZED_DECODED_DATA_SUCCESS = "Fetched normalized and decoded data with AES successfully.",
  FETCHING_AES_NORMALIZED_DECODED_DATA_ERROR = "Error while fetching normalized and decoded data with AES",

  ANCHOR_DECODED_DATA_KEY_VALIDATE = "Validate decoded data anchors",
  ANCHOR_DECODED_DATA_KEY_SUCCESS = "anchors key is present with valid data.",
  ANCHOR_DECODED_DATA_KEY_ERROR = "Invalid credential.",

  PATH_DECODED_DATA_KEY_VALIDATE = "Validate decoded data path",
  PATH_DECODED_DATA_KEY_SUCCESS = "path key is present with valid data.",
  PATH_DECODED_DATA_KEY_ERROR = "path key is not present or having invalid data list.",

  MERKLEROOT_DECODED_DATA_KEY_VALIDATE = "Validate decoded data merkleRoot",
  MERKLEROOT_DECODED_DATA_KEY_SUCCESS = "merkleRoot key is present with valid data.",
  MERKLEROOT_DECODED_DATA_KEY_ERROR = "merkleRoot key is not present or having invalid data list.",

  TARGETHASH_DECODED_DATA_KEY_VALIDATE = "Validate decoded data targetHash",
  TARGETHASH_DECODED_DATA_KEY_SUCCESS = "targetHash key is present with valid data.",
  TARGETHASH_DECODED_DATA_KEY_ERROR = "targetHash key is not present or having invalid data list.",

  BLOCKCHAIN_DATA_VALIDATE = "Validate data retrieval from Blockchain API.",
  SELECTED_ANCHOR_RETRIEVAL_ERROR = "Failed to retrieve selected anchor.",
  REQUIRED_VALUES_RETRIEVAL_ERROR = "Failed to retrieve required values from the selected anchor.",
  BASE_API_OR_NETWORK_RETRIEVAL_ERROR = "Failed to retrieve base API or base network value.",
  NO_MATCHING_API_FOUND_ERROR = "No matching API found.",
  URL_OR_APIKEY_RETRIEVAL_ERROR = "Failed to retrieve URL or API key from the matched API.",
  TRANSACTION_NOT_FOUND_ERROR = "Transaction not found.",
  DATA_FETCHED_ERROR = "Failed to fetch data from the blockchain API.",
  DATA_FETCHED_SUCCESS = "Data successfully fetched from the blockchain API.",

  MERKLE_PROOF_VALIDATE = 'Validate Merkleproof',

  CALCULATED_HASH_DIFFER_FROM_MERKLEROOT = "The calculated hash does not match the provided merkleRoot.",
  CALCULATED_HASH_MATCHES_WITH_MERKLEROOT = "The calculated hash matches the provided merkleRoot.",

  VALIDATE_TARGET_HASH = 'Validate target hash',

  CALCULATED_HASH_DIFFER_FROM_TARGETHASH = "The calculated hash does not match the provided targetHash.",
  CALCULATED_HASH_MATCHES_WITH_TARGETHASH = "The calculated hash matches the provided targetHash.",

  MERKLE_PROOF_2019_VALIDATION = "MerkleProof2019 validation",
  MERKLE_PROOF_2019_VALIDATION_SUCCESS = "MerkleProof2019 validation successful.",
  MERKLE_PROOF_2019_VALIDATION_FAILED = "MerkleProof2019 validation failed.",

}
