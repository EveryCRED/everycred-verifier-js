export enum Messages {
  TYPE_KEY_VALIDATE = "Checking Credential type...",
  TYPE_KEY_SUCCESS = "Credential type key is present in the credential with valid data.",
  TYPE_KEY_ERROR = "Credential type key is not present or having invalid data in the credential.",

  CONTEXT_KEY_VALIDATE = "Checking credential @context...",
  CONTEXT_KEY_SUCCESS = "Credential @context key is present in the credential with valid data.",
  CONTEXT_KEY_ERROR = "Credential @context key is not present or having invalid data in the credential.",

  ID_KEY_VALIDATE = "Checking credential id...",
  ID_KEY_SUCCESS = "Credential id key is present in the credential with valid data.",
  ID_KEY_ERROR = "Credential id key is not present or having invalid data in the credential.",

  CREDENTIAL_SUBJECT_KEY_VALIDATE = "Checking credential credentialSubject...",
  CREDENTIAL_SUBJECT_KEY_SUCCESS = "Credential credential subject key is present in the certificate with valid data.",
  CREDENTIAL_SUBJECT_KEY_ERROR = "Credential credentialSubject key is not present or having invalid data in the credential.",

  PROOF_KEY_VALIDATE = "Checking credential proof...",
  PROOF_KEY_SUCCESS = "Credential proof key is present in the credential with valid data.",
  PROOF_KEY_ERROR = "Credential proof key is not present or having invalid data in the credential.",

  ISSUANCE_DATE_KEY_VALIDATE = "Checking issuance date...",
  ISSUANCE_DATE_KEY_SUCCESS = "Credential issuance date key is present in the credential with valid data.",
  ISSUANCE_DATE_KEY_ERROR = "Credential issuance date key is not present or having invalid data in the credential.",

  ISSUER_VALIDATION_STARTED = "Credential issuer validation started...",
  ISSUER_KEY_SUCCESS = "Credential issuer validation successful.",
  ISSUER_KEY_ERROR = "Credential issuer key is not present or having invalid data in the credential.",

  FETCHING_ISSUER_PROFILE = "Fetching issuer validation started...",
  FETCHING_ISSUER_PROFILE_SUCCESS = "Fetching issuer profile details successfully.",
  FETCHING_ISSUER_PROFILE_ERROR = "Error while fetching issuer profile details",

  CONTEXT_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information @context...",
  CONTEXT_ISSUER_PROFILE_KEY_SUCCESS = "@context key is present in the issuer profile information with valid data.",
  CONTEXT_ISSUER_PROFILE_KEY_ERROR = "Credential @context key is not present or having invalid data in the issuer profile information.",

  TYPE_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information type...",
  TYPE_ISSUER_PROFILE_KEY_SUCCESS = "type key is present in the issuer profile information with valid data.",
  TYPE_ISSUER_PROFILE_KEY_ERROR = "type key is not present or having invalid data in the issuer profile information.",

  ID_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information id...",
  ID_ISSUER_PROFILE_KEY_SUCCESS = "id key is present in the issuer profile information with valid data.",
  ID_ISSUER_PROFILE_KEY_ERROR = "id key is not present or having invalid data in the issuer profile information.",

  NAME_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information name...",
  NAME_ISSUER_PROFILE_KEY_SUCCESS = "name key is present in the issuer profile information with valid data.",
  NAME_ISSUER_PROFILE_KEY_ERROR = "name key is not present or having invalid data in the issuer profile information.",

  EMAIL_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information email...",
  EMAIL_ISSUER_PROFILE_KEY_SUCCESS = "email key is present in the issuer profile information with valid data.",
  EMAIL_ISSUER_PROFILE_KEY_ERROR = "email key is not present or having invalid data in the issuer profile information.",

  REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information revocationList...",
  REVOCATION_LIST_ISSUER_PROFILE_KEY_SUCCESS = "revocationList key is present in the issuer profile information with valid data.",
  REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR = "revocationList key is not present or having invalid data in the issuer profile information.",

  PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE = "Checking issuer profile information publicKey...",
  PUBLIC_KEY_ISSUER_PROFILE_KEY_SUCCESS = "publicKey key is present in the issuer profile information with valid data.",
  PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR = "publicKey key is not present or having invalid data in the issuer profile information.",

  FETCHING_REVOCATION_LIST_ISSUER_PROFILE = "Fetching revocation list started...",
  FETCHING_REVOCATION_LIST_ISSUER_PROFILE_SUCCESS = "Fetching revocation list details successfully.",
  FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR = "Error while fetching revocation list",

  CONTEXT_REVOCATION_LIST_KEY_VALIDATE = "Checking revocation list @context...",
  CONTEXT_REVOCATION_LIST_KEY_SUCCESS = "@context key is present in the revocation list with valid data.",
  CONTEXT_REVOCATION_LIST_KEY_ERROR = "@context key is not present or having invalid data in the revocation list.",

  TYPE_REVOCATION_LIST_KEY_VALIDATE = "Checking revocation list @context...",
  TYPE_REVOCATION_LIST_KEY_SUCCESS = "@context key is present in the revocation list with valid data.",
  TYPE_REVOCATION_LIST_KEY_ERROR = "@context key is not present or having invalid data in the revocation list.",

  ID_REVOCATION_LIST_KEY_VALIDATE = "Checking revocation list id...",
  ID_REVOCATION_LIST_KEY_SUCCESS = "id key is present in the revocation list with valid data.",
  ID_REVOCATION_LIST_KEY_ERROR = "id key is not present or having invalid data in the revocation list.",

  ISSUER_REVOCATION_LIST_KEY_VALIDATE = "Checking revocation list issuer...",
  ISSUER_REVOCATION_LIST_KEY_SUCCESS = "issuer key is present in the revocation list with valid data.",
  ISSUER_REVOCATION_LIST_KEY_ERROR = "issuer key is not present or having invalid data in the revocation list.",

  REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE = "Checking revocation list revokedAssertions...",
  REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_SUCCESS = "revokedAssertions key is present in the revocation list with valid data.",
  REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR = "revokedAssertions key is not present or having invalid data in the revocation list.",

  VALID_UNTIL_DATE_KEY_VALIDATE = "Checking credential validUntil...",
  VALID_UNTIL_DATE_KEY_SUCCESS = "validUntil key is present in the credential with valid data.",
  VALID_UNTIL_DATE_KEY_ERROR = "credential is expired.",

  CERTIFICATE_REVOCATION_LIST_STATUS = "Credential is valid and not revoked.",
}
