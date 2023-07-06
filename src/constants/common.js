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
export var CREDENTIALS_VALIDATORS_KEYS;
(function (CREDENTIALS_VALIDATORS_KEYS) {
    CREDENTIALS_VALIDATORS_KEYS["type"] = "type";
    CREDENTIALS_VALIDATORS_KEYS["context"] = "@context";
    CREDENTIALS_VALIDATORS_KEYS["id"] = "id";
    CREDENTIALS_VALIDATORS_KEYS["credentialSubject"] = "credentialSubject";
    CREDENTIALS_VALIDATORS_KEYS["proof"] = "proof";
    CREDENTIALS_VALIDATORS_KEYS["issuanceDate"] = "issuanceDate";
    CREDENTIALS_VALIDATORS_KEYS["validUntilDate"] = "validUntil";
})(CREDENTIALS_VALIDATORS_KEYS || (CREDENTIALS_VALIDATORS_KEYS = {}));
/* Defining an enum called `CREDENTIALS_ISSUER_VALIDATORS_KEYS` which contains keys used for validating
the properties of a verifiable credential issuer. Each key is assigned a string value. This enum can
be exported and used in other parts of the code to ensure consistency in the keys used for
validation. */
export var CREDENTIALS_ISSUER_VALIDATORS_KEYS;
(function (CREDENTIALS_ISSUER_VALIDATORS_KEYS) {
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["issuer"] = "issuer";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["context"] = "@context";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["type"] = "type";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["id"] = "id";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["name"] = "name";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["email"] = "email";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["revocationList"] = "revocationList";
    CREDENTIALS_ISSUER_VALIDATORS_KEYS["publicKey"] = "publicKey";
})(CREDENTIALS_ISSUER_VALIDATORS_KEYS || (CREDENTIALS_ISSUER_VALIDATORS_KEYS = {}));
/* Defining an enum called `STATUS_REVOCATION_CHECK` which contains keys used for checking the status
of a revocation check. Each key is assigned a string value. This enum can be exported and used in
other parts of the code to ensure consistency in the keys used for revocation check. */
export var REVOCATION_STATUS_CHECK_KEYS;
(function (REVOCATION_STATUS_CHECK_KEYS) {
    REVOCATION_STATUS_CHECK_KEYS["context"] = "@context";
    REVOCATION_STATUS_CHECK_KEYS["type"] = "type";
    REVOCATION_STATUS_CHECK_KEYS["id"] = "id";
    REVOCATION_STATUS_CHECK_KEYS["issuer"] = "issuer";
    REVOCATION_STATUS_CHECK_KEYS["revokedAssertions"] = "revokedAssertions";
})(REVOCATION_STATUS_CHECK_KEYS || (REVOCATION_STATUS_CHECK_KEYS = {}));
export var CHECKSUM_MERKLEPROOF_CHECK_KEYS;
(function (CHECKSUM_MERKLEPROOF_CHECK_KEYS) {
    CHECKSUM_MERKLEPROOF_CHECK_KEYS["decoded_proof_value"] = "decoded_proof_value";
    CHECKSUM_MERKLEPROOF_CHECK_KEYS["get_byte_array_to_issue"] = "get_byte_array_to_issue";
    CHECKSUM_MERKLEPROOF_CHECK_KEYS["anchors"] = "anchors";
    CHECKSUM_MERKLEPROOF_CHECK_KEYS["path"] = "path";
    CHECKSUM_MERKLEPROOF_CHECK_KEYS["merkleRoot"] = "merkleRoot";
    CHECKSUM_MERKLEPROOF_CHECK_KEYS["targetHash"] = "targetHash";
})(CHECKSUM_MERKLEPROOF_CHECK_KEYS || (CHECKSUM_MERKLEPROOF_CHECK_KEYS = {}));
export const BLOCKCHAIN_API_LIST = [
    { id: "ethereumMainnet", url: "https://api.etherscan.io/", apiKey: "FJ3CZWH8PQBV8W5U6JR8TMKAYDHBKQ3B1D" },
    { id: "ethereumSepolia", url: "https://api-sepolia.etherscan.io/", apiKey: "FJ3CZWH8PQBV8W5U6JR8TMKAYDHBKQ3B1D" },
];
export var BASE_API;
(function (BASE_API) {
    BASE_API["eth"] = "ethereum";
})(BASE_API || (BASE_API = {}));
export var BASE_NETWORK;
(function (BASE_NETWORK) {
    BASE_NETWORK["sepolia"] = "Sepolia";
    BASE_NETWORK["mainnet"] = "Mainnet";
})(BASE_NETWORK || (BASE_NETWORK = {}));
export var GENERAL_KEYWORDS;
(function (GENERAL_KEYWORDS) {
    GENERAL_KEYWORDS["url"] = "url";
    GENERAL_KEYWORDS["apiKey"] = "apiKey";
})(GENERAL_KEYWORDS || (GENERAL_KEYWORDS = {}));
export const MERKLE_TREE_VALIDATION_API = 'http://192.168.1.23:8888/user/credential/MarkelTreeVerification?markel_tree_data=normalize_data';
