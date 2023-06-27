"use strict";
exports.__esModule = true;
exports.CREDENTIALS_VALIDATORS_KEYS = exports.CREDENTIALS_CONSTANTS = void 0;
exports.CREDENTIALS_CONSTANTS = {
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
    proofTypeSupported: ["MerkleProof2019"]
};
var CREDENTIALS_VALIDATORS_KEYS;
(function (CREDENTIALS_VALIDATORS_KEYS) {
    CREDENTIALS_VALIDATORS_KEYS["type"] = "type";
    CREDENTIALS_VALIDATORS_KEYS["context"] = "@context";
    CREDENTIALS_VALIDATORS_KEYS["id"] = "id";
    CREDENTIALS_VALIDATORS_KEYS["credentialSubject"] = "credentialSubject";
    CREDENTIALS_VALIDATORS_KEYS["proof"] = "proof";
    CREDENTIALS_VALIDATORS_KEYS["issuanceDate"] = "issuanceDate";
    CREDENTIALS_VALIDATORS_KEYS["issuer"] = "issuer";
})(CREDENTIALS_VALIDATORS_KEYS = exports.CREDENTIALS_VALIDATORS_KEYS || (exports.CREDENTIALS_VALIDATORS_KEYS = {}));
