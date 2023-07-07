"use strict";
exports.__esModule = true;
exports.EveryCredVerifier = void 0;
var credential_issuer_validator_1 = require("./validator/credential-issuer-validator");
var credential_validator_1 = require("./validator/credential-validator");
var EveryCredVerifier = /** @class */ (function () {
    //private credentialIssuerValidation: boolean = false;
    function EveryCredVerifier() {
        var _this = this;
        this.credentialValidation = false;
        this.verify = function (certificate) {
            _this.credentialValidation = new credential_validator_1.CredentialValidator().validate(certificate);
            if (_this.credentialValidation) {
                new credential_issuer_validator_1.CredentialIssuerValidator().validate(certificate);
            }
        };
    }
    return EveryCredVerifier;
}());
exports.EveryCredVerifier = EveryCredVerifier;
