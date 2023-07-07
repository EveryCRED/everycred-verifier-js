"use strict";
exports.__esModule = true;
exports.CredentialValidator = void 0;
var credential_util_1 = require("../utils/credential-util");
var common_1 = require("../constants/common");
var messages_1 = require("../constants/messages");
var logger_1 = require("../utils/logger");
var CredentialValidator = /** @class */ (function () {
    function CredentialValidator() {
    }
    CredentialValidator.prototype.validate = function (credentialData) {
        this.credential = credential_util_1.deepCloneData(credentialData);
        if (this.validateCredentialType() &&
            this.validateCredentialContext() &&
            this.validateCredentialID() &&
            this.validateCredentialCredentialSubject() &&
            this.validateCredentialProof() &&
            this.validateCredentialIssuanceDate()) {
            return true;
        }
        return false;
    };
    CredentialValidator.prototype.validateCredentialType = function () {
        logger_1.logger(messages_1.Messages.TYPE_KEY_VALIDATE);
        if (credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.type)) {
            var typeData = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.type);
            if (typeData.includes(common_1.CREDENTIALS_CONSTANTS.verifiable_credential)) {
                logger_1.logger(messages_1.Messages.TYPE_KEY_SUCCESS);
                return true;
            }
            logger_1.logger(messages_1.Messages.TYPE_KEY_ERROR, "error");
        }
        else {
            logger_1.logger(messages_1.Messages.TYPE_KEY_ERROR, "error");
        }
        return false;
    };
    CredentialValidator.prototype.validateCredentialContext = function () {
        logger_1.logger(messages_1.Messages.CONTEXT_KEY_VALIDATE);
        if (credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.context)) {
            var contextData_1 = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.context);
            if (common_1.CREDENTIALS_CONSTANTS.context_values.some(function (data) {
                return contextData_1.includes(data);
            })) {
                logger_1.logger(messages_1.Messages.CONTEXT_KEY_SUCCESS);
                return true;
            }
            logger_1.logger(messages_1.Messages.CONTEXT_KEY_ERROR, "error");
        }
        else {
            logger_1.logger(messages_1.Messages.CONTEXT_KEY_ERROR, "error");
        }
        return false;
    };
    CredentialValidator.prototype.validateCredentialID = function () {
        logger_1.logger(messages_1.Messages.ID_KEY_VALIDATE);
        if (credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.id)) {
            var idData = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.credentialSubject);
            if (idData) {
                logger_1.logger(messages_1.Messages.ID_KEY_SUCCESS);
                return true;
            }
            logger_1.logger(messages_1.Messages.ID_KEY_ERROR, "error");
        }
        else {
            logger_1.logger(messages_1.Messages.ID_KEY_ERROR, "error");
        }
        return false;
    };
    CredentialValidator.prototype.validateCredentialCredentialSubject = function () {
        logger_1.logger(messages_1.Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE);
        if (credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.credentialSubject)) {
            var credentialSubjectData_1 = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.credentialSubject);
            if (credentialSubjectData_1 &&
                common_1.CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys.every(function (data) {
                    return Object.keys(credentialSubjectData_1).includes(data);
                })) {
                var flag = false;
                for (var _i = 0, _a = common_1.CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys; _i < _a.length; _i++) {
                    var key = _a[_i];
                    if (!credentialSubjectData_1[key]) {
                        flag = true;
                        break;
                    }
                }
                if (!flag) {
                    logger_1.logger(messages_1.Messages.CREDENTIAL_SUBJECT_KEY_SUCCESS);
                    return true;
                }
            }
            logger_1.logger(messages_1.Messages.CREDENTIAL_SUBJECT_KEY_ERROR, "error");
        }
        else {
            logger_1.logger(messages_1.Messages.CREDENTIAL_SUBJECT_KEY_ERROR, "error");
        }
        return false;
    };
    CredentialValidator.prototype.validateCredentialProof = function () {
        logger_1.logger(messages_1.Messages.PROOF_KEY_VALIDATE);
        if (credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.proof)) {
            var proofData_1 = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.proof);
            if (proofData_1 &&
                common_1.CREDENTIALS_CONSTANTS.proofRequiredKeys.every(function (data) {
                    return Object.keys(proofData_1).includes(data);
                })) {
                var flag = false;
                for (var _i = 0, _a = common_1.CREDENTIALS_CONSTANTS.proofRequiredKeys; _i < _a.length; _i++) {
                    var key = _a[_i];
                    if (!proofData_1[key]) {
                        flag = true;
                        break;
                    }
                }
                if (!flag &&
                    common_1.CREDENTIALS_CONSTANTS.proofTypeSupported.some(function (data) { return proofData_1.type === data; })) {
                    logger_1.logger(messages_1.Messages.PROOF_KEY_SUCCESS);
                    return true;
                }
            }
            logger_1.logger(messages_1.Messages.PROOF_KEY_ERROR, "error");
        }
        else {
            logger_1.logger(messages_1.Messages.PROOF_KEY_ERROR, "error");
        }
        return false;
    };
    CredentialValidator.prototype.validateCredentialIssuanceDate = function () {
        logger_1.logger(messages_1.Messages.ISSUANCE_DATE_KEY_VALIDATE);
        if (credential_util_1.isKeyPresent(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.issuanceDate)) {
            var issuanceDateData = credential_util_1.getDataFromKey(this.credential, common_1.CREDENTIALS_VALIDATORS_KEYS.issuanceDate);
            if (issuanceDateData) {
                logger_1.logger(messages_1.Messages.ISSUANCE_DATE_KEY_SUCCESS);
                return true;
            }
        }
        else {
            logger_1.logger(messages_1.Messages.ISSUANCE_DATE_KEY_ERROR, "error");
        }
        return false;
    };
    return CredentialValidator;
}());
exports.CredentialValidator = CredentialValidator;
