var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { CREDENTIALS_CONSTANTS, CREDENTIALS_ISSUER_VALIDATORS_KEYS, } from "../constants/common";
import { Messages } from "../constants/messages";
import { deepCloneData, isKeyPresent, getDataFromKey, getDataFromAPI, } from "../utils/credential-util";
import { logger } from "../utils/logger";
export class CredentialIssuerValidator {
    constructor() { }
    /**
     * This is an asynchronous function that validates credential data and returns the validation status
     * along with issuer profile and revocation list data.
     * @param {any} credentialData - The data that needs to be validated for a credential.
     * @returns The function `validate` returns an object with three properties:
     * `issuerProfileValidationStatus`, `issuerProfileData`, and `revocationListData`. The values of
     * these properties depend on the result of the `validateCredentialIssuer` function. If
     * `validateCredentialIssuer` returns a truthy value, then `issuerProfileValidationStatus` will be
     * set to that value, and `issuerProfileData`
     */
    validate(credentialData) {
        return __awaiter(this, void 0, void 0, function* () {
            this.credential = deepCloneData(credentialData);
            logger(this.credential);
            let status = yield this.validateCredentialIssuer();
            if (status) {
                return {
                    issuerProfileValidationStatus: status,
                    issuerProfileData: this.issuerProfileData,
                    revocationListData: this.revocationListData,
                };
            }
            return {
                issuerProfileValidationStatus: status,
                issuerProfileData: null,
                revocationListData: null,
            };
        });
    }
    /**
     * This is a private async function that validates the credential issuer's profile data.
     * @returns a Promise that resolves to a boolean value.
     */
    validateCredentialIssuer() {
        return __awaiter(this, void 0, void 0, function* () {
            logger(Messages.ISSUER_VALIDATION_STARTED);
            if (isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer)) {
                let issuerData = getDataFromKey(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer);
                logger(issuerData);
                if (issuerData && new URL(issuerData)) {
                    logger(Messages.ISSUER_KEY_SUCCESS);
                    logger(Messages.FETCHING_ISSUER_PROFILE);
                    this.issuerProfileData = yield getDataFromAPI(issuerData);
                    this.issuerProfileData
                        ? logger(Messages.FETCHING_ISSUER_PROFILE_SUCCESS)
                        : logger(Messages.FETCHING_ISSUER_PROFILE_ERROR);
                    if (this.issuerProfileData &&
                        this.validateIssuerProfileContext() &&
                        this.validateCredentialType() &&
                        this.validateIssuerProfileID() &&
                        this.validateIssuerProfileName() &&
                        this.validateIssuerProfileEmail() &&
                        this.validateIssuerProfileRevocationList() &&
                        this.validateIssuerProfilePublicKey() &&
                        (yield this.validateRevocationListFromIssuerProfile())) {
                        logger(Messages.ISSUER_KEY_SUCCESS);
                        return true;
                    }
                }
            }
            else {
                logger(Messages.ISSUER_KEY_ERROR);
            }
            return false;
        });
    }
    /**
     * This function validates the issuer profile context and returns a boolean value indicating whether
     * it is valid or not.
     * @returns This function returns a boolean value (either true or false) depending on whether the
     * validation of the issuer profile context is successful or not.
     */
    validateIssuerProfileContext() {
        logger(Messages.CONTEXT_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.context) &&
            CREDENTIALS_CONSTANTS.issuer_profile_context_values.some((data) => this.issuerProfileData[CREDENTIALS_ISSUER_VALIDATORS_KEYS.context].includes(data))) {
            logger(Messages.CONTEXT_ISSUER_PROFILE_KEY_SUCCESS);
            return true;
        }
        logger(Messages.CONTEXT_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the type of a credential issuer profile key.
     * @returns a boolean value.
     */
    validateCredentialType() {
        logger(Messages.TYPE_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.type)) {
            let typeData = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.type);
            if (CREDENTIALS_CONSTANTS.issuerProfileTypeSupported.includes(typeData)) {
                logger(Messages.TYPE_ISSUER_PROFILE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.TYPE_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the issuer profile ID by checking if it is present in the credential and
     * matches the issuer profile data.
     * @returns a boolean value, either true or false.
     */
    validateIssuerProfileID() {
        logger(Messages.ID_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.id)) {
            let idData = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.id);
            if (idData &&
                idData ===
                    getDataFromKey(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer)) {
                logger(Messages.ID_ISSUER_PROFILE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.ID_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the issuer profile name and returns a boolean value indicating whether the
     * validation was successful or not.
     * @returns a boolean value, either true or false.
     */
    validateIssuerProfileName() {
        logger(Messages.NAME_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.name)) {
            let nameData = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.name);
            if (nameData) {
                logger(Messages.NAME_ISSUER_PROFILE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.NAME_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the email key in the issuer profile data and returns a boolean value
     * indicating whether it is present or not.
     * @returns a boolean value, either true or false.
     */
    validateIssuerProfileEmail() {
        logger(Messages.EMAIL_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.email)) {
            let emailData = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.email);
            if (emailData) {
                logger(Messages.EMAIL_ISSUER_PROFILE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.EMAIL_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the revocation list key in the issuer profile data.
     * @returns A boolean value is being returned.
     */
    validateIssuerProfileRevocationList() {
        logger(Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList)) {
            let revocationListData = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList);
            if (revocationListData && new URL(revocationListData)) {
                logger(Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the issuer profile public key and returns a boolean value indicating
     * whether the validation was successful or not.
     * @returns A boolean value is being returned.
     */
    validateIssuerProfilePublicKey() {
        logger(Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE);
        if (isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.publicKey)) {
            let publicKeyData = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.publicKey);
            if (publicKeyData && publicKeyData.length) {
                for (const index in publicKeyData) {
                    let flag = false;
                    if (!CREDENTIALS_CONSTANTS.issuerProfilePublicKeyFields.every((data) => Object.keys(publicKeyData[index]).includes(data))) {
                        flag = true;
                    }
                    if (!flag) {
                        logger(Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_SUCCESS);
                        return true;
                    }
                }
            }
        }
        logger(Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates a revocation list from an issuer profile and returns a boolean indicating
     * success or failure.
     * @returns A Promise that resolves to a boolean value.
     */
    validateRevocationListFromIssuerProfile() {
        return __awaiter(this, void 0, void 0, function* () {
            logger(Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE);
            if (this.issuerProfileData) {
                this.revocationListData = yield getDataFromAPI(getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList));
                if (this.revocationListData) {
                    logger(Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_SUCCESS);
                    return true;
                }
            }
            logger(Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR, "error");
            return false;
        });
    }
}
