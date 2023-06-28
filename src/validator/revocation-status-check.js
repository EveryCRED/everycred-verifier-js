var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { CREDENTIALS_CONSTANTS, CREDENTIALS_ISSUER_VALIDATORS_KEYS, CREDENTIALS_VALIDATORS_KEYS, REVOCATION_STATUS_CHECK_KEYS, } from "../constants/common";
import { Messages } from "../constants/messages";
import { deepCloneData, getDataFromKey, isDateExpired, isKeyPresent } from "../utils/credential-util";
import { logger } from "../utils/logger";
export class RevocationStatusCheck {
    constructor() { }
    validate(revocationListData, credentialData, issuerProfileData) {
        return __awaiter(this, void 0, void 0, function* () {
            this.credential = deepCloneData(credentialData);
            this.issuerProfileData = deepCloneData(issuerProfileData);
            this.revocationListData = deepCloneData(revocationListData);
            return yield this.statusRevocationCheck();
        });
    }
    /**
     * The function checks various conditions related to revocation and returns true if all conditions are
     * met, otherwise it returns false.
     * @returns The method is returning a boolean value. If all the conditions in the if statement are
     * true, then it returns true. Otherwise, it returns false.
     */
    statusRevocationCheck() {
        if (this.checkRevocationContext() &&
            this.checkRevocationType() &&
            this.checkRevocationID() &&
            this.checkRevocationIssuer() &&
            this.checkRevocationRevokedAssertions() &&
            this.checkValidUntilDate()) {
            return true;
        }
        return false;
    }
    /**
     * This function checks if a specific key is present in a data object and if its value matches certain
     * predefined values, returning true if successful and false otherwise.
     * @returns a boolean value - either true or false.
     */
    checkRevocationContext() {
        logger(Messages.CONTEXT_REVOCATION_LIST_KEY_VALIDATE);
        if (isKeyPresent(this.revocationListData, REVOCATION_STATUS_CHECK_KEYS.context) &&
            CREDENTIALS_CONSTANTS.revocation_list_context_values.some((data) => this.revocationListData[REVOCATION_STATUS_CHECK_KEYS.context].includes(data))) {
            logger(Messages.CONTEXT_REVOCATION_LIST_KEY_SUCCESS);
            return true;
        }
        logger(Messages.CONTEXT_REVOCATION_LIST_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function checks if the revocation list type is supported and returns a boolean value.
     * @returns a boolean value, either true or false.
     */
    checkRevocationType() {
        logger(Messages.TYPE_REVOCATION_LIST_KEY_VALIDATE);
        if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.type)) {
            let typeData = getDataFromKey(this.revocationListData, REVOCATION_STATUS_CHECK_KEYS.type);
            if (typeData.includes(CREDENTIALS_CONSTANTS.revocation_list_type_supported)) {
                logger(Messages.TYPE_REVOCATION_LIST_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.TYPE_REVOCATION_LIST_KEY_ERROR, "error");
        return false;
    }
    /* The `checkRevocationID()` function is checking if the ID of the credential being validated matches
    the ID of the revocation list in the issuer profile data. If the IDs match, it logs a success
    message and returns `true`, otherwise it logs an error message and returns `false`. */
    checkRevocationID() {
        logger(Messages.ID_REVOCATION_LIST_KEY_VALIDATE);
        if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.id)) {
            let idData = getDataFromKey(this.revocationListData, REVOCATION_STATUS_CHECK_KEYS.id);
            if (idData &&
                idData === getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList)) {
                logger(Messages.ID_REVOCATION_LIST_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.ID_REVOCATION_LIST_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function checks if the issuer of a credential is present in a revocation list and returns a
     * boolean value based on the result.
     * @returns A boolean value is being returned.
     */
    checkRevocationIssuer() {
        logger(Messages.ISSUER_REVOCATION_LIST_KEY_VALIDATE);
        if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.issuer)) {
            let issuerData = getDataFromKey(this.revocationListData, REVOCATION_STATUS_CHECK_KEYS.issuer);
            if (issuerData &&
                issuerData === getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.id)) {
                logger(Messages.ISSUER_REVOCATION_LIST_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.ISSUER_REVOCATION_LIST_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function checks if a credential has been revoked by looking for its ID in a revocation list.
     * @returns a boolean value.
     */
    checkRevocationRevokedAssertions() {
        logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE);
        if (isKeyPresent(this.revocationListData, REVOCATION_STATUS_CHECK_KEYS.revokedAssertions)) {
            let revokedAssertionsData = getDataFromKey(this.revocationListData, REVOCATION_STATUS_CHECK_KEYS.revokedAssertions);
            if (revokedAssertionsData && revokedAssertionsData.length) {
                logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_SUCCESS);
                let data = revokedAssertionsData.filter((data) => data.id === this.credential.id);
                if (data.length) {
                    logger(getDataFromKey(data, ['0', 'revocationReason']));
                    return false; // terminate and display reason from the array
                }
            }
            else {
                logger(Messages.CERTIFICATE_REVOCATION_LIST_STATUS);
                return true;
            }
        }
        logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR, "error");
        return false;
    }
    /**
     * The function `checkValidUntilDate` checks if a validUntilDate key is present in the credential
     * object, and if so, validates if the date is not expired.
     * @returns a boolean value.
     */
    checkValidUntilDate() {
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.validUntilDate)) {
            logger(Messages.VALID_UNTIL_DATE_KEY_VALIDATE);
            let validUntilDate = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.validUntilDate);
            if (validUntilDate && !isDateExpired(validUntilDate)) {
                logger(Messages.VALID_UNTIL_DATE_KEY_SUCCESS);
                return true;
            }
            logger(Messages.VALID_UNTIL_DATE_KEY_ERROR, "error");
            return false;
        }
        return true;
    }
}
