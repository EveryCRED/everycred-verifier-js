import { deepCloneData, getDataFromKey, isKeyPresent, } from "../utils/credential-util";
import { CREDENTIALS_CONSTANTS, CREDENTIALS_VALIDATORS_KEYS, } from "../constants/common";
import { Messages } from "../constants/messages";
import { logger } from "../utils/logger";
export class CredentialValidator {
    credential;
    constructor() { }
    /**
     * The function validates a credential's data and returns a boolean value indicating whether the
     * validation was successful or not.
     * @param {any} credentialData - It is an object containing the data of a credential that needs to be
     * validated.
     * @returns A boolean value is being returned, either true or false.
     */
    validate(credentialData) {
        this.credential = deepCloneData(credentialData);
        if (this.validateCredentialType() &&
            this.validateCredentialContext() &&
            this.validateCredentialID() &&
            this.validateCredentialCredentialSubject() &&
            this.validateCredentialProof() &&
            this.validateCredentialIssuanceDate()) {
            return true;
        }
        return false;
    }
    /**
     * This function validates the type of a verifiable credential.
     * @returns a boolean value, either true or false.
     */
    validateCredentialType() {
        logger(Messages.TYPE_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.type)) {
            let typeData = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.type);
            if (typeData.includes(CREDENTIALS_CONSTANTS.verifiable_credential)) {
                logger(Messages.TYPE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.TYPE_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates a credential context and returns a boolean value indicating whether it is
     * valid or not.
     * @returns a boolean value, either true or false.
     */
    validateCredentialContext() {
        logger(Messages.CONTEXT_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.context)) {
            let contextData = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.context);
            if (CREDENTIALS_CONSTANTS.context_values.some((data) => contextData.includes(data))) {
                logger(Messages.CONTEXT_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.CONTEXT_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the ID key in a credential object and returns a boolean value indicating
     * whether the validation was successful or not.
     * @returns A boolean value is being returned.
     */
    validateCredentialID() {
        logger(Messages.ID_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.id)) {
            let idData = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.id);
            if (idData) {
                logger(Messages.ID_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.ID_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the presence and correctness of required keys in the credential subject of
     * a given credential object.
     * @returns A boolean value is being returned.
     */
    validateCredentialCredentialSubject() {
        logger(Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.credentialSubject)) {
            let credentialSubjectData = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.credentialSubject);
            if (credentialSubjectData &&
                CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys.every((data) => Object.keys(credentialSubjectData).includes(data))) {
                let flag = false;
                for (const key of CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys) {
                    if (!credentialSubjectData[key]) {
                        flag = true;
                        break;
                    }
                }
                if (!flag) {
                    logger(Messages.CREDENTIAL_SUBJECT_KEY_SUCCESS);
                    return true;
                }
            }
        }
        logger(Messages.CREDENTIAL_SUBJECT_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the proof key in a credential object.
     * @returns A boolean value is being returned.
     */
    validateCredentialProof() {
        logger(Messages.PROOF_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.proof)) {
            let proofData = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.proof);
            if (proofData &&
                CREDENTIALS_CONSTANTS.proofRequiredKeys.every((data) => Object.keys(proofData).includes(data))) {
                let flag = false;
                for (const key of CREDENTIALS_CONSTANTS.proofRequiredKeys) {
                    if (!proofData[key]) {
                        flag = true;
                        break;
                    }
                }
                if (!flag &&
                    CREDENTIALS_CONSTANTS.proofTypeSupported.some((data) => proofData.type === data)) {
                    logger(Messages.PROOF_KEY_SUCCESS);
                    return true;
                }
            }
        }
        logger(Messages.PROOF_KEY_ERROR, "error");
        return false;
    }
    /**
     * This function validates the issuance date of a credential.
     * @returns a boolean value, either true or false.
     */
    validateCredentialIssuanceDate() {
        logger(Messages.ISSUANCE_DATE_KEY_VALIDATE);
        if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.issuanceDate)) {
            let issuanceDateData = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.issuanceDate);
            if (issuanceDateData) {
                logger(Messages.ISSUANCE_DATE_KEY_SUCCESS);
                return true;
            }
        }
        logger(Messages.ISSUANCE_DATE_KEY_ERROR, "error");
        return false;
    }
}
