import {
  deepCloneData,
  getDataFromKey,
  isKeyPresent,
} from "../utils/credential-util";

import {
  CREDENTIALS_CONSTANTS,
  CREDENTIALS_VALIDATORS_KEYS,
} from "../constants/common";
import { Messages } from '../constants/messages';
import { logger } from '../utils/logger';

export class CredentialValidator {
  private credential: any;
  private progressCallback: (step: string, status: boolean) => void;

  constructor(progressCallback: (step: string, status: boolean) => void) {
    this.progressCallback = progressCallback;
  }

  async validate(credentialData: any): Promise<{ message: string; status: boolean; }> {
    this.credential = deepCloneData(credentialData);

    if (
      await this.validateCredentialType() &&
      await this.validateCredentialContext() &&
      await this.validateCredentialID() &&
      await this.validateCredentialCredentialSubject() &&
      await this.validateCredentialProof() &&
      await this.validateCredentialIssuanceDate()
    ) {
      return { message: '', status: true };
    }

    this.failedAllStages();
    return { message: Messages.CREDENTIALS_VALIDATION_FAILED, status: false };
  }

  /**
   * This function validates the type of a verifiable credential.
   * @returns a boolean value, either true or false.
   */
  private async validateCredentialType(): Promise<boolean> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.type)) {
      let typeData: string[] = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.type
      );
      if (typeData.includes(CREDENTIALS_CONSTANTS.verifiable_credential)) {
        return true;
      }
    }

    this.failedAllStages();
    logger(Messages.TYPE_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function validates a credential context and returns a boolean value indicating whether it is
   * valid or not.
   * @returns a boolean value, either true or false.
   */
  private async validateCredentialContext(): Promise<boolean> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.context)) {
      let contextData: string[] = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.context
      );
      if (
        CREDENTIALS_CONSTANTS.context_values.some((data) => contextData.includes(data))
      ) {
        return true;
      }
    }

    this.failedAllStages();
    logger(Messages.CONTEXT_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function validates the ID key in a credential object and returns a boolean value indicating
   * whether the validation was successful or not.
   * @returns A boolean value is being returned.
   */
  private async validateCredentialID(): Promise<boolean> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.id)) {
      if (getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.id)) {
        return true;
      }
    }

    this.failedAllStages();
    logger(Messages.ID_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function validates the presence and correctness of required keys in the credential subject of
   * a given credential object.
   * @returns A boolean value is being returned.
   */
  private async validateCredentialCredentialSubject(): Promise<boolean> {
    if (
      isKeyPresent(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.credentialSubject
      )
    ) {
      let credentialSubjectData = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.credentialSubject
      );

      if (
        credentialSubjectData &&
        CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys.every((data) =>
          Object.keys(credentialSubjectData).includes(data)
        )
      ) {
        let flag = false;

        for (const key of CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys) {
          if (!credentialSubjectData[key]) {
            flag = true;
            break;
          }
        }

        if (!flag) {
          return true;
        }
      }
    }

    this.failedAllStages();
    logger(Messages.CREDENTIAL_SUBJECT_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function validates the proof key in a credential object.
   * @returns A boolean value is being returned.
   */
  private async validateCredentialProof(): Promise<boolean> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.proof)) {
      let proofData = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.proof
      );

      if (
        proofData &&
        CREDENTIALS_CONSTANTS.proofRequiredKeys.every((data) =>
          Object.keys(proofData).includes(data)
        )
      ) {
        let flag = false;

        for (const key of CREDENTIALS_CONSTANTS.proofRequiredKeys) {
          if (!proofData[key]) {
            flag = true;
            break;
          }
        }

        if (
          !flag &&
          CREDENTIALS_CONSTANTS.proofTypeSupported.some(
            (data) => proofData.type === data
          )
        ) {
          return true;
        }
      }
    }

    this.failedAllStages();
    logger(Messages.PROOF_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function validates the issuance date of a credential.
   * @returns a boolean value, either true or false.
   */
  private async validateCredentialIssuanceDate(): Promise<boolean> {
    if (
      isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.issuanceDate)
    ) {
      let issuanceDateData = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.issuanceDate
      );
      if (issuanceDateData) {
        return true;
      }
    }

    this.failedAllStages();
    logger(Messages.ISSUANCE_DATE_KEY_ERROR, "error");
    return false;
  }

  private failedAllStages() {
    this.progressCallback(Messages.CHECKING_VALIDATION, false);
    this.progressCallback(Messages.VERIFY_AUTHENTICITY, false);

    this.progressCallback(Messages.FORMAT_VALIDATION, false);
    this.progressCallback(Messages.COMPARING_HASHES, false);
    this.progressCallback(Messages.COMPARING_MERKLE_ROOT, false);
    this.progressCallback(Messages.CHECKING_HOLDER, false);

    this.progressCallback(Messages.CHECKING_REVOKE_STATUS, false);
    this.progressCallback(Messages.CHECKING_AUTHENTICITY, false);
    this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, false);
  }
}
