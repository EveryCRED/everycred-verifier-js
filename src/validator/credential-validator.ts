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
import { Stages } from '../constants/stages';

export class CredentialValidator {
  private credential: any;

  constructor(private progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }

  /**
   * The function `validate` is an asynchronous function that validates a credential object and returns
   * a message and status indicating whether the validation was successful or not.
   * @param {any} credentialData - The `credentialData` parameter is an object that contains the data
   * of a credential.
   * @returns The function `validate` returns a promise that resolves to an object with two properties:
   * `message` and `status`.
   */
  async validate(credentialData: any): Promise<{ message: string; status: boolean; }> {
    this.credential = deepCloneData(credentialData);

    if (
      (await this.validateCredentialType()).status &&
      (await this.validateCredentialContext()).status &&
      (await this.validateCredentialID()).status &&
      (await this.validateCredentialSubject()).status &&
      (await this.validateCredentialProof()).status &&
      (await this.validateCredentialIssuanceDate()).status
    ) {
      this.progressCallback(Stages.validateCredential, Messages.CREDENTIAL_VALIDATION, true, Messages.CREDENTIAL_VALIDATION_SUCCESS);
      return { message: Messages.CREDENTIAL_VALIDATION_SUCCESS, status: true };
    }

    this.progressCallback(Stages.validateCredential, Messages.CREDENTIAL_VALIDATION, false, Messages.CREDENTIAL_VALIDATION_FAILED);
    return { message: Messages.CREDENTIAL_VALIDATION_FAILED, status: false };
  }

  /**
   * The function `validateCredentialType` checks if a specific type of credential is present in the
   * `credential` object and returns a boolean value indicating whether it is valid or not.
   * @returns a Promise that resolves to a boolean value.
   */
  private async validateCredentialType(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.type)) {
      let typeData: string[] = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.type
      );
      if (typeData.includes(CREDENTIALS_CONSTANTS.verifiable_credential)) {
        this.progressCallback(Stages.validateCredentialType, Messages.TYPE_KEY_VALIDATE, true, Messages.TYPE_KEY_SUCCESS);
        return { step: Stages.validateCredentialType, title: Messages.TYPE_KEY_VALIDATE, status: true, reason: Messages.TYPE_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateCredentialType, Messages.TYPE_KEY_VALIDATE, false, Messages.TYPE_KEY_ERROR);
    return { step: Stages.validateCredentialType, title: Messages.TYPE_KEY_VALIDATE, status: false, reason: Messages.TYPE_KEY_ERROR };
  }

  /**
   * The function `validateCredentialContext` checks if a specific key is present in a credential
   * object and if its value matches certain predefined values, returning true if it does and false
   * otherwise.
   * @returns a Promise that resolves to a boolean value.
   */
  private async validateCredentialContext(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.context)) {
      let contextData: string[] = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.context
      );
      if (
        CREDENTIALS_CONSTANTS.context_values.some((data) => contextData.includes(data))
      ) {
        this.progressCallback(Stages.validateCredentialContext, Messages.CONTEXT_KEY_VALIDATE, true, Messages.CONTEXT_KEY_SUCCESS);
        return { step: Stages.validateCredentialContext, title: Messages.CONTEXT_KEY_VALIDATE, status: true, reason: Messages.CONTEXT_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateCredentialContext, Messages.CONTEXT_KEY_VALIDATE, false, Messages.CONTEXT_KEY_ERROR);
    return { step: Stages.validateCredentialContext, title: Messages.CONTEXT_KEY_VALIDATE, status: false, reason: Messages.CONTEXT_KEY_ERROR };
  }

  /**
   * The function "validateCredentialID" checks if a specific key is present in a credential object and
   * returns true if it is, otherwise it logs an error message and returns false.
   * @returns a Promise that resolves to a boolean value.
   */
  private async validateCredentialID(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
    if (isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.id)) {
      if (getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.id)) {
        this.progressCallback(Stages.validateCredentialID, Messages.ID_KEY_VALIDATE, true, Messages.ID_KEY_SUCCESS);
        return { step: Stages.validateCredentialID, title: Messages.ID_KEY_VALIDATE, status: true, reason: Messages.ID_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateCredentialID, Messages.ID_KEY_VALIDATE, false, Messages.ID_KEY_ERROR);
    return { step: Stages.validateCredentialID, title: Messages.ID_KEY_VALIDATE, status: false, reason: Messages.ID_KEY_ERROR };
  }

  /**
   * The function `validateCredentialSubject` checks if the required keys are present in the
   * `credentialSubject` object and returns true if they are, otherwise it returns false.
   * @returns a Promise<boolean>.
   */
  private async validateCredentialSubject(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
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
          this.progressCallback(Stages.validateCredentialSubject, Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, true, Messages.CREDENTIAL_SUBJECT_KEY_SUCCESS);
          return { step: Stages.validateCredentialSubject, title: Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, status: true, reason: Messages.CREDENTIAL_SUBJECT_KEY_SUCCESS };
        }
      }
    }

    this.progressCallback(Stages.validateCredentialSubject, Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, false, Messages.CREDENTIAL_SUBJECT_KEY_ERROR);
    return { step: Stages.validateCredentialSubject, title: Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, status: false, reason: Messages.CREDENTIAL_SUBJECT_KEY_ERROR };
  }

  /**
   * The function `validateCredentialProof` checks if a proof key is present in a credential object and
   * validates its data.
   * @returns a Promise<boolean>.
   */
  private async validateCredentialProof(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
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
          this.progressCallback(Stages.validateCredentialProof, Messages.PROOF_KEY_VALIDATE, true, Messages.PROOF_KEY_SUCCESS);
          return { step: Stages.validateCredentialProof, title: Messages.PROOF_KEY_VALIDATE, status: true, reason: Messages.PROOF_KEY_SUCCESS };
        }
      }
    }

    this.progressCallback(Stages.validateCredentialProof, Messages.PROOF_KEY_VALIDATE, false, Messages.PROOF_KEY_ERROR);
    return { step: Stages.validateCredentialProof, title: Messages.PROOF_KEY_VALIDATE, status: false, reason: Messages.PROOF_KEY_ERROR };
  }

  /**
   * The function validates the issuance date of a credential and returns true if it is present,
   * otherwise it returns false and logs an error message.
   * @returns a Promise that resolves to a boolean value.
   */
  private async validateCredentialIssuanceDate(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
    if (
      isKeyPresent(this.credential, CREDENTIALS_VALIDATORS_KEYS.issuanceDate)
    ) {
      let issuanceDateData = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.issuanceDate
      );
      if (issuanceDateData) {
        this.progressCallback(Stages.validateCredentialIssuanceDate, Messages.ISSUANCE_DATE_KEY_VALIDATE, true, Messages.ISSUANCE_DATE_KEY_SUCCESS);
        return { step: Stages.validateCredentialIssuanceDate, title: Messages.ISSUANCE_DATE_KEY_VALIDATE, status: true, reason: Messages.ISSUANCE_DATE_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateCredentialIssuanceDate, Messages.ISSUANCE_DATE_KEY_VALIDATE, false, Messages.ISSUANCE_DATE_KEY_ERROR);
    return { step: Stages.validateCredentialIssuanceDate, title: Messages.ISSUANCE_DATE_KEY_VALIDATE, status: false, reason: Messages.ISSUANCE_DATE_KEY_ERROR };
  }

}
