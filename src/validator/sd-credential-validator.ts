import {
  deepCloneData,
  getDataFromKey,
  isKeyPresent,
} from "../utils/credential-util";

import {
  CREDENTIALS_CONSTANTS,
  SD_CREDENTIALS_CONSTANTS,
  SD_CREDENTIAL_VALIDATORS_KEYS,
  ALGORITHM_TYPES,
} from "../constants/common";
import { Messages } from '../constants/messages';
import { Stages } from '../constants/stages';
import { ProcessStepStatus, ResponseMessage } from '../models/common.model';

export class SdCredentialValidator {
  private sdCredential: any;

  constructor(
    private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void
  ) { }

  /**
   * Validates a selective disclosure (SD) credential by performing a comprehensive set of validation checks.
   * 
   * This method performs the following validations in sequence:
   * - Credential type validation
   * - Credential context validation
   * - Credential ID validation
   * - Credential subject validation
   * - Issuer validation
   * - Credential evidence (proof) validation
   * - Credential issuance date validation
   * s
   * All validations must pass for the credential to be considered valid. The method clones the input
   * credential data to avoid mutating the original object during validation.
   * 
   * @param credentialData - The SD credential data object to validate. This should be a complete
   *                        credential object following the SD credential structure.
   * @returns A Promise that resolves to a ResponseMessage object containing:
   *          - `status`: `true` if all validations pass, `false` otherwise
   *          - `message`: A success or failure message indicating the validation result
   * 
   * @example
   * ```typescript
   * const validator = new SdCredentialValidator(progressCallback);
   * const result = await validator.validate(credentialData);
   * if (result.status) {
   *   console.log('Credential is valid:', result.message);
   * } else {
   *   console.error('Credential validation failed:', result.message);
   * }
   * ```
   */
  async validate(credentialData: any): Promise<ResponseMessage> {
    this.sdCredential = deepCloneData(credentialData);

    if (
      (await this.validateCredentialType()).status &&
      (await this.validateCredentialContext()).status &&
      (await this.validateCredentialID()).status &&
      (await this.validateCredentialSubject()).status &&
      (await this.validateIssuer()).status &&
      (await this.validateCredentialEvidence()).status &&
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
  private async validateCredentialType(): Promise<ProcessStepStatus> {
    if (isKeyPresent(this.sdCredential, SD_CREDENTIAL_VALIDATORS_KEYS.type)) {
      let typeData: string[] = getDataFromKey(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.type
      );
      if (
        CREDENTIALS_CONSTANTS.verifiable_credential.some((data) => typeData.includes(data))
      ) {
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
  private async validateCredentialContext(): Promise<ProcessStepStatus> {
    if (isKeyPresent(this.sdCredential, SD_CREDENTIAL_VALIDATORS_KEYS.context)) {
      let contextData: string[] = getDataFromKey(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.context
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
  private async validateCredentialID(): Promise<ProcessStepStatus> {
    if (isKeyPresent(this.sdCredential, SD_CREDENTIAL_VALIDATORS_KEYS.id)) {
      if (getDataFromKey(this.sdCredential, SD_CREDENTIAL_VALIDATORS_KEYS.id)) {
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
  private async validateCredentialSubject(): Promise<ProcessStepStatus> {
    if (
      isKeyPresent(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.credentialSubject
      )
    ) {
      let credentialSubjectData = getDataFromKey(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.credentialSubject
      );

      if (Object.keys(credentialSubjectData).length) {
        const hasRequiredKeys = CREDENTIALS_CONSTANTS.credentialSubjectRequiredKeys.every(key =>
          Object.keys(credentialSubjectData).includes(key) && credentialSubjectData[key]
        );

        if (hasRequiredKeys) {
          this.progressCallback(Stages.validateCredentialSubject, Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, true, Messages.CREDENTIAL_SUBJECT_KEY_SUCCESS);
          return { step: Stages.validateCredentialSubject, title: Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, status: true, reason: Messages.CREDENTIAL_SUBJECT_KEY_SUCCESS };
        }
      }
    }

    this.progressCallback(Stages.validateCredentialSubject, Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, false, Messages.CREDENTIAL_SUBJECT_KEY_ERROR);
    return { step: Stages.validateCredentialSubject, title: Messages.CREDENTIAL_SUBJECT_KEY_VALIDATE, status: false, reason: Messages.CREDENTIAL_SUBJECT_KEY_ERROR };
  }

  /**
   * The function `validateIssuer` checks if the required issuer keys are present in the credential
   * data and returns a status based on the validation result.
   * @returns This `validateIssuer` function returns a `ProcessStepStatus` object with properties
   * `step`, `title`, `status`, and `reason`. The returned object contains information about the
   * validation status of the issuer key in the credential being processed.
   */
  private async validateIssuer(): Promise<ProcessStepStatus> {
    if (
      isKeyPresent(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.issuer
      )
    ) {
      let issuerData = getDataFromKey(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.issuer
      );

      if (
        Object.keys(issuerData).length &&
        CREDENTIALS_CONSTANTS.issuerRequiredKeys.every(
          (data) => Object.keys(issuerData).includes(data)
        )
      ) {
        let flag = false;

        for (const key of CREDENTIALS_CONSTANTS.issuerRequiredKeys) {
          if (!issuerData[key]) {
            flag = true;
            break;
          }
        }

        if (!flag) {
          this.progressCallback(Stages.validateIssuer, Messages.ISSUER_KEY_VALIDATE, true, Messages.ISSUER_KEY_SUCCESS);
          return { step: Stages.validateIssuer, title: Messages.ISSUER_KEY_VALIDATE, status: true, reason: Messages.ISSUER_KEY_SUCCESS };
        }
      }
    }

    this.progressCallback(Stages.validateIssuer, Messages.ISSUER_KEY_VALIDATE, false, Messages.ISSUER_KEY_ERROR);
    return { step: Stages.validateIssuer, title: Messages.ISSUER_KEY_VALIDATE, status: false, reason: Messages.ISSUER_KEY_ERROR };
  }

  /**
   * The function `validateCredentialProof` checks the evidence field for MerkleProof2019 proofs.
   * @returns a Promise<boolean>.
   */
  private async validateCredentialEvidence(): Promise<ProcessStepStatus> {
    const evidenceData = getDataFromKey(this.sdCredential, SD_CREDENTIAL_VALIDATORS_KEYS.evidence);

    if (!Array.isArray(evidenceData) || evidenceData.length === 0) {
      return this.getProofFailureStatus();
    }

    const firstEvidence = evidenceData[0];
    if (!firstEvidence || firstEvidence.type !== ALGORITHM_TYPES.MERKLEPROOF) {
      return this.getProofFailureStatus();
    }

    if (!this.hasMerkleProofRequiredKeys(firstEvidence)) {
      return this.getProofFailureStatus();
    }

    const hasMissingMerkleProofData = this.hasMissingMerkleProofData(firstEvidence);
    const proofTypeIsValid = firstEvidence.type === ALGORITHM_TYPES.MERKLEPROOF;

    if (!hasMissingMerkleProofData && proofTypeIsValid) {
      this.progressCallback(Stages.validateCredentialProof, Messages.PROOF_KEY_VALIDATE, true, Messages.PROOF_KEY_SUCCESS);
      return this.getProofSuccessStatus();
    }

    this.progressCallback(Stages.validateCredentialProof, Messages.PROOF_KEY_VALIDATE, false, Messages.PROOF_KEY_ERROR);
    return this.getProofFailureStatus();
  }

  private hasMerkleProofRequiredKeys(proofData: any): boolean {
    return SD_CREDENTIALS_CONSTANTS.merkleProof2019RequiredKeys.every(key => key in proofData);
  }

  private hasMissingMerkleProofData(proofData: any): boolean {
    return SD_CREDENTIALS_CONSTANTS.merkleProof2019RequiredKeys.some(key => {
      const value = proofData[key];
      if (key === 'path' || key === 'anchors') {
        return !Array.isArray(value);
      }
      return !value;
    });
  }

  private getProofSuccessStatus(): ProcessStepStatus {
    return { step: Stages.validateCredentialProof, title: Messages.PROOF_KEY_VALIDATE, status: true, reason: Messages.PROOF_KEY_SUCCESS };
  }

  private getProofFailureStatus(): ProcessStepStatus {
    return { step: Stages.validateCredentialProof, title: Messages.PROOF_KEY_VALIDATE, status: false, reason: Messages.PROOF_KEY_ERROR };
  }

  /**
   * The function validates the issuance date of a credential and returns true if it is present,
   * otherwise it returns false and logs an error message.
   * @returns a Promise that resolves to a boolean value.
   */
  private async validateCredentialIssuanceDate(): Promise<ProcessStepStatus> {
    if (
      isKeyPresent(this.sdCredential, SD_CREDENTIAL_VALIDATORS_KEYS.issuanceDate)
    ) {
      let issuanceDateData = getDataFromKey(
        this.sdCredential,
        SD_CREDENTIAL_VALIDATORS_KEYS.issuanceDate
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
