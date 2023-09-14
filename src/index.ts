import { get } from "lodash";
import { MerkleProofValidator2019 } from './checksum/merkle-proof-2019-validation';
import { Messages } from './constants/messages';
import { deepCloneData } from "./utils/credential-util";
import { sleep } from './utils/sleep';
import { CredentialIssuerValidator } from "./validator/credential-issuer-validator";
import { CredentialValidator } from "./validator/credential-validator";
import { RevocationStatusCheck } from './validator/revocation-status-check';

export class EveryCredVerifier {
  private certificate: any = {};
  private issuerProfileData: any = {};
  private revocationListData: any = {};
  private isChecksumValidated: boolean = false;
  private credentialValidation: boolean = false;
  private credentialIssuerValidation: boolean = false;
  private revocationStatusValidation: boolean = false;
  private networkName: string = '';

  constructor(private progressCallback: (step: string, status: boolean) => void) { }

  /**
   * The function verifies a certificate by performing credential validation, checksum validation, and
   * revocation status check, and returns a message and status indicating whether the verification was
   * successful or not.
   * @param {any} certificate - The `certificate` parameter is an object that represents a certificate.
   * It is passed to the `verify` function for validation.
   * @returns The function `verify` returns an object with the properties `message`, `status`, and
   * `networkName`. The values of these properties depend on the outcome of the validation process. If
   * all validations pass, the `message` property will be set to `Messages.VERIFIED`, the `status`
   * property will be set to `true`, and the `networkName` property will be set to the
   */
  async verify(certificate: any) {
    this.certificate = deepCloneData(certificate);
    this.credentialValidation = await this.validateCredentials();

    if (this.credentialValidation) {
      this.isChecksumValidated = await this.validateChecksum();

      if (this.isChecksumValidated) {
        this.revocationStatusValidation = await this.revocationStatusCheck();

        if (this.revocationStatusValidation) {
          this.progressCallback(Messages.VERIFIED, true);
          this.certificate = {};
          this.issuerProfileData = {};
          this.revocationListData = {};
          return { message: Messages.VERIFIED, status: true, networkName: this.networkName };
        }
      }
    }

    this.certificate = {};
    this.issuerProfileData = {};
    this.revocationListData = {};
    this.progressCallback(Messages.FAILED, false);
    return { message: Messages.FAILED, status: false, networkName: '' };
  };

  /**
   * The function `validateCredentials` is an asynchronous function that validates credentials by using
   * a credential validator and a credential issuer validator, and returns a boolean indicating whether
   * the validation was successful.
   * @returns a Promise<boolean>.
   */
  private async validateCredentials(): Promise<boolean> {
    await sleep(250);

    const credentialValidator = new CredentialValidator(this.progressCallback);
    const result = await credentialValidator.validate(this.certificate);

    if (result.status) {
      let data = await new CredentialIssuerValidator(this.progressCallback).validate(this.certificate);

      this.credentialIssuerValidation = get(data, "issuerProfileValidationStatus");
      this.issuerProfileData = get(data, "issuerProfileData");
      this.revocationListData = get(data, "revocationListData");
    }

    if (result.status && this.credentialIssuerValidation) {
      this.progressCallback(Messages.AUTHENTICITY_VALIDATION, true);
      return true;
    }

    this.failedTwoStages();
    this.progressCallback(Messages.AUTHENTICITY_VALIDATION, false);
    return false;
  }

  /**
   * The function `validateChecksum` is a private asynchronous function that validates a checksum using
   * a MerkleProofValidator2019 and returns a boolean indicating whether the validation was successful.
   * @returns a Promise<boolean>.
   */
  private async validateChecksum(): Promise<boolean> {
    await sleep(500);

    const validate = await new MerkleProofValidator2019(this.progressCallback).validate(this.certificate);
    this.isChecksumValidated = validate?.status;
    this.networkName = validate.networkName;

    this.progressCallback(Messages.HASH_COMPARISON, this.isChecksumValidated);

    if (!this.isChecksumValidated) {
      this.failedLastStage();
    }

    return this.isChecksumValidated;
  }

  /**
   * The function `revocationStatusCheck` is an asynchronous function that performs a revocation status
   * check and returns a boolean indicating the validation status.
   * @returns a boolean value, which is the value of the variable `this.revocationStatusValidation`.
   */
  private async revocationStatusCheck(): Promise<boolean> {
    await sleep(750);

    this.revocationStatusValidation = (await new RevocationStatusCheck(this.progressCallback).validate(
      this.revocationListData,
      this.certificate,
      this.issuerProfileData
    )).status;

    this.progressCallback(Messages.STATUS_CHECK, this.revocationStatusValidation);
    return this.revocationStatusValidation;
  }

  /**
   * The function "failedTwoStages" updates the progress callback for several messages and then calls
   * another function.
   */
  private failedTwoStages() {
    this.progressCallback(Messages.HASH_COMPARISON, false);

    this.progressCallback(Messages.FORMAT_VALIDATION, false);
    this.progressCallback(Messages.COMPARING_HASHES, false);
    this.progressCallback(Messages.COMPARING_MERKLE_ROOT, false);
    this.progressCallback(Messages.CHECKING_HOLDER, false);

    this.failedLastStage();
  }

  /**
   * The function "failedLastStage" updates the progress status by calling the "progressCallback"
   * function with different messages.
   */
  private failedLastStage() {
    this.progressCallback(Messages.STATUS_CHECK, false);

    this.progressCallback(Messages.CHECKING_REVOKE_STATUS, false);
    this.progressCallback(Messages.CHECKING_AUTHENTICITY, false);
    this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, false);
  }

}
