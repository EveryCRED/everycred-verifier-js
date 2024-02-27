import { MerkleProofValidator2019 } from './checksum/merkle-proof-2019-validation';
import { Messages } from './constants/messages';
import { Stages } from './constants/stages';
import { deepCloneData, getDataFromKey } from "./utils/credential-util";
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

  constructor(private progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }

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
          return { message: Messages.VERIFICATION_SUCCESS, status: true, networkName: this.networkName };
        }
      }
    }

    return { message: Messages.VERIFICATION_FAILED, status: false, networkName: this.networkName };
  };

  /**
   * The function `validateCredentials` is an asynchronous function that validates credentials and
   * returns a boolean indicating whether the validation was successful or not.
   * @returns a Promise<boolean>.
   */
  private async validateCredentials(): Promise<boolean> {
    await sleep(150);

    const credentialValidator = new CredentialValidator(this.progressCallback);
    const result = await credentialValidator.validate(this.certificate);

    if (result.status) {
      let data = await new CredentialIssuerValidator(this.progressCallback).validate(this.certificate);

      this.credentialIssuerValidation = getDataFromKey(data, "issuerProfileValidationStatus");
      this.issuerProfileData = getDataFromKey(data, "issuerProfileData");
      this.revocationListData = getDataFromKey(data, "revocationListData");
    }

    if (result.status && this.credentialIssuerValidation) {
      this.progressCallback(Stages.validateCredentials, Messages.CREDENTIALS_VALIDATION, true, Messages.CREDENTIALS_VALIDATION_SUCCESS);
      return true;
    }

    this.progressCallback(Stages.validateCredentials, Messages.CREDENTIALS_VALIDATION, false, Messages.CREDENTIALS_VALIDATION_FAILED);
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
    this.networkName = validate.networkName ?? '';

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

    return this.revocationStatusValidation;
  }

}
