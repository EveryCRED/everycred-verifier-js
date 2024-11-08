import { MerkleProofValidator2019 } from './checksum/merkle-proof-2019-validation';
import { CREDENTIALS_ISSUER_VALIDATORS_KEYS, CREDENTIALS_VALIDATORS_KEYS } from './constants/common';
import { Messages } from './constants/messages';
import { Stages } from './constants/stages';
import { deepCloneData, getDataFromAPI, getDataFromKey, isKeyPresent } from "./utils/credential-util";
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
  private offChainVerification: boolean = false;

  constructor(private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }

  /**
   * The function verifies a certificate by performing credential validation, checksum validation, and
   * revocation status check, and returns a message and status indicating whether the verification was
   * successful or not.
   * @param {any} certificate - The `certificate` parameter is an object that represents a certificate.
   * It is passed to the `verify` function for validation.
   * @param [offChainVerification=false] - The `offChainVerification` parameter is a boolean flag that
   * determines whether the verification process should be done off-chain or on-chain. If
   * `offChainVerification` is set to `true`, the `verify` method will call the `offChainVerify` method.
   * @returns The function `verify` returns an object with the properties `message`, `status`, and
   * `networkName`. The values of these properties depend on the outcome of the validation process. If
   * all validations pass, the `message` property will be set to `Messages.VERIFIED`, the `status`
   * property will be set to `true`, and the `networkName` property will be set to the
   */
  async verify(certificate: any, offChainVerification = false) {
    this.offChainVerification = offChainVerification;
    this.certificate = deepCloneData(certificate);

    if (this.offChainVerification) {
      return await this.offChainVerify();
    } else {
      return await this.onChainVerify();
    }
  };

  /**
   * The function `offChainVerify` asynchronously validates checksum and revocation status, returning a
   * success message if both validations pass.
   * @returns The `offChainVerify` method returns an object with the following properties:
   * - `message`: Either "VERIFICATION_SUCCESS" or "VERIFICATION_FAILED" based on the validation results.
   * - `status`: Either `true` or `false` based on the validation results.
   * - `networkName`: The value of the `networkName` property in the current object.
   */
  private async offChainVerify() {
    this.isChecksumValidated = await this.validateChecksum();
    if (this.isChecksumValidated) {
      this.revocationStatusValidation = await this.revocationStatusCheck();
      if (this.revocationStatusValidation) {
        return { message: Messages.VERIFICATION_SUCCESS, status: true, networkName: this.networkName };
      }
    }
    return { message: Messages.VERIFICATION_FAILED, status: false, networkName: this.networkName };
  }

  /**
   * The function "onChainVerify" asynchronously validates credentials, checksum, and revocation status,
   * returning a success message if all validations pass.
   * @returns The `onChainVerify` method returns an object with the following properties:
   * - `message`: A message indicating the verification status (either `Messages.VERIFICATION_SUCCESS` or
   * `Messages.VERIFICATION_FAILED`).
   * - `status`: A boolean value indicating the overall verification status (true for success, false for
   * failure).
   * - `networkName`: The name of the network being verified on.
   */
  private async onChainVerify() {
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
  }

  /**
   * The function `validateCredentials` is an asynchronous function that validates credentials and
   * returns a boolean indicating whether the validation was successful or not.
   * @returns a Promise<boolean>.
   */
  private async validateCredentials(): Promise<boolean> {
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
    const validate = await new MerkleProofValidator2019(this.progressCallback).validate(this.certificate, this.offChainVerification);
    this.isChecksumValidated = validate?.status;
    this.networkName = validate.networkName ?? '';

    return this.isChecksumValidated;
  }

  /**
   * This TypeScript function checks the revocation status by fetching issuer and revocation data and
   * performing validation.
   * @returns The `revocationStatusCheck` method returns a Promise that resolves to a boolean value,
   * specifically the `revocationStatusValidation` property.
   */
  private async revocationStatusCheck(): Promise<boolean> {
    if (this.offChainVerification && navigator.onLine) {
      await this.fetchIssuerAndRevocationData();
    }

    this.revocationStatusValidation = await this.performRevocationStatusValidation();
    return this.revocationStatusValidation;
  }

  /**
   * The function fetches issuer and revocation data from specified URLs if the necessary keys are
   * present in the certificate and issuer profile data.
   */
  private async fetchIssuerAndRevocationData(): Promise<void> {
    if (isKeyPresent(this.certificate, CREDENTIALS_VALIDATORS_KEYS.issuer)) {
      const issuerDataUrl = getDataFromKey(this.certificate, CREDENTIALS_VALIDATORS_KEYS.issuer).profile;
      if (issuerDataUrl) {
        this.issuerProfileData = await getDataFromAPI(issuerDataUrl);
        if (isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList)) {
          const revocationListUrl = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList);
          if (revocationListUrl) {
            this.revocationListData = await getDataFromAPI(revocationListUrl);
          }
        }
      }
    }
  }

  /**
   * The function `performRevocationStatusValidation` asynchronously validates the revocation status of a
   * certificate using various data inputs.
   * @returns The `performRevocationStatusValidation` method is returning a boolean value, specifically
   * the `status` property of the `validationResponse` object.
   */
  private async performRevocationStatusValidation(): Promise<boolean> {
    const validationResponse = await new RevocationStatusCheck(this.progressCallback).validate(
      this.revocationListData,
      this.certificate,
      this.issuerProfileData,
    );
    return validationResponse.status;
  }
}
