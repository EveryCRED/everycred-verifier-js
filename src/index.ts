import { get } from "lodash";
import { MerkleProofValidator2019 } from './checksum/merkle-proof-2019-validation';
import { deepCloneData } from "./utils/credential-util";
import { logger } from './utils/logger';
import { CredentialIssuerValidator } from "./validator/credential-issuer-validator";
import { CredentialValidator } from "./validator/credential-validator";
import { RevocationStatusCheck } from './validator/revocation-status-check';

export class EveryCredVerifier {
  private certificate: any;
  private issuerProfileData: any;
  private revocationListData: any;
  private credentialValidation: boolean = false;
  private credentialIssuerValidation: boolean = false;
  private checksumValidation: boolean = false;

  constructor() { }

  /**
   * This function is main entry point of the credential verifier.
   */
  verify = async (certificate: any) => {
    this.certificate = deepCloneData(certificate);

    if (!(await this.validateCredentials()) || !(await this.revocationStatusCheck())) {
      logger('CREDENTIAL VALIDATION FAILED');
      return false; // Stop program execution if any check fails
    }

    if (!(await this.validateChecksum())) {
      logger('CHECKSUM VALIDATION FAILED');
      return false; // Stop program execution if any check fails
    }
    logger('CHECKSUM VALIDATION SUCCESSFUL');
    logger('CREDENTIAL VALIDATION SUCCESSFUL');

    return true;
  };

  /**
   * This function validates credentials using a CredentialValidator and CredentialIssuerValidator, and
   * retrieves issuer profile and revocation list data if validation is successful.
   */
  private async validateCredentials(): Promise<boolean> {
    this.credentialValidation = new CredentialValidator().validate(
      this.certificate
    );
    if (this.credentialValidation) {
      let data = await new CredentialIssuerValidator().validate(
        this.certificate
      );
      this.credentialIssuerValidation = get(
        data,
        "issuerProfileValidationStatus"
      );
      this.issuerProfileData = get(data, "issuerProfileData");
      this.revocationListData = get(data, "revocationListData");
    }

    if (this.credentialValidation && this.credentialIssuerValidation) {
      return true;
    };
    return false;
  }

  /**
   * This is a private asynchronous function that performs a revocation status check on a certificate
   * using data from a revocation list and an issuer profile.
   */
  private async revocationStatusCheck() {
    this.credentialIssuerValidation = await new RevocationStatusCheck().validate(
      this.revocationListData,
      this.certificate,
      this.issuerProfileData
    );

    return this.credentialIssuerValidation;
  }

  /**
   * The function `validateChecksum` is a private asynchronous method that uses the
   * `MerkleProofValidator2019` class to validate a certificate's checksum and returns the result.
   * @returns the result of the checksum validation, which is stored in the variable
   * `this.checksumValidation`.
   */
  private async validateChecksum() {
    this.checksumValidation = await new MerkleProofValidator2019().validate(
      this.certificate
    );

    return this.checksumValidation;
  }

}
