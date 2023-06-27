import { get } from "lodash";
import { deepCloneData } from "./utils/credential-util";
import { logger } from "./utils/logger";
import { CredentialIssuerValidator } from "./validator/credential-issuer-validator";
import { CredentialValidator } from "./validator/credential-validator";
import { RevocationStatusCheck } from './validator/revocation-status-check';

export class EveryCredVerifier {
  private certificate: any;
  private issuerProfileData: any;
  private revocationListData: any;
  private credentialValidation: boolean = false;
  private credentialIssuerValidation: boolean = false;

  constructor() { }

  /**
   * This function is main entry point of the credential verifier.
   */
  verify = async (certificate: any) => {
    logger('---------------// S //----------------');
    this.certificate = deepCloneData(certificate);

    if (!(await this.validateCredentials()) || !(await this.revocationStatusCheck())) {
      logger(
        "------------------ CREDENTIAL VALIDATION FAILED ------------------ " +
        this.credentialIssuerValidation
      );
      logger('---------------// E //----------------');
      return; // Stop program execution if any check fails
    }

    logger(this.certificate);
    logger(this.issuerProfileData);
    logger(this.revocationListData);
    logger(
      "------------------ CREDENTIAL VALIDATION SUCCESSFUL ------------------ " +
      this.credentialIssuerValidation
    );

    logger('---------------// E //----------------');
  };

  /**
   * This function validates credentials using a CredentialValidator and CredentialIssuerValidator, and
   * retrieves issuer profile and revocation list data if validation is successful.
   */
  private async validateCredentials(): Promise<boolean> {
    this.credentialValidation = await new CredentialValidator().validate(
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

}
