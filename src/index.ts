import { get } from "lodash";
import { MerkleProofValidator2019 } from './checksum/merkle-proof-2019-validation';
import { Messages } from './constants/messages';
import { deepCloneData } from "./utils/credential-util";
import { sleep } from './utils/sleep';
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
  private revocationStatusValidation: boolean = false;
  private networkName: string = '';
  private progressCallback: (step: string, status: boolean) => void;

  constructor(progressCallback: (step: string, status: boolean) => void) {
    this.progressCallback = progressCallback;
  }

  verify = async (
    certificate: any,
  ) => {
    this.certificate = deepCloneData(certificate);

    this.credentialValidation = await this.validateCredentials();

    if (this.credentialValidation) {
      this.checksumValidation = await this.validateChecksum();

      if (this.checksumValidation) {
        this.revocationStatusValidation = await this.revocationStatusCheck();

        if (this.revocationStatusValidation) {
          this.progressCallback(Messages.VERIFIED, true);
          return { message: Messages.VERIFIED, status: true, networkName: this.networkName };
        }
      }
    }

    this.progressCallback(Messages.FAILED, false);
    return { message: Messages.FAILED, status: false, networkName: '' };
  };

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

  private async validateChecksum(): Promise<boolean> {
    await sleep(500);

    const validate = await new MerkleProofValidator2019(this.progressCallback).validate(this.certificate);
    this.checksumValidation = validate?.status;
    this.networkName = validate.networkName;

    this.progressCallback(Messages.HASH_COMPARISON, this.checksumValidation);

    if (!this.checksumValidation) {
      this.failedLastStage();
    }

    return this.checksumValidation;
  }

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

  private failedTwoStages() {
    this.progressCallback(Messages.HASH_COMPARISON, false);

    this.progressCallback(Messages.FORMAT_VALIDATION, false);
    this.progressCallback(Messages.COMPARING_HASHES, false);
    this.progressCallback(Messages.COMPARING_MERKLE_ROOT, false);
    this.progressCallback(Messages.CHECKING_HOLDER, false);

    this.failedLastStage();
  }

  private failedLastStage() {
    this.progressCallback(Messages.STATUS_CHECK, false);

    this.progressCallback(Messages.CHECKING_REVOKE_STATUS, false);
    this.progressCallback(Messages.CHECKING_AUTHENTICITY, false);
    this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, false);
  }

}
