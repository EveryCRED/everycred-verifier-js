import {
  CREDENTIALS_CONSTANTS,
  CREDENTIALS_ISSUER_VALIDATORS_KEYS,
} from "../constants/common";
import { Messages } from "../constants/messages";
import {
  deepCloneData,
  getDataFromAPI,
  getDataFromKey,
  isKeyPresent,
} from "../utils/credential-util";
import { logger } from "../utils/logger";
import { sleep } from '../utils/sleep';

export class CredentialIssuerValidator {
  private credential: any;
  private issuerProfileData: any;
  private revocationListData: any;

  constructor(private progressCallback: (step: string, status: boolean) => void) { }

  /**
   * This is an asynchronous function that validates credential data and returns the validation status
   * along with issuer profile and revocation list data.
   * @param {any} credentialData - The data that needs to be validated for a credential.
   * @returns The function `validate` returns an object with three properties:
   * `issuerProfileValidationStatus`, `issuerProfileData`, and `revocationListData`. The values of
   * these properties depend on the result of the `validateCredentialIssuer` function. If
   * `validateCredentialIssuer` returns a truthy value, then `issuerProfileValidationStatus` will be
   * set to that value, and `issuerProfileData`
   */
  async validate(credentialData: any): Promise<any> {
    await sleep(250);

    this.credential = deepCloneData(credentialData);
    let status = (await this.validateCredentialIssuer())?.status;

    if (status) {
      this.progressCallback(Messages.VERIFY_AUTHENTICITY, true);
      return {
        issuerProfileValidationStatus: status,
        issuerProfileData: this.issuerProfileData,
        revocationListData: this.revocationListData,
      };
    }

    this.progressCallback(Messages.VERIFY_AUTHENTICITY, false);
    return {
      issuerProfileValidationStatus: status,
      issuerProfileData: null,
      revocationListData: null,
    };
  }

  /**
   * This is a private async function that validates the credential issuer's profile data.
   * @returns a Promise that resolves to a boolean value.
   */
  private async validateCredentialIssuer(): Promise<{ message: string; status: boolean; }> {
    if (
      isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer)
    ) {
      let issuerData: string = getDataFromKey(
        this.credential,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer
      );
      if (issuerData && new URL(issuerData)) {
        try {
          this.issuerProfileData = await getDataFromAPI(issuerData);
        } catch (error) {
          this.failedAllStages();
        }

        if (!this.issuerProfileData) {
          this.failedAllStages();
          logger(Messages.FETCHING_ISSUER_PROFILE_ERROR, "error");
          return { message: Messages.FETCHING_ISSUER_PROFILE_ERROR, status: false };
        }

        if (
          this.issuerProfileData &&
          (await this.validateIssuerProfileContext()).status &&
          this.validateCredentialType().status &&
          this.validateIssuerProfileID().status &&
          this.validateIssuerProfileName().status &&
          this.validateIssuerProfileEmail().status &&
          this.validateIssuerProfileRevocationList().status &&
          this.validateIssuerProfilePublicKey().status &&
          (await this.validateRevocationListFromIssuerProfile()).status
        ) {
          return { message: '', status: true };
        }
      }
    } else {
      this.failedAllStages();
      logger(Messages.ISSUER_KEY_ERROR, "error");
      return { message: Messages.ISSUER_KEY_ERROR, status: false };
    }

    this.failedAllStages();
    return { message: Messages.FETCHING_ISSUER_PROFILE_ERROR, status: false };
  }

  /**
   * This function validates the issuer profile context and returns a boolean value indicating whether
   * it is valid or not.
   * @returns This function returns a boolean value (either true or false) depending on whether the
   * validation of the issuer profile context is successful or not.
   */
  private async validateIssuerProfileContext(): Promise<{ message: string; status: boolean; }> {
    await sleep(500);

    if (
      isKeyPresent(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.context
      ) &&
      CREDENTIALS_CONSTANTS.issuer_profile_context_values.some((data) =>
        this.issuerProfileData[
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.context
        ].includes(data)
      )
    ) {
      return { message: '', status: true };
    }

    this.failedAllStages();
    logger(Messages.CONTEXT_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.CONTEXT_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates the type of a credential issuer profile key.
   * @returns a boolean value.
   */
  private validateCredentialType(): { message: string; status: boolean; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.type)
    ) {
      let typeData: string = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.type
      );
      if (CREDENTIALS_CONSTANTS.issuerProfileTypeSupported.includes(typeData)) {
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.TYPE_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.TYPE_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates the issuer profile ID by checking if it is present in the credential and
   * matches the issuer profile data.
   * @returns a boolean value, either true or false.
   */
  private validateIssuerProfileID(): { message: string; status: boolean; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.id)
    ) {
      let idData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.id
      );
      if (
        idData &&
        idData ===
        getDataFromKey(
          this.credential,
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer
        )
      ) {
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.ID_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.ID_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates the issuer profile name and returns a boolean value indicating whether the
   * validation was successful or not.
   * @returns a boolean value, either true or false.
   */
  private validateIssuerProfileName(): { message: string; status: boolean; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.name)
    ) {
      let nameData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.name
      );
      if (nameData) {
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.NAME_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.NAME_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates the email key in the issuer profile data and returns a boolean value
   * indicating whether it is present or not.
   * @returns a boolean value, either true or false.
   */
  private validateIssuerProfileEmail(): { message: string; status: boolean; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.email)
    ) {
      let emailData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.email
      );
      if (emailData) {
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.EMAIL_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.EMAIL_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates the revocation list key in the issuer profile data.
   * @returns A boolean value is being returned.
   */
  private validateIssuerProfileRevocationList(): { message: string; status: boolean; } {
    if (
      isKeyPresent(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList
      )
    ) {
      let revocationListData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList
      );
      if (revocationListData && new URL(revocationListData)) {
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates the issuer profile public key and returns a boolean value indicating
   * whether the validation was successful or not.
   * @returns A boolean value is being returned.
   */
  private validateIssuerProfilePublicKey(): { message: string; status: boolean; } {
    if (
      isKeyPresent(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.publicKey
      )
    ) {
      let publicKeyData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.publicKey
      );
      if (publicKeyData?.length) {
        for (const index in publicKeyData) {
          let flag = false;
          if (
            !CREDENTIALS_CONSTANTS.issuerProfilePublicKeyFields.every((data) =>
              Object.keys(publicKeyData[index]).includes(data)
            )
          ) {
            flag = true;
          }

          if (!flag) {
            return { message: '', status: true };
          }
        }
      }
    }

    this.failedAllStages();
    logger(Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR, "error");
    return { message: Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR, status: false };
  }

  /**
   * This function validates a revocation list from an issuer profile and returns a boolean indicating
   * success or failure.
   * @returns A Promise that resolves to a boolean value.
   */
  private async validateRevocationListFromIssuerProfile(): Promise<{ message: string; status: boolean; }> {
    if (this.issuerProfileData) {
      this.revocationListData = await getDataFromAPI(
        getDataFromKey(
          this.issuerProfileData,
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList
        )
      );
      if (this.revocationListData) {
        this.progressCallback(Messages.CHECKING_VALIDATION, true);
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR, "error");
    return { message: Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR, status: false };
  }

  private failedAllStages() {
    this.progressCallback(Messages.CHECKING_VALIDATION, false);
    this.progressCallback(Messages.VERIFY_AUTHENTICITY, false);
  }
}
