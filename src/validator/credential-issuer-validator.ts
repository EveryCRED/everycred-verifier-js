import {
  CREDENTIALS_CONSTANTS,
  CREDENTIALS_ISSUER_VALIDATORS_KEYS,
} from "../constants/common";
import { Messages } from "../constants/messages";
import { Stages } from '../constants/stages';
import {
  deepCloneData,
  getDataFromAPI,
  getDataFromKey,
  isKeyPresent,
  isValidURL,
} from "../utils/credential-util";

export class CredentialIssuerValidator {
  private credential: any;
  private issuerProfileData: any;
  private revocationListData: any;

  constructor(private progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }

  /**
   * The `validate` function takes in `credentialData`, performs some asynchronous operations,
   * validates the credential issuer, and returns an object with the validation status, issuer profile
   * data, and revocation list data.
   * @param {any} credentialData - The `credentialData` parameter is an object that contains the data
   * of a credential. It is used to validate the issuer of the credential.
   * @returns The function `validate` returns an object with the following properties:
   */
  async validate(credentialData: any): Promise<any> {
    this.credential = deepCloneData(credentialData);
    let status = (await this.validateCredentialIssuer())?.status;

    if (status) {
      this.progressCallback(Stages.validateIssuerCredentials, Messages.ISSUER_VALIDATION, true, Messages.ISSUER_VALIDATION_SUCCESS);
      return {
        issuerProfileValidationStatus: status,
        issuerProfileData: this.issuerProfileData,
        revocationListData: this.revocationListData,
      };
    }

    this.progressCallback(Stages.validateIssuerCredentials, Messages.ISSUER_VALIDATION, false, Messages.ISSUER_VALIDATION_FAILED);
    return {
      issuerProfileValidationStatus: status,
      issuerProfileData: null,
      revocationListData: null,
    };
  }

  /**
   * The function `validateCredentialIssuer` validates the issuer profile data of a credential.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string message, and the "status" property contains a boolean value.
   */
  private async validateCredentialIssuer(): Promise<{ message: string; status: boolean; }> {
    if (!isKeyPresent(this.credential, CREDENTIALS_ISSUER_VALIDATORS_KEYS.issuer)) {
      this.progressCallback(Stages.validateCredentialIssuer, Messages.ISSUER_VALIDATION, false, Messages.ISSUER_KEY_ERROR);
      return { status: false, message: Messages.ISSUER_KEY_ERROR };
    }

    const issuerData = getDataFromKey(this.credential.issuer, CREDENTIALS_ISSUER_VALIDATORS_KEYS.profile);

    if (!issuerData || !isValidURL(issuerData)) {
      this.progressCallback(Stages.validateCredentialIssuer, Messages.ISSUER_VALIDATION, false, Messages.FETCHING_ISSUER_PROFILE_ERROR);
      return { status: false, message: Messages.FETCHING_ISSUER_PROFILE_ERROR };
    }

    try {
      this.issuerProfileData = await getDataFromAPI(issuerData);

      if (!Object.keys(this.issuerProfileData)?.length) {
        this.progressCallback(Stages.validateCredentialIssuer, Messages.ISSUER_VALIDATION, false, Messages.FETCHING_ISSUER_PROFILE_ERROR);
        return { status: false, message: Messages.FETCHING_ISSUER_PROFILE_ERROR };
      }

      if (
        (await this.validateIssuerProfileContext()).status &&
        this.validateIssuerCredentialType().status &&
        this.validateIssuerProfileID().status &&
        this.validateIssuerProfileName().status &&
        this.validateIssuerProfileEmail().status &&
        this.validateIssuerProfileRevocationList().status &&
        this.validateIssuerProfilePublicKey().status &&
        (await this.validateRevocationListFromIssuerProfile()).status
      ) {
        this.progressCallback(Stages.validateCredentialIssuer, Messages.ISSUER_VALIDATION, true, Messages.ISSUER_KEY_SUCCESS);
        return { status: true, message: Messages.ISSUER_KEY_SUCCESS };
      }
    } catch (error) {
      this.progressCallback(Stages.validateCredentialIssuer, Messages.FETCHING_ISSUER_PROFILE, false, Messages.FETCHING_ISSUER_PROFILE_ERROR);
    }

    this.progressCallback(Stages.validateCredentialIssuer, Messages.ISSUER_VALIDATION, false, Messages.ISSUER_KEY_ERROR);
    return { status: false, message: Messages.ISSUER_KEY_ERROR };
  }

  /**
   * The function validates the issuer profile context and returns a message and status indicating
   * whether the validation was successful or not.
   * @returns a Promise that resolves to an object with two properties: "message" and "status".
   */
  private async validateIssuerProfileContext(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {

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
      this.progressCallback(Stages.validateIssuerProfileContext, Messages.CONTEXT_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.CONTEXT_ISSUER_PROFILE_KEY_SUCCESS);
      return { step: Stages.validateIssuerProfileContext, title: Messages.CONTEXT_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.CONTEXT_ISSUER_PROFILE_KEY_SUCCESS };
    }

    this.progressCallback(Stages.validateIssuerProfileContext, Messages.CONTEXT_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.CONTEXT_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerProfileContext, title: Messages.CONTEXT_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.CONTEXT_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * The function validates the credential type in the issuer profile data and returns a message and
   * status indicating whether the validation was successful or not.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string message, and the "status" property contains a boolean value.
   */
  private validateIssuerCredentialType(): { step: string, title: string, status: boolean, reason: string; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.type)
    ) {
      let typeData: string = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.type
      );
      if (CREDENTIALS_CONSTANTS.issuerProfileTypeSupported.includes(typeData)) {
        this.progressCallback(Stages.validateIssuerCredentialType, Messages.TYPE_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.TYPE_ISSUER_PROFILE_KEY_SUCCESS);
        return { step: Stages.validateIssuerCredentialType, title: Messages.TYPE_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.TYPE_ISSUER_PROFILE_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateIssuerCredentialType, Messages.TYPE_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.TYPE_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerCredentialType, title: Messages.TYPE_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.TYPE_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * The function validates the issuer profile ID and returns a message and status indicating whether
   * the validation was successful or not.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string value, and the "status" property contains a boolean value.
   */
  private validateIssuerProfileID(): { step: string, title: string, status: boolean, reason: string; } {
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
          this.credential.issuer,
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.profile
        )
      ) {
        this.progressCallback(Stages.validateIssuerProfileID, Messages.ID_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.ID_ISSUER_PROFILE_KEY_SUCCESS);
        return { step: Stages.validateIssuerProfileID, title: Messages.ID_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.ID_ISSUER_PROFILE_KEY_SUCCESS };
      }
    }
    this.progressCallback(Stages.validateIssuerProfileID, Messages.ID_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.ID_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerProfileID, title: Messages.ID_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.ID_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * The function `validateIssuerProfileName` checks if the name key is present in the issuer profile
   * data and returns a status and message accordingly.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private validateIssuerProfileName(): { step: string, title: string, status: boolean, reason: string; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.name)
    ) {
      let nameData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.name
      );
      if (nameData) {
        this.progressCallback(Stages.validateIssuerProfileName, Messages.NAME_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.NAME_ISSUER_PROFILE_KEY_SUCCESS);
        return { step: Stages.validateIssuerProfileName, title: Messages.NAME_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.NAME_ISSUER_PROFILE_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateIssuerProfileName, Messages.NAME_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.NAME_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerProfileName, title: Messages.NAME_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.NAME_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * The function validates the email field in an issuer profile and returns a message and status
   * indicating whether the validation was successful or not.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private validateIssuerProfileEmail(): { step: string, title: string, status: boolean, reason: string; } {
    if (
      isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.email)
    ) {
      let emailData = getDataFromKey(
        this.issuerProfileData,
        CREDENTIALS_ISSUER_VALIDATORS_KEYS.email
      );
      if (emailData) {
        this.progressCallback(Stages.validateIssuerProfileEmail, Messages.EMAIL_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.EMAIL_ISSUER_PROFILE_KEY_SUCCESS);
        return { step: Stages.validateIssuerProfileEmail, title: Messages.EMAIL_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.EMAIL_ISSUER_PROFILE_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateIssuerProfileEmail, Messages.EMAIL_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.EMAIL_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerProfileEmail, title: Messages.EMAIL_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.EMAIL_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * The function validates the revocation list key in the issuer profile data and returns a status and
   * message.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string value, and the "status" property contains a boolean value.
   */
  private validateIssuerProfileRevocationList(): { step: string, title: string, status: boolean, reason: string; } {
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
        this.progressCallback(Stages.validateIssuerProfileRevocationList, Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_SUCCESS);
        return { step: Stages.validateIssuerProfileRevocationList, title: Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateIssuerProfileRevocationList, Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerProfileRevocationList, title: Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.REVOCATION_LIST_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * The function validates the issuer profile public key and returns a message and status indicating
   * whether the validation was successful or not.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string message, and the "status" property contains a boolean value.
   */
  private validateIssuerProfilePublicKey(): { step: string, title: string, status: boolean, reason: string; } {
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
            this.progressCallback(Stages.validateIssuerProfilePublicKey, Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE, true, Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_SUCCESS);
            return { step: Stages.validateIssuerProfilePublicKey, title: Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE, status: true, reason: Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_SUCCESS };
          }
        }
      }
    }

    this.progressCallback(Stages.validateIssuerProfilePublicKey, Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE, false, Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR);
    return { step: Stages.validateIssuerProfilePublicKey, title: Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_VALIDATE, status: false, reason: Messages.PUBLIC_KEY_ISSUER_PROFILE_KEY_ERROR };
  }

  /**
   * This function validates a revocation list from an issuer profile.
   * @returns a Promise that resolves to an object with two properties: "message" and "status".
   */
  private async validateRevocationListFromIssuerProfile(): Promise<{ step: string, title: string, status: boolean, reason: string; }> {
    if (this.issuerProfileData) {
      this.revocationListData = await getDataFromAPI(
        getDataFromKey(
          this.issuerProfileData,
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList
        )
      );
      if (this.revocationListData) {
        this.progressCallback(Stages.validateRevocationListFromIssuerProfile, Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE, true, Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_SUCCESS);
        return { step: Stages.validateRevocationListFromIssuerProfile, title: Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE, status: true, reason: Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_SUCCESS };
      }
    }

    this.progressCallback(Stages.validateRevocationListFromIssuerProfile, Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE, false, Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR);
    return { step: Stages.validateRevocationListFromIssuerProfile, title: Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE, status: false, reason: Messages.FETCHING_REVOCATION_LIST_ISSUER_PROFILE_ERROR };
  }

}
