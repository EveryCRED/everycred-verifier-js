import {
  CREDENTIALS_CONSTANTS,
  CREDENTIALS_ISSUER_VALIDATORS_KEYS,
  CREDENTIALS_VALIDATORS_KEYS,
  REVOCATION_STATUS_CHECK_KEYS,
} from "../constants/common";
import { Messages } from "../constants/messages";
import { Stages } from '../constants/stages';
import { ResponseMessage } from '../models/common.model';
import {
  deepCloneData,
  formatCustomDate,
  getDataFromKey,
  isDateExpired,
  isFutureDate,
  isKeyPresent
} from "../utils/credential-util";

export class RevocationStatusCheck {
  private credential: any;
  private issuerProfileData: any;
  private revocationListData: any;

  constructor(private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }


  /**
   * The function `validate` performs revocation status check on a credential and returns the result
   * along with a message.
   * @param {any} revocationListData - The `revocationListData` parameter likely contains information
   * about revoked credentials or certificates. This data is used to check if the credential being
   * validated has been revoked or is still valid. The `validate` function you provided seems to be
   * performing a revocation status check on a credential using this data along with
   * @param {any} credentialData - The `credentialData` parameter in the `validate` function likely
   * contains information about the credential being validated. This data could include details such as
   * the credential type, issuer, issue date, expiration date, and any other relevant information related
   * to the credential.
   * @param {any} issuerProfileData - The `issuerProfileData` parameter in the `validate` function likely
   * contains data related to the issuer of the credential. This data could include information such as
   * the issuer's name, contact details, public key, or any other relevant information needed for
   * validating the credential.
   * @returns The `validate` function returns a Promise that resolves to a `ResponseMessage` object. The
   * `ResponseMessage` object contains a `message` property with the reason for the revocation status
   * check (either success or failure) and a `status` property indicating whether the revocation status
   * check was successful (true) or failed (false).
   */
  async validate(
    revocationListData: any,
    credentialData: any,
    issuerProfileData: any,
  ): Promise<ResponseMessage> {
    this.credential = deepCloneData(credentialData);
    this.issuerProfileData = deepCloneData(issuerProfileData);
    this.revocationListData = deepCloneData(revocationListData);

    const result = await this.statusRevocationCheck();

    const reason = result
      ? Messages.REVOCATION_STATUS_CHECK_SUCCESS
      : Messages.REVOCATION_STATUS_CHECK_FAILED;

    this.progressCallback(Stages.revocationStatusCheck, Messages.REVOCATION_STATUS_VALIDATION, result, reason);
    return { message: reason, status: result };
  }

  /**
   * The `statusRevocationCheck` function asynchronously checks for revocation status and validity dates,
   * prioritizing online status.
   * @returns The `statusRevocationCheck` method returns a boolean value.
   */
  private async statusRevocationCheck(): Promise<boolean> {
    if (!navigator.onLine) {
      this.progressCallback(Stages.revocationStatusCheck, Messages.OFFLINE_STATUS_CHECK, true, Messages.SKIP_REVOCATION_STATUS_CHECK);
      return await this.checkValidityDates();
    }

    return (await this.completeRevocationChecks()) &&
      (await this.checkValidityDates());
  }

  private async checkValidityDates(): Promise<boolean> {
    return (await this.checkValidFromDate()).status &&
      (await this.checkValidUntilDate()).status;
  }

  private async completeRevocationChecks(): Promise<boolean> {
    return (await this.checkRevocationContext()).status &&
      this.checkRevocationType().status &&
      this.checkRevocationID().status &&
      (await this.checkRevocationIssuer()).status &&
      this.checkRevocationRevokedAssertions().status;
  }

  /**
   * The function checks if a specific key is present in a revocation list data object and returns a
   * message and status based on the result.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string value, and the "status" property contains a boolean value.
   */
  private async checkRevocationContext(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.context
      ) &&
      CREDENTIALS_CONSTANTS.context_values.some((data) =>
        this.revocationListData[REVOCATION_STATUS_CHECK_KEYS.context].includes(data)
      )
    ) {
      this.progressCallback(Stages.checkRevocationContext, Messages.CONTEXT_REVOCATION_LIST_KEY_VALIDATE, true, Messages.CONTEXT_REVOCATION_LIST_KEY_SUCCESS);
      return { message: Messages.CONTEXT_REVOCATION_LIST_KEY_SUCCESS, status: true };
    }

    this.progressCallback(Stages.checkRevocationContext, Messages.CONTEXT_REVOCATION_LIST_KEY_VALIDATE, false, Messages.CONTEXT_REVOCATION_LIST_KEY_ERROR);
    return { message: Messages.CONTEXT_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  /**
   * The function checks if a specific type of key is present in a credential and returns a message and
   * status based on the result.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private checkRevocationType(): ResponseMessage {
    if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.type)) {
      let typeData: string[] = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.type
      );

      if (typeData.includes(CREDENTIALS_CONSTANTS.revocation_list_type_supported)) {
        this.progressCallback(Stages.checkRevocationType, Messages.TYPE_REVOCATION_LIST_KEY_VALIDATE, true, Messages.TYPE_REVOCATION_LIST_KEY_SUCCESS);
        return { message: Messages.TYPE_REVOCATION_LIST_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkRevocationType, Messages.TYPE_REVOCATION_LIST_KEY_VALIDATE, false, Messages.TYPE_REVOCATION_LIST_KEY_ERROR);
    return { message: Messages.TYPE_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  /**
   * The function checks if a revocation ID is present and matches the revocation list in the issuer
   * profile data.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private checkRevocationID(): ResponseMessage {
    if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.id)) {
      let idData = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.id
      );
      if (
        idData &&
        idData === getDataFromKey(
          this.issuerProfileData,
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList
        )
      ) {
        this.progressCallback(Stages.checkRevocationID, Messages.ID_REVOCATION_LIST_KEY_VALIDATE, true, Messages.ID_REVOCATION_LIST_KEY_SUCCESS);
        return { message: Messages.ID_REVOCATION_LIST_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkRevocationID, Messages.ID_REVOCATION_LIST_KEY_VALIDATE, false, Messages.ID_REVOCATION_LIST_KEY_ERROR);
    return { message: Messages.ID_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  /**
   * The function checks if the revocation issuer is valid and returns a message and status.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string message, and the "status" property contains a boolean value.
   */
  private async checkRevocationIssuer(): Promise<ResponseMessage> {
    if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.issuer)) {
      let issuerData = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.issuer
      );
      if (
        issuerData &&
        issuerData === getDataFromKey(
          this.issuerProfileData,
          CREDENTIALS_ISSUER_VALIDATORS_KEYS.id
        )
      ) {
        this.progressCallback(Stages.checkRevocationIssuer, Messages.ISSUER_REVOCATION_LIST_KEY_VALIDATE, true, Messages.ISSUER_REVOCATION_LIST_KEY_SUCCESS);
        return { message: Messages.ISSUER_REVOCATION_LIST_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkRevocationIssuer, Messages.ISSUER_REVOCATION_LIST_KEY_VALIDATE, false, Messages.ISSUER_REVOCATION_LIST_KEY_ERROR);
    return { message: Messages.ISSUER_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  /**
   * The function checks if a given assertion is revoked based on a revocation list.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private checkRevocationRevokedAssertions(): ResponseMessage {
    if (
      isKeyPresent(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.revokedAssertions
      )
    ) {
      const revokedAssertionsData = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.revokedAssertions
      );

      if (Array.isArray(revokedAssertionsData)) {
        const revokedData = revokedAssertionsData.filter(
          (data: any) => data.id === this.credential.id
        );

        if (revokedData.length) {
          this.progressCallback(Stages.checkRevocationRevokedAssertions, Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE, false, getDataFromKey(revokedData[0], ['0', 'revocationReason']));
          return { message: getDataFromKey(revokedData[0], ['0', 'revocationReason']), status: false };
        }

        this.progressCallback(Stages.checkRevocationRevokedAssertions, Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE, true, Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_SUCCESS);
        return { message: Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkRevocationRevokedAssertions, Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE, false, Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR);
    return { message: Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  /**
   * The function checks if a valid from date is present in a credential object and returns a message
   * and status indicating if the validation was successful.
   * @returns a Promise that resolves to an object with two properties: "message" and "status".
   */
  private async checkValidFromDate(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.validFromDate
      )
    ) {
      let validFromDate = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.validFromDate
      );

      if (validFromDate?.length && !isFutureDate(validFromDate)) {
        this.progressCallback(Stages.checkValidFromDate, Messages.VALID_FROM_DATE_KEY_VALIDATE, true, Messages.VALID_FROM_DATE_KEY_SUCCESS);
        return { message: Messages.VALID_FROM_DATE_KEY_SUCCESS, status: true };
      }

      const formattedDate = formatCustomDate(new Date(validFromDate));

      this.progressCallback(Stages.checkValidFromDate, Messages.VALID_FROM_DATE_KEY_VALIDATE, false, `${Messages.VALID_FROM_DATE_KEY_ERROR} ${formattedDate}`);
      return { message: `${Messages.VALID_FROM_DATE_KEY_ERROR} ${formattedDate}`, status: false };
    }

    this.progressCallback(Stages.checkValidFromDate, Messages.VALID_FROM_DATE_KEY_VALIDATE, true, Messages.VALID_FROM_DATE_KEY_SUCCESS);
    return { message: Messages.VALID_FROM_DATE_KEY_SUCCESS, status: true };
  }

  /**
   * The function `checkValidUntilDate` checks if a validUntilDate key is present in the credential
   * object and if it is not expired.
   * @returns a Promise that resolves to an object with two properties: "message" and "status".
   */
  private async checkValidUntilDate(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.validUntilDate
      )
    ) {
      let validUntilDate = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.validUntilDate
      );

      if (validUntilDate?.length && !isDateExpired(validUntilDate)) {
        this.progressCallback(Stages.checkValidUntilDate, Messages.VALID_UNTIL_DATE_KEY_VALIDATE, true, Messages.VALID_UNTIL_DATE_KEY_SUCCESS);
        return { message: Messages.VALID_UNTIL_DATE_KEY_SUCCESS, status: true };
      }

      const formattedDate = formatCustomDate(new Date(validUntilDate));

      this.progressCallback(Stages.checkValidUntilDate, Messages.VALID_UNTIL_DATE_KEY_VALIDATE, false, `${Messages.VALID_UNTIL_DATE_KEY_ERROR} ${formattedDate}`);
      return { message: `${Messages.VALID_UNTIL_DATE_KEY_ERROR} ${formattedDate}`, status: false };
    }

    this.progressCallback(Stages.checkValidUntilDate, Messages.VALID_UNTIL_DATE_KEY_VALIDATE, true, Messages.VALID_UNTIL_DATE_KEY_SUCCESS);
    return { message: Messages.VALID_UNTIL_DATE_KEY_SUCCESS, status: true };
  }
}