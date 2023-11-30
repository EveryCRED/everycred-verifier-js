import {
  CREDENTIALS_CONSTANTS,
  CREDENTIALS_ISSUER_VALIDATORS_KEYS,
  CREDENTIALS_VALIDATORS_KEYS,
  REVOCATION_STATUS_CHECK_KEYS,
} from "../constants/common";
import { Messages } from "../constants/messages";
import { Stages } from '../constants/stages';
import {
  deepCloneData,
  formatCustomDate,
  getDataFromKey,
  isDateExpired,
  isFutureDate,
  isKeyPresent
} from "../utils/credential-util";
import { sleep } from '../utils/sleep';

export class RevocationStatusCheck {
  private credential: any;
  private issuerProfileData: any;
  private revocationListData: any;

  constructor(private progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }

  /**
   * The function `validate` takes in three parameters, performs some data cloning operations, and then
   * checks the revocation status before returning a result object.
   * @param {any} revocationListData - The `revocationListData` parameter is the data of the revocation
   * list. It contains information about revoked credentials, such as the credential ID and the
   * revocation status.
   * @param {any} credentialData - The `credentialData` parameter is the data of the credential that
   * needs to be validated. It contains information such as the issuer, subject, and any additional
   * attributes or claims associated with the credential.
   * @param {any} issuerProfileData - The `issuerProfileData` parameter is the data of the issuer
   * profile. It contains information about the issuer, such as their name, address, and contact
   * details. This data is used to verify the authenticity of the issuer and ensure that the credential
   * being validated is issued by a trusted source.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * that represents the result of the revocation status check, and the "status" property is a boolean
   * value indicating whether the revocation status check passed or failed.
   */
  async validate(
    revocationListData: any,
    credentialData: any,
    issuerProfileData: any
  ): Promise<{ message: string; status: boolean; }> {
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
   * The statusRevocationCheck function checks various revocation-related conditions and returns a
   * boolean indicating whether all conditions are met.
   * @returns a Promise that resolves to a boolean value.
   */
  private async statusRevocationCheck(): Promise<boolean> {
    return ((await this.checkRevocationContext()).status &&
      this.checkRevocationType().status &&
      this.checkRevocationID().status &&
      (await this.checkRevocationIssuer()).status &&
      this.checkRevocationRevokedAssertions().status &&
      (await this.checkValidFromDate()).status &&
      (await this.checkValidUntilDate()).status);
  }

  /**
   * The function checks if a specific key is present in a revocation list data object and returns a
   * message and status based on the result.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string value, and the "status" property contains a boolean value.
   */
  private async checkRevocationContext(): Promise<{ message: string; status: boolean; }> {
    await sleep(250);

    if (
      isKeyPresent(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.context
      ) &&
      CREDENTIALS_CONSTANTS.revocation_list_context_values.some((data) =>
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
  private checkRevocationType(): { message: string; status: boolean; } {
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
  private checkRevocationID(): { message: string; status: boolean; } {
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
  private async checkRevocationIssuer(): Promise<{ message: string; status: boolean; }> {
    await sleep(350);

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
  private checkRevocationRevokedAssertions(): { message: string; status: boolean; } {
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
  private async checkValidFromDate(): Promise<{ message: string; status: boolean; }> {
    await sleep(400);

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
  private async checkValidUntilDate(): Promise<{ message: string; status: boolean; }> {
    await sleep(400);

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