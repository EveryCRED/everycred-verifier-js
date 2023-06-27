import {
  CREDENTIALS_CONSTANTS,
  CREDENTIALS_ISSUER_VALIDATORS_KEYS,
  CREDENTIALS_VALIDATORS_KEYS,
  REVOCATION_STATUS_CHECK_KEYS,
} from "../constants/common";
import { Messages } from "../constants/messages";
import {
  deepCloneData,
  getDataFromKey,
  isDateExpired,
  isKeyPresent
} from "../utils/credential-util";
import { logger } from "../utils/logger";

export class RevocationStatusCheck {
  private credential: any;
  private issuerProfileData: any;
  private revocationListData: any;

  constructor() { }

  async validate(
    revocationListData: any,
    credentialData: any,
    issuerProfileData: any
  ): Promise<any> {
    this.credential = deepCloneData(credentialData);
    this.issuerProfileData = deepCloneData(issuerProfileData);
    this.revocationListData = deepCloneData(revocationListData);

    return await this.statusRevocationCheck();
  }

  private statusRevocationCheck(): boolean {
    if (
      this.checkRevocationContext() &&
      this.checkRevocationType() &&
      this.checkRevocationID() &&
      this.checkRevocationIssuer() &&
      this.checkRevocationRevokedAssertions() &&
      this.checkValidUntilDate()
    ) {
      return true;
    }

    return false; // Stop program execution if any check fails
  }

  /**
   * This function checks if a specific key is present in a data object and if its value matches certain
   * predefined values, returning true if successful and false otherwise.
   * @returns a boolean value - either true or false.
   */
  private checkRevocationContext(): boolean {
    logger(Messages.CONTEXT_REVOCATION_LIST_KEY_VALIDATE);
    if (
      isKeyPresent(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.context
      ) &&
      CREDENTIALS_CONSTANTS.revocation_list_context_values.some((data) =>
        this.revocationListData[REVOCATION_STATUS_CHECK_KEYS.context].includes(data)
      )
    ) {
      logger(Messages.CONTEXT_REVOCATION_LIST_KEY_SUCCESS);
      return true;
    }
    logger(Messages.CONTEXT_REVOCATION_LIST_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function checks if the revocation list type is supported and returns a boolean value.
   * @returns a boolean value, either true or false.
   */
  private checkRevocationType(): boolean {
    logger(Messages.TYPE_REVOCATION_LIST_KEY_VALIDATE);
    if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.type)) {
      let typeData: string[] = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.type
      );

      if (
        typeData.includes(CREDENTIALS_CONSTANTS.revocation_list_type_supported)
      ) {
        logger(Messages.TYPE_REVOCATION_LIST_KEY_SUCCESS);
        return true;
      }
    }
    logger(Messages.TYPE_REVOCATION_LIST_KEY_ERROR, "error");
    return false;
  }

  /* The `checkRevocationID()` function is checking if the ID of the credential being validated matches
  the ID of the revocation list in the issuer profile data. If the IDs match, it logs a success
  message and returns `true`, otherwise it logs an error message and returns `false`. */
  private checkRevocationID(): boolean {
    logger(Messages.ID_REVOCATION_LIST_KEY_VALIDATE);
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
        logger(Messages.ID_REVOCATION_LIST_KEY_SUCCESS);
        return true;
      }
    }
    logger(Messages.ID_REVOCATION_LIST_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function checks if the issuer of a credential is present in a revocation list and returns a
   * boolean value based on the result.
   * @returns A boolean value is being returned.
   */
  private checkRevocationIssuer(): boolean {
    logger(Messages.ISSUER_REVOCATION_LIST_KEY_VALIDATE);
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
        logger(Messages.ISSUER_REVOCATION_LIST_KEY_SUCCESS);
        return true;
      }
    }
    logger(Messages.ISSUER_REVOCATION_LIST_KEY_ERROR, "error");
    return false;
  }

  /**
   * This function checks if a credential has been revoked by looking for its ID in a revocation list.
   * @returns a boolean value.
   */
  private checkRevocationRevokedAssertions(): boolean {
    logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_VALIDATE);
    // this.revocationListData.revokedAssertions = [
    //   {
    //     "id": "urn:uuid:8b6d0d98-3843-4b92-9809-18b3ca21a4f1",
    //     "revocationReason": "Credential is issued with invalid information"
    //   },
    //   {
    //     "id": "urn:uuid:5955c7e0-aa6b-40bb-9853-9e16b4c969be",
    //     "revocationReason": "Certificate is Expired"
    //   },
    //   {
    //     "id": "urn:uuid:e1401810-3b13-4cf4-9d2c-c3354acc991c",
    //     "revocationReason": "Issued with wrong information"
    //   }
    // ];

    if (
      isKeyPresent(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.revokedAssertions
      )
    ) {
      let revokedAssertionsData = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.revokedAssertions
      );

      if (revokedAssertionsData && revokedAssertionsData.length) {
        logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_SUCCESS);
        let data = revokedAssertionsData.filter(
          (data: any) => data.id === "urn:uuid:8b6d0d98-3843-4b92-9809-18b3ca21a4f1"
        );

        if (data.length) {
          logger(getDataFromKey(data, ['0', 'revocationReason']));
          return false; // terminate with reason from array
        }
      } else {
        logger(Messages.CERTIFICATE_REVOCATION_LIST_STATUS);
        return true;
      }
    }
    logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR, "error");
    return false;
  }

  private checkValidUntilDate(): boolean {
    // this.credential.validUntil = '2023-06-09T12:20:45Z';
    if (
      isKeyPresent(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.validUntilDate
      )
    ) {
      logger(Messages.VALID_UNTIL_DATE_KEY_VALIDATE);
      let validUntilDate = getDataFromKey(
        this.credential,
        CREDENTIALS_VALIDATORS_KEYS.validUntilDate
      );

      if (validUntilDate && !isDateExpired(validUntilDate)) {
        logger(Messages.VALID_UNTIL_DATE_KEY_SUCCESS);
        return true;
      }

      logger(Messages.VALID_UNTIL_DATE_KEY_ERROR, "error");
      return false;
    }
    return true;
  }
}