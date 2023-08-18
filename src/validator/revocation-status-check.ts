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
import { sleep } from '../utils/sleep';

export class RevocationStatusCheck {
  private credential: any;
  private issuerProfileData: any;
  private revocationListData: any;

  constructor(private progressCallback: (step: string, status: boolean) => void) { }

  async validate(
    revocationListData: any,
    credentialData: any,
    issuerProfileData: any
  ): Promise<{ message: string; status: boolean; }> {
    this.credential = deepCloneData(credentialData);
    this.issuerProfileData = deepCloneData(issuerProfileData);
    this.revocationListData = deepCloneData(revocationListData);

    const result = await this.statusRevocationCheck();

    if (!result) {
      this.failedAllStages();
    }

    return { message: result ? '' : Messages.REVOCATION_STATUS_CHECK_FAILED, status: result, };
  }

  private async statusRevocationCheck(): Promise<boolean> {
    return (await this.checkRevocationContext()).status &&
      this.checkRevocationType().status &&
      this.checkRevocationID().status &&
      (await this.checkRevocationIssuer()).status &&
      this.checkRevocationRevokedAssertions().status &&
      (await this.checkValidUntilDate()).status;
  }

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
      return { message: '', status: true };
    }

    this.failedAllStages();
    logger(Messages.CONTEXT_REVOCATION_LIST_KEY_ERROR, "error");
    return { message: Messages.CONTEXT_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  private checkRevocationType(): { message: string; status: boolean; } {
    if (isKeyPresent(this.credential, REVOCATION_STATUS_CHECK_KEYS.type)) {
      let typeData: string[] = getDataFromKey(
        this.revocationListData,
        REVOCATION_STATUS_CHECK_KEYS.type
      );

      if (typeData.includes(CREDENTIALS_CONSTANTS.revocation_list_type_supported)) {
        this.progressCallback(Messages.CHECKING_REVOKE_STATUS, true);
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.TYPE_REVOCATION_LIST_KEY_ERROR, "error");
    return { message: Messages.TYPE_REVOCATION_LIST_KEY_ERROR, status: false };
  }

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
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.ID_REVOCATION_LIST_KEY_ERROR, "error");
    return { message: Messages.ID_REVOCATION_LIST_KEY_ERROR, status: false };
  }

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
        this.progressCallback(Messages.CHECKING_AUTHENTICITY, true);
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
    logger(Messages.ISSUER_REVOCATION_LIST_KEY_ERROR, "error");
    return { message: Messages.ISSUER_REVOCATION_LIST_KEY_ERROR, status: false };
  }

  private checkRevocationRevokedAssertions(): { message: string; status: boolean; } {
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

      if (revokedAssertionsData?.length) {
        let data = revokedAssertionsData.filter(
          (data: any) => data.id === this.credential.id
        );

        if (data.length) {
          return { message: getDataFromKey(data, ['0', 'revocationReason']), status: false };
        }
      } else {
        return { message: '', status: true };
      }
    }

    this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, false);
    logger(Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR, "error");
    return { message: Messages.REVOKED_ASSERTIONS_REVOCATION_LIST_KEY_ERROR, status: false };
  }

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

      if (validUntilDate && !isDateExpired(validUntilDate)) {
        this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, true);
        return { message: '', status: true };
      }

      this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, false);
      return { message: Messages.VALID_UNTIL_DATE_KEY_ERROR, status: false };
    }

    this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, true);
    return { message: '', status: true };
  }

  private failedAllStages(): void {
    this.progressCallback(Messages.CHECKING_AUTHENTICITY, false);
    this.progressCallback(Messages.CHECKING_EXPIRATION_DATE, false);
  }

}