import { SdMerkleProofValidator2019 } from '../checksum/sd-merkle-proof-2019-validation';
import { CREDENTIALS_ISSUER_VALIDATORS_KEYS, CREDENTIALS_VALIDATORS_KEYS, SD_CREDENTIAL_VALIDATORS_KEYS, SDCredentialFormat } from '../constants/common';
import { Messages } from '../constants/messages';
import { Stages } from '../constants/stages';
import { SDCredentialInput, VerificationConfig } from '../models/common.model';
import { getDataFromAPI, getDataFromKey, isKeyPresent } from '../utils/credential-util';
import { logDiagnosticStep } from '../utils/helper';
import { extractAndNormalizeJwt, parseJwtToken } from '../utils/jwt-utils';
import { RevocationStatusCheck } from '../validator/revocation-status-check';
import { SdCredentialValidator } from '../validator/sd-credential-validator';
import { SignatureValidator } from '../validator/signature-validator';

export class JsonWebSignatureVerifier {
  private sdJwtCredential!: SDCredentialInput;
  private credential!: any;
  private credentialValidation!: boolean;
  private isChecksumValidated!: boolean;
  private revocationStatusValidation!: boolean;
  private signatureValidation!: boolean;
  private networkName!: string;
  private issuerProfileData: any = {};
  private revocationListData: any = {};
  private isBlockchainVerificationEnabled!: boolean;
  private offChainVerification!: boolean;

  private jwtToken: string = '';
  private header: any = {};
  private payload: any = {};
  private manualParsingMode: boolean = false;
  private headerB64: string = '';
  private payloadB64: string = '';
  private signatureB64: string = '';

  constructor(
    private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void,
    private readonly config: VerificationConfig = {}
  ) {
    this.isBlockchainVerificationEnabled = this.config?.isBlockchainVerificationEnabled ?? this.isBlockchainVerificationEnabled;
    this.offChainVerification = this.config?.offChainVerification ?? this.offChainVerification;
    if (this.config?.logDiagnosticStep) {
      this.progressCallback = (step: string, title: string, status: boolean, reason: string) => {
        logDiagnosticStep({ step, title, status, reason }, this.credential);
      };
    }
  }

  private validateSDCredentialFormatAndStructure(sdJwtCredential: any): boolean {
    const stage = Stages.validateSDCredentialFormatAndStructure;
    this.sdJwtCredential = sdJwtCredential as SDCredentialInput;

    // Helper to send consistent errors
    const fail = (message: string) => {
      this.progressCallback(stage, message, false, message);
      return false;
    };

    // Basic object validation
    if (!this.sdJwtCredential || typeof this.sdJwtCredential !== "object") {
      return fail(Messages.INVALID_OBJECT);
    }

    // Format validation
    if (this.sdJwtCredential.format !== SDCredentialFormat.EXPECTED_FORMAT) {
      return fail(Messages.INVALID_FORMAT);
    }

    // Credential string validation
    if (typeof this.sdJwtCredential.credential !== "string") {
      return fail(Messages.INVALID_CREDENTIAL);
    }

    // Disclosures validation
    if (!Array.isArray(this.sdJwtCredential.disclosures)) {
      return fail(Messages.INVALID_DISCLOSURES);
    }

    // Issuer validation
    if (typeof this.sdJwtCredential.issuer !== "string") {
      return fail(Messages.INVALID_ISSUER);
    }

    // Issued_at validation
    if (typeof this.sdJwtCredential.issued_at !== "string") {
      return fail(Messages.INVALID_ISSUED_AT);
    }

    // SUCCESS
    this.progressCallback(
      stage,
      Messages.VALID_SD_CREDENTIAL_FORMAT_AND_STRUCTURE_SUCCESS,
      true,
      ''
    );

    return true;
  }


  private validateJwtToken(jwtToken: string) {
    this.jwtToken = extractAndNormalizeJwt(jwtToken);

    if (!this.jwtToken || typeof this.jwtToken !== 'string' || this.jwtToken.trim().length === 0) {
      this.progressCallback(Stages.validateSDCredentialJwtToken, Messages.INVALID_JWT_TOKEN, false, Messages.INVALID_JWT_TOKEN);
      return false;
    }
    const parsed = parseJwtToken(this.jwtToken);
    if (!parsed) {
      this.progressCallback(Stages.validateSDCredentialJwtToken, Messages.INVALID_JWT_TOKEN, false, Messages.JWT_TOKEN_PARSING_FAILED);
      return false;
    }
    const { header, payload, manualParsingMode, headerB64, payloadB64, signatureB64 } = parsed;
    this.header = header;
    this.payload = payload;
    this.headerB64 = headerB64;
    this.payloadB64 = payloadB64;
    this.signatureB64 = signatureB64;
    this.manualParsingMode = manualParsingMode;
    //TODO: refactor this after development is complete as we have to mange the globle level variables at one place
    this.credential = payload;

    if (this.manualParsingMode) {
      this.progressCallback(Stages.validateSDCredentialJwtToken, Messages.INVALID_JWT_TOKEN, false, Messages.JWT_TOKEN_PARSING_FAILED);
      return false;
    }

    if (!this.header || !this.payload || !this.headerB64 || !this.payloadB64 || !this.signatureB64) {
      this.progressCallback(Stages.validateSDCredentialJwtToken, Messages.INVALID_JWT_TOKEN, false, Messages.INVALID_JWT_TOKEN);
      return false;
    }

    this.progressCallback(Stages.validateSDCredentialJwtToken, Messages.VALID_SD_CREDENTIAL_JWT_TOKEN_SUCCESS, true, Messages.VALID_SD_CREDENTIAL_JWT_TOKEN_SUCCESS);
    return true;
  }

  async verify(sdCredential: SDCredentialInput) {
    const isFormatAndStructureValid = this.validateSDCredentialFormatAndStructure(sdCredential);
    if (!isFormatAndStructureValid) {
      return { message: Messages.VALID_SD_CREDENTIAL_FORMAT_AND_STRUCTURE_FAILED, status: false, networkName: this.networkName };
    }

    const credentialData = sdCredential;
    this.jwtToken = credentialData.credential;

    const jwtValidationResult = this.validateJwtToken(this.jwtToken);
    if (!jwtValidationResult) {
      return { message: Messages.VALID_SD_CREDENTIAL_JWT_TOKEN_FAILED, status: false, networkName: this.networkName };
    }

    const hasEvidence = this.hasEvidence(this.payload);
    if (hasEvidence) {
      this.isBlockchainVerificationEnabled = false;
    }

    if (this.isBlockchainVerificationEnabled) {
      this.credentialValidation = await this.validateCredentials();
      if (this.credentialValidation) {
        //TODO: validate checksum is not working as expected so we are keeping it as it is for now
        this.isChecksumValidated = await this.validateChecksum();
        if (this.isChecksumValidated) {
          this.revocationStatusValidation = await this.revocationStatusCheck();
          if (this.revocationStatusValidation) {
            const signatureValidationResult = await this.verifySignature();
            if (signatureValidationResult) {
              return { message: Messages.VERIFICATION_SUCCESS, status: true, networkName: this.networkName };
            }
          }
        }
      }
    } else {
      this.credentialValidation = await this.validateCredentials();
      if (this.credentialValidation) {
        this.progressCallback(Stages.validateCredentials, Messages.BLOCKCHAIN_VALIDATION_SKIPPED, true, '');
        this.revocationStatusValidation = await this.revocationStatusCheck();
        if (this.revocationStatusValidation) {
          this.signatureValidation = await this.verifySignature();
          if (this.signatureValidation) {
            return { message: Messages.VERIFICATION_SUCCESS, status: true, networkName: this.networkName };
          }
        }
      }
    }
    this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, '');
    return { message: Messages.VERIFICATION_FAILED, status: false, networkName: this.networkName };
  }

  private async validateCredentials(): Promise<boolean> {
    const sdCredentialValidator = new SdCredentialValidator(this.progressCallback);
    const result = await sdCredentialValidator.validate(this.credential);

    if (result.status) {
      return true;
    }

    this.progressCallback(Stages.validateCredentials, Messages.CREDENTIALS_VALIDATION, false, Messages.CREDENTIALS_VALIDATION_FAILED);
    return false;
  }

  private hasEvidence(credential: any): boolean {
    return isKeyPresent(credential, SD_CREDENTIAL_VALIDATORS_KEYS.evidence);
  }

  /**
   * The function `validateChecksum` is a private asynchronous function that validates a checksum using
   * a MerkleProofValidator2019 and returns a boolean indicating whether the validation was successful.
   * @returns a Promise<boolean>.
   */
  private async validateChecksum(): Promise<boolean> {
    const validate = await new SdMerkleProofValidator2019(this.progressCallback).validate(this.credential, false);
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
    if (!this.offChainVerification && navigator.onLine) {
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
    if (isKeyPresent(this.credential, SD_CREDENTIAL_VALIDATORS_KEYS.issuer)) {
      const issuerDataUrl = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.issuer).profile;
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
      this.credential,
      this.issuerProfileData,
    );
    return validationResponse.status;
  }

  private async verifySignature(): Promise<boolean> {
    const signatureValidator = new SignatureValidator(this.progressCallback);
    const signatureValidationResult = await signatureValidator.validate(this.jwtToken, this.header);
    const status = signatureValidationResult?.status;
    if (!status) {
      this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, 'Signature verification failed');
      return false;
    }
    this.progressCallback(Stages.verification, Messages.VERIFICATION_SUCCESS, true, Messages.VERIFICATION_SUCCESS);
    return true;
  }
}