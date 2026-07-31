import { SdMerkleProofValidator2019 } from '../checksum/sd-merkle-proof-2019-validation';
import { CREDENTIALS_ISSUER_VALIDATORS_KEYS, CREDENTIALS_VALIDATORS_KEYS, DEFAULT_CONFIG, SD_CREDENTIAL_VALIDATORS_KEYS, SDCredentialFormat } from '../constants/common';
import { Messages } from '../constants/messages';
import { Stages } from '../constants/stages';
import { SDCredentialInput, VerificationConfig } from '../models/common.model';
import { getDataFromAPI, getDataFromKey, hasEvidence, isKeyPresent, isOnline } from '../utils/credential-util';
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
  private jwtToken: string = '';
  private header: any = {};
  private payload: any = {};
  private manualParsingMode = false;
  private headerB64: string = '';
  private payloadB64: string = '';
  private signatureB64: string = '';
  private isBlockchainVerificationEnabled = DEFAULT_CONFIG.isBlockchainVerificationEnabled;
  private readonly offChainVerification = DEFAULT_CONFIG.offChainVerification;
  private readonly isLogDiagnosticStep = DEFAULT_CONFIG.logDiagnosticStep;
  
  constructor(
    private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void,
    private readonly config: VerificationConfig = {}
  ) {
    this.isBlockchainVerificationEnabled = this.config?.isBlockchainVerificationEnabled ?? this.isBlockchainVerificationEnabled;
    this.offChainVerification = this.config?.offChainVerification ?? this.offChainVerification;
    this.isLogDiagnosticStep = this.config?.logDiagnosticStep ?? this.isLogDiagnosticStep;
    if (this.isLogDiagnosticStep) {
      this.progressCallback = (step: string, title: string, status: boolean, reason: string) => {
        logDiagnosticStep({ step, title, status, reason }, this.credential);
      };
    }
  }

  /**
   * Validates the format and structure of an SD-JWT credential.
   * Checks for valid object type, expected format, credential string, disclosures array, issuer, and issued_at fields.
   * @param sdJwtCredential - The SD-JWT credential object to validate.
   * @returns True if all validations pass, false otherwise.
   */
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


  /**
   * Validates and parses a JWT token string.
   * Extracts and normalizes the JWT, then parses header, payload, and signature components.
   * @param jwtToken - The raw JWT token string to validate.
   * @returns True if the JWT is valid and successfully parsed, false otherwise.
   */
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

  /**
   * Main entry point for verifying an SD-JWT credential.
   * Validates format, structure, and JWT token, then delegates to blockchain or non-blockchain verification flow.
   * @param sdCredential - The SD-JWT credential input to verify.
   * @returns A promise resolving to a response message with verification status and network name.
   */
  async verify(sdCredential: SDCredentialInput) {
    const isFormatAndStructureValid = this.validateSDCredentialFormatAndStructure(sdCredential);
    if (!isFormatAndStructureValid) {
      return { message: Messages.VALID_SD_CREDENTIAL_FORMAT_AND_STRUCTURE_FAILED, status: false, networkName: this.networkName };
    }

    const credentialData = sdCredential;
    this.jwtToken = credentialData.credential;

    const jwtValidationResult = this.validateJwtToken(this.jwtToken);
    if (!jwtValidationResult || !this.payload) {
      return { message: Messages.VALID_SD_CREDENTIAL_JWT_TOKEN_FAILED, status: false, networkName: this.networkName };
    }

    this.isBlockchainVerificationEnabled = !!hasEvidence(this.payload);

    return this.isBlockchainVerificationEnabled ? await this.withBlockchainVerification() : await this.withoutBlockchainVerification();
  }

  /**
   * Validates the credential payload using the SD credential validator.
   * @returns A promise resolving to true if validation passes, false otherwise.
   */
  private async validateCredentials(): Promise<boolean> {
    const sdCredentialValidator = new SdCredentialValidator(this.progressCallback);
    const result = await sdCredentialValidator.validate(this.credential);

    if (result.status) {
      return true;
    }

    this.progressCallback(Stages.validateCredentials, Messages.CREDENTIALS_VALIDATION, false, Messages.CREDENTIALS_VALIDATION_FAILED);
    return false;
  }

  /**
   * Performs full verification flow including blockchain checksum validation.
   * Executes credential validation, checksum validation, revocation status check, and signature verification.
   * @returns A promise resolving to a response message with verification status and network name.
   */
  private async withBlockchainVerification() {
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

    this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, '');
    return { message: Messages.VERIFICATION_FAILED, status: false, networkName: this.networkName };
  }

  /**
   * Performs verification flow without blockchain checksum validation.
   * Executes credential validation, revocation status check, and signature verification.
   * @returns A promise resolving to a response message with verification status and network name.
   */
  private async withoutBlockchainVerification() {
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
    
    this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, '');
    return { message: Messages.VERIFICATION_FAILED, status: false, networkName: this.networkName };
  }

  /**
   * Validates the credential checksum using Merkle proof validation.
   * Uses SdMerkleProofValidator2019 to verify the credential integrity on blockchain.
   * The off-chain flag is forwarded so the blockchain anchor lookup can be skipped.
   * @returns A promise resolving to true if checksum validation passes, false otherwise.
   */
  private async validateChecksum(): Promise<boolean> {
    const validate = await new SdMerkleProofValidator2019(this.progressCallback, this.config).validate(this.credential, this.offChainVerification);
    this.isChecksumValidated = validate?.status;
    this.networkName = validate.networkName ?? '';
    return this.isChecksumValidated;
  }

  /**
   * Checks the revocation status of the credential.
   *
   * The revocation list is a plain HTTP resource, not blockchain data, so the fetch
   * is gated on connectivity alone — NOT on `offChainVerification`, which only means
   * "skip blockchain anchor lookups". Gating it on the off-chain flag left
   * `revocationListData` empty while still online, which RevocationStatusCheck
   * (correctly) treats as an unfetchable list and fails on.
   * @returns A promise resolving to true if credential is not revoked, false otherwise.
   */
  private async revocationStatusCheck(): Promise<boolean> {
    if (isOnline()) {
      await this.fetchIssuerAndRevocationData();
    }

    this.revocationStatusValidation = await this.performRevocationStatusValidation();
    return this.revocationStatusValidation;
  }

  /**
   * Fetches issuer profile and revocation list data from remote URLs.
   * Retrieves issuer profile URL from credential, then fetches revocation list if available.
   * @returns A promise that resolves when data fetching is complete.
   */
  private async fetchIssuerAndRevocationData(): Promise<void> {
    await this.ensureIssuerProfileData();
    if (isKeyPresent(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList)) {
      const revocationListUrl = getDataFromKey(this.issuerProfileData, CREDENTIALS_ISSUER_VALIDATORS_KEYS.revocationList);
      if (revocationListUrl) {
        this.revocationListData = await getDataFromAPI(revocationListUrl);
      }
    }
  }

  /**
   * Fetches the issuer profile (from credential.issuer.profile) once and caches it.
   * Used by both signature verification (DID-document key resolution) and the
   * revocation step. Skipped entirely when offline; failures are swallowed so
   * signature verification can fall back to a pinned key (`config.offlinePublicKey`)
   * or the legacy header-embedded key path.
   */
  private async ensureIssuerProfileData(): Promise<void> {
    if (this.issuerProfileData && Object.keys(this.issuerProfileData).length) {
      return;
    }
    if (!isOnline()) {
      return;
    }
    if (!isKeyPresent(this.credential, SD_CREDENTIAL_VALIDATORS_KEYS.issuer)) {
      return;
    }
    const issuerProfileUrl = getDataFromKey(this.credential, CREDENTIALS_VALIDATORS_KEYS.issuer)?.profile;
    if (!issuerProfileUrl) {
      return;
    }
    try {
      this.issuerProfileData = await getDataFromAPI(issuerProfileUrl);
    } catch (error) {
      // Leave issuerProfileData unset; signature verification falls back to the legacy header path.
    }
  }

  /**
   * Performs revocation status validation using the RevocationStatusCheck validator.
   * @returns A promise resolving to true if credential is not revoked, false otherwise.
   */
  private async performRevocationStatusValidation(): Promise<boolean> {
    const validationResponse = await new RevocationStatusCheck(this.progressCallback).validate(
      this.revocationListData,
      this.credential,
      this.issuerProfileData,
    );
    return validationResponse.status;
  }

  /**
   * Verifies the cryptographic signature of the JWT token.
   * Uses SignatureValidator to validate the token signature against the header algorithm.
   * @returns A promise resolving to true if signature is valid, false otherwise.
   */
  private async verifySignature(): Promise<boolean> {
    await this.ensureIssuerProfileData();
    const signatureValidator = new SignatureValidator(this.progressCallback, this.config);
    const signatureValidationResult = await signatureValidator.validate(this.jwtToken, this.header, this.issuerProfileData);
    const status = signatureValidationResult?.status;
    if (!status) {
      this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, 'Signature verification failed');
      return false;
    }
    this.progressCallback(Stages.verification, Messages.VERIFICATION_SUCCESS, true, Messages.VERIFICATION_SUCCESS);
    return true;
  }
}