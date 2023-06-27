var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { get } from "lodash";
// import { MerkleProofValidator2019 } from './checksum/merkle-proof-2019-validation';
import { deepCloneData } from "./utils/credential-util";
import { logger } from "./utils/logger";
import { CredentialIssuerValidator } from "./validator/credential-issuer-validator";
import { CredentialValidator } from "./validator/credential-validator";
import { RevocationStatusCheck } from './validator/revocation-status-check';
export class EveryCredVerifier {
    constructor() {
        this.credentialValidation = false;
        this.credentialIssuerValidation = false;
        this.proofValue = "z7veGu1qoKR3AS5AJiC3Kx6RxqS2rXV3g5fx6UrKcqU3nYCYaaccg5fN5dRUUG3STft5gbCHda3AHwFjBbVvZ5S9hjNo324XeqyUUXYG71RJV37Uyzf7ifaoW6SoUoqFtSaC3tagu7BMP2NSGpK3WbqRU6nsm1n6TctiukMKDB95tvx4KFxF3YEy4mpL4LhzRR9YnnCuB3rGQeDXhnGL8cvsesGnUb8ruxYRmSesP1aUTcbQH4uhugwEwAt2nk9zE3dxCGqhYtxD5VGScYojsNV2p3boFYiB2FTaPp1EjpDV7aFrBCzADZ";
        /**
         * This function is main entry point of the credential verifier.
         */
        this.verify = (certificate) => __awaiter(this, void 0, void 0, function* () {
            logger('---------------// S //----------------');
            this.certificate = deepCloneData(certificate);
            if (!(yield this.validateCredentials()) || !(yield this.revocationStatusCheck())) {
                logger("------------------ CREDENTIAL VALIDATION FAILED ------------------ " +
                    this.credentialIssuerValidation);
                logger('---------------// E //----------------');
                return; // Stop program execution if any check fails
            }
            logger(this.certificate);
            logger(this.issuerProfileData);
            logger(this.revocationListData);
            logger("------------------ CREDENTIAL VALIDATION SUCCESSFUL ------------------ " +
                this.credentialIssuerValidation);
            // const mkTest = new MerkleProofValidator2019().decodeProofValue(this.proofValue);
            // logger(`MK Test: ${mkTest}`);
            logger('---------------// E //----------------');
        });
    }
    /**
     * This function validates credentials using a CredentialValidator and CredentialIssuerValidator, and
     * retrieves issuer profile and revocation list data if validation is successful.
     */
    validateCredentials() {
        return __awaiter(this, void 0, void 0, function* () {
            this.credentialValidation = yield new CredentialValidator().validate(this.certificate);
            if (this.credentialValidation) {
                let data = yield new CredentialIssuerValidator().validate(this.certificate);
                this.credentialIssuerValidation = get(data, "issuerProfileValidationStatus");
                this.issuerProfileData = get(data, "issuerProfileData");
                this.revocationListData = get(data, "revocationListData");
            }
            if (this.credentialValidation && this.credentialIssuerValidation) {
                return true;
            }
            ;
            return false;
        });
    }
    /**
     * This is a private asynchronous function that performs a revocation status check on a certificate
     * using data from a revocation list and an issuer profile.
     */
    revocationStatusCheck() {
        return __awaiter(this, void 0, void 0, function* () {
            this.credentialIssuerValidation = yield new RevocationStatusCheck().validate(this.revocationListData, this.certificate, this.issuerProfileData);
            return this.credentialIssuerValidation;
        });
    }
}
