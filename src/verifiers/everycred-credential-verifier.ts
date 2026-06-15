import { SDCredentialFormat } from "../constants/common";
import { ResponseMessage, VerificationConfig } from "../models/common.model";
import { Ed25519CredentialVerifier } from "./ed25519-credential-verifier";
import { JsonWebSignatureVerifier } from "./json-web-signature-verifier";

/**
 * Main verifier class for EveryCred credentials.
 * Automatically delegates to the appropriate verifier based on credential format.
 */
export class EveryCredVerifier {
  
  constructor(
    private readonly progressCallback: (
      step: string,
      title: string,
      status: boolean,
      reason: string
    ) => void,
    private readonly config: VerificationConfig = {}
  ) { }

  /**
   * Verifies a credential by delegating to the appropriate verifier.
   * Uses JsonWebSignatureVerifier for SD-JWT credentials, Ed25519CredentialVerifier otherwise.
   * @param credential - The credential object to verify.
   * @returns A promise resolving to the verification result message.
   */
  async verify(credential: any): Promise<ResponseMessage> {
    if (credential?.format === SDCredentialFormat.EXPECTED_FORMAT) {
      const verifier = new JsonWebSignatureVerifier(this.progressCallback, {
        ...this.config,
      });
      return await verifier.verify(credential);
    } else {
      const verifier = new Ed25519CredentialVerifier(this.progressCallback, {
        ...this.config,
      });
      return await verifier.verify(credential);
    }
  }
}
