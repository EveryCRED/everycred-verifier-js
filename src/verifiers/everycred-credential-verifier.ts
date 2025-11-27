import { SDCredentialFormat } from "../constants/common";
import { ResponseMessage, VerificationConfig } from "../models/common.model";
import { Ed25519CredentialVerifier } from "./ed25519-credential-verifier";
import { JsonWebSignatureVerifier } from "./json-web-signature-verifier";

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
