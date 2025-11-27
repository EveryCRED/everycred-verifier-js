export interface ResponseMessage {
  message: string;
  status: boolean;
}

export interface ProcessStepStatus {
  step: string,
  title: string,
  status: boolean,
  reason: string;
}

export interface SDCredentialInput {
  format: string;
  credential: string;
  disclosures: string[];
  issuer: string;
  issued_at: string;
}

export interface VerificationConfig {
  offChainVerification?: boolean,
  isBlockchainVerificationEnabled?: boolean
  logDiagnosticStep?: boolean
}

export interface SDCredentialInput {
  format: string;
  credential: string;
  disclosures: string[];
  issuer: string;
  issued_at: string;
}