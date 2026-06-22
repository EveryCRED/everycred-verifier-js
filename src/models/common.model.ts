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

/**
 * Blockchain explorer API keys supplied by the consumer at runtime.
 * Keys are NEVER bundled with the library — the caller must provide their own.
 * - `ethereum`: Etherscan API key. Used for Ethereum Mainnet, Ethereum Sepolia,
 *   and Polygon Mainnet (which is queried through the Etherscan v2 multichain endpoint).
 * - `polygon`: Polygonscan API key. Used for Polygon Testnet.
 * Polygon Amoy is accessed via a public RPC endpoint and requires no key.
 */
export interface BlockchainApiKeys {
  ethereum?: string;
  polygon?: string;
}

export interface VerificationConfig {
  offChainVerification?: boolean,
  isBlockchainVerificationEnabled?: boolean
  logDiagnosticStep?: boolean
  blockchainApiKeys?: BlockchainApiKeys
}

export interface SDCredentialInput {
  format: string;
  credential: string;
  disclosures: string[];
  issuer: string;
  issued_at: string;
}