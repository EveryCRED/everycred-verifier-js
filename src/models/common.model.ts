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
 * A JSON Web Key as it appears inside an issuer profile's verificationMethod.
 * Supports OKP (Ed25519) and RSA keys; extra members are allowed for forward
 * compatibility and to support Web Crypto's importKey('jwk', ...) directly.
 */
export interface PublicKeyJwk {
  kty: string;
  crv?: string;
  alg?: string;
  kid?: string;
  x?: string; // OKP/EC public key coordinate (base64 or base64url)
  y?: string; // EC only
  n?: string; // RSA modulus
  e?: string; // RSA exponent
  [key: string]: unknown;
}

/**
 * A DID-document style verificationMethod entry carrying a publicKeyJwk.
 */
export interface VerificationMethod {
  id: string;
  type: string;
  controller?: string;
  publicKeyJwk?: PublicKeyJwk;
}

/**
 * An issuer profile expressed as a DID document: it exposes one or more
 * verificationMethod entries instead of a legacy `publicKey` array.
 */
export interface DidDocumentProfile {
  id?: string;
  name?: string;
  email?: string;
  url?: string;
  description?: string;
  verificationMethod?: VerificationMethod[];
  [key: string]: unknown;
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