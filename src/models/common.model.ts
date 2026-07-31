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
 *   and for Polygon Mainnet and Polygon Amoy (both queried through the Etherscan
 *   v2 multichain endpoint, distinguished by `chainId`).
 * - `polygon`: Polygonscan API key. Used for Polygon Testnet.
 */
export interface BlockchainApiKeys {
  ethereum?: string;
  polygon?: string;
}

/**
 * A caller-pinned Ed25519 public key for fully offline verification, used when
 * the issuer profile (DID document) cannot be fetched — e.g. `offChainVerification`
 * with no network access. This is intentionally minimal (a raw key, not a whole
 * issuer profile/DID document) so it stays cheap to carry in size-constrained
 * transports such as a CBOR-encoded QR payload.
 */
export interface OfflineVerificationKey {
  /**
   * Matches the credential's `proof.verificationMethod` / JWT `kid` (or its `#fragment`).
   * Omit when the issuer has a single key and no disambiguation is needed.
   */
  id?: string;
  /**
   * Key material:
   * - Ed25519: base64/base64url `jwk.x` (32 bytes) — JSON-LD Ed25519 or SD-JWT EdDSA
   * - RSA: PEM string (`-----BEGIN PUBLIC KEY-----...`) — SD-JWT RS256
   */
  publicKey: string;
}

export interface VerificationConfig {
  offChainVerification?: boolean,
  isBlockchainVerificationEnabled?: boolean
  logDiagnosticStep?: boolean
  blockchainApiKeys?: BlockchainApiKeys
  /** Pinned key(s) for offline signature verification. See `OfflineVerificationKey`. */
  offlinePublicKey?: OfflineVerificationKey | OfflineVerificationKey[]
}

export interface SDCredentialInput {
  format: string;
  credential: string;
  disclosures: string[];
  issuer: string;
  issued_at: string;
}