/* Defining a constant object called `CREDENTIALS_CONSTANTS` which contains various properties related
to verifiable credentials. These properties include the type of verifiable credential, the context
values, the required keys for the credential subject and proof, the supported proof type, the
context values for the issuer profile, the supported issuer profile type, and the required public
key fields for the issuer profile. This object can be exported and used in other parts of the code
to ensure consistency in the values used for verifiable credentials. */
export const CREDENTIALS_CONSTANTS = {
  verifiable_credential: [
    'VerifiableCredential',
    'EveryCREDCredential'
  ],
  context_values: [
    'https://w3id.org/everycred/v1',
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/ns/credentials/v2',
  ],
  credentialSubjectRequiredKeys: ['id', 'profile'],
  issuerRequiredKeys: ['id', 'profile'],
  proofRequiredKeys: [
    'type',
    'cryptosuite',
    'created',
    'proofPurpose',
    'proofValue',
    'verificationMethod',
  ],
  proofTypeSupported: ['Ed25519Signature2020'],
  issuerProfileTypeSupported: ['Profile'],
  issuerProfilePublicKeyFields: ['id', 'created'],
  revocation_list_type_supported: 'RevocationList',
};

/* Defining an enum called `CREDENTIALS_VALIDATORS_KEYS` which contains keys used for validating the
properties of a verifiable credential. Each key is assigned a string value. This enum can be
exported and used in other parts of the code to ensure consistency in the keys used for validation. */
export enum CREDENTIALS_VALIDATORS_KEYS {
  type = 'type',
  context = '@context',
  id = 'id',
  credentialSubject = 'credentialSubject',
  proof = 'proof',
  issuanceDate = 'issuanceDate',
  validUntilDate = 'validUntil',
  validFromDate = 'validFrom',
  issuer = 'issuer'
}

/* Defining an enum called `CREDENTIALS_ISSUER_VALIDATORS_KEYS` which contains keys used for validating
the properties of a verifiable credential issuer. Each key is assigned a string value. This enum can
be exported and used in other parts of the code to ensure consistency in the keys used for
validation. */
export enum CREDENTIALS_ISSUER_VALIDATORS_KEYS {
  issuer = 'issuer',
  context = '@context',
  type = 'type',
  id = 'id',
  name = 'name',
  email = 'email',
  revocationList = 'revocationList',
  publicKey = 'publicKey',
  profile = 'profile',
}

/* Defining an enum called `STATUS_REVOCATION_CHECK` which contains keys used for checking the status
of a revocation check. Each key is assigned a string value. This enum can be exported and used in
other parts of the code to ensure consistency in the keys used for revocation check. */
export enum REVOCATION_STATUS_CHECK_KEYS {
  context = '@context',
  type = 'type',
  id = 'id',
  issuer = 'issuer',
  revokedAssertions = 'revokedAssertions',
}

/* The `CHECKSUM_MERKLEPROOF_CHECK_KEYS` enum is defining keys used for checking the checksum of a
Merkle proof. Each key is assigned a string value that represents a specific property or field
related to the Merkle proof. */
export enum CHECKSUM_MERKLEPROOF_CHECK_KEYS {
  decoded_proof_value = 'decoded_proof_value',
  get_byte_array_to_issue = 'get_byte_array_to_issue',
  anchors = 'anchors',
  path = 'path',
  merkleRoot = 'merkleRoot',
  targetHash = 'targetHash',
  proofValue = 'proofValue',
  publicKey = 'publicKey[0].publicKey',
  verificationMethod = 'verificationMethod'
}

/* BLOCKCHAIN_API_LIST contains an array of objects representing various blockchain APIs.
Each object has an 'id' identifying the blockchain, 'url' indicating the API endpoint, and 'apiKey' for authentication.
Use these APIs to interact with Ethereum Mainnet, Ethereum Sepolia, Polygon Mainnet, Polygon Testnet, and Polygon Amoy.
Ensure to use the respective API key for authentication purposes. */
export const BLOCKCHAIN_API_LIST = [
  { id: 'ethereumMainnet', url: 'https://api.etherscan.io/', apiKey: '9RS1QFI8HR3WF11YKESZYRJCW44QC4W1G7' },
  { id: 'ethereumSepolia', url: 'https://api-sepolia.etherscan.io/', apiKey: '9RS1QFI8HR3WF11YKESZYRJCW44QC4W1G7' },
  { id: 'polygonMainnet', url: 'https://api.polygonscan.com/', apiKey: 'Z6G5RJPZIP7WFXZTJE2MRY1191XCR7X955' },
  { id: 'polygonTestnet', url: 'https://api-testnet.polygonscan.com/', apiKey: 'Z6G5RJPZIP7WFXZTJE2MRY1191XCR7X955' },
  { id: 'polygonAmoy', url: 'https://rpc-amoy.polygon.technology/', apiKey: '9876543210' }, // No API Key is needed, provided placeholder
];

/* The `export enum BASE_API` is defining an enumeration called `BASE_API` that represents different
blockchain APIs. It assigns string values to each enum member, where `eth` is assigned the value
`'ethereum'` and `poly` is assigned the value `'polygon'`. This enum can be exported and used in
other parts of the code to refer to specific blockchain APIs, providing a convenient way to ensure
consistency in the values used for different APIs. */
export enum BASE_API {
  eth = 'ethereum',
  poly = 'polygon',
}

/* The `export enum BASE_NETWORK` is defining an enumeration called `BASE_NETWORK` that represents
different network types. Each enum member is assigned a specific string value, where:
- `sepolia` is assigned the value `'Sepolia'`
- `mainnet` is assigned the value `'Mainnet'`
- `testnet` is assigned the value `'Testnet'`
- `amoy` is assigned the value `'Amoy'` */
export enum BASE_NETWORK {
  sepolia = 'Sepolia',
  mainnet = 'Mainnet',
  testnet = 'Testnet',
  amoy = 'Amoy'
}

/* The `export enum GENERAL_KEYWORDS` is defining an enumeration called `GENERAL_KEYWORDS` that
represents general keywords used in the code. It assigns string values to each enum member, where
`url` is assigned the value `'url'` and `apiKey` is assigned the value `'apiKey'`. */
export enum GENERAL_KEYWORDS {
  url = 'url',
  apiKey = 'apiKey'
}

/* The `MERKLE_TREE` constant is an object that contains properties related to the validation of a
Merkle tree. */
export const MERKLE_TREE = {
  validation_api: 'user/credential/merkle_tree_verification?merkle_tree_data=',
  data_type: 'normalize_data',
  algorithm: '&algorithm='
};

/* The `export enum HTTP_METHODS` is defining an enumeration called `HTTP_METHODS` that represents
different HTTP methods. It assigns string values to each enum member, where `GET` is assigned the
value `'GET'`, `POST` is assigned the value `'POST'`, `PUT` is assigned the value `'PUT'`, `PATCH`
is assigned the value `'PATCH'`, and `DELETE` is assigned the value `'DELETE'`. */
export enum HTTP_METHODS {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  PATCH = 'PATCH',
  DELETE = 'DELETE',
}

/* The `export enum ALGORITHM_TYPES` is defining an enumeration called `ALGORITHM_TYPES` that
represents different algorithm types used in the code. It assigns string values to each enum member,
where `MERKLEPROOF` is assigned the value `'MerkleProof2019'` and `ED25519SIGNATURE2020` is
assigned the value `'Ed25519Signature2020'`. */
export enum ALGORITHM_TYPES {
  MERKLEPROOF = 'MerkleProof2019',
  ED25519SIGNATURE2020 = 'Ed25519Signature2020',
}

/* The line `const APPLICATION_JSON = 'application/json';` is defining a constant variable called
`APPLICATION_JSON` and assigning it the value `'application/json'`. */
export const APPLICATION_JSON = 'application/json';

/* The line `const REQUEST_BODY = 'body';` is defining a constant variable called `REQUEST_BODY` and
assigning it the value `'body'`. This constant is likely used to represent the request body in a
code implementation. It can be used as a reference or a parameter in functions or methods that
handle HTTP requests, indicating that the value being passed or accessed is the request body. */
export const REQUEST_BODY = 'body';

/* The line `export const DATE_TIME_FORMAT_OPTIONS: Intl.DateTimeFormatOptions = { year: 'numeric',
month: 'long', day: 'numeric' };` is defining a constant variable called `DATE_TIME_FORMAT_OPTIONS`
and assigning it an object of type `Intl.DateTimeFormatOptions`. */
export const DATE_TIME_FORMAT_OPTIONS: Intl.DateTimeFormatOptions = {
  day: '2-digit',
  month: 'long',
  year: 'numeric',
  hour: 'numeric',
  minute: 'numeric',
  hour12: true,
};

/* The line `export const DATE_TIME_FORMAT_LOCALE = 'en-US';` is defining a constant variable called
`DATE_TIME_FORMAT_LOCALE` and assigning it the value `'en-US'`. */
export const DATE_TIME_FORMAT_LOCALE = 'en-US';

/* The line `export const BUFFER_ENCODING_TYPE = 'hex';` is defining a constant variable called
`BUFFER_ENCODING_TYPE` and assigning it the value `'hex'`. */
export const BUFFER_ENCODING_TYPE = 'hex';

/** The `export enum EnvironmentApis` is defining an enumeration
 *  called `EnvironmentApis` that represents different environments or APIs.
 * It assigns string values to each enum member.
*/
export enum EnvironmentApis {
  Production = 'https://verifier.everycred.com',
  Staging = 'https://staging-verifier.everycred.com',
  Development = 'https://evrc-verifier.everycred.com',
  Demo = 'https://demo-verifier.everycred.com',
  Local = 'http://localhost:4200',
}

/** The code `API_URLS` is creating a constant variable called `API_URLS`
 * and assigning it a new `Map` object.
*/
export const API_URLS = new Map<EnvironmentApis, string>([
  [EnvironmentApis.Production, 'https://product-api.everycred.com'],
  [EnvironmentApis.Staging, 'https://service-api.everycred.com'],
  [EnvironmentApis.Development, 'https://evrc-service.everycred.com'],
  [EnvironmentApis.Local, 'https://evrc-service.everycred.com'],
  [EnvironmentApis.Demo, 'https://demo-service-api.everycred.com'],
]);

/** Below line is defining a constant variable called `DEFAULT_API_URL`
 * and assigning it the value `'https://product-api.everycred.com'`.
 * This constant represents the default API URL that will be used
 * if no specific API URL is provided.
*/
export const DEFAULT_API_URL = 'https://product-api.everycred.com';