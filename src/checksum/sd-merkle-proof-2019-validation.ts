import { Buffer } from 'buffer';
import { isEmpty } from 'lodash';
import sha256 from 'sha256';
import Web3 from 'web3';
import {
  ALGORITHM_TYPES,
  BASE_API,
  BASE_NETWORK,
  BLOCKCHAIN_API_LIST,
  BUFFER_ENCODING_TYPE,
  CHECKSUM_MERKLEPROOF_CHECK_KEYS,
  SD_CREDENTIAL_VALIDATORS_KEYS
} from '../constants/common';
import { Messages } from '../constants/messages';
import { Stages } from '../constants/stages';
import { CreateResponse, NetworkResponseStatus } from '../models/checksum.model';
import { ResponseMessage, VerificationConfig } from '../models/common.model';
import {
  deepCloneData,
  getDataFromAPI,
  getDataFromKey,
  isKeyPresent,
  isObjectEmpty
} from '../utils/credential-util';
import { logger } from '../utils/logger';

export class SdMerkleProofValidator2019 {
  private credential: any;
  private decodedData: any;
  private normalizedDecodedData: any;
  private blockchainApiResponse: any;
  private isMerkleProofVerified: boolean = false;
  networkName: string = '';

  constructor(
    private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void,
    private readonly config: VerificationConfig = {}
  ) { }

  /**
   * The function `validate` performs various checks on credential data and returns a response
   * indicating the status of the data integrity check.
   * @param {any} credentialData - The `credentialData` parameter is an object that contains the data
   * needed for the validation process. It is used as input for various validation checks and
   * verification steps within the `validate` function.
   * @param offChainVerification - When true, the blockchain anchor lookup is skipped;
   * all local integrity checks still run.
   * @returns The function `validate` returns a promise that resolves to an object with the following
   * properties: `message` (string), `status` (boolean), and `networkName` (string).
   */
  async validate(credentialData: any, offChainVerification: boolean = false): Promise<NetworkResponseStatus> {
    await this.getData(credentialData);

    const evidenceData = getDataFromKey(this.credential, SD_CREDENTIAL_VALIDATORS_KEYS.evidence);
    const firstEvidence = Array.isArray(evidenceData) && evidenceData.length > 0 ? evidenceData[0] : null;

    // fallback for optional blockchain verification (No blockchain data found)
    if (!Object.keys(firstEvidence || {}).length) {
      return this.createResponse(Stages.dataIntegrityCheck, Messages.DATA_INTEGRITY_CHECK_SUCCESS, true, '');
    }

    if (isObjectEmpty(this.decodedData)) {
      return this.createResponse(Stages.dataIntegrityCheck, Messages.FETCHING_NORMALIZED_DECODED_DATA_ERROR, false, '');
    }

    // The local integrity checks need no network access, so they always run —
    // including verifyMerkleRootHash(), whose result verifyMerkleProof() depends on.
    const checks = [
      this.checkDecodedAnchors(),
      this.checkDecodedPath(),
      this.checkDecodedMerkleRoot(),
      this.checkDecodedTargetHash(),
      this.verifyMerkleRootHash()
    ];

    // The blockchain anchor lookup is the only step that requires an explorer/RPC
    // call, so it is the only one skipped for off-chain verification.
    if (!offChainVerification) {
      checks.push(this.fetchDataFromBlockchainAPI());
    } else {
      // fetchDataFromBlockchainAPI() is where networkName would normally be set, so
      // derive it here to keep reporting it when the lookup is skipped.
      this.networkName = this.resolveNetworkName();
    }

    const results = await Promise.all(checks);
    if (!results.every(check => check.status)) {
      return this.createResponse(Stages.dataIntegrityCheck, Messages.DATA_INTEGRITY_CHECK_FAILED, false, '');
    }

    const verificationStatus = (await this.verifyMerkleProof()).status;
    if (verificationStatus) {
      return this.createResponse(Stages.dataIntegrityCheck, Messages.DATA_INTEGRITY_CHECK_SUCCESS, true, this.networkName);
    }

    return this.createResponse(Stages.dataIntegrityCheck, Messages.DATA_INTEGRITY_CHECK_FAILED, false, this.networkName);
  }

  /**
   * This function verifies the integrity of data using a Merkle proof.
   * @returns an object with the following properties:
   * - message: A string indicating the result of the data integrity check.
   * - status: A boolean indicating whether the data integrity check was successful or not.
   * - networkName: A string indicating the name of the network.
   */
  private async verifyMerkleProof(): Promise<NetworkResponseStatus> {
    const normalizedData = getDataFromKey(
      this.normalizedDecodedData,
      CHECKSUM_MERKLEPROOF_CHECK_KEYS.get_byte_array_to_issue
    );
    const encodedHash = await this.calculateHash(normalizedData);

    if (this.isMerkleProofVerified && encodedHash === this.decodedData.targetHash) {
      this.progressCallback(Stages.verifyTargetHash, Messages.VALIDATE_TARGET_HASH, true, Messages.CALCULATED_HASH_MATCHES_WITH_TARGETHASH);
      return { message: Messages.DATA_INTEGRITY_CHECK_SUCCESS, status: true, networkName: this.networkName };
    } else {
      this.progressCallback(Stages.verifyTargetHash, Messages.VALIDATE_TARGET_HASH, false, Messages.CALCULATED_HASH_DIFFER_FROM_TARGETHASH);
      return { message: Messages.DATA_INTEGRITY_CHECK_FAILED, status: false, networkName: this.networkName };
    }
  }

  /**
   * The `getData` function retrieves and processes data based on the provided credential data.
   * @param {any} credentialData - The `credentialData` parameter is an object that contains data
   * related to a credential. It may have the following properties:
   */
  private async getData(credentialData: any): Promise<void> {
    this.credential = deepCloneData(credentialData);
    const evidenceData = getDataFromKey(this.credential, SD_CREDENTIAL_VALIDATORS_KEYS.evidence)[0];

    if (evidenceData?.type === ALGORITHM_TYPES.ED25519SIGNATURE2020 || Object.keys(evidenceData || {}).length) {
      this.normalizedDecodedData = await this.getNormalizedData();
      this.decodedData = getDataFromKey(
        this.normalizedDecodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.decoded_proof_value
      );
    } else {
      this.decodedData = {};
    }
  }

  /**
   * The function `getNormalizedData` returns an object with a stringified version of `this.credential`
   * and the `merkleProof` value from `this.credential.evidence[0]`.
   * @returns an object with two properties: "get_byte_array_to_issue" and "decoded_proof_value". The
   * value of "get_byte_array_to_issue" is a stringified JSON representation of the "dataToNormalize"
   * object, with the "evidence" property removed. The value of "decoded_proof_value" is the value of
   * "this.credential.evidence[0].merkleProof".
   */
  private async getNormalizedData() {
    const dataToNormalize = { ...this.credential };
    delete dataToNormalize.evidence;

    if(isKeyPresent(dataToNormalize, CHECKSUM_MERKLEPROOF_CHECK_KEYS.iat)) {
      delete dataToNormalize.iat;
    }

    const evidenceData = getDataFromKey(this.credential, SD_CREDENTIAL_VALIDATORS_KEYS.evidence)[0];

    return { get_byte_array_to_issue: JSON.stringify(dataToNormalize), decoded_proof_value: evidenceData };
  }

  /**
   * The function checks if the decoded anchors data is present and returns a status and message
   * accordingly.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private async checkDecodedAnchors(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.anchors
      )
    ) {
      const anchorsData = getDataFromKey(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.anchors
      );

      if (anchorsData?.length) {
        this.progressCallback(Stages.checkDecodedAnchors, Messages.ANCHOR_DECODED_DATA_KEY_VALIDATE, true, Messages.ANCHOR_DECODED_DATA_KEY_SUCCESS);
        return { message: Messages.ANCHOR_DECODED_DATA_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkDecodedAnchors, Messages.ANCHOR_DECODED_DATA_KEY_VALIDATE, false, Messages.ANCHOR_DECODED_DATA_KEY_ERROR);
    return { message: Messages.ANCHOR_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * The function `checkDecodedPath` checks if a specific key is present in the `decodedData` object and
   * returns a status and message accordingly.
   * @returns an object with two properties: "message" and "status". The "message" property is an empty
   * string if a certain condition is met, otherwise it is set to the value of
   * "Messages.PATH_DECODED_DATA_KEY_ERROR". The "status" property is set to true if the condition is
   * met, otherwise it is set to false.
   */
  private async checkDecodedPath(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.path
      )
    ) {
      this.progressCallback(Stages.checkDecodedPath, Messages.PATH_DECODED_DATA_KEY_VALIDATE, true, Messages.PATH_DECODED_DATA_KEY_SUCCESS);
      return { message: Messages.PATH_DECODED_DATA_KEY_SUCCESS, status: true };
    }

    this.progressCallback(Stages.checkDecodedPath, Messages.PATH_DECODED_DATA_KEY_VALIDATE, false, Messages.PATH_DECODED_DATA_KEY_ERROR);
    return { message: Messages.PATH_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * The function checks if a decoded merkle root is present and returns a message and status
   * indicating success or failure.
   * @returns a Promise that resolves to an object with two properties: "message" and "status". The
   * "message" property is a string and the "status" property is a boolean.
   */
  private async checkDecodedMerkleRoot(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.merkleRoot
      )
    ) {
      const merkleRootData = getDataFromKey(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.merkleRoot
      );
      if (merkleRootData?.length && typeof merkleRootData === 'string') {
        this.progressCallback(Stages.checkDecodedMerkleRoot, Messages.MERKLEROOT_DECODED_DATA_KEY_VALIDATE, true, Messages.MERKLEROOT_DECODED_DATA_KEY_SUCCESS);
        return { message: Messages.MERKLEROOT_DECODED_DATA_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkDecodedMerkleRoot, Messages.MERKLEROOT_DECODED_DATA_KEY_VALIDATE, false, Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR);
    return { message: Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * The function checks if the target hash is present in the decoded data and returns a status and
   * message accordingly.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private async checkDecodedTargetHash(): Promise<ResponseMessage> {
    if (
      isKeyPresent(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.targetHash
      )
    ) {
      const targetHashData = getDataFromKey(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.targetHash
      );
      if (targetHashData?.length && typeof targetHashData === 'string') {
        this.progressCallback(Stages.checkDecodedTargetHash, Messages.TARGETHASH_DECODED_DATA_KEY_VALIDATE, true, Messages.TARGETHASH_DECODED_DATA_KEY_SUCCESS);
        return { message: Messages.TARGETHASH_DECODED_DATA_KEY_SUCCESS, status: true };
      }
    }

    this.progressCallback(Stages.checkDecodedTargetHash, Messages.TARGETHASH_DECODED_DATA_KEY_VALIDATE, false, Messages.TARGETHASH_DECODED_DATA_KEY_ERROR);
    return { message: Messages.TARGETHASH_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * Derives the network name from the credential's anchor string. This is a purely
   * local lookup (anchor -> BASE_API + BASE_NETWORK), so it stays available when the
   * blockchain call is skipped for off-chain verification.
   * @returns The network name, or an empty string when the anchor cannot be resolved.
   */
  private resolveNetworkName(): string {
    const anchorParts = getDataFromKey(this.decodedData?.anchors, ['0'])?.split(':') || [];
    const blinkValue = getDataFromKey(anchorParts, ['1']);
    const networkType = getDataFromKey(anchorParts, ['2']);

    if (!blinkValue || !networkType) {
      return '';
    }

    const baseAPIValue = getDataFromKey(BASE_API, blinkValue);
    const baseNetworkValue = getDataFromKey(BASE_NETWORK, networkType);

    if (!baseAPIValue || !baseNetworkValue) {
      return '';
    }

    return `${baseAPIValue}${baseNetworkValue}`;
  }

  /**
   * The function fetchDataFromBlockchainAPI is an asynchronous function that fetches data from a
   * blockchain API and performs various error handling and logging operations.
   * @returns The function `fetchDataFromBlockchainAPI` returns a Promise that resolves to an object
   * with two properties: `message` and `status`.
   */
  private async fetchDataFromBlockchainAPI(): Promise<ResponseMessage> {
    // Fetching the selected anchor from decodedData
    const anchorParts = getDataFromKey(this.decodedData?.anchors, ['0'])?.split(':') || [];
    if (!anchorParts?.length) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.SELECTED_ANCHOR_RETRIEVAL_ERROR);
      return { message: Messages.SELECTED_ANCHOR_RETRIEVAL_ERROR, status: false };
    }

    // Extracting blinkValue, networkType, and transactionID from anchorParts
    const [blinkValue, networkType, transactionID] = [
      getDataFromKey(anchorParts, ['1']),
      getDataFromKey(anchorParts, ['2']),
      getDataFromKey(anchorParts, ['3'])
    ];

    if (!blinkValue || !networkType || !transactionID) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.REQUIRED_VALUES_RETRIEVAL_ERROR);
      return { message: Messages.REQUIRED_VALUES_RETRIEVAL_ERROR, status: false };
    }

    // Retrieving baseAPIValue and baseNetworkValue using blinkValue and networkType
    const baseAPIValue = getDataFromKey(BASE_API, blinkValue);
    const baseNetworkValue = getDataFromKey(BASE_NETWORK, networkType);

    if (!baseAPIValue || !baseNetworkValue) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.BASE_API_OR_NETWORK_RETRIEVAL_ERROR);
      return { message: Messages.BASE_API_OR_NETWORK_RETRIEVAL_ERROR, status: false };
    }

    this.networkName = `${baseAPIValue}${baseNetworkValue}`;

    // Finding the matchedAPI based on baseAPIValue and baseNetworkValue
    const matchedAPI = BLOCKCHAIN_API_LIST.find(api => api.id === this.networkName);

    if (!matchedAPI) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.NO_MATCHING_API_FOUND_ERROR);
      return { message: Messages.NO_MATCHING_API_FOUND_ERROR, status: false };
    }

    // Retrieving the URL from the matched API and the API key from the runtime config.
    // Keys are never bundled — the consumer supplies them via config.blockchainApiKeys.
    const url = matchedAPI.url;
    const apiKey = matchedAPI.provider ? this.config?.blockchainApiKeys?.[matchedAPI.provider] : undefined;

    // An API key is required only for explorer-backed networks (those with a provider).
    // RPC-node networks have no provider and therefore need no key.
    const requiresApiKey = Boolean(matchedAPI.provider);

    if (!url || (requiresApiKey && !apiKey)) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.URL_OR_APIKEY_RETRIEVAL_ERROR);
      return { message: Messages.URL_OR_APIKEY_RETRIEVAL_ERROR, status: false };
    }


    try {
      // RPC-node networks (matchedAPI.rpc === true) are queried over web3.js JSON-RPC (HTTP POST);
      // explorer-backed networks use the REST API (HTTP GET) via the built finalUrl.
      if (matchedAPI.rpc) {
        // Fetching data using the RPC URL using WEB3 js
        const web3 = new Web3(new Web3.providers.HttpProvider(`${matchedAPI.url}`));
        this.blockchainApiResponse = await web3.eth.getTransaction(transactionID);
      } else {
        // Building the final URL using buildTransactionUrl method
        const finalUrl = await this.buildTransactionUrl(url, apiKey ?? '', transactionID, matchedAPI.chainId);

        // Fetching data from the API using finalUrl
        this.blockchainApiResponse = await getDataFromAPI(finalUrl);
      }
    } catch (error) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.TRANSACTION_NOT_FOUND_ERROR);
      return { message: Messages.TRANSACTION_NOT_FOUND_ERROR, status: false };
    }

    // Explorer APIs (Etherscan/Polygonscan) reply HTTP 200 with { status: "0", message: "NOTOK", result }
    // on failure (invalid/expired key, rate limit, deprecated endpoint, etc.). A non-empty body is NOT
    // proof of success, so detect and reject the error envelope explicitly.
    const apiError = this.isBlockchainApiError(this.blockchainApiResponse);
    if (apiError) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, apiError);
      return { message: apiError, status: false };
    }

    if (!isEmpty(this.blockchainApiResponse)) {
      this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, true, Messages.DATA_FETCHED_SUCCESS);
      return { message: Messages.DATA_FETCHED_SUCCESS, status: true };
    }

    this.progressCallback(Stages.fetchDataFromBlockchainAPI, Messages.BLOCKCHAIN_DATA_VALIDATE, false, Messages.DATA_FETCHED_ERROR);
    return { message: Messages.DATA_FETCHED_ERROR, status: false };
  }

  /**
   * Detects an explorer-API error envelope ({ status: "0" } or { message: "NOTOK" }).
   * @param response - The raw response returned by the blockchain explorer API.
   * @returns A human-readable error reason when the response is an error envelope, otherwise null.
   */
  private isBlockchainApiError(response: any): string | null {
    if (!response || typeof response !== 'object') {
      return null;
    }
    const isError = `${response.status}` === '0' || response.message === 'NOTOK';
    if (!isError) {
      return null;
    }
    // Prefer the explorer's own message (e.g. "deprecated V1 endpoint") when present.
    const detail = typeof response.result === 'string' ? response.result : '';
    return detail ? `${Messages.BLOCKCHAIN_API_ERROR_RESPONSE} ${detail}` : Messages.BLOCKCHAIN_API_ERROR_RESPONSE;
  }

  /**
   * The function `verifyMerkleProof` takes in decoded data and verifies the Merkle proof by calculating
   * the hash and comparing it with the Merkle root.
   * @param {any} decodedData - The `decodedData` parameter is an object that contains the following
   * properties:
   * @returns The function `verifyMerkleProof` returns an object with two properties: `message` and
   * `status`. The `message` property contains a string message indicating whether the calculated hash
   * matches with the merkle root or not. The `status` property is a boolean value indicating whether the
   * merkle proof is verified or not.
   */
  private async verifyMerkleRootHash(): Promise<ResponseMessage> {
    const targetHash = getDataFromKey(
      this.decodedData,
      CHECKSUM_MERKLEPROOF_CHECK_KEYS.targetHash
    );
    const merkleRoot = getDataFromKey(
      this.decodedData,
      CHECKSUM_MERKLEPROOF_CHECK_KEYS.merkleRoot
    );
    const path = getDataFromKey(
      this.decodedData,
      CHECKSUM_MERKLEPROOF_CHECK_KEYS.path
    );

    if (!targetHash?.length || !merkleRoot?.length) {
      this.isMerkleProofVerified = false;
      this.progressCallback(Stages.verifyMerkleProof, Messages.MERKLE_PROOF_VALIDATE, false, Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR);
      return { message: Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR, status: this.isMerkleProofVerified };
    }

    let currentHash = targetHash;

    for (const proofElement of path) {
      if (proofElement?.left) {
        const concatenatedHash = proofElement?.left + currentHash;
        const buffer = Buffer.from(concatenatedHash, BUFFER_ENCODING_TYPE);
        currentHash = await this.calculateHash(buffer);
      } else if (proofElement?.right) {
        const concatenatedHash = currentHash + proofElement?.right;
        const buffer = Buffer.from(concatenatedHash, BUFFER_ENCODING_TYPE);
        currentHash = await this.calculateHash(buffer);
      }
    }

    this.isMerkleProofVerified = currentHash === merkleRoot;

    if (!this.isMerkleProofVerified) {
      this.progressCallback(Stages.verifyMerkleProof, Messages.MERKLE_PROOF_VALIDATE, false, Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT);
      logger(Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT, "error");
    }

    this.progressCallback(
      Stages.verifyMerkleProof,
      Messages.MERKLE_PROOF_VALIDATE,
      this.isMerkleProofVerified,
      this.isMerkleProofVerified
        ? Messages.CALCULATED_HASH_MATCHES_WITH_MERKLEROOT
        : Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT
    );
    return {
      message: this.isMerkleProofVerified
        ? Messages.CALCULATED_HASH_MATCHES_WITH_MERKLEROOT
        : Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT,
      status: this.isMerkleProofVerified
    };
  }

  /**
   * The function builds a transaction URL by concatenating the base URL, endpoint, and query parameters.
   * @param {string} url - The `url` parameter is the base URL of the API endpoint you want to call. It
   * should be a string representing the URL of the API server.
   * @param {string} apiKey - The `apiKey` parameter is a string that represents the API key required to
   * access the API endpoint. This key is used to authenticate the user and ensure that only authorized
   * users can access the endpoint.
   * @param {string} transactionID - The `transactionID` parameter is a string that represents the hash
   * of a transaction in the Ethereum blockchain.
   * @returns a string that represents the complete transaction URL.
   */
  private async buildTransactionUrl(url: string, apiKey: string, transactionID: string, chainid: number): Promise<string> {
    const endpoint = "api?module=proxy&action=eth_getTransactionByHash";
    const queryParams = `&apikey=${apiKey}&txhash=${transactionID}&chainid=${chainid}`;

    return `${url}${endpoint}${queryParams}`;
  }

  /**
   * The function calculates the SHA256 hash of a given buffer of data.
   * @param {Buffer} data - The `data` parameter is of type `Buffer`, which is a binary data buffer. It
   * is the input data for which you want to calculate the hash.
   * @returns The calculateHash function returns a Promise that resolves to a string.
   */
  private async calculateHash(data: Buffer): Promise<string> {
    return sha256(data);
  }

  /**
 * The function creates a response object with a message, status, and network name, and calls a
 * progress callback function.
 * @param {Stages} stage - The stage parameter is of type Stages. It represents the current stage of
 * the process.
 * @param {string} message - A string that represents the response message.
 * @param {boolean} status - The `status` parameter is a boolean value indicating the success or
 * failure of the operation.
 * @param {string} networkName - The `networkName` parameter is a string that represents the name of
 * the network. It is used as a property in the returned object.
 * @returns an object with three properties: "message" (string), "status" (boolean), and "networkName"
 * (string).
 */
  private createResponse(stage: Stages, message: string, status: boolean, networkName: string): CreateResponse {
    this.progressCallback(stage, message, status, status ? Messages.DATA_INTEGRITY_CHECK_SUCCESS : Messages.DATA_INTEGRITY_CHECK_FAILED);
    return { message, status, networkName };
  }
}