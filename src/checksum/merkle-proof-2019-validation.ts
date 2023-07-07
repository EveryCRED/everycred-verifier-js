import { Buffer } from 'buffer';
import { isEmpty } from 'lodash';
import sha256 from 'sha256';
import { BASE_API, BASE_NETWORK, BLOCKCHAIN_API_LIST, CHECKSUM_MERKLEPROOF_CHECK_KEYS, GENERAL_KEYWORDS, HTTP_METHODS, MERKLE_TREE } from '../constants/common';
import { Messages } from '../constants/messages';
import { MERKLE_TREE_VALIDATION_API_URL } from '../utils/config';
import { deepCloneData, getDataFromAPI, getDataFromKey, isKeyPresent } from '../utils/credential-util';
import { logger } from '../utils/logger';

export class MerkleProofValidator2019 {
  private credential: any;
  private decodedData: any;
  private normalizedDecodedData: any;
  private blockchainApiResponse: any;
  private isMerkleProofVerified: boolean = false;

  constructor() { }

  /**
   * The `validate` function performs a series of checks and validations on a given credential data
   * using a Merkle proof algorithm and returns a boolean indicating whether the validation was
   * successful or not.
   * @param {any} credentialData - The `credentialData` parameter is an object that contains the data
   * needed for validating a Merkle proof. It is used to perform various checks and calculations to
   * determine if the Merkle proof is valid.
   * @returns The function `validate` returns a Promise that resolves to a boolean value.
   */
  async validate(credentialData: any): Promise<boolean> {
    logger(Messages.MERKLE_PROOF_2019_VALIDATION_STARTED);
    this.credential = deepCloneData(credentialData);
    this.normalizedDecodedData = await this.getNormalizedDecodedData();
    this.decodedData = getDataFromKey(
      this.normalizedDecodedData,
      CHECKSUM_MERKLEPROOF_CHECK_KEYS.decoded_proof_value
    );

    const isSignatureValid = (
      this.checkDecodedAnchors() &&
      this.checkDecodedPath() &&
      this.checkDecodedMerkleRoot() &&
      this.checkDecodedTargetHash()
    );

    if (
      isSignatureValid &&
      (await this.fetchDataFromBlockchainAPI()) &&
      (await this.verifyMerkleProof(this.decodedData))
    ) {
      const normalizedData = getDataFromKey(
        this.normalizedDecodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.get_byte_array_to_issue
      );
      const encodedHash = await this.calculateHash(normalizedData);

      if (this.isMerkleProofVerified && encodedHash === this.decodedData.targetHash) {
        logger(Messages.CALCULATED_HASH_MATCHES_WITH_TARGETHASH);
        logger(Messages.MERKLE_PROOF_2019_VALIDATION_SUCCESS);
        return true;
      } else {
        logger(Messages.CALCULATED_HASH_DIFFER_FROM_TARGETHASH, "error");
        logger(Messages.MERKLE_PROOF_2019_VALIDATION_FAILED, "error");
        return false;
      }
    }

    logger(Messages.MERKLE_PROOF_2019_VALIDATION_FAILED, "error");
    return false;
  }

  /**
   * The function validates the normalized decoded data by checking if certain keys are present in the
   * response object.
   * @param {any} response - The `response` parameter is an object that contains the data received from
   * an API or any other source.
   * @returns a boolean value.
   */
  private validateNormalizedDecodedData(response: any): boolean {
    logger(Messages.FETCHING_NORMALIZED_DECODED_DATA);
    if (
      !isKeyPresent(response, CHECKSUM_MERKLEPROOF_CHECK_KEYS.decoded_proof_value) &&
      !isKeyPresent(response, CHECKSUM_MERKLEPROOF_CHECK_KEYS.get_byte_array_to_issue)
    ) {
      logger(Messages.FETCHING_NORMALIZED_DECODED_DATA_ERROR);
      return false;
    }

    logger(Messages.FETCHING_NORMALIZED_DECODED_DATA_SUCCESS);
    return true;
  }

  /**
   * The function sends a POST request to an API with a JSON payload, validates the response, and
   * returns the response if it is valid.
   * @returns a Promise that resolves to an object of type `any`.
   */
  private async getNormalizedDecodedData(): Promise<any> {
    const apiUrl = `${MERKLE_TREE_VALIDATION_API_URL}${MERKLE_TREE.validation_api}${MERKLE_TREE.data_type}`;
    const formData = new FormData();
    const blob = new Blob([JSON.stringify(this.credential)], { type: 'application/json' });
    formData.append('body', blob);

    const options = {
      method: HTTP_METHODS.POST,
      headers: {
        Accept: 'application/json',
      },
      body: formData,
    };

    const response = await getDataFromAPI(apiUrl, options);
    const isValidResponse = this.validateNormalizedDecodedData(response);

    if (isValidResponse) {
      return response;
    }
  }

  /**
   * The function verifies a Merkle proof by calculating the hash of a target hash and a series of proof
   * elements, and checking if the resulting hash matches the Merkle root.
   * @param {any} decodedData - The `decodedData` parameter is an object that contains the following
   * properties:
   * @param {string} target_hash - The target_hash parameter is a string representing the hash of the
   * target data that you want to verify in the Merkle tree.
   * @param {string[]} proof - An array of strings representing the proof path in the Merkle tree. Each
   * element in the array represents a sibling node in the path, starting from the leaf node and ending
   * at the root node.
   * @param {string} merkle_root - The `merkle_root` parameter is a string representing the root hash of
   * the Merkle tree. It is the topmost hash in the tree and serves as a summary of all the data in the
   * tree.
   * @returns a Promise that resolves to a boolean value.
   */
  private async verifyMerkleProof(decodedData: any): Promise<boolean> {
    const { targetHash, path, merkleRoot } = decodedData;
    let currentHash = targetHash;

    for (const proofElement of path) {
      if (proofElement.left) {
        const concatenatedHash = proofElement.left + currentHash;
        const buffer = Buffer.from(concatenatedHash, 'hex');
        currentHash = await this.calculateHash(buffer);
      } else if (proofElement.right) {
        const concatenatedHash = currentHash + proofElement.right;
        const buffer = Buffer.from(concatenatedHash, 'hex');
        currentHash = await this.calculateHash(buffer);
      }
    }

    this.isMerkleProofVerified = currentHash === merkleRoot;
    logger(
      this.isMerkleProofVerified
        ? Messages.CALCULATED_HASH_MATCHES_WITH_MERKLEROOT
        : Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT,
      this.isMerkleProofVerified ? "log" : "error"
    );

    return this.isMerkleProofVerified;
  }

  /**
   * Checks if a specific key is present in the `decodedData` object and returns true if it is,
   * otherwise returns false.
   * @returns {boolean} - A boolean value indicating the presence of the key.
   * If the condition `pathData?.length` is true, it returns `true`. Otherwise, it returns `false`.
   */
  private checkDecodedAnchors(): boolean {
    logger(Messages.ANCHOR_DECODED_DATA_KEY_VALIDATE);
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
        logger(Messages.ANCHOR_DECODED_DATA_KEY_SUCCESS);
        return true;
      }
    }
    logger(Messages.ANCHOR_DECODED_DATA_KEY_ERROR, "error");
    return false;
  }

  /**
   * The function checks if a specific key is present in the `decodedData` object
   * and returns true if it is, otherwise it returns false.
   * @returns a boolean value. If the condition `pathData?.length` is true, it returns `true`. Otherwise,
   * it returns `false`.
   */
  private checkDecodedPath(): boolean {
    logger(Messages.PATH_DECODED_DATA_KEY_VALIDATE);
    if (
      isKeyPresent(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.path
      )
    ) {
      logger(Messages.PATH_DECODED_DATA_KEY_SUCCESS);
      return true;
    }
    logger(Messages.PATH_DECODED_DATA_KEY_ERROR, "error");
    return false;
  }

  /**
   * The function checks if a merkle root signature is present in the decoded data and returns true if
   * it is, otherwise it returns false.
   * @returns a boolean value. If the condition `merkleRootData?.length && typeof merkleRootData ===
   * 'string'` is true, it returns `true`. Otherwise, it returns `false`.
   */
  private checkDecodedMerkleRoot(): boolean {
    logger(Messages.MERKLEROOT_DECODED_DATA_KEY_VALIDATE);
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
        logger(Messages.MERKLEROOT_DECODED_DATA_KEY_SUCCESS);
        return true;
      }
    }
    logger(Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR, "error");
    return false;
  }

  /**
   * The function checks if a target hash is present in the decoded data and returns true if it is,
   * otherwise it returns false.
   * @returns a boolean value. If the condition `targetHashData?.length && typeof targetHashData ===
   * 'string'` is true, it will return `true`. Otherwise, it will return `false`.
   */
  private checkDecodedTargetHash(): boolean {
    logger(Messages.TARGETHASH_DECODED_DATA_KEY_VALIDATE);
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
        logger(Messages.TARGETHASH_DECODED_DATA_KEY_SUCCESS);
        return true;
      }
    }
    logger(Messages.TARGETHASH_DECODED_DATA_KEY_ERROR, "error");
    return false;
  }

  /**
   * The function `getHashFromBlockchain` retrieves a transaction hash from a blockchain API and
   * returns a boolean indicating whether the retrieval was successful.
   * @returns a boolean value.
   */
  private async fetchDataFromBlockchainAPI(): Promise<boolean> {
    // Fetching the selected anchor from decodedData
    const selectedAnchor = getDataFromKey(this.decodedData?.anchors, ['0'])?.split(':');
    if (!selectedAnchor) {
      // Logging an error when selectedAnchor retrieval fails
      logger(Messages.SELECTED_ANCHOR_RETRIEVAL_ERROR, "error");
      return false;
    }

    // Extracting blinkValue, networkType, and transactionID from selectedAnchor
    const [blinkValue, networkType, transactionID] = [
      getDataFromKey(selectedAnchor, ['1']),
      getDataFromKey(selectedAnchor, ['2']),
      getDataFromKey(selectedAnchor, ['3'])
    ];

    if (!blinkValue || !networkType || !transactionID) {
      // Logging an error when required values retrieval fails
      logger(Messages.REQUIRED_VALUES_RETRIEVAL_ERROR, "error");
      return false;
    }

    // Retrieving baseAPIValue and baseNetworkValue using blinkValue and networkType
    const baseAPIValue = getDataFromKey(BASE_API, blinkValue);
    const baseNetworkValue = getDataFromKey(BASE_NETWORK, networkType);

    if (!baseAPIValue || !baseNetworkValue) {
      // Logging an error when baseAPIValue or baseNetworkValue retrieval fails
      logger(Messages.BASE_API_OR_NETWORK_RETRIEVAL_ERROR, "error");
      return false;
    }

    // Finding the matchedAPI based on baseAPIValue and baseNetworkValue
    const matchedAPI = BLOCKCHAIN_API_LIST.find(api => api.id === `${baseAPIValue}${baseNetworkValue}`);

    if (!matchedAPI) {
      // Logging an error when no matching API is found
      logger(Messages.NO_MATCHING_API_FOUND_ERROR, "error");
      return false;
    }

    // Retrieving the URL and apiKey from matchedAPI
    const url = getDataFromKey(matchedAPI, GENERAL_KEYWORDS.url);
    const apiKey = getDataFromKey(matchedAPI, GENERAL_KEYWORDS.apiKey);

    if (!url || !apiKey) {
      // Logging an error when URL or apiKey retrieval fails
      logger(Messages.URL_OR_APIKEY_RETRIEVAL_ERROR, "error");
      return false;
    }

    // Building the final URL using buildTransactionUrl method
    const finalUrl = await this.buildTransactionUrl(url, apiKey, transactionID);

    try {
      // Fetching data from the API using finalUrl
      this.blockchainApiResponse = await getDataFromAPI(finalUrl);
    } catch (error) {
      // Logging an error when the transaction is not found
      logger(Messages.TRANSACTION_NOT_FOUND_ERROR, "error");
      return false;
    }

    if (!isEmpty(this.blockchainApiResponse)) {
      // Logging success message when data is fetched successfully
      logger(Messages.DATA_FETCHED_SUCCESS);
      return true;
    }

    // Logging an error when data fetch fails
    logger(Messages.DATA_FETCHED_ERROR, "error");
    return false;
  }

  /**
   * The function builds a transaction URL by concatenating the base URL, endpoint, and query parameters.
   * @param {string} url - The `url` parameter is a string representing the base URL of the API endpoint
   * you want to call. It should include the protocol (e.g., "https://") and the domain name (e.g.,
   * "api.example.com").
   * @param {string} apiKey - The `apiKey` parameter is a string that represents the API key required to
   * access the API endpoint. It is used to authenticate the user and ensure that only authorized users
   * can access the endpoint.
   * @param {string} transactionID - The `transactionID` parameter is a string that represents the hash
   * of a transaction in the Ethereum blockchain.
   * @returns a string that represents a transaction URL.
   */
  private async buildTransactionUrl(url: string, apiKey: string, transactionID: string): Promise<string> {
    const endpoint = "api?module=proxy&action=eth_getTransactionByHash";
    const queryParams = `&apikey=${apiKey}&txhash=${transactionID}`;

    return `${url}${endpoint}${queryParams}`;
  }

  /**
   * The function calculates the SHA256 hash of a given string asynchronously.
   * @param {string} data - The `data` parameter is a string that represents the input data for which you
   * want to calculate the hash.
   * @returns The calculateHash function is returning the SHA256 hash of the input data.
   */
  private async calculateHash(data: any) {
    return sha256(data);
  }

}