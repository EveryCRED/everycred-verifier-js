import { Buffer } from 'buffer';
import { isEmpty } from 'lodash';
import sha256 from 'sha256';
import { BASE_API, BASE_NETWORK, BLOCKCHAIN_API_LIST, CHECKSUM_MERKLEPROOF_CHECK_KEYS, GENERAL_KEYWORDS, HTTP_METHODS, MERKLE_TREE } from '../constants/common';
import { Messages } from '../constants/messages';
import { MERKLE_TREE_VALIDATION_API_URL } from '../utils/config';
import { deepCloneData, getDataFromAPI, getDataFromKey, isKeyPresent } from '../utils/credential-util';
import { logger } from '../utils/logger';
import { sleep } from '../utils/sleep';

export class MerkleProofValidator2019 {
  private credential: any;
  private decodedData: any;
  private normalizedDecodedData: any;
  private blockchainApiResponse: any;
  private isMerkleProofVerified: boolean = false;
  networkName: string = '';

  constructor(private progressCallback: (step: string, status: boolean) => void) { }

  /**
   * The `validate` function performs various checks and validations on a given credential data and
   * returns a status and message indicating whether the validation was successful or not.
   * @param {any} credentialData - The `credentialData` parameter is an object that contains the data
   * needed for validation. It is passed to the `validate` function as an argument.
   * @returns an object with the properties `message`, `status`, and `networkName`.
   */
  async validate(credentialData: any): Promise<{ message: string; status: boolean; networkName: string; }> {
    this.credential = deepCloneData(credentialData);
    this.normalizedDecodedData = await this.getNormalizedDecodedData();
    this.decodedData = getDataFromKey(
      this.normalizedDecodedData,
      CHECKSUM_MERKLEPROOF_CHECK_KEYS.decoded_proof_value
    );

    if (
      (await this.checkDecodedAnchors()).status &&
      (await this.checkDecodedPath()).status &&
      (await this.checkDecodedMerkleRoot()).status &&
      (await this.checkDecodedTargetHash()).status &&
      (await this.fetchDataFromBlockchainAPI()).status &&
      (await this.verifyMerkleProof(this.decodedData)).status
    ) {
      const normalizedData = getDataFromKey(
        this.normalizedDecodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.get_byte_array_to_issue
      );
      const encodedHash = await this.calculateHash(normalizedData);

      if (this.isMerkleProofVerified && encodedHash === this.decodedData.targetHash) {
        this.progressCallback(Messages.CHECKING_HOLDER, true);
        return { message: '', status: true, networkName: this.networkName };
      } else {
        this.progressCallback(Messages.CHECKING_HOLDER, false);
        logger(Messages.CALCULATED_HASH_DIFFER_FROM_TARGETHASH, "error");
        logger(Messages.MERKLE_PROOF_2019_VALIDATION_FAILED, "error");
        return { message: Messages.MERKLE_PROOF_2019_VALIDATION_FAILED, status: false, networkName: '' };
      }
    }

    logger(Messages.MERKLE_PROOF_2019_VALIDATION_FAILED, "error");
    return { message: Messages.MERKLE_PROOF_2019_VALIDATION_FAILED, status: false, networkName: '' };
  }

  /**
   * The function validates the normalized decoded data and returns a status and message.
   * @param {any} response - The `response` parameter is an object that contains data received from an
   * API or some other source.
   * @returns an object with two properties: "message" and "status". The "message" property contains a
   * string value, and the "status" property contains a boolean value.
   */
  private validateNormalizedDecodedData(response: any): { message: string; status: boolean; } {
    if (
      !isKeyPresent(response, CHECKSUM_MERKLEPROOF_CHECK_KEYS.decoded_proof_value) &&
      !isKeyPresent(response, CHECKSUM_MERKLEPROOF_CHECK_KEYS.get_byte_array_to_issue)
    ) {
      this.failedAllStages();
      logger(Messages.FETCHING_NORMALIZED_DECODED_DATA_ERROR, "error");
      return { message: Messages.FETCHING_NORMALIZED_DECODED_DATA_ERROR, status: false };
    }

    return { message: '', status: true };
  }

  /**
   * The function `getNormalizedDecodedData` sends a POST request to an API with a JSON payload,
   * retrieves the response, validates it, and returns the response if it is valid.
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

    try {
      const apiResponse = (await getDataFromAPI(apiUrl, options))?.data;
      const isValidResponse = this.validateNormalizedDecodedData(apiResponse).status;

      if (isValidResponse) {
        return apiResponse;
      }
    } catch (error) {
      this.failedAllStages();
    }
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
  private async verifyMerkleProof(decodedData: any): Promise<{ message: string; status: boolean; }> {
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

    if (!this.isMerkleProofVerified) {
      this.progressCallback(Messages.CHECKING_HOLDER, false);
      logger(Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT, "error");
    }

    return {
      message: this.isMerkleProofVerified
        ? Messages.CALCULATED_HASH_MATCHES_WITH_MERKLEROOT
        : Messages.CALCULATED_HASH_DIFFER_FROM_MERKLEROOT,
      status: this.isMerkleProofVerified
    };
  }

  /**
   * The function checks if the decoded anchors data is present and returns a status and message
   * accordingly.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private async checkDecodedAnchors(): Promise<{ message: string; status: boolean; }> {
    await sleep(250);

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
        this.progressCallback(Messages.FORMAT_VALIDATION, true);
        return { message: '', status: true };
      }
    }

    this.failedAllStages();
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
  private async checkDecodedPath(): Promise<{ message: string; status: boolean; }> {
    await sleep(500);

    if (
      isKeyPresent(
        this.decodedData,
        CHECKSUM_MERKLEPROOF_CHECK_KEYS.path
      )
    ) {
      return { message: '', status: true };
    }

    this.failedThreeStages();
    logger(Messages.PATH_DECODED_DATA_KEY_ERROR, "error");
    return { message: Messages.PATH_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * The function checks if a decoded merkle root is present and returns a message and status
   * indicating success or failure.
   * @returns a Promise that resolves to an object with two properties: "message" and "status". The
   * "message" property is a string and the "status" property is a boolean.
   */
  private async checkDecodedMerkleRoot(): Promise<{ message: string; status: boolean; }> {
    await sleep(750);

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
        this.progressCallback(Messages.COMPARING_HASHES, true);
        return { message: '', status: true };
      }
    }

    this.failedThreeStages();
    logger(Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR, "error");
    return { message: Messages.MERKLEROOT_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * The function checks if the target hash is present in the decoded data and returns a status and
   * message accordingly.
   * @returns an object with two properties: "message" and "status". The "message" property is a string
   * and the "status" property is a boolean.
   */
  private async checkDecodedTargetHash(): Promise<{ message: string; status: boolean; }> {
    await sleep(1000);

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
        return { message: '', status: true };
      }
    }

    this.failedTwoStages();
    logger(Messages.TARGETHASH_DECODED_DATA_KEY_ERROR, "error");
    return { message: Messages.TARGETHASH_DECODED_DATA_KEY_ERROR, status: false };
  }

  /**
   * The function fetchDataFromBlockchainAPI is an asynchronous function that fetches data from a
   * blockchain API and performs various error handling and logging operations.
   * @returns The function `fetchDataFromBlockchainAPI` returns a Promise that resolves to an object
   * with two properties: `message` and `status`.
   */
  private async fetchDataFromBlockchainAPI(): Promise<{ message: string; status: boolean; }> {
    // Fetching the selected anchor from decodedData
    const selectedAnchor = getDataFromKey(this.decodedData?.anchors, ['0'])?.split(':');
    if (!selectedAnchor) {
      // Logging an error when selectedAnchor retrieval fails
      this.failedTwoStages();
      logger(Messages.SELECTED_ANCHOR_RETRIEVAL_ERROR, "error");
      return { message: Messages.SELECTED_ANCHOR_RETRIEVAL_ERROR, status: false };
    }

    // Extracting blinkValue, networkType, and transactionID from selectedAnchor
    const [blinkValue, networkType, transactionID] = [
      getDataFromKey(selectedAnchor, ['1']),
      getDataFromKey(selectedAnchor, ['2']),
      getDataFromKey(selectedAnchor, ['3'])
    ];

    if (!blinkValue || !networkType || !transactionID) {
      // Logging an error when required values retrieval fails
      this.failedTwoStages();
      logger(Messages.REQUIRED_VALUES_RETRIEVAL_ERROR, "error");
      return { message: Messages.REQUIRED_VALUES_RETRIEVAL_ERROR, status: false };
    }

    // Retrieving baseAPIValue and baseNetworkValue using blinkValue and networkType
    const baseAPIValue = getDataFromKey(BASE_API, blinkValue);
    const baseNetworkValue = getDataFromKey(BASE_NETWORK, networkType);

    if (!baseAPIValue || !baseNetworkValue) {
      // Logging an error when baseAPIValue or baseNetworkValue retrieval fails
      this.failedTwoStages();
      logger(Messages.BASE_API_OR_NETWORK_RETRIEVAL_ERROR, "error");
      return { message: Messages.BASE_API_OR_NETWORK_RETRIEVAL_ERROR, status: false };
    }

    this.networkName = `${baseAPIValue}${baseNetworkValue}`;

    // Finding the matchedAPI based on baseAPIValue and baseNetworkValue
    const matchedAPI = BLOCKCHAIN_API_LIST.find(api => api.id === `${baseAPIValue}${baseNetworkValue}`);

    if (!matchedAPI) {
      // Logging an error when no matching API is found
      this.failedTwoStages();
      logger(Messages.NO_MATCHING_API_FOUND_ERROR, "error");
      return { message: Messages.NO_MATCHING_API_FOUND_ERROR, status: false };
    }

    // Retrieving the URL and apiKey from matchedAPI
    const url = getDataFromKey(matchedAPI, GENERAL_KEYWORDS.url);
    const apiKey = getDataFromKey(matchedAPI, GENERAL_KEYWORDS.apiKey);

    if (!url || !apiKey) {
      // Logging an error when URL or apiKey retrieval fails
      this.failedTwoStages();
      logger(Messages.URL_OR_APIKEY_RETRIEVAL_ERROR, "error");
      return { message: Messages.URL_OR_APIKEY_RETRIEVAL_ERROR, status: false };
    }

    // Building the final URL using buildTransactionUrl method
    const finalUrl = await this.buildTransactionUrl(url, apiKey, transactionID);

    try {
      // Fetching data from the API using finalUrl
      this.blockchainApiResponse = await getDataFromAPI(finalUrl);
    } catch (error) {
      // Logging an error when the transaction is not found
      this.failedTwoStages();
      logger(Messages.TRANSACTION_NOT_FOUND_ERROR, "error");
      return { message: Messages.TRANSACTION_NOT_FOUND_ERROR, status: false };
    }

    if (!isEmpty(this.blockchainApiResponse)) {
      this.progressCallback(Messages.COMPARING_MERKLE_ROOT, true);
      return { message: '', status: true };
    }

    // Logging an error when data fetch fails
    this.failedTwoStages();
    logger(Messages.DATA_FETCHED_ERROR, "error");
    return { message: Messages.DATA_FETCHED_ERROR, status: false };
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
  private async buildTransactionUrl(url: string, apiKey: string, transactionID: string): Promise<string> {
    const endpoint = "api?module=proxy&action=eth_getTransactionByHash";
    const queryParams = `&apikey=${apiKey}&txhash=${transactionID}`;

    return `${url}${endpoint}${queryParams}`;
  }

  /**
   * The function calculates the SHA256 hash of the given data.
   * @param {any} data - The `data` parameter is the input data for which you want to calculate the hash.
   * It can be of any type, such as a string, number, object, or array.
   * @returns The calculateHash function is returning the result of the sha256 function, which is the
   * hash value of the input data.
   */
  private async calculateHash(data: any) {
    return sha256(data);
  }

  /**  The below code is defining a series of private methods in a TypeScript class.
   * Each method calls a `progressCallback` function with a specific message and a `false` value.
   * The `progressCallback` function is likely used to update the progress of some operation or task. The methods are called in a cascading manner, with each method calling the next one in the sequence.
  */
  private failedAllStages() {
    this.progressCallback(Messages.FORMAT_VALIDATION, false);
    this.failedThreeStages();
  }

  private failedThreeStages() {
    this.progressCallback(Messages.COMPARING_HASHES, false);
    this.failedTwoStages();
  }

  private failedTwoStages() {
    this.progressCallback(Messages.COMPARING_MERKLE_ROOT, false);
    this.progressCallback(Messages.CHECKING_HOLDER, false);
  }

}