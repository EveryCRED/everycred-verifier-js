import { Messages } from "../constants/messages";
import { Stages } from "../constants/stages";
import { base64UrlDecode, base64UrlToArrayBuffer, extractAndNormalizeJwt } from "../utils/jwt-utils";


export class SignatureValidator {

    constructor(private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void) { }

    async validate(jwtToken: string, header: Record<string, unknown>): Promise<{ status: boolean, message: string }> {
        const normalizedJwt = extractAndNormalizeJwt(jwtToken);
        if (!normalizedJwt) {
            this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, 'Invalid JWT token');
            return { status: false, message: 'Invalid JWT token' };
        }
        const publicKeyPem = this.getPublicKeyFromJwtHeader(header);
        if (!publicKeyPem) {
            this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, 'Missing public key in JWT header');
            return { status: false, message: 'Missing public key in JWT header' };
        }

        const verifyWithWebCryptoResult = await this.verifyWithWebCrypto(normalizedJwt, publicKeyPem);
        if (!verifyWithWebCryptoResult.status) {
            this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, verifyWithWebCryptoResult.message);
            return { status: false, message: verifyWithWebCryptoResult.message };
        }
        this.progressCallback(Stages.verification, Messages.VERIFICATION_SUCCESS, true, Messages.VERIFICATION_SUCCESS);
        return { status: true, message: Messages.VERIFICATION_SUCCESS };
    }

    /**
     * Extract the public key from the JWT header's kid field
     * The kid contains a DID with the public key embedded after the # symbol
     * @param {any} header - JWT header object
     * @returns {string} Public key in PEM format
     */
    getPublicKeyFromJwtHeader(header: Record<string, unknown>): string {
        if (!header || typeof header !== 'object' || !('kid' in header)) {
            throw new Error('Missing kid in JWT header');
        }

        const kid = header['kid'] as string;

        // Extract the part after # which contains the public key
        const hashIndex = kid.indexOf('#');
        if (hashIndex === -1) {
            throw new Error('Invalid kid format: missing # separator');
        }

        // Get the public key part (everything after #)
        const publicKeyPart = kid.substring(hashIndex + 1);

        // Replace \n with actual newlines to get proper PEM format
        const publicKeyPem = publicKeyPart.replaceAll('\\n', '\n');

        return publicKeyPem;
    }

    /**
* Verify signature using Web Crypto API
* @param {string} token - Full JWT token
* @param {string} publicKeyPem - Public key in PEM format
* @returns {Promise<Object>} Verification result
*/
    async verifyWithWebCrypto(token: string, publicKeyPem: string): Promise<{ status: boolean, message: string }> {

        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                return {
                    status: false,
                    message: "Invalid token format for Web Crypto verification"
                };
            }

            const [headerB64, payloadB64, signatureB64] = parts;

            // Decode header to get algorithm info
            let headerData;
            try {
                headerData = JSON.parse(base64UrlDecode(headerB64 ?? ''));
            } catch (headerError) {
                console.warn("⚠️ Could not parse header:", headerError);
                return {
                    status: false,
                    message: "Error parsing token header during verification"
                };
            }

            // Check if algorithm is supported
            if (headerData.alg !== 'RS256') {
                console.warn(`⚠️ Algorithm ${headerData.alg} not supported by Web Crypto`);
                return {
                    status: false,
                    message: `Algorithm '${headerData.alg}' is not supported. Only RS256 is supported in browser.`
                };
            }

            // Import the public key
            let cryptoKey;
            try {
                cryptoKey = await this.importPublicKey(publicKeyPem);
                if (!cryptoKey) {
                    return {
                        status: false,
                        message: 'Failed to import public key'
                    };
                }
            } catch (keyError: any) {
                return {
                    status: false,
                    message: `Error importing public key: ${keyError.message}`
                };
            }

            // Prepare the data to verify
            const signedData = `${headerB64}.${payloadB64}`;
            const signedDataBuffer = new TextEncoder().encode(signedData);

            // Convert base64url signature to ArrayBuffer
            const signatureArrayBuffer = base64UrlToArrayBuffer(signatureB64 ?? '');

            // Verify the signature
            try {
                const isValid = await crypto.subtle.verify(
                    {
                        name: 'RSASSA-PKCS1-v1_5',
                        hash: { name: 'SHA-256' },
                    },
                    cryptoKey,
                    signatureArrayBuffer,
                    signedDataBuffer
                );

                return {
                    status: isValid,
                    message: isValid
                        ? "Signature verified successfully with Web Crypto API"
                        : "Signature verification failed - invalid signature"
                };
            } catch (verifyError: any) {
                console.error("Error during Web Crypto verification:", verifyError);
                return {
                    status: false,
                    message: `Web Crypto API verification error: ${verifyError.message}`
                };
            }
        } catch (e: any) {
            console.error("Unexpected error in Web Crypto verification:", e);
            return {
                status: false,
                message: `Verification error: ${e.message}`
            };
        }
    }

    async importPublicKey(pemKey: string): Promise<CryptoKey | undefined> {
        if (!pemKey || pemKey.trim() === '') {
            console.error("❌ Empty public key provided");
            throw new Error('Public key is required for signature verification');
        }

        try {
            // Normalize line endings and remove whitespace
            let formattedKey = pemKey.replace(/\r\n/g, '\n').trim();

            // Check for PEM format
            if (!formattedKey.includes('-----BEGIN PUBLIC KEY-----')) {
                console.warn("⚠️ Public key doesn't have standard BEGIN marker");
                // Try to add PEM wrapper if missing
                if (!formattedKey.includes('-----BEGIN')) {
                    formattedKey = `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n-----END PUBLIC KEY-----`;
                } else {
                    console.error("❌ Unsupported key format detected");
                    throw new Error('Unsupported key format. Please provide a PEM formatted RSA public key.');
                }
            }

            // Extract the base64 part
            const matches = formattedKey.match(/-----BEGIN PUBLIC KEY-----\s*([\s\S]*?)\s*-----END PUBLIC KEY-----/);
            if (!matches || !matches[1]) {
                console.error("❌ Failed to extract key data from PEM format");
                throw new Error('Invalid PEM format');
            }

            // Get the base64 encoded key and remove all whitespace
            const pemContents = matches[1].replace(/\s+/g, '');

            // Decode the base64 key to get the DER format
            let binaryDer;
            try {
                binaryDer = atob(pemContents);
            } catch (e: any) {
                console.error("❌ Base64 decoding error in key:", e);
                throw new Error(`Failed to decode key: ${e.message}`);
            }

            const derBytes = new Uint8Array(binaryDer.length);
            for (let i = 0; i < binaryDer.length; i++) {
                derBytes[i] = binaryDer.charCodeAt(i);
            }

            // Import the key using Web Crypto API
            try {
                const cryptoKey = await crypto.subtle.importKey(
                    'spki',
                    derBytes,
                    {
                        name: 'RSASSA-PKCS1-v1_5',
                        hash: { name: 'SHA-256' }
                    },
                    false,
                    ['verify']
                );

                return cryptoKey;
            } catch (e: any) {
                console.error("❌ Error importing key with Web Crypto API:", e);
                return undefined;
            }
        } catch (e: any) {
            console.error("❌ Error processing public key:", e);
            return undefined;
        }
    }
}