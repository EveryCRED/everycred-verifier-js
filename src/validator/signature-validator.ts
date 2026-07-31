import { Messages } from "../constants/messages";
import { Stages } from "../constants/stages";
import { DidDocumentProfile, VerificationConfig } from "../models/common.model";
import {
    decodeBase64OrBase64Url,
    ed25519PublicKeyFromJwk,
    importRsaCryptoKeyFromJwk,
    isDidDocumentProfile,
    isPemPublicKey,
    isVerificationMethodBoundToIssuer,
    matchOfflineVerificationKey,
    pemEmbeddedInJwkModulus,
    resolveVerificationMethod,
    verifyEddsaJwt,
} from "../utils/did-key-resolver";
import { base64UrlDecode, base64UrlToArrayBuffer, extractAndNormalizeJwt } from "../utils/jwt-utils";
import { logger } from "../utils/logger";

/** Prefix for issuer-key-resolution diagnostic logs (filter in the console). */
const LOG_PREFIX = '[EveryCred:key-resolution]';


export class SignatureValidator {

    constructor(
        private readonly progressCallback: (step: string, title: string, status: boolean, reason: string) => void,
        private readonly config: VerificationConfig = {}
    ) { }

    /**
     * Verifies the JWT signature.
     * Key resolution order:
     *   1. A caller-pinned key from `config.offlinePublicKey` (needs no network) —
     *      Ed25519 jwk.x for EdDSA, or RSA PEM for RS256.
     *   2. The issuer profile's verificationMethod[].publicKeyJwk when it is a DID
     *      document (EdDSA via tweetnacl, RS256 via Web Crypto).
     *   3. Legacy: a PEM key embedded in the JWT header `kid` (RS256).
     * @param jwtToken - The raw/normalizable JWT token.
     * @param header - The parsed JWT header (provides `kid`).
     * @param issuerProfile - Optional issuer profile; enables DID-document key resolution.
     */
    async validate(jwtToken: string, header: Record<string, unknown>, issuerProfile?: any): Promise<{ status: boolean, message: string }> {
        const normalizedJwt = extractAndNormalizeJwt(jwtToken);
        if (!normalizedJwt) {
            this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, 'Invalid JWT token');
            return { status: false, message: 'Invalid JWT token' };
        }

        // A pinned key takes priority — it works even when the issuer profile is
        // unreachable. Null means none was configured/matched, so fall through.
        const pinned = await this.verifyFromPinnedKey(normalizedJwt, header);
        const result = pinned
            ?? (isDidDocumentProfile(issuerProfile)
                ? await this.verifyFromIssuerProfile(normalizedJwt, header, issuerProfile)
                : await this.verifyFromHeaderPem(normalizedJwt, header));

        if (!result.status) {
            this.progressCallback(Stages.verification, Messages.VERIFICATION_FAILED, false, result.message);
            return result;
        }
        this.progressCallback(Stages.verification, Messages.VERIFICATION_SUCCESS, true, Messages.VERIFICATION_SUCCESS);
        return { status: true, message: Messages.VERIFICATION_SUCCESS };
    }

    /**
     * Verification using a caller-pinned key from `config.offlinePublicKey`.
     * Supports Ed25519 (jwk.x) for EdDSA and RSA PEM for RS256. Makes no network
     * request, so it works fully offline.
     * @returns The verification result, or null when no pinned key is configured or
     * matches the header `kid` — signalling the caller to fall through to the
     * issuer-profile / legacy paths.
     */
    private async verifyFromPinnedKey(normalizedJwt: string, header: Record<string, unknown>): Promise<{ status: boolean, message: string } | null> {
        const kid = typeof header?.['kid'] === 'string' ? (header['kid'] as string) : '';
        const match = matchOfflineVerificationKey(this.config?.offlinePublicKey, kid);
        if (!match?.publicKey) {
            return null;
        }

        // Procedure follows the RESOLVED KEY; token `alg` must be consistent with it.
        const alg = typeof header?.['alg'] === 'string' ? (header['alg'] as string) : '';

        if (isPemPublicKey(match.publicKey)) {
            if (alg !== 'RS256') {
                logger(`${LOG_PREFIX} alg mismatch: header alg="${alg}" but offlinePublicKey is RSA PEM (expected "RS256")`, 'warn');
                return { status: false, message: Messages.ALG_KEY_MISMATCH };
            }
            logger(`${LOG_PREFIX} SD-JWT path: using caller-supplied offlinePublicKey PEM from config`);
            return await this.verifyWithWebCrypto(normalizedJwt, match.publicKey);
        }

        if (alg !== 'EdDSA') {
            logger(`${LOG_PREFIX} alg mismatch: header alg="${alg}" but offlinePublicKey is Ed25519 (expected "EdDSA")`, 'warn');
            return { status: false, message: Messages.ALG_KEY_MISMATCH };
        }

        const parts = normalizedJwt.split('.');
        if (parts.length !== 3) {
            return { status: false, message: 'Invalid token format for signature verification' };
        }

        let pubKey: Uint8Array;
        try {
            pubKey = decodeBase64OrBase64Url(match.publicKey);
            if (pubKey.length !== 32) {
                logger(`${LOG_PREFIX} offlinePublicKey has unexpected length: ${pubKey.length} (expected 32)`, 'error');
                return { status: false, message: 'Invalid offlinePublicKey length for Ed25519' };
            }
        } catch {
            return { status: false, message: 'offlinePublicKey could not be decoded as base64/base64url' };
        }

        logger(`${LOG_PREFIX} SD-JWT path: using caller-supplied offlinePublicKey from config`);
        const [headerB64, payloadB64, signatureB64] = parts;
        try {
            const isValid = verifyEddsaJwt(headerB64 ?? '', payloadB64 ?? '', signatureB64 ?? '', pubKey);
            return {
                status: isValid,
                message: isValid ? Messages.VERIFICATION_SUCCESS : 'Signature verification failed - invalid signature',
            };
        } catch (error: any) {
            return { status: false, message: `Error verifying EdDSA signature: ${error?.message}` };
        }
    }

    /**
     * Legacy verification: extract a PEM public key embedded in the JWT header
     * `kid` and verify with RS256 via the Web Crypto API.
     */
    private async verifyFromHeaderPem(normalizedJwt: string, header: Record<string, unknown>): Promise<{ status: boolean, message: string }> {
        let publicKeyPem: string;
        try {
            publicKeyPem = this.getPublicKeyFromJwtHeader(header);
        } catch (error: any) {
            return { status: false, message: error?.message || 'Missing public key in JWT header' };
        }
        if (!publicKeyPem) {
            return { status: false, message: 'Missing public key in JWT header' };
        }
        return await this.verifyWithWebCrypto(normalizedJwt, publicKeyPem);
    }

    /**
     * DID-document verification: resolve the verificationMethod referenced by the
     * JWT header `kid`, then verify with its publicKeyJwk (EdDSA or RS256).
     */
    private async verifyFromIssuerProfile(normalizedJwt: string, header: Record<string, unknown>, issuerProfile: DidDocumentProfile): Promise<{ status: boolean, message: string }> {
        const kid = typeof header?.['kid'] === 'string' ? (header['kid'] as string) : '';
        const alg = typeof header?.['alg'] === 'string' ? (header['alg'] as string) : '';
        logger(`${LOG_PREFIX} SD-JWT path: resolving key from DID-document issuer profile (header kid="${kid}", alg="${alg}")`);
        const vm = resolveVerificationMethod(issuerProfile, kid);
        if (!vm?.publicKeyJwk) {
            return { status: false, message: Messages.VERIFICATION_METHOD_NOT_FOUND };
        }

        // The resolved key's declared owner (controller / id DID) must match the DID
        // named in the kid; otherwise a credential could reference a foreign key.
        // The profile's own `id` is not compared — it may be a DID or a profile URL.
        if (!isVerificationMethodBoundToIssuer(vm, kid)) {
            return { status: false, message: Messages.KEY_ISSUER_BINDING_ERROR };
        }

        const parts = normalizedJwt.split('.');
        if (parts.length !== 3) {
            return { status: false, message: 'Invalid token format for signature verification' };
        }
        const [headerB64, payloadB64, signatureB64] = parts;
        const jwk = vm.publicKeyJwk;
        logger(`${LOG_PREFIX} SD-JWT path: using publicKeyJwk (kty="${jwk.kty}", crv="${jwk.crv ?? ''}", alg="${jwk.alg ?? ''}")`);

        // The verification procedure is chosen from the RESOLVED KEY's type, and the
        // token's `alg` header must be consistent with it — never the other way
        // around, to rule out algorithm-confusion attacks.

        // EdDSA / Ed25519
        if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
            if (alg !== 'EdDSA') {
                logger(`${LOG_PREFIX} alg mismatch: header alg="${alg}" but resolved key is OKP/Ed25519 (expected "EdDSA")`, 'warn');
                return { status: false, message: Messages.ALG_KEY_MISMATCH };
            }
            try {
                const pubKey = ed25519PublicKeyFromJwk(jwk);
                const isValid = verifyEddsaJwt(headerB64 ?? '', payloadB64 ?? '', signatureB64 ?? '', pubKey);
                return {
                    status: isValid,
                    message: isValid ? Messages.VERIFICATION_SUCCESS : 'Signature verification failed - invalid signature',
                };
            } catch (error: any) {
                return { status: false, message: `Error verifying EdDSA signature: ${error?.message}` };
            }
        }

        // RSA / RS256
        if (jwk.kty === 'RSA') {
            if (alg !== 'RS256') {
                logger(`${LOG_PREFIX} alg mismatch: header alg="${alg}" but resolved key is RSA (expected "RS256")`, 'warn');
                return { status: false, message: Messages.ALG_KEY_MISMATCH };
            }
            try {
                // Non-standard EveryCred profiles embed a full PEM in `n` instead of the
                // base64url modulus; import those as SPKI/PEM, standard JWKs directly.
                const embeddedPem = pemEmbeddedInJwkModulus(jwk);
                const cryptoKey = embeddedPem
                    ? await this.importPublicKey(embeddedPem)
                    : await importRsaCryptoKeyFromJwk(jwk);
                if (!cryptoKey) {
                    return { status: false, message: 'Failed to import RSA public key from issuer profile' };
                }
                return await this.verifyRs256WithCryptoKey(normalizedJwt, cryptoKey);
            } catch (error: any) {
                return { status: false, message: `Error importing RSA public key: ${error?.message}` };
            }
        }

        return { status: false, message: Messages.UNSUPPORTED_JWK_ALGORITHM };
    }

    /**
     * Verify an RS256 JWT against an already-imported CryptoKey (used for the
     * JWK-resolved RSA path). The PEM path keeps using verifyWithWebCrypto.
     */
    private async verifyRs256WithCryptoKey(token: string, cryptoKey: CryptoKey): Promise<{ status: boolean, message: string }> {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { status: false, message: 'Invalid token format for Web Crypto verification' };
        }
        const [headerB64, payloadB64, signatureB64] = parts;
        const signedDataBuffer = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
        const signatureArrayBuffer = base64UrlToArrayBuffer(signatureB64 ?? '');
        try {
            const isValid = await crypto.subtle.verify(
                { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
                cryptoKey,
                signatureArrayBuffer,
                signedDataBuffer
            );
            return {
                status: isValid,
                message: isValid ? Messages.VERIFICATION_SUCCESS : 'Signature verification failed - invalid signature',
            };
        } catch (error: any) {
            return { status: false, message: `Web Crypto API verification error: ${error?.message}` };
        }
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