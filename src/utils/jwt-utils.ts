/**
 * Extracts and normalizes the JWT portion from an SD-JWT string.
 * Removes whitespace, extracts the JWT part before any disclosures (separated by ~),
 * and validates the JWT format (header.payload.signature).
 *
 * @param sdJwtString - The SD-JWT string containing the JWT and optional disclosures
 * @returns The normalized JWT string with three parts separated by dots
 * @throws {Error} If the JWT format is invalid (doesn't have exactly 3 parts)
 */
export function extractAndNormalizeJwt(sdJwtString: string): string {
    // Remove any whitespace, newlines or carriage returns
    const cleanedInput = sdJwtString.replace(/\s/g, '');

    // Split by ~ to get just the JWT part (before any disclosures)
    const parts = cleanedInput.split('~');
    const jwt = parts[0] ?? '';

    // Verify the JWT has the correct format (header.payload.signature)
    const jwtParts = jwt?.split('.');
    if (jwtParts?.length !== 3) {
        // Some JWTs may have line breaks or other issues
        const normalizedJwt = jwt?.replace(/[^A-Za-z0-9_\-\.]/g, '');
        const normalizedParts = normalizedJwt?.split('.');

        if (normalizedParts?.length === 3) {
            return normalizedJwt;
        }

        console.error(`Invalid JWT format: expected 3 parts, got ${jwtParts.length}`);
        throw new Error("Invalid JWT format: token doesn't have the expected 3 parts");
    }

    return jwt ?? '';
}


/**
 * Converts a base64url-encoded string to an ArrayBuffer for cryptographic operations.
 * Handles padding and character conversion from base64url to standard base64 format.
 *
 * @param base64url - The base64url-encoded string to convert
 * @returns An ArrayBuffer containing the decoded binary data
 */
export function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
    // Convert base64url to base64
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');

    // Decode base64 to binary string
    const binary = atob(padded);

    // Convert to ArrayBuffer
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return buffer;
}

/**
 * Splits a JWT token into its three base64url-encoded parts: header, payload, and signature.
 *
 * @param jwtToken - The JWT token string in format "header.payload.signature"
 * @returns An object containing the three base64url-encoded parts
 * @throws {Error} If the JWT format is invalid (missing parts or incorrect structure)
 */
export function splitJwtIntoParts(jwtToken: string): { headerB64: string; payloadB64: string; signatureB64: string } {
    const parts = jwtToken.split('.');
    if (parts.length !== 3) {
        throw new Error("Invalid JWT format: must have header, payload, and signature parts");
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    if (!headerB64 || !payloadB64) {
        throw new Error("Invalid JWT format: missing parts");
    }

    return { headerB64, payloadB64, signatureB64: signatureB64 ?? '' };
}

/**
 * Decodes and parses a base64url-encoded JWT header into a JavaScript object.
 *
 * @param headerB64 - The base64url-encoded JWT header string
 * @returns The parsed JWT header as a record of key-value pairs
 * @throws {Error} If the header cannot be decoded or parsed as valid JSON
 */
export function decodeJwtHeader(headerB64: string): Record<string, unknown> {
    try {
        const decoded = base64UrlDecode(headerB64);
        return JSON.parse(decoded) as Record<string, unknown>;
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Failed to parse JWT header: ${message}`);
    }
}

/**
 * Decodes and parses a base64url-encoded JWT payload into a JavaScript object.
 *
 * @param payloadB64 - The base64url-encoded JWT payload string
 * @returns The parsed JWT payload as a record of key-value pairs
 * @throws {Error} If the payload cannot be decoded or parsed as valid JSON
 */
export function decodeJwtPayload(payloadB64: string): Record<string, unknown> {
    try {
        const decoded = base64UrlDecode(payloadB64);
        return JSON.parse(decoded) as Record<string, unknown>;
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Failed to parse JWT payload: ${message}`);
    }
}

/**
 * Extracts the signed data portion of a JWT (header.payload) for signature verification.
 * This is the portion of the JWT that was actually signed, excluding the signature itself.
 *
 * @param jwtToken - The JWT token string
 * @returns The signed data string in format "header.payload"
 * @throws {Error} If the JWT format is invalid
 */
export function getJwtSignedData(jwtToken: string): string {
    const { headerB64, payloadB64 } = splitJwtIntoParts(jwtToken);
    return `${headerB64}.${payloadB64}`;
}

/**
 * Decodes a base64url-encoded string to a binary string.
 * Handles malformed input by attempting recovery through chunk-based decoding.
 * Sanitizes input by removing non-base64url characters before decoding.
 *
 * @param input - The base64url-encoded string to decode
 * @returns The decoded binary string
 * @throws {Error} If the input is empty or cannot be decoded even after recovery attempts
 */
export function base64UrlDecode(input: string): string {
    // Handle empty or null input
    if (!input) {
        throw new Error('Empty input to decode');
    }

    try {
        // Sanitize input - strip any non-base64url chars
        input = input.replace(/[^A-Za-z0-9\-_]/g, '');

        // Replace non-url compatible chars with base64 standard chars
        input = input.replaceAll('-', '+').replaceAll('_', '/');

        // Pad with '=' if needed
        const pad = input.length % 4;
        if (pad) {
            input += '='.repeat(4 - pad);
        }

        // Decode
        const base64 = atob(input);
        return base64;
    } catch (e) {
        console.error("Base64 decoding error:", e, "for input:", input);

        // Fallback approach for malformed input
        try {
            // Try decoding smaller chunks to avoid potential corruption
            let validInput = '';

            // Process 4 chars at a time (base64 uses 4-char groups)
            for (let i = 0; i < input.length; i += 4) {
                const chunk = input.slice(i, i + 4);
                try {
                    // Test if this chunk can be decoded
                    atob(chunk);
                    validInput += chunk;
                } catch (error_: any) {
                    // Skip invalid chunks
                    console.warn("Skipping invalid base64 chunk:", chunk, error_.message);
                }
            }

            // If we have any valid input, try to decode it
            if (validInput) {
                return atob(validInput);
            }

            throw new Error('Failed to recover from malformed base64');
        } catch (error_: any) {
            // If all recovery attempts fail, throw a clear error
            throw new Error('Invalid base64url format: ' + error_.message);
        }
    }
}

/**
 * Parses a JWT token into its constituent parts: header, payload, and signature.
 * Attempts to decode and parse both header and payload as JSON objects.
 * If parsing fails, returns partial results with error information and a manual parsing mode flag.
 *
 * @param jwt - The JWT token string to parse
 * @returns An object containing:
 *   - header: The parsed header object (or error object if parsing failed)
 *   - payload: The parsed payload object (or error object if parsing failed)
 *   - headerB64: The base64url-encoded header string
 *   - payloadB64: The base64url-encoded payload string
 *   - signatureB64: The base64url-encoded signature string
 *   - manualParsingMode: Boolean indicating if parsing failed and manual mode is active
 *   - originalError?: Error message if parsing failed
 *   - jwt?: Truncated JWT string for debugging if parsing failed
 */
export function parseJwtToken(jwt: string) {
    let header = null;
    let payload = null;
    let jwtParts = [];
    let headerB64 = '';
    let payloadB64 = '';
    let signatureB64 = '';

    try {
        // Split JWT into parts
        jwtParts = jwt.split('.');
        if (jwtParts.length !== 3) {
            throw new Error("Invalid JWT format: must have header, payload, and signature parts");
        }

        [headerB64, payloadB64, signatureB64] = [jwtParts[0]!, jwtParts[1]!, jwtParts[2]!];

        if (!headerB64 || !payloadB64) {
            throw new Error("Invalid JWT format: missing parts");
        }

        // Decode header
        try {
            header = JSON.parse(base64UrlDecode(headerB64));
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error("Failed to parse JWT header: " + message);
        }

        // Decode payload
        try {
            payload = JSON.parse(base64UrlDecode(payloadB64));
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error("Failed to parse JWT payload: " + message);
        }

        return { header, payload, manualParsingMode: false, headerB64, payloadB64, signatureB64 };
    } catch (jwtParseError: any) {
        console.error("JWT parsing failed, attempting manual extraction:", jwtParseError);

        // Return partial parsing results with a flag that we're in manual mode
        return {
            header: header ?? { error: "Could not parse header" },
            payload: payload ?? { error: "Could not parse payload" },
            headerB64,
            payloadB64,
            signatureB64,
            manualParsingMode: true,
            originalError: jwtParseError.message,
            jwt: jwt.substring(0, 100) + "...[truncated]"
        };
    }
}