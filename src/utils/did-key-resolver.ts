import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { DidDocumentProfile, OfflineVerificationKey, PublicKeyJwk, VerificationMethod } from '../models/common.model';
import { base64UrlToArrayBuffer } from './jwt-utils';
import { logger } from './logger';

/** Prefix for issuer-key-resolution diagnostic logs (filter in the console). */
const LOG_PREFIX = '[EveryCred:key-resolution]';

/**
 * Decode a base64 OR base64url string into raw bytes.
 *
 * The JWK spec mandates base64url for members like `x`, but real-world issuers
 * have been observed emitting STANDARD base64 (with `+`/`/` and `=` padding).
 * This helper accepts either encoding by normalizing base64url characters to
 * the standard alphabet and re-padding before decoding.
 *
 * @param value - A base64 or base64url encoded string.
 * @returns The decoded bytes as a Uint8Array.
 */
export function decodeBase64OrBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    '='
  );
  return naclUtil.decodeBase64(padded);
}

/**
 * Determine whether an issuer profile is a DID document, i.e. it exposes one or
 * more `verificationMethod` entries (instead of the legacy `publicKey` array).
 *
 * @param profile - The fetched issuer profile object.
 * @returns True when a non-empty verificationMethod array is present.
 */
export function isDidDocumentProfile(profile: any): profile is DidDocumentProfile {
  return Array.isArray(profile?.verificationMethod) && profile.verificationMethod.length > 0;
}

/**
 * Check that a resolved verificationMethod actually belongs to the DID named by
 * the credential's key reference, so a credential cannot pass with a key whose
 * declared owner is a different DID.
 *
 * NOTE: the issuer profile's own `id` is intentionally NOT used as the anchor —
 * real EveryCred profiles set it to either the DID or the profile URL, so it is
 * not a reliable comparison target. The binding is internal consistency between
 * the credential-side reference and the profile-side key entry:
 *   - When `kid` is a full DID URL (contains ':' and '#'), its DID part must
 *     match `vm.controller` (when present) and the DID part of `vm.id`.
 *   - Bare fragments/thumbprints carry no DID, so there is nothing to check.
 *
 * @param vm - The resolved verificationMethod entry.
 * @param kid - The key reference from the credential (JWT header `kid`).
 * @returns True when no binding rule is violated.
 */
export function isVerificationMethodBoundToIssuer(
  vm: VerificationMethod,
  kid: string
): boolean {
  const kidDid = kid && kid.includes('#') && kid.includes(':') ? kid.split('#')[0] : '';
  if (!kidDid) {
    return true;
  }

  if (vm?.controller && vm.controller !== kidDid) {
    logger(`${LOG_PREFIX} verificationMethod controller "${vm.controller}" does not match kid DID "${kidDid}"`, 'warn');
    return false;
  }

  const vmDid = vm?.id && vm.id.includes('#') && vm.id.includes(':') ? vm.id.split('#')[0] : '';
  if (vmDid && vmDid !== kidDid) {
    logger(`${LOG_PREFIX} verificationMethod id DID "${vmDid}" does not match kid DID "${kidDid}"`, 'warn');
    return false;
  }

  return true;
}

/**
 * Detect the non-standard EveryCred profile quirk where `publicKeyJwk.n` holds a
 * full PEM public key instead of the base64url RSA modulus required by the JWK
 * spec. Such keys must be imported as SPKI/PEM, not via the JWK import path.
 *
 * @param jwk - The publicKeyJwk to inspect.
 * @returns The embedded PEM string, or null when `n` is a standard modulus.
 */
export function pemEmbeddedInJwkModulus(jwk: PublicKeyJwk): string | null {
  return typeof jwk?.n === 'string' && jwk.n.includes('-----BEGIN') ? jwk.n : null;
}

/**
 * Resolve the verificationMethod entry referenced by a credential.
 *
 * The reference is either the SD-JWT header `kid` or the Ed25519
 * `proof.verificationMethod`. Matching is tolerant because the reference shape
 * varies between issuers: it may be a bare JWK thumbprint, a full DID URL, or a
 * DID URL fragment. Match order:
 *   1. publicKeyJwk.kid === ref
 *   2. verificationMethod.id === ref
 *   3. fragment-only match against either kid or id (after '#')
 *   4. single-entry fallback (only one verificationMethod present)
 *
 * @param profile - The DID-document issuer profile.
 * @param ref - The key reference taken from the credential.
 * @returns The matching VerificationMethod, or null when none matches.
 */
export function resolveVerificationMethod(
  profile: DidDocumentProfile,
  ref: string
): VerificationMethod | null {
  const methods = profile?.verificationMethod;
  if (!Array.isArray(methods) || methods.length === 0) {
    logger(`${LOG_PREFIX} no verificationMethod array in issuer profile`, 'warn');
    return null;
  }

  logger(`${LOG_PREFIX} resolving key for ref="${ref}" among ${methods.length} verificationMethod(s)`);

  const fragmentOf = (value?: string): string | undefined =>
    value && value.includes('#') ? value.split('#').pop() : value;
  const refFragment = fragmentOf(ref);

  let match: VerificationMethod | undefined;
  let strategy = '';

  if (!ref) {
    match = methods.length === 1 ? methods[0] : undefined;
    strategy = 'single-entry (no ref provided)';
  } else if ((match = methods.find((m) => m?.publicKeyJwk?.kid === ref))) {
    strategy = 'publicKeyJwk.kid === ref';
  } else if ((match = methods.find((m) => m?.id === ref))) {
    strategy = 'verificationMethod.id === ref';
  } else if ((match = methods.find((m) => !!refFragment && (fragmentOf(m?.publicKeyJwk?.kid) === refFragment || fragmentOf(m?.id) === refFragment)))) {
    strategy = 'fragment match';
  } else if (methods.length === 1) {
    match = methods[0];
    strategy = 'single-entry fallback';
  }

  if (match) {
    logger(`${LOG_PREFIX} matched verificationMethod id="${match.id}" via ${strategy}`);
    return match;
  }

  logger(`${LOG_PREFIX} NO verificationMethod matched ref="${ref}"`, 'warn');
  return null;
}

/** True when `publicKey` is an RSA PEM (SPKI), not Ed25519 jwk.x material. */
export function isPemPublicKey(publicKey: string): boolean {
  return publicKey.includes('-----BEGIN');
}

/**
 * Match a caller-pinned key from `config.offlinePublicKey` by id / fragment.
 *
 * Matching mirrors `resolveVerificationMethod`'s fragment-tolerant strategy: an
 * entry whose `id` matches the reference (or its `#fragment`) wins; a lone entry
 * with no `id` acts as a catch-all.
 *
 * @param configured - The `offlinePublicKey` config value (single entry or array).
 * @param ref - The key reference from the credential (`proof.verificationMethod` or JWT `kid`).
 * @returns The matched entry, or null when nothing is configured or matches.
 */
export function matchOfflineVerificationKey(
  configured: OfflineVerificationKey | OfflineVerificationKey[] | undefined,
  ref: string
): OfflineVerificationKey | null {
  if (!configured) {
    return null;
  }

  const candidates = Array.isArray(configured) ? configured : [configured];
  const fragmentOf = (value?: string): string | undefined =>
    value && value.includes('#') ? value.split('#').pop() : value;
  const refFragment = fragmentOf(ref);

  const [onlyCandidate] = candidates;
  const singleUnlabeledCandidate =
    candidates.length === 1 && onlyCandidate && !onlyCandidate.id ? onlyCandidate : undefined;
  const match =
    candidates.find((k) => k.id && (k.id === ref || fragmentOf(k.id) === refFragment)) ??
    singleUnlabeledCandidate;

  return match?.publicKey ? match : null;
}

/**
 * Resolve a caller-pinned Ed25519 public key from `config.offlinePublicKey`.
 *
 * Used for fully offline verification, where the issuer profile (DID document)
 * cannot be fetched. PEM entries are skipped — use `matchOfflineVerificationKey`
 * + the RS256 path for those.
 *
 * @param configured - The `offlinePublicKey` config value (single entry or array).
 * @param ref - The key reference from the credential (`proof.verificationMethod` or JWT `kid`).
 * @returns The 32-byte public key, or null when nothing is configured or matches.
 */
export function resolveOfflinePublicKey(
  configured: OfflineVerificationKey | OfflineVerificationKey[] | undefined,
  ref: string
): Uint8Array | null {
  const match = matchOfflineVerificationKey(configured, ref);
  if (!match?.publicKey) {
    return null;
  }

  // RSA PEM belongs on the RS256 path — do not try to decode it as Ed25519 jwk.x.
  if (isPemPublicKey(match.publicKey)) {
    return null;
  }

  try {
    const bytes = decodeBase64OrBase64Url(match.publicKey);
    if (bytes.length !== 32) {
      logger(`${LOG_PREFIX} offlinePublicKey has unexpected length: ${bytes.length} (expected 32)`, 'error');
      return null;
    }
    logger(`${LOG_PREFIX} using caller-supplied offlinePublicKey (id="${match.id ?? '<unlabeled>'}")`);
    return bytes;
  } catch (error) {
    logger(`${LOG_PREFIX} offlinePublicKey could not be decoded as base64/base64url`, 'error');
    return null;
  }
}

/**
 * Extract the raw 32-byte Ed25519 public key from an OKP/Ed25519 JWK.
 *
 * @param jwk - The publicKeyJwk (expected kty "OKP", crv "Ed25519").
 * @returns The 32-byte public key as a Uint8Array.
 * @throws When the JWK is not a valid Ed25519 key or decodes to the wrong length.
 */
export function ed25519PublicKeyFromJwk(jwk: PublicKeyJwk): Uint8Array {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
    throw new Error('Invalid Ed25519 (OKP) JWK');
  }

  const bytes = decodeBase64OrBase64Url(jwk.x);
  if (bytes.length !== 32) {
    throw new Error(`Unexpected Ed25519 public key length: ${bytes.length} (expected 32)`);
  }
  logger(`${LOG_PREFIX} decoded Ed25519 public key from JWK (kid="${jwk.kid}", ${bytes.length} bytes)`);
  return bytes;
}

/**
 * Import an RSA JWK as a Web Crypto CryptoKey for RS256 verification.
 * Web Crypto consumes the JWK directly — no PEM/DER conversion needed.
 *
 * @param jwk - The publicKeyJwk (expected kty "RSA").
 * @returns A CryptoKey usable with crypto.subtle.verify.
 */
export async function importRsaCryptoKeyFromJwk(jwk: PublicKeyJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk as unknown as JsonWebKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
    false,
    ['verify']
  );
}

/**
 * Verify an EdDSA-signed JWT against an Ed25519 public key.
 * The signing input is the ASCII `${headerB64}.${payloadB64}`; the JWT
 * signature is base64url-encoded.
 *
 * @param headerB64 - The base64url-encoded JWT header segment.
 * @param payloadB64 - The base64url-encoded JWT payload segment.
 * @param signatureB64 - The base64url-encoded JWT signature segment.
 * @param publicKey - The 32-byte Ed25519 public key.
 * @returns True when the signature is valid.
 */
export function verifyEddsaJwt(
  headerB64: string,
  payloadB64: string,
  signatureB64: string,
  publicKey: Uint8Array
): boolean {
  const signingInput = naclUtil.decodeUTF8(`${headerB64}.${payloadB64}`);
  const signature = new Uint8Array(base64UrlToArrayBuffer(signatureB64));
  return nacl.sign.detached.verify(signingInput, signature, publicKey);
}
