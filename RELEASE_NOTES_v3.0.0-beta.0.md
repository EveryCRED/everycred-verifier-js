# Release Notes - v3.0.0-beta.0

## First Pre-release of the 3.0.0 Line

`3.0.0-beta.0` is the first beta of the 3.0.0 major version line, published to the npm `beta`
dist-tag. It is **not** merged into `main` and does **not** become the `latest` stable release.
It bundles two breaking changes carried over from prior unreleased work on this branch, plus a
new feature: issuer signing keys are now resolved from the issuer's published DID document.

> ⚠️ **This is a pre-release.** APIs and behavior may still change before `3.0.0` is finalized.
> Test thoroughly against your own issuer profiles and credentials before adopting in production.

## Breaking Changes

### 1. Blockchain explorer API keys are no longer bundled

The library no longer ships hardcoded Etherscan/Polygonscan API keys. Callers must supply their
own via the new `VerificationConfig.blockchainApiKeys` option:

```typescript
const verifier = new EveryCredVerifier(progressCallback, {
  isBlockchainVerificationEnabled: true,
  blockchainApiKeys: {
    ethereum: process.env.ETHERSCAN_API_KEY,   // Etherscan v2 multichain: ETH Mainnet, ETH Sepolia, Polygon Mainnet
    polygon: process.env.POLYGONSCAN_API_KEY,  // Polygonscan: Polygon Testnet (Amoy needs no key)
  },
});
```

On-chain verification fails with a clear error (`Failed to retrieve URL or API key from the matched API.`)
if a required key is missing. Off-chain verification is unaffected. Blockchain requests now also detect
and surface `NOTOK` responses from the explorer APIs instead of silently treating them as valid data.
See [README → Configuration Options](./README.md#configuration-options) and
[README → Migrating from v2.x to v3.0.0](./README.md#migrating-from-v2x-to-v300).

### 2. Revocation checking is now strict — issuer profiles must publish a revocation list

Previously, an issuer profile with a missing or unfetchable `revocationList` URL was treated as
"nothing to revoke against" and verification passed. **That leniency has been removed.**

| Scenario | v2.0.0 | v3.0.0-beta.0 |
|---|---|---|
| `revocationList` URL missing from issuer profile | Pass | **Fail** |
| `revocationList` URL present but unfetchable (network error, non-JSON, empty) | Pass | **Fail** (new `REVOCATION_LIST_FETCH_ERROR` message) |
| `revocationList` fetched with `revokedAssertions: []` | Pass | Pass (unchanged — empty list is a valid "nothing revoked yet" response) |
| Credential ID present in `revokedAssertions` | Fail | Fail (unchanged) |

> **⚠️ Known consequence:** any issuer profile that does not currently publish a `revocationList`
> (for example, some existing `assets.evrc.viitorcloud.in` profiles at the time of writing) will
> now **fail verification** until that issuer publishes one. This is intentional per product
> decision, but it is a real behavioral change from `2.0.0` and from the plain `3.0.0` version
> tentatively staged before this beta. Confirm the issuers you verify against have published a
> revocation list before adopting this release.

## New Feature: Issuer Key Resolution from DID Documents

Issuer signing keys are now resolved from the issuer's **published DID-document-style profile**
(`verificationMethod[].publicKeyJwk`) rather than trusted directly from the credential itself
(the SD-JWT header `kid`/embedded PEM, or the JSON-LD `proof.verificationMethod` embedded key).
Both legacy forms remain supported as a fallback for issuers that have not migrated.

- **New module** `src/utils/did-key-resolver.ts`:
  - `isDidDocumentProfile` — detects a DID-document-style issuer profile.
  - `resolveVerificationMethod` — matches the credential's key reference (`kid`) against the
    profile's `verificationMethod[]` entries, trying exact `publicKeyJwk.kid`, exact `id`,
    fragment match, and finally a single-entry fallback, in that order.
  - `isVerificationMethodBoundToIssuer` — the resolved key's `controller`/`id` DID must match the
    DID named in the credential's `kid`, preventing a credential from being verified against a
    foreign or attacker-supplied key. (Deliberately does **not** compare against the issuer
    profile's own `id` field, since real EveryCRED profiles inconsistently set `id` to either the
    DID or the profile URL.)
  - `pemEmbeddedInJwkModulus` and dual-mode RSA import — handles a real-world EveryCRED issuer
    profile quirk where `publicKeyJwk.n` holds a full PEM string instead of the spec's base64url
    modulus; both formats now import transparently.
- **Algorithm/key-type consistency gate** in `signature-validator.ts`: the expected algorithm
  (EdDSA ↔ OKP/Ed25519, RS256 ↔ RSA) is now derived from the *resolved* key, not the JWT's own
  `alg` header, closing an algorithm-confusion gap. New message `ALG_KEY_MISMATCH`.
- Same DID-document key-resolution path applied to the JSON-LD Ed25519 proof flow in
  `merkle-proof-2019-validation.ts`.
- `credential-issuer-validator.ts` gained a relaxed validation chain for DID-document-style
  profiles (`verificationMethod` + `name` + `email`) alongside the legacy `@context`/`type`/
  `publicKey[]` chain.
- New messages in `src/constants/messages.ts`: `VERIFICATION_METHOD_VALIDATE`,
  `VERIFICATION_METHOD_SUCCESS`, `VERIFICATION_METHOD_ERROR`, `VERIFICATION_METHOD_NOT_FOUND`,
  `UNSUPPORTED_JWK_ALGORITHM`, `KEY_ISSUER_BINDING_ERROR`, `ALG_KEY_MISMATCH`,
  `REVOCATION_LIST_FETCH_ERROR`.
- New model types in `src/models/common.model.ts`: `PublicKeyJwk`, `VerificationMethod`,
  `DidDocumentProfile`.

This was manually verified end-to-end against live issuer profiles and multiple real signed
SD-JWT credentials from the demo issuer — signature verification, issuer/key binding, and
revocation all passed end-to-end against live data (both an RSA-signed and, separately, key
resolution against an Ed25519 verificationMethod entry).

> **⚠️ Known limitation:** if an issuer profile publishes signing keys under **both** the legacy
> `publicKey[]` array *and* the DID-document `verificationMethod[]` array (mixing key styles,
> e.g. an Ed25519 key under `publicKey` alongside an RSA key under `verificationMethod`), only the
> `verificationMethod[]` keys are resolvable. A credential signed with the key that only exists in
> `publicKey[]` will fail with `VERIFICATION_METHOD_NOT_FOUND`, even though the key is present in
> the profile. Discovered during pre-release testing against a real demo profile; no credential in
> our test set actually triggers it today, but issuers should avoid mixing key locations until a
> fast-follow beta merges lookup across both arrays.

## Migration Notes

- **No public API surface changes** to `EveryCredVerifier` — the breaking changes are behavioral
  (see tables above), not signature changes.
- If you supply blockchain explorer keys, see
  [README → Migrating from v2.x to v3.0.0](./README.md#migrating-from-v2x-to-v300).
- If any of your issuers do not yet publish a `revocationList`, verification for their credentials
  will fail starting with this release until they do.
- If your issuer profiles are DID documents, no code changes are required — key resolution happens
  automatically. Legacy (`publicKey[]`) issuer profiles continue to work unchanged.

## Beta Notice

This is a pre-release published to the npm `beta` dist-tag only (`latest` is unaffected). Install
explicitly with:

```shell
npm i @viitorcloudtechnologies/everycred-verifier-js@beta
```

Please report issues before this line is promoted to a stable `3.0.0`.
