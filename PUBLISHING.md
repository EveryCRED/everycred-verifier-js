# Publishing & Release Guide

This document describes how the **`@viitorcloudtechnologies/everycred-verifier-js`** package is
versioned, branched, tagged, and published to npm. Follow it for every release.

---

## 1. Package overview

| Field | Value |
|-------|-------|
| npm package | `@viitorcloudtechnologies/everycred-verifier-js` (scoped, **public**) |
| Registry | `https://registry.npmjs.org/` |
| Entry point | `dist/index.js` |
| Types | `dist/index.d.ts` |
| Build output | `dist/` (git-ignored — **must be built before publishing**) |
| Repository | https://github.com/EveryCRED/everycred-verifier-js |

The published tarball contains **only** `dist/`, `README.md`, `LICENSE`, `package.json`
(plus a couple of config files). `src/`, `index.html`, and `tsconfig.json` are excluded
via `.npmignore`. Verify the contents any time with:

```shell
npm pack --dry-run
```

---

## 2. Versioning model

Semantic Versioning (`MAJOR.MINOR.PATCH`), with optional pre-release suffixes
(`-beta.N`).

- **`main` always holds the latest *stable* release.** Its `package.json` version equals
  the current npm `latest` dist-tag.
- **Pre-releases (betas) are NOT merged into `main`.** They live only on their own
  version branches and are published to the npm `beta` dist-tag.

### Branch structure — one branch per version

Every release gets a dedicated branch named after its version:

```
v1.0.0, v1.0.1, … v1.0.17, v1.1.0, v1.1.1, v1.1.3,   ← stable lines
v2.0.0-beta.0, v2.0.0-beta.1, v2.0.0-beta.2,         ← pre-release lines
v2.0.0                                               ← stable release
```

Workflow: create the version branch → open a PR into `main` → merge.
(Feature work happens on `feat/*` branches that merge into the version branch first.)

> Stable version branches are merged into `main`. Beta branches are kept as history but
> are **not** merged into `main`.

### Tag structure

- Tags are **lightweight** and named after the version: `v2.0.0`, `v2.0.0-beta.2`, etc.
- A tag is created on the **merge commit** (for stable) or the release commit (for beta),
  **after** the branch is merged/finalized.
- Keep all historical branches and tags — never delete released tags.

> **Naming note:** historically tagging has been inconsistent (e.g. `v1.1.3-release` used a
> `-release` suffix, and some early `v1.0.x` branches were never tagged). Going forward use
> the **plain `vX.Y.Z`** form to match the v2.0.0 line.

### npm dist-tags

| dist-tag | Meaning | Set when you publish… |
|----------|---------|------------------------|
| `latest` | Current stable; what `npm install <pkg>` gives | a stable version with **no** `--tag` flag |
| `beta`   | Current pre-release | a beta with `--tag beta` |

Check live state: `npm view @viitorcloudtechnologies/everycred-verifier-js dist-tags`

---

## 3. Prerequisites for publishing

1. **npm account** that is a member of the `@viitorcloudtechnologies` org with
   **read+write** publish rights to this package.
2. **Two-factor authentication (2FA) is REQUIRED to publish.** The registry rejects
   publishes without it (see Troubleshooting → `E403`). You need either:
   - 2FA enabled on your account + a one-time code at publish time, **or**
   - a **granular access token** scoped to this package with **"Bypass 2FA"** enabled.
3. Be logged in: `npm whoami` should print your username.

---

## 4. Release process — STABLE (e.g. `2.0.0`)

> Example below promotes `2.0.0-beta.2` → `2.0.0`. Adjust versions as needed.

### Step 1 — Create the version branch & bump version
```shell
git checkout -b v2.0.0           # fresh branch from the finalized pre-release state
# edit package.json: "version": "2.0.0"
git add package.json
git commit -m "chore: release v2.0.0"
```

### Step 2 — Update docs
- `README.md`: version badge + any version mentions + config defaults that changed.
- Update/append release notes (`RELEASE_NOTES_*.md`) if you keep them.
```shell
git add README.md
git commit -m "docs: update README for v2.0.0 release"
```

### Step 3 — Push & open PR into `main`
```shell
git push -u origin v2.0.0
gh pr create --base main --head v2.0.0 \
  --title "Release v2.0.0" \
  --body "Promote 2.0.0-beta.2 to stable 2.0.0"
```
Get the PR reviewed & **merged**.

### Step 4 — Sync main & tag the merge commit
```shell
git checkout main
git pull origin main
# confirm package.json on main now shows the new version
git tag v2.0.0                       # lightweight tag on the merge commit
git push origin refs/tags/v2.0.0
```

### Step 5 — Build the artifact
```shell
npm run build-prod                   # tsc + webpack -> dist/
npm pack --dry-run                   # sanity-check tarball contents
```

### Step 6 — Publish to npm (`latest`)
```shell
npm whoami
npm publish --access public --otp=<6-digit-code>   # 2FA required (see §3)
```
Default publish sets the `latest` dist-tag. Because the new version is higher than the
previous stable, it becomes the install default automatically.

### Step 7 — Verify
```shell
npm view @viitorcloudtechnologies/everycred-verifier-js dist-tags
#   expect: { latest: '2.0.0', beta: '2.0.0-beta.2' }
npm view @viitorcloudtechnologies/everycred-verifier-js@2.0.0 version
```
Optionally create a **GitHub Release** from the `v2.0.0` tag using the release notes.

---

## 5. Release process — PRE-RELEASE / BETA (e.g. `2.0.0-beta.3`)

Betas do **not** merge into `main`.

```shell
git checkout -b v2.0.0-beta.3
# edit package.json: "version": "2.0.0-beta.3"
git commit -am "chore: release v2.0.0-beta.3"
git push -u origin v2.0.0-beta.3

git tag v2.0.0-beta.3
git push origin refs/tags/v2.0.0-beta.3

npm run build-prod
npm publish --access public --tag beta --otp=<6-digit-code>   # NOTE: --tag beta
```
Verify:
```shell
npm view @viitorcloudtechnologies/everycred-verifier-js dist-tags
#   expect: beta: '2.0.0-beta.3'  (latest unchanged)
```

---

## 6. Quick reference

| Action | Command |
|--------|---------|
| Who am I on npm | `npm whoami` |
| Build dist | `npm run build-prod` |
| Inspect tarball | `npm pack --dry-run` |
| Publish stable | `npm publish --access public --otp=<code>` |
| Publish beta | `npm publish --access public --tag beta --otp=<code>` |
| Check dist-tags | `npm view <pkg> dist-tags` |
| List published versions | `npm view <pkg> versions` |
| Create tag | `git tag vX.Y.Z <commit>` |
| Push tag | `git push origin refs/tags/vX.Y.Z` |
| Move a wrong tag | `git tag -d <t>` → `git tag <t> <commit>` → `git push origin :refs/tags/<t>` → `git push origin refs/tags/<t>` |

---

## 7. Troubleshooting

### `E403 … Two-factor authentication … is required to publish packages`
The org enforces 2FA on publish. Fix with one of:
- **One-time code:** `npm publish --access public --otp=<6-digit-code>` (read the fresh code
  from your authenticator right before running).
- **Granular access token with "Bypass 2FA":** create it on npmjs.com → Access Tokens →
  Granular, scope to this package with read+write, then
  `npm config set //registry.npmjs.org/:_authToken=<TOKEN>` and publish normally.
- If you have no 2FA at all, enable it first (npm → Account → Two-Factor Authentication).

### `E404 No match found for version X` when checking
The version was never successfully published. `npm view` only reads the registry —
re-running it won't change anything until a publish actually succeeds. Run the publish step.

### `npm publish` says version already exists
A given version can only be published **once**. Bump to a new version; you cannot overwrite
or re-publish the same number.

### A tag points at the wrong commit (it happens)
Lightweight tags can be moved. Delete locally and on remote, recreate, re-push:
```shell
git tag -d vX.Y.Z
git tag vX.Y.Z <correct-commit>
git push origin :refs/tags/vX.Y.Z      # delete the remote tag
git push origin refs/tags/vX.Y.Z       # push the corrected one
```
Anyone who already fetched the old tag must `git fetch --tags --force`.

---

## 8. Release checklist (copy into the PR)

- [ ] Version bumped in `package.json`
- [ ] `README.md` version badge + mentions + config defaults updated
- [ ] Release notes updated
- [ ] Version branch pushed, PR opened into `main`
- [ ] PR reviewed & merged
- [ ] `main` synced locally; version confirmed
- [ ] Tag `vX.Y.Z` created on the merge commit & pushed
- [ ] `npm run build-prod` succeeded; `npm pack --dry-run` looks correct
- [ ] `npm publish` succeeded (2FA/OTP supplied)
- [ ] `npm view … dist-tags` shows the expected `latest`/`beta`
- [ ] GitHub Release created from the tag (optional)
