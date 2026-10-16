# Automatic updates (v0.8.0)

On a protected Mac the everyday account is a **Standard** user, and only `paxadmin` (whose password
sits behind the wait) is an administrator. Updates therefore have to be installed by something that is
already root: **pax-guard** (`guard/pax_update.py`). The app only shows the state (Settings › Updates)
and offers **Update now**; updates can't be switched off.

## Why not Sparkle

* Sparkle's installer runs in the user's session and asks for an administrator to replace an app in
  `/Applications`. The Standard user can't give one, so every update would stall, or Pax would have to
  hand the user a way to elevate, which is exactly what Pax prevents.
* It only updates the app bundle; Pax must also update `/Library/PaxGuard` (the root daemon) in step with
  it, and roll both back together.
* It adds a framework plus XPC services to a project that otherwise ships only Apple frameworks and the
  Command Line Tools' Python, and its EdDSA check duplicates the Ed25519 verification pax-guard already
  has.

## How it works

1. At most every 6 hours (or on **Update now**) pax-guard fetches `pax-update.json` from
   `https://github.com/paxtechnologies/pax-apple/releases/latest/download/pax-update.json`, else the
   jsDelivr mirror (`@releases` branch).
   **v0.8.6:** the update zip (about 75 MB with the bundled Python) is over jsDelivr's 20 MB per-file
   limit, so the mirror carries it as **parts** of at most 15 MiB (`parts/<version>/Pax-<v>.zip.part-NNN`
   on the `releases` branch, and the same files on the GitHub Release). The signed manifest lists each
   part's name, size and SHA-256 and the base URLs; pax-guard tries the whole zip from GitHub first, then
   fetches every part from the first base that serves it intact, joins them, and checks the joined file
   against the zip's signed SHA-256 and size before unpacking anything. So the Ed25519 signature covers
   exactly the bytes installed, from either source. Splitting was chosen over shipping the runtime as a
   separate asset: the app stays one signed, notarised bundle (the iPhone helper needs the runtime inside
   it), and there is still one thing to verify, unpack and roll back.
2. The manifest must be signed by a pinned Ed25519 key (`guard/pax_signing.py`, also in
   `PaxCore/Updates.swift`). Unsigned or wrongly signed manifests are ignored.
3. No downgrades; a manifest older than one already seen is refused (stale mirror).
4. `installed < minimum_version` installs at once with a calm notice; otherwise silently when Pax isn't
   open, or after 24 hours.
5. The zip is checked (SHA-256 and size from the manifest), unpacked, its version checked,
   `codesign --verify --deep --strict` run, the Team ID compared when the installed app has a Developer
   ID, and the new pax-guard self-tested. v0.8.6: the new app's Python is copied for pax-guard
   (`updates/staging/runtime`, checked against Team ID Z94GSK7JA8 and every file's hash; see
   `guard/guard_runtime.py`) and the self-test runs on that copy.
6. Swap with rollback: the old app, guard and (v0.8.6) runtime move to `/Library/PaxGuard/updates/rollback`;
   a watchdog (on the *old* runtime) restarts pax-guard and, if the new one doesn't report healthy within
   3 minutes, puts the old ones back and marks that version bad. `/etc/hosts` and pf stay in force
   throughout.

Filter lists update separately and daily from the signed `lists-manifest.json` under the release tag
`lists` (`guard/filter_lists.py`, [FILTER_LISTS.md](FILTER_LISTS.md)).

## The manifest

```json
{"payload": {"schema": "pax.update.v1", "version": "0.8.1", "minimum_version": "0.8.0",
             "url": "https://github.com/paxtechnologies/pax-apple/releases/download/v0.8.1/Pax-0.8.1.zip",
             "mirrors": [],
             "sha256": "<hex of the whole zip>", "size": 78123456, "published_at": "2026-10-20T00:00:00+00:00",
             "parts": {"base_urls": ["https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/parts/0.8.1/",
                                     "https://github.com/paxtechnologies/pax-apple/releases/download/v0.8.1/"],
                       "files": [{"name": "Pax-0.8.1.zip.part-000", "size": 15728640, "sha256": "<hex>"}, "..."]}},
 "signature": "<base64 Ed25519 over the canonical payload>", "key_id": "<8 hex>"}
```

`parts` (v0.8.6) is an addition: the schema stays `pax.update.v1` and every older field means what it
did, so 0.8.4/0.8.5 pax-guard (whole zip from GitHub, ignores `parts`), the app's own check
(`UpdateManifest`) and the server self-updater (reads `version`, then clones the tag) read it unchanged.
Up to 0.8.5 `mirrors` held the jsDelivr copy of the whole zip; it stays empty now, because jsDelivr
refuses files over 20 MB.

Canonical payload = `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
in UTF-8; Swift builds the same bytes (`SignedDocument.canonical`).

## Releasing

1. Bump `PAX_VERSION` in `.github/workflows/build-dmg.yml`, and the app and pax-guard versions.
2. Push a tag `v<version>`. The **Build DMG** workflow builds `Pax-<version>.dmg` and `Pax-<version>.zip`,
   then (tags only):
   * signs `pax-update.json` with `scripts/sign-release.py` using the secret `PAX_UPDATE_SIGNING_KEY`
     (it refuses to run without the secret, or with a key that isn't pinned);
   * splits the zip into parts (`--parts-dir`, `--part-base` for jsDelivr and the release; each under
     20 MB, checked) and signs them into the manifest; `verify --parts-dir` checks they join into the zip;
   * creates the GitHub Release `v<version>` (marked latest) with the DMG, zip, parts and manifest;
   * re-signs and uploads the filter lists to the release `lists` (a prerelease, never "latest", so
     `releases/latest` keeps pointing at the app);
   * force-pushes the mirrors: branch `releases` (manifest + `parts/<version>/`; no whole zip since v0.8.6)
     and branch `pax-lists` (lists).
3. Locally you can do the same by hand:
   ```sh
   python3 scripts/sign-release.py sign --zip mac-app/dist/Pax-0.8.6.zip --version 0.8.6 \
       --parts-dir parts --part-base https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/parts/0.8.6/ \
       --key-file /path/to/PAX_UPDATE_SIGNING_KEY.txt --out pax-update.json
   python3 scripts/sign-release.py verify pax-update.json --zip mac-app/dist/Pax-0.8.6.zip --parts-dir parts
   ```

## The signing key

* Private key: base64 of a 32-byte Ed25519 seed. It lives **only** in the GitHub Actions secret
  `PAX_UPDATE_SIGNING_KEY` (repo Settings › Secrets and variables › Actions) and in the maintainer's own safe
  copy. Never commit it.
* Public key (pinned): `0ad387f103fcd5104604b968741da264cc6e97242aaf228b2e2f57d80f497204`.
* New key: `scripts/sign-release.py keygen --out new-key.txt` prints only the public key.
* Rotation: add the new public key to `PUBLIC_KEYS_HEX` (guard) and `UpdatePolicy.publicKeysHex` (app),
  ship a release signed with the **old** key, then switch the secret to the new key.
* Lost key: Macs can't take signed updates any more; ship a manual DMG that pins a new key.
