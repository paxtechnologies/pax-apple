Vendored from https://github.com/apple/device-management (branch `release`,
commit 09f249a06e7e3289930bf6d05f38fb562f748ebf, 2026-09-17), MIT licence (see LICENSE.txt).
Used only by the test-suite to check that every key Pax emits exists in Apple's schema with the right type.

`skipkeys.yaml` (Setup Assistant skip keys) was fetched from the same repository's `release` branch on
2026-10-12 (Pax v0.2). It is used by `device/tests` to check every pane Pax skips is an Apple key.

`com.apple.ManagedClient.preferences.yaml` was fetched from the same repository's `release` branch on
2026-10-14 (Pax v0.4) to check the Mac self-lock profile's browser-policy payloads.

v0.5: `com.apple.applicationaccess.yaml` is **trimmed** to the header, the notes and the six
restriction keys Pax emits (`allowCloudPrivateRelay`, `allowEraseContentAndSettings`,
`allowUIConfigurationProfileInstallation`, `allowVPNCreation`, `blockedAppBundleIDs`,
`blacklistedAppBundleIDs`), so every file in the repo stays under ~90 KB. If Pax starts emitting
another restriction key, copy its block back in from the upstream file (same commit).
