# Build and signing

## Local development

Requires macOS 27 and Xcode 27 / Swift 6.2 or newer. Start with:

```sh
./script/local_build.sh --check
./script/local_build.sh
open dist/Sliccy.app
```

The first command checks the OS and selected SDK without downloading, compiling,
signing or launching. The second fetches checksum-pinned CLI 1.59.0 and uses
`script/build_and_run.sh --build` to build and ad-hoc sign the app. It does not
launch, install, notarize or upload anything. It rejects all proof-build flags.
If the wrong SDK is selected, choose Xcode 27 in Xcode Settings → Locations or set
`DEVELOPER_DIR` to the intended Xcode developer directory before building.

The app can run the UI and CLI integrations but cannot activate native screen
sharing. Screen controls are hidden; `--preview --screen-demo` exposes only the
simulated UI. The release policy still has no approved capture scopes or CLI
capture identities, and capture-audit maintenance stays off.

For an isolated UI preview, launch with:

```sh
open -n dist/Sliccy.app --args --preview --show-overview
```

This local-build path keeps the existing CLI pin. Newer runtime integration and
release signing are separate work; a local build is not a signed distribution.

## Hosted signing

The `Release Sliccy` workflow runs only for pushes to `main` in
`ai-ecoverse/sliccy-app`. It uses GitHub's `xcode-27` hosted runner, tests the app,
downloads the checksum-pinned CLI, and builds the bundle before accessing signing
credentials. The `signing` environment allows only the `main` branch. The PR test
workflow references no signing credentials.

The signing step consumes the existing organization secrets
`APPLE_CERTIFICATE_BASE64`, `APPLE_DEVELOPER_CERTIFICATE_PASSWORD`,
`APPLE_API_KEY_ID`, `APPLE_API_KEY_ISSUER_ID`, and `APPLE_API_KEY_P8_BASE64`.
`APPLE_TEAM_ID` is a public repository variable. Certificate import and notary key
files are private temporary files deleted on exit. Signing scripts reject events,
refs and repositories outside the upstream push-to-main path.

The app uses identifier `ai.sliccy.mac`, the version in `release/version.json`, Developer ID, hardened
runtime and empty entitlements. The bundled CLI retains its upstream signature and
bytes. The workflow notarizes and staples the app, verifies its signature and
Gatekeeper assessment, and uploads only the app ZIP, SHA-256 checksum and public
signing metadata. It does not upload signing keys, certificates or diagnostic logs.

Download the latest GitHub Release ZIP, verify `SHA256SUMS`, and extract it
with `ditto -x -k`. Verify locally with:

```sh
codesign --verify --deep --strict Sliccy.app
xcrun stapler validate Sliccy.app
spctl --assess --type execute Sliccy.app
codesign -dvvv Sliccy.app
```

A valid signed bundle does not enable screen capture. Runtime pins, native identity
validation and supported source scopes remain separate conditions in the app.

## Production release pipeline

The automatic main workflow now builds only the production app and publishes a versioned GitHub Release. The historical six-variant proof signing matrix is no longer run on ordinary main pushes. Its source and retained evidence remain in Git history; no capture dispatch is part of release publication.

Semantic-release derives the next version and notes from conventional commits since the last release tag. Fixes release a patch, features a minor, and breaking changes a major; chores/docs/tests alone skip publication. Its prepare hook generates `release/version.json` and `release/notes.md` in CI before testing/building/signing. The Sparkle build is incremented from the previous published appcast (or the higher checked-in baseline), independently of the semantic version. Generated files are retained as workflow artifacts, not committed back to main. `release/version.json` in Git is the local development baseline and feed/key configuration. Sparkle is pinned in `Package.swift` and `Package.resolved`, embedded in `Contents/Frameworks`, and signed inside-out by the existing Developer ID CI identity. The upstream CLI signature is preserved. The workflow signs the notarized ZIP using `SPARKLE_PRIVATE_KEY` from the signing environment and independently checks that signature against `SUPublicEDKey` before publishing. The feed is `releases/latest/download/appcast.xml`; archive URLs are immutable per-version release assets. ZIP, feed and checksums are uploaded to a draft before publication.

CI prefetches the Sparkle binary into the normal SwiftPM artifact cache using a 60-second pinned-manifest fetch and a 300-second archive fetch. The revision comes from `Package.resolved`; the checksum comes from that exact upstream manifest. A checksum mismatch fails before caching, and SwiftPM still checks the cached archive during resolution. This avoids an unbounded URLSession download consuming the entire release job. No dependency version or checksum is overridden.

Local `./script/local_build.sh` remains an ad-hoc development build with the updater disabled. Set `SLICCY_RELEASE=1` only when assembling a release candidate; CI alone imports Developer ID and notarization secrets. `Sliccy → Check for Updates…` and the General settings panel use Sparkle's standard UI. Automatic checks are on for release builds, automatic installation is off, and profiling is disabled.

The following sections describe historical diagnostic fixtures, not the production release route.

## Connection diagnostic build

The guarded signing workflow also produces a separate `Sliccy-IPC-Proof` artifact
(version 0.1.0, build 3). Only that compile-time variant accepts `--screen-proof`.
It reads a synthetic loopback join URL from stdin, launches the exact bundled
v1.58.1 CLI with isolated settings, and exercises the native connection and Stop
path. It refuses grants and image submission and starts no capture stream.
Its Stop Test panel and keyboard shortcut use the same stop relay as sharing.
The ordinary app retains disabled native screen authority. Diagnostic output
reports connection stages and elapsed times; it does not establish capture
exclusion or active-capture stop latency. Signed bundles are assembled only by CI.

The proof variant also supports fixed `--case parent-exec` and `--case lifecycle`
options after `--screen-proof`. The first uses a separate CI-signed helper to
replace the app process and clean up its inherited child. That helper is never
included in ordinary builds and has a different signing identifier. The second
checks child invalidation and stale identity refusal after reaping. Case results
use schema 2; the original no-capture diagnostic keeps schema 1. These diagnostic
paths do not request screen permission or enable image grants.
