# Sliccy

A native macOS 27 launcher for managing SLICC instances and their access, built
with SwiftUI and AppKit. The unified entitlement view prioritizes running agents, model assignments,
shared credential metadata and screen access. Transcripts and prompt composition
are not part of the launcher UI.

## Local build

Requires macOS 27 and Xcode 27 / Swift 6.2 or newer. No Swift package dependencies.

```sh
./script/local_build.sh --check  # macOS / selected Xcode prerequisites only
./script/local_build.sh          # fetch pinned CLI v1.59.0, build; do not launch
open dist/Sliccy.app             # launch when ready
```

The local build rejects proof-build flags and leaves native capture disabled.
It requires network access to fetch the checksum-verified CLI. The CLI is bundled
without replacing the system installation. Settings → Runtime
can select another executable and check compatibility. The build script stages and
ad-hoc signs `dist/Sliccy.app`; this is a development build, not notarized.
The push-to-main workflow publishes a Developer-ID-signed and notarized GitHub release when the release version increases;
see [build and signing](docs/BUILDING.md). Signing does not enable screen sharing.
`--build`, `--verify`, `--debug`, `--logs`, and `--telemetry` support development.
To try the UI without loading or changing saved sessions:

```sh
open -n dist/Sliccy.app --args --preview --show-overview
```

Screen controls are hidden by default. Add `--screen-demo` to that preview command
to show simulated controls; this does not enable native capture or request screen
permission. Capture-audit maintenance does not start while the release policy is disabled.

The bundled CLI is the existing integration baseline, not a claim of compatibility
with newer CLI releases. Updating it is separate from getting this local build running.

## Current behavior

- Normal launches show saved real connections, initially disconnected, or an empty
  connection screen. New Session joins an existing SLICC instance using its join URL.
  Sample sessions and their simulated controls are available only with `--preview`.
  Old demo data is preserved separately and no longer appears in the normal workspace.
- Live agent/model and credential rows come from the connected runtime; missing
  data stays unavailable. Local sessions launch or reuse the SLICC Chrome profile through the bundled CLI, with browser and network access. Disconnecting preserves Chrome and its profile.
- One view contains inline switches for browser, network, shell, SFTP, credentials,
  folder sharing and write access. No tabs or edit dialog.
  The folder picker adds paths; switching access off retains the folder configuration.
- In the optional screen demo, scope can be full screen (all apps) or a selected window, both view-only.
  The two scopes are alternatives, each with an immediate off switch.
- New Session connects through `slicc - follow --json`.
  Live connections report lifecycle and effective resource grants. They offer no
  Mac folders, browser, network exit, shell or credential broker by default. They do not start
  transcript watching or fetch conversation history.
- Live credential controls use v1.56's process-local lease metadata. “Allow new
  credentials” explicitly enables the broker (reconnecting once), then controls
  future issuance. Each issued lease has an off switch to request revocation.
  Provider revocation and SLICC vault removal are reported separately.
- Live agent inventory uses `agents --json --watch` from CLI v1.57: running counts,
  opaque agent/parent IDs, status, queued requests, provider and model. Whole snapshots
  replace rows, including after agent restarts. Stale/disconnected data is labeled.
  SLICC must support inventory (bios#1240); unsupported instances show an unavailable
  message and Retry. No names are invented, and missing models stay unreported.
- Complete vault inventories are not reported; lease metadata is not vault contents.
- Screen selection remains demo-only. No screen is captured or OS capture permission requested.
  Credential controls send metadata-only requests to the app-owned CLI; the app never reads tokens.
- Instance settings and sample grants persist locally. Join URLs stay in app memory
  and pass to the CLI via stdin; reconnect after relaunch asks for the URL again.
- Closing the window keeps the menu-bar app running. Quitting disconnects live
  links. Live connections and simulated screen sharing never resume automatically.

Native view-only components remain disabled. The bounded hosted capture trial is
closed with [explicit limitations](https://github.com/ai-ecoverse/sliccy-app/issues/11);
no end-to-end case passed. Capture probes and proof builds are not part of the local
UI build instructions.

See [access-management design and dependencies](docs/ACCESS-MANAGEMENT.md) for the
approved agent-inventory work and proposed credential/screen contracts. The
[CLI contract](docs/CLI-CONTRACT.md) records released transport capabilities and
the older internal prototype adapters, now removed from the user-facing flow.

### Local browser controls

Local sessions report the CLI's live capabilities and network policy. Access changes
reconnect the owned CLI after its previous process exits, keeping the selected browser open.
Browser control off disconnects the whole local link. Network relay off denies
IPv4, IPv6 and the CLI's explicit LAN/loopback allow ranges, and disables its
kernel listener; it does not firewall Chrome or commands run through shell access.
Shell and SFTP are explicit opt-ins (SFTP also needs shell). Credential offering is
memory-only; turning it off does not revoke leases already issued.

“Show in [browser]” activates the unique SLICC app tab at the CLI-reported local
endpoint. It does not create a duplicate tab or navigate unrelated tabs. The welcome
screen defaults to the existing dedicated Chrome profile. Browser and profile menus
let you choose an installed Chrome, Edge, Brave or Chromium browser and an existing
SLICC profile, or name a new profile. These are separate from everyday browser
profiles. New sessions enable browser control and network, with shell and SFTP off.
The same choices are available in the new-session form.

### Releases and automatic updates

Download the latest signed [GitHub release](https://github.com/ai-ecoverse/sliccy-app/releases/latest), open the DMG, and drag Sliccy to Applications. The release supports Apple silicon and macOS 27 or newer. Install 0.2.0 once if you are using an older test build.

Release builds use Sparkle 2.10.1 to check for updates automatically. Use **Sliccy → Check for Updates…** or **Settings → General** to check manually or disable automatic checks. Installation requires confirmation and restarts Sliccy; Chrome stays open, and local links need reconnecting. Update archives are Ed25519-signed in addition to Developer ID signing and notarization. Development/preview/proof builds do not start the updater.

Maintainers: update `release/version.json` (both version and monotonically increasing build) and `release/notes.md`, then push reviewed code to main. The release workflow tests, builds, signs nested Sparkle components and the app, notarizes/staples, verifies the update signature against the bundled public key, and publishes a signed/notarized DMG, the updater ZIP, SHA256SUMS and appcast together. Existing versions are never overwritten. The Sparkle private key is in the GitHub `signing` environment and the local `ai.ecoverse.sliccy-app` Keychain account; it is never committed. See [Sparkle's integration guide](https://sparkle-project.org/documentation/) for the upstream update model.
