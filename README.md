# Sliccy

A native macOS 27 launcher for managing seven instances and their access, built
with SwiftUI and AppKit. The unified entitlement view prioritizes running agents, model assignments,
shared credential metadata and screen access. Transcripts and prompt composition
are not part of the launcher UI.

## Run

Requires macOS 27 and Xcode 27 / Swift 6.2 or newer. No Swift package dependencies.

```sh
./script/fetch_cli.sh       # pinned, checksum-verified CLI v1.58.1
./script/build_and_run.sh
/usr/bin/xcrun swift test
```

The CLI is bundled without replacing the system installation. Settings → Runtime
can select another executable and check compatibility. The build script stages and
ad-hoc signs `dist/Sliccy.app`; this is a development build, not notarized.
The push-to-main workflow produces a Developer-ID-signed and notarized test artifact;
see [build and signing](docs/BUILDING.md). Signing does not enable screen sharing.
`--build`, `--verify`, `--debug`, `--logs`, and `--telemetry` support development.
Launch with `--preview --show-overview` for an in-memory demo that does not change saved sessions.

## Current behavior

- The native overview shows sample agents and their models, credential scopes,
  demo credential switches, and a view-only screen-sharing mock.
- One view contains inline switches for browser, network, shell, SFTP, credentials,
  folder sharing and write access, and screen access. No tabs or edit dialog.
  The folder picker adds paths; switching access off retains the folder configuration.
- Screen scope can be full screen (all apps) or a selected window, both view-only.
  The two scopes are alternatives, each with an immediate off switch.
- New Session offers opt-in live remote connections through `slicc - follow --json`.
  Live connections report lifecycle and effective resource grants. They offer no
  Mac folders, browser, network exit, shell or credential broker by default. They do not start
  transcript watching or fetch conversation history.
- Live credential controls use v1.56's process-local lease metadata. “Allow new
  credentials” explicitly enables the broker (reconnecting once), then controls
  future issuance. Each issued lease has an off switch to request revocation.
  Provider revocation and seven vault removal are reported separately.
- Live agent inventory uses `agents --json --watch` from CLI v1.57: running counts,
  opaque agent/parent IDs, status, queued requests, provider and model. Whole snapshots
  replace rows, including after agent restarts. Stale/disconnected data is labeled.
  Seven must support inventory (bios#1240); unsupported instances show an unavailable
  message and Retry. No names are invented, and missing models stay unreported.
- Complete vault inventories are not reported; lease metadata is not vault contents.
- Screen selection remains demo-only. No screen is captured or OS capture permission requested.
  Credential controls send metadata-only requests to the app-owned CLI; the app never reads tokens.
- Instance settings and sample grants persist locally. Join URLs stay in app memory
  and pass to the CLI via stdin; reconnect after relaunch asks for the URL again.
- Closing the window keeps the menu-bar app running. Quitting disconnects live
  links. Live connections and simulated screen sharing never resume automatically.

Native view-only components are being integrated; the development app cannot
activate them. Verification commands:

```sh
./script/test_screen_filter.sh  # real SCK construction, synthetic window, no capture
./script/test_screen_socket.sh  # descriptor rejection and private child bootstrap
```

These probes do not establish capture exclusion or signed end-to-end readiness.

See [access-management design and dependencies](docs/ACCESS-MANAGEMENT.md) for the
approved agent-inventory work and proposed credential/screen contracts. The
[CLI contract](docs/CLI-CONTRACT.md) records released transport capabilities and
the older internal prototype adapters, now removed from the user-facing flow.
