# Access management

Sliccy manages seven instances and their access from one native window. It does
not display session transcripts or compose prompts.

## Unified entitlement view

The instance view puts browser, network, shell, SFTP, credential, folder and screen
access together with inline switches. Wide windows use two columns; narrow windows
stack the same sections. Folder switches retain their configured paths and access
mode. SFTP requires shell access, so disabling shell also disables SFTP.

Sample instances provide interactive demonstrations. Their switches change sample
state only. Screen selection lists sample windows and never requests recording
permission, captures pixels, or transmits content. Disconnecting or relaunching
clears simulated screen access.

## Live connections

A live remote connection uses the CLI's JSON lifecycle events and reported resource
grants. New connections offer no local resources by default. Browser, network,
shell and folder grants are currently read-only in the live view.

Agent inventory comes from whole snapshots reported by seven through the CLI.
The view shows running counts, provider/model, opaque agent and parent identifiers,
status and queued requests. Missing names are not invented, missing models remain
unreported, and stale or disconnected inventory is labeled. An unsupported seven
shows an update/start-agent message and Retry.

Credential controls distinguish future issuance from already-issued leases.
Enabling the broker for the first time reconnects after the user's explicit
choice. Subsequent issuance switches use seal-on/seal-off; each lease has a revoke
switch. Changes wait for acknowledgement. Revocation at the provider and removal
from seven are separate outcomes. Lease metadata is kept in memory; the app never
reads credential tokens or treats a lease list as the complete vault inventory.

## Screen sharing status

Screen controls are currently explicit mocks. Native view-only components are
under development: ScreenCaptureKit filter construction, private CLI transport,
bounded JPEG encoding, a local sharing indicator and stop shortcut, and
content-free audit records. Input injection is not implemented.

The development app has no approved screen runtime pins or enabled capture scopes.
Signing an app does not enable screen sharing. Native runtime integration and
source validation must pass before these components can be connected to the UI.

The filter probe constructs real ScreenCaptureKit filters around a synthetic
window and consumes the CLI's fixture vectors without starting a capture stream.
It verifies construction behavior, not capture exclusion or end-to-end sharing.
Every source or protection change ends the view session. A subsequent local grant
must create a fresh session; its frame sequence starts again at 1. An invalidated
output gate cannot resume or accept an updated binding.

Audit files use UTC day buckets and share a 100 MiB quota with the CLI. Cleanup
removes files aged 30 days from the earlier of their bucket start or modification
time; appends do not extend retention. The app sweeps both app and broker journals
at startup, every five minutes while running, and after wake, even with no active
connection or audit events. A shared lock coordinates cleanup with both writers;
contention defers a sweep until the next scheduled attempt. Invalid journal
entries cause cleanup to fail and report a fixed diagnostic without record data.

The app also cleans broker journals while the broker is stopped. With both
processes stopped or the Mac asleep, no cleanup runs; the next startup or wake
performs it. No background daemon is installed. Preview mode does not touch the
user's journals. Audit writes continue to prune before appending.

See [CLI contracts](CLI-CONTRACT.md) for released functionality and fixture versions.
