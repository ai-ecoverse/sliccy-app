# Native UI integration contract

**Product direction update:** Sliccy is an access-management launcher. Transcript
views and the composer are removed from the UI; live linking no longer starts a
watcher. The prompt/watch sections below describe retained internal prototype
adapters, not active product behavior. See [Access management](ACCESS-MANAGEMENT.md)
for the current agent, model, credential and screen requirements.

Verified against the **v1.57.0**
release and its README on November 2, 2026. The CLI README is authoritative:
https://github.com/ai-ecoverse/slicc-cli/blob/v1.57.0/README.md

## Released support

- v1.51: `capabilities --json`, contract 1. Check supported commands and control
  operations, not version-string ordering. Unknown additive fields are tolerated.
- v1.52: lifecycle JSON for attach, open, pair, follow; connecting, reconnecting,
  errors with retryable; linked.resources reports browsers and ownership, effective
  and rejected mounts, network policy, compute, credential broker, kernel port.
- v1.53: control status.ops, detach, stop; default-run `--keep-browsers` makes
  SIGTERM leave launched browsers alive. SIGINT still closes them. JSON mode
  satisfies the keep-browsers noninteractive requirement.
- v1.54: `unpair --json` lists peers or returns removed/closed fingerprints.
  `revoke` closes current links and rechecks negotiating links when they come up;
  a closed snapshot may omit a link that closes afterward. Older processes without
  revoke retain their links. Paired-device management is not exposed in this UI yet.
- v1.55: `watch --since <id>`; own opened/head/gap/busy and reconnecting/attempt/wait
  events. Wait is milliseconds. There is still no full-history API or run id.
- v1.56: credential metadata events; process-local leases, unseal, seal-off and
  seal-on. Live operations require the owned process's status.ops. Unseal allows
  75 seconds for the broker (80-second client response deadline).
- v1.57: `agents --json --watch`, full snapshots with instance/agent IDs, counts,
  status, per-agent queue, provider/model and timestamps. Requires seven inventory
  support (bios#1240). Lower sequence means restart; repeated sequences refresh
  the report time. No names or transcripts are requested.
- A retryable error does not end a run. `closed` is the lifecycle terminal event;
  process exit also ends observation if startup failed before selection.
- Control sockets: `$TMPDIR/slicc-<uid>/<pid>.sock`, falling back to `/tmp` when
  the path is too long. Query status.ops before sending detach to an existing
  process. The app does not control external CLI processes yet.

## Implemented live path

New Session has an explicit live remote toggle. The adapter checks capabilities,
then invokes `slicc - follow --json` with the join URL on stdin. It offers no
network exit, shell, SFTP, folders, browsers or credential broker by default. Access displays
linked.resources; loss of a link clears that snapshot. Demo access editing is
not available for live sessions.

The inline credential switch explicitly reconnects with `--jerk-seal` when the
user first enables it. Subsequent changes use seal-on/off after querying status.ops.
Leases refresh from the owned child's same-user socket and update from lifecycle
events. Replies from previous process generations are discarded. Only acknowledged
revocations remove rows; a process-local tombstone prevents the known #601 stale
listing from restoring a released lease. Errors/timeouts retain unconfirmed state.
Metadata is memory-only; no broker tokens are read. Process exit leaves a warning
that leases may remain valid and need host-side jerk revocation. Provider revocation
and seven removal are never conflated. No real credential mutation was used for tests.

Agent inventory runs in a separate read-only `slicc - agents --json --watch`
child, with the join URL on stdin. It starts after a live link and stops on link
loss/disconnect. Inventory, errors and reconnects never enter transcript reducers.
Data stays in memory. The UI uses reported counts, distinguishes queued agents
from queued requests, and labels unknown provider/model fields. Full snapshots
replace prior rows even when seq decreases after a restart; same-sequence refreshes
are valid. Reports older than 60 seconds or a stopped stream are not shown as live.
Seven's report time and local receipt age are checked independently. Missing/future
or unparseable timestamps do not create a fresh count. Exit 1 gives an honest
update/start-agent suggestion; exit 3 explains Linked devices permission. There is
no stderr parsing, automatic permission grant or transcript subscription.

Prompts use `slicc - prompt --json [--steer] -`, with the join URL on stdin's first
line and prompt text afterward. Text deltas group by opaque transcript entry id;
there are no run ids. Follow-ups queue locally until the current prompt completes.
Failures clear queued prompts rather than silently sending them after a lost link.
Stop sends `slicc - abort` and waits for acknowledgement; cancelling a stream is
not presented as aborting the agent. Disconnect and app quit end owned follow
and prompt processes. Follow launches no browsers, so SIGTERM on this path cannot
close one. Browser-preserving default-run detach is deferred with browser launch.

Credentials stay in memory, never argv, UserDefaults or logs. Reconnecting after
app relaunch requests the join URL again. The CLI itself maintains its own
pairing/device state according to its contract. Session activity and drafts are
saved locally. Every live session restores disconnected; no implicit reconnect.

The subprocess adapter drains stdout off the main thread, discards human stderr,
limits buffers, accepts arbitrary UTF-8 boundaries, and reports nonzero exits.
Human stderr is never used to infer lifecycle state. The generic exit diagnostic
is currently less detailed than the CLI's human error output.

## Live Feed

Watch support is gated by capabilities.commands.watch and agent.own containing
opened/reconnecting. Compatible older CLIs still support the prompt workspace.
Each live session owns a separate `slicc - watch --json [--since <cursor>]` child,
started after linking. Closing the connection or quitting also stops the watcher.
A terminated watcher offers Retry; in-process reconnects are handled by the CLI.

The Live Feed has its own persisted entries and cursor, separate from prompt
responses. Its user events are labeled User, since they may originate elsewhere.
The cursor advances on consumed transcript entries, never on opened.head. On a
new watcher, the first replay of the saved text entry replaces that entry's text;
subsequent deltas append. During CLI-managed reconnects, slicc already removes
replayed prefixes and duplicate entries, so the app does not replace them again.
Gap events add a visible notice, clear the stale cursor and retain local history.
Run events have no id; busy state is unknown again when a stream reconnects.
Writes of feed data are coalesced to at most twice a second, plus shutdown saves.

The raw credential stays in memory. A SHA-256 fingerprint scopes the replay cursor
to the join URL across app launches. A changed URL clears the cursor and source ids
while preserving old visible activity. This also conservatively resets replay
when a URL rotates for the same remote seven.

## Fixtures and validation

`Tests/SliccyTests/Fixtures/` copies generated native integration fixtures from
v1.55.0's `test/integration/testdata/native/`, with credential/capabilities fixtures
updated to v1.56.0, and agents/capabilities to v1.57.0. The test version string is synthetic.
Tests cover handshake gates, lifecycle/error transitions, effective grants,
credential transport, restored state, entry ids, subprocess bytes/exit status,
watch replay across process restarts versus reconnects, gap notices, and cursor scoping.
The bundled release's actual capabilities response was also checked. No real
seven join credential was supplied for end-to-end live connection testing.

`script/fetch_cli.sh` downloads v1.57.0 with pinned per-architecture SHA-256
checksums. The build script bundles it if present; otherwise Settings can select
an installed binary. App-owned CLI updates must go through app packaging.

## Pending CLI / seven work

The lifecycle, control, pairing and resumable-watch CLI interfaces have shipped. Local browser
launch/pairing, control-socket detach and the unpair UI are still app integration
work. The prompt conversation shows prompts sent here; Live Feed watches activity
from seven and resumes only within its retained transcript. Unknown events are
ignored. Neither view claims complete initial history.

Host tray URL/rotate/unlink/retry, full history, run ids, attachment import and
seven-files access require seven/bios changes. `--mount` exports Mac folders to
seven; it does not implement a Finder File Provider for seven's files.
