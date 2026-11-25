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

Approvals run in another separate child, `slicc - approvals --json --watch` (or
`approvals --cdp <endpoint> --origin … --json --watch` for local sessions), started on
`linked` and stopped on link loss or disconnect. It is gated on `capabilities --json`
listing `approvals` (events) and `decide`. Each `approvals` event is a whole snapshot of
seven's pending `user`-tier items; an item that leaves it has settled, and its
notification is withdrawn. Items are kept in memory only. `reconnecting`, `error` and
process exit mark the list not live and disable answers. Exit 1 from the watcher means
seven doesn't support approvals; exit 3 explains the Linked devices permission.

Each answer runs `slicc - decide --json -- <id> once|always|deny|stop` and waits for it.
Exit 0 with a `decided` line is answered (the row waits for the next snapshot). Exit 1
shows the `error` line's `message`, the agent's refusal sentence, and exit 3 (`EACCES`)
explains Linked devices. stderr is not read. Always is offered only when the item's `always` is true, Deny and
stop only when `stoppable` is true; missing flags mean not offered. Notifications offer
Allow once (requiring an unlocked Mac) and Deny only. Their body is the item's scrubbed
detail, which macOS may show on the lock screen depending on preview settings. Guest message text is a prompt and is never displayed.
`Tests/SliccyTests/Fixtures/approvals.ndjson` and `capabilities-approvals.json` are copied
from slicc-cli v1.68.0's `test/integration/testdata/native/`; the released binary's
`capabilities --json` lists `approvals` and `decide` as events commands and agent ops. When the CLI reports `agent.ops`,
it must also list `approvals` and `decide`.

Prompts use `slicc - prompt --json [--steer] -`, with the join URL on stdin's first
line and prompt text afterward. Text deltas group by opaque transcript entry id;
there are no run ids. Follow-ups queue locally until the current prompt completes.
Failures clear queued prompts rather than silently sending them after a lost link.
Stop sends `slicc - abort` and waits for acknowledgement; cancelling a stream is
not presented as aborting the agent. Disconnect and app quit end owned follow
and prompt processes. Follow launches no browsers, so SIGTERM on this path cannot
close one. Browser-preserving default-run detach is deferred with browser launch.

Credentials never go to argv, UserDefaults or logs. A join URL that linked is kept
in the login keychain, and on signed iCloud builds in iCloud key-value storage in
slicc's `RecentJoinStore` format (see the README). Reconnecting after relaunch
uses it; a session without one requests the join URL again. The CLI itself maintains its own
pairing/device state according to its contract. Session activity and drafts are
saved locally. Every live session restores disconnected; no implicit reconnect,
except after an in-app update relaunch. That case follows the CLI's dashboard
update (`SLICC_RESUME`): the old app detaches local links with `--keep-browsers`
and records only session IDs, credential-offer state and the old CLI PIDs (never a
join URL) with the old build number. The new app consumes the record once. It
ignores a record from its own build or one older than 10 minutes. It waits for the old
PIDs as an access change does. If they exited, it links those sessions again: local
ones, and remote ones with a saved join URL. See `UpdateResume`.

The subprocess adapter drains stdout off the main thread, limits buffers, accepts
arbitrary UTF-8 boundaries, and reports nonzero exits. The local-browser and follow
children also drain human stderr into bounded, printable status lines. Each complete
line is redacted before it is cleaned and cut to 240 characters; a raw line over 8 KiB
is dropped whole. The reader keeps the last three lines and wakes the main actor at
most once per drain. The output stream reports exit only after stderr reaches EOF
(waiting at most one second), so a nonzero exit includes the final line. Other
children still discard stderr.

Status lines are display-only and never change lifecycle state. Text the app derives
(status lines, the CLI's waiting reason, stall advice) only replaces an empty
connection message or one it derived itself; a JSON-contract message such as an
`error` stays until the contract clears it. The saved stall notice omits stderr.

## Local browser launch and stalled links

In SLICC six's profile (`--profile six`) the app passes no `--page`, so the CLI
opens its documented six page `https://www.sliccy.ai/7/` and adopts only tabs on
six's app routes. `--origin https://www.sliccy.ai` keeps the origin explicit. Other
profiles pass `--page https://www.sliccy.ai/7/`; the bare origin redirects (to
sliccy.com without six's service worker). Inventory (`agents --cdp … --origin`) and
tab activation use the same origin.

If `linked` doesn't follow seven's `attached`/`launched` within 20 seconds, the
session shows Waiting for SLICC and explains that the tab hasn't linked, with the
latest status line, and suggests closing duplicate SLICC tabs and Retry Connection.
For `no-seven-tab` it says that the browser has no SLICC tab instead.
The CLI process is not stopped. When `capabilities --json` lists a `waiting`
lifecycle event (slicc-cli#782: `reason` `no-ready-seven` or `no-seven-tab`,
`message`, `candidates`), its message is shown at once and replaces the status line
in that explanation. Older CLIs, such as 1.67.12, use the timer only; the bundled 1.68.0 lists it.

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

The raw credential is never saved with the session. A SHA-256 fingerprint scopes the replay cursor
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

`script/fetch_cli.sh` downloads v1.68.0 with pinned per-architecture SHA-256
checksums and verifies its Developer ID role and Team ID. This bundling pin does
not enable native screen grants; runtime screen pins and capture scopes remain
disabled pending native validation. The build script bundles it if present;
otherwise Settings can select an installed binary. App-owned CLI updates must go through app packaging.

## Signed browser leases (unreleased, disabled)

A **Browser leases · one task tab** section on a local live connection is distinct
from Browser control, Keys & credentials, and Seven approvals. With the bundled
v1.68.0 CLI it says **Browser leases unavailable**; no connect/grant button is
offered. No `decide`, browser-sharing switch or ordinary follow fallback.

**Selecting a route.** The owner selects a local browser/profile with the
existing picker. This increment only accepts a connected browser *launched by
its owned CLI*. It does not launch a browser for a remote job, discover a
localhost service, or adopt an arbitrary browser. It retains the literal
loopback HTTP origin (port required) from that process's lifecycle event in
memory. For a dedicated, previously paired job tray the owner supplies a local
link label (`^[a-z][a-z0-9-]{0,47}$`, no normalization) and the HTTPS join URL
in a secure field. Comparing device
fingerprints and pinning the peer under that label is a broker prerequisite;
Sliccy does not perform pairing or silently trust a new peer.

**Launch gates.** In addition to the usual native contract, the executable's
`capabilities --json` must report `commands.follow.cdpLeaseV1: true` and
`control.ops` must include `status` and all four operations below. Check again
before starting a separate child with `- follow --json --lease-browser <origin>
--name <label>`. The join URL goes on stdin; Sliccy never puts it in argv,
the keychain or iCloud. No automatic restart of this child on app or parent-session restart.
No agent inventory, notifications, human stderr, credential offers or approval
watcher for it. A relink invalidates all open review sheets.

**Owner control v1.** Only the app-owned, linked child's UID- and peer-PID-
checked Unix socket is used. Require its `status.pid` to match, `status.offers`
**exactly** `["cdp-lease-v1"]`, and `status.ops` to include all operations. No
PID, socket path or browser endpoint comes from the requester.

| op | arguments | success |
|---|---|---|
| `cdp-lease-list` | none | `{v:1,ok:true,pending:[…],active:[…]}` |
| `cdp-lease-approve` / `cdp-lease-deny` | `request` | `{v:1,ok:true}`; reload |
| `cdp-lease-revoke` | `lease` | `{v:1,ok:true}`; reload |

Requests also carry `v:1`. The broker projects metadata only: full bare RFC 7638
`jkt`, `browser` (must equal the selected origin), `link` (must equal the
selected label) and typed `allow:[{kind,url}]`. Each pending row has `request`
and **either** `ttlSeconds` (initial) **or** `parent` (expansion). Active rows
have `lease` and `exp` (exclusive Unix seconds). Never put a compact grant,
private key, login/tray secret or secret-bearing URL in this projection. Display
only validated fields, locally and in memory. IDs in this protocol are not
authority. No lease metadata or outcomes enter the persisted session history.

Opening a sheet does nothing. Review the full fingerprint, rule type, literal
URL, browser/profile, link and duration. Return selects **Deny**; Escape leaves
the request pending. For an expansion show only additions beside what stays,
with the active parent's actual deadline and no time extension. Denial leaves
the original scope intact. An unmatched, changed or expired parent cannot be
approved. Each decision rechecks the route and reads a fresh list; do not send
from an invalidated sheet or retry an ambiguous acknowledgement. Refresh is
manual. The broker must atomically validate the immutable offer, parent, time,
worker and browser epoch at mutation; UI preflight is not authorization.

**Release gate and verification.** `BrowserLeaseControl.verifiedForRelease` is
false in this increment, with no CLI flag, preference or environment override.
The static or dynamic claims of a development binary alone cannot turn this
on. Run `swift test --filter BrowserLeaseTests` for the disposable local
executable/socket fixture, including startup, expiry, changed offers, denial,
replacement, revoke, a lost ack, and missing/excess capabilities. It uses a
fresh Ed25519 test holder and never opens a browser. The released v1.68.0
binary's actual capabilities omit the launch bit and the four lease ops.

Before enabling, repeat the owner flows with a real paired broker and job
adapter, disposable keys and a fresh test profile; confirm no grant before
explicit approval, no access on denial, retained expiry and same task tab on
expansion, and no data after expiry, revoke, peer mismatch or link loss. Verify
broker proof/replay checks, guarded redirects/frames and mediated action/output
containment. Inspect keyboard/default action and full URL/fingerprint rendering
in the actual native sheet. Fixture success is **not** that release evidence.

## Pending CLI / seven work

The lifecycle, control, pairing and resumable-watch CLI interfaces have shipped. Local browser
launch/pairing, control-socket detach and the unpair UI are still app integration
work. The prompt conversation shows prompts sent here; Live Feed watches activity
from seven and resumes only within its retained transcript. Unknown events are
ignored. Neither view claims complete initial history.

Host tray URL/rotate/unlink/retry, full history, run ids, attachment import and
seven-files access require seven/bios changes. `--mount` exports Mac folders to
seven; it does not implement a Finder File Provider for seven's files.
