# Optional computer access through Cua

Sliccy can connect a **local, connected SLICC session** to an independently
installed Cua app. This is computer access, not view-only capture: Cua can expose
screen, accessibility, keyboard/mouse, file and other tools according to its own
configuration. Sliccy's browser, shell and SFTP switches do not restrict those
tools. The old Sliccy native capture implementation remains disabled.

## Setup

1. Install [Cua Spaces](https://cua.ai/docs/cua-driver/guides/cua-spaces), or
   [standalone Cua Driver](https://cua.ai/docs/cua-driver/quickstart). Open it and
   complete its own Accessibility and Screen Recording setup. Sliccy does not
   install Cua, grant these permissions, or change its permission mode.
2. In a connected local browser session with **Network relay** enabled, find
   **Computer access via Cua**. Select the installation if both exist, then
   enable access and confirm.
3. Click **Copy Setup Command**, then run it in that session's **SLICC terminal**
   (not macOS Terminal). It replaces this connection's prior `sliccy-cua-<id>`
   MCP registration. The terminal can report that a prior registration did not
   exist before successfully adding it. `mcp list` in SLICC confirms registration;
   Sliccy reports bridge readiness, not successful remote registration.
4. Ask SLICC to consult Cua's `get_guide` before operating apps.

The setup command is a secret. It includes a random 256-bit capability URL. It
is scoped to an enablement lifetime, **not cryptographically bound to a browser
or agent**. Anyone holding it with access to this Mac's loopback interface can
use the bridge while enabled. Do not share it or paste it into an unrelated
session. SLICC may retain it in its MCP store and terminal history. Sliccy keeps
it only in memory; copying puts it on the system clipboard.

Turning access off, disconnecting, losing the CLI link, or quitting closes the
listener and terminates Sliccy's MCP proxy. It invalidates the URL without
changing Cua's OS grants, shared daemon, or other clients. An action already
forwarded may finish or have lasting effects (including launched apps or other
Cua-managed operations); the off switch does not undo it. Use Cua's controls to
stop its remaining operations. Re-enabling creates a fresh URL and requires
running the setup command again. Consent is not restored after app restart.
Remote join-URL connections are not supported by this first implementation.

## Integration boundary

No Cua library or binary is bundled. Discovery reads standard installs in
`~/Applications` and `/Applications` and checks their bundle metadata:

| Installation | Executable | Invocation |
|---|---|---|
| Stable Cua Spaces (`com.trycua.spaces.macos`) | `Contents/Helpers/cua-driver` | `mcp --embedded --socket ~/.cua/run/cua-driver.sock --host-bundle-id com.trycua.spaces.macos` |
| Cua Driver (`com.trycua.driver`) | `Contents/MacOS/cua-driver` | `mcp` |

The Spaces invocation connects to **Spaces' existing** service. Its `--embedded`
flag requires that service; Sliccy never starts `serve`, a direct runtime, or a
private embedded host. Missing/paused Spaces fails; there is no fallback to a
second standalone daemon. Custom channels, relocated apps, and custom Spaces
homes are not auto-detected. Metadata discovery is not a signature/notarization
verification of the independently installed app; users should install from Cua.

The process has a small explicit environment without inherited `CUA_DRIVER_*`
overrides. No `--direct`, grants, installer, updater, shell command, global agent
configuration modification, or permission probe is run. On macOS the ordinary
standalone MCP invocation proxies to CuaDriver.app, retaining Cua's TCC identity.

A loopback-only HTTP bridge translates the SLICC HTTP MCP client to newline
JSON-RPC over Cua's stdio MCP proxy. It initializes the upstream once, uses its
own request IDs, and preserves each downstream ID. The exposed HTTP subset uses
MCP `2025-06-18`; `server/discover` returns `-32601` so SLICC falls back to legacy
`initialize`. Tools and resources pass through; client sampling, roots,
elicitation, subscriptions and a long-lived SSE channel are not offered.

The listener binds **127.0.0.1**, a random port, and a fresh secret path. It
requires the matching numeric Host, rejects Origin headers (no direct browser
CORS), duplicate headers, chunked requests and pipelining. Requests must be
JSON POSTs with Content-Length. The existing CLI network relay supplies this
path; shell/SFTP access is unnecessary. Limits: 8 concurrent connections and
RPCs, 8 KiB HTTP headers, 1 MiB requests, 16 MiB MCP response frames, 50 s tool
request deadline, 10 s initialization and 60 s HTTP connection lifetime. A
protocol failure, upstream exit or RPC timeout closes the bridge; it does not
retry possibly completed actions. Larger captures must be reduced through Cua.

## License and permission ownership

This change is an independent protocol client. It neither copies Cua's source
nor redistributes Cua's binary, models or optional extensions. The Cua Driver
repository's [MIT license](https://github.com/trycua/cua/blob/01df64326f94f5b1f52b02d444a83382552875b0/LICENSE.md)
permits commercial integration. Cua Spaces and optional components have their
own terms, which users accept when installing them. Bundling them in a future
release would require a separate distribution/license review.

Upstream integration references, inspected against Driver 0.47.13:
- [Connect an agent](https://cua.ai/docs/cua-driver/guides/connect-your-agent)
- [Spaces installation and permission ownership](https://cua.ai/docs/cua-driver/guides/cua-spaces)
- [Spaces' MCP invocation](https://github.com/trycua/cua/blob/01df64326f94f5b1f52b02d444a83382552875b0/apps/cua-spaces-macos/Sources/CuaSpacesMacKit/Models/EmbeddedDriver.swift)

## Validation and remaining manual check

`CuaAccessTests` exercises actual loopback HTTP → stdio JSON-RPC using a synthetic
Python MCP server. It covers discovery, initialize/list/call, request IDs,
secret-path rejection, Host/Origin/framing/size restrictions, EOF/timeout, token
rotation, disconnect and nonpersistent consent. It performs no real GUI access.

Before release, test a disposable local SLICC session with each supported Cua
installation: registration, `get_guide`, a deliberately selected test window,
off/re-enable and Cua-denied permission. Confirm the OS permission entry belongs
to the chosen Cua app. Full SLICC/Cua GUI end-to-end testing is not established
by the synthetic bridge tests, and Cua's general desktop access does not inherit
the old proof's exclusions or capture guarantees.
