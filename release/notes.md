# Sliccy 0.2.0

A native Mac companion for SLICC. Requires **macOS 27 or newer on Apple silicon**.

- Start SLICC in a dedicated browser profile, choose another supported browser or profile, or join a remote session.
- Inspect live agent and resource status. Browser control and network are on by default; shell, SFTP and credentials are opt-in.
- Bring the connected SLICC tab forward from the app.
- Check for signed updates automatically or from Sliccy → Check for Updates.
- Includes the Sliccstart icon and bundled, signed SLICC CLI 1.59.0.

Download the ZIP, extract it, and move Sliccy.app to Applications. The app is Developer-ID signed and notarized. Existing test builds do not include the updater; install this release once to receive future updates.

Screen capture remains disabled. Local access changes reconnect the CLI while preserving the browser. Network relay controls do not firewall browser traffic or shell commands. Updating or quitting the app disconnects its local links; reconnect after relaunch.
