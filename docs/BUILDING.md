# Build and signing

Local builds use `script/build_and_run.sh --build` and ad-hoc signing. They can
run the UI and CLI integrations but cannot activate native screen sharing.

The `Signed app` workflow runs only for pushes to `main` in
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

The app uses identifier `ai.sliccy.mac`, version `0.1.0`, Developer ID, hardened
runtime and empty entitlements. The bundled CLI retains its upstream signature and
bytes. The workflow notarizes and staples the app, verifies its signature and
Gatekeeper assessment, and uploads only the app ZIP, SHA-256 checksum and public
signing metadata. It does not upload signing keys, certificates or diagnostic logs.

Download the successful workflow's `Sliccy-0.1.0-arm64-<commit>` artifact, verify
`SHA256SUMS`, and extract the ZIP with `ditto -x -k`. Verify locally with:

```sh
codesign --verify --deep --strict Sliccy.app
xcrun stapler validate Sliccy.app
spctl --assess --type execute Sliccy.app
codesign -dvvv Sliccy.app
```

A valid signed bundle does not enable screen capture. Runtime pins, native identity
validation and supported source scopes remain separate conditions in the app.
