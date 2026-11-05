#!/bin/bash
set -euo pipefail
umask 077
[[ $# == 0 && "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/proof/helper12-signing-v1 && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == macOS && "${RUNNER_ARCH:-}" == ARM64 ]] || { echo 'Helper12 requires its reviewed hosted signing branch.' >&2; exit 2; }
cd "$(dirname "$0")/.."
[[ "$(/usr/bin/git rev-parse HEAD)" == "$GITHUB_SHA" ]] || exit 2
[[ ! -e dist-helper12 ]] || exit 2
python3 -B Tests/Helper12Packaging/test_source.py
./script/test_surface_presence.sh
surface_app=dist-helper12/ScreenProofSurface.app
mkdir -p "$surface_app/Contents/MacOS"
/usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macos27.0 Tests/NativeCaptureSurface/surface-presence.swift Tests/NativeCaptureSurface/surface-app.swift -o "$surface_app/Contents/MacOS/ScreenProofSurface"
/usr/bin/python3 - "$surface_app/Contents/Info.plist" <<'PY'
import plistlib,sys
with open(sys.argv[1],'xb') as output:
    plistlib.dump({'CFBundleIdentifier':'ai.sliccy.proof-helper','CFBundleExecutable':'ScreenProofSurface',
        'CFBundleName':'ScreenProofSurface','CFBundlePackageType':'APPL','CFBundleShortVersionString':'0.1.0',
        'CFBundleVersion':'12','LSMinimumSystemVersion':'27.0','NSPrincipalClass':'NSApplication',
        'NSHighResolutionCapable':True,'LSUIElement':True},output)
PY
[[ "$(/usr/bin/lipo -archs "$surface_app/Contents/MacOS/ScreenProofSurface")" == arm64 ]] || exit 2
