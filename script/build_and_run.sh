#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
case "$MODE" in
  run|--build|--debug|--logs|--telemetry|--verify) ;;
  *) echo "usage: $0 [--build|--debug|--logs|--telemetry|--verify]" >&2; exit 2 ;;
esac

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="Sliccy"
BUNDLE_ID="ai.sliccy.mac"
APP_BUNDLE="$ROOT_DIR/dist/$APP_NAME.app"
SWIFT_FLAGS=(--scratch-path "$ROOT_DIR/.build")
BUILD_NUMBER=1
if [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" == 1 || "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" == 1 || "${SLICCY_SNAPSHOT_PROOF:-0}" == 1 || "${SLICCY_HOSTED_PID_PROOF:-0}" == 1 || "${SLICCY_CAPTURE_RUNNER_PROOF:-0}" == 1 ]]; then
  [[ "$MODE" == --build && "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main ]] || { echo 'Build the diagnostic bundle through upstream main CI.' >&2; exit 2; }
  SWIFT_FLAGS=(--scratch-path "$ROOT_DIR/.build/native-proof" -Xswiftc -DSLICCY_NATIVE_SCREEN_PROOF)
  APP_BUNDLE="$ROOT_DIR/dist-proof/$APP_NAME.app"
  BUILD_NUMBER=6
  if [[ "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" == 1 ]]; then
    APP_BUNDLE="$ROOT_DIR/dist-universal-proof/$APP_NAME.app"
    BUILD_NUMBER=7
  fi
  if [[ "${SLICCY_SNAPSHOT_PROOF:-0}" == 1 ]]; then
    [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" != 1 && "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" != 1 && "$(uname -m)" == arm64 ]] || { echo 'Snapshot fixture requires its separate arm64 variant.' >&2; exit 2; }
    SWIFT_FLAGS=(--scratch-path "$ROOT_DIR/.build/snapshot-proof" -Xswiftc -DSLICCY_NATIVE_SCREEN_PROOF -Xswiftc -DSLICCY_SNAPSHOT_PROOF)
    APP_BUNDLE="$ROOT_DIR/dist-snapshot-proof/$APP_NAME.app"
    BUILD_NUMBER=8
  fi
  if [[ "${SLICCY_HOSTED_PID_PROOF:-0}" == 1 ]]; then
    [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" != 1 && "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" != 1 && "${SLICCY_SNAPSHOT_PROOF:-0}" != 1 && "$(uname -m)" == arm64 ]] || { echo 'Hosted PID fixture requires its separate arm64 variant.' >&2; exit 2; }
    SWIFT_FLAGS=(--scratch-path "$ROOT_DIR/.build/hosted-pid-proof" -Xswiftc -DSLICCY_NATIVE_SCREEN_PROOF -Xswiftc -DSLICCY_HOSTED_PID_PROOF)
    APP_BUNDLE="$ROOT_DIR/dist-hosted-pid-proof/$APP_NAME.app"
    BUILD_NUMBER=10
  fi
  if [[ "${SLICCY_CAPTURE_RUNNER_PROOF:-0}" == 1 ]]; then
    [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" != 1 && "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" != 1 && "${SLICCY_SNAPSHOT_PROOF:-0}" != 1 && "${SLICCY_HOSTED_PID_PROOF:-0}" != 1 && "$(uname -m)" == arm64 ]] || { echo 'Capture fixture requires its separate arm64 variant.' >&2; exit 2; }
    SWIFT_FLAGS=(--scratch-path "$ROOT_DIR/.build/capture-runner-proof" -Xswiftc -DSLICCY_NATIVE_SCREEN_PROOF -Xswiftc -DSLICCY_CAPTURE_RUNNER_PROOF)
    APP_BUNDLE="$ROOT_DIR/dist-capture-proof/$APP_NAME.app"
    BUILD_NUMBER=11
  fi
fi
SWIFT="${SLICCY_SWIFT:-$(/usr/bin/xcrun --find swift)}"
cd "$ROOT_DIR"
export CLANG_MODULE_CACHE_PATH="$ROOT_DIR/.build/ModuleCache"

if [[ "$MODE" != "--build" ]]; then
  /usr/bin/pkill -x "$APP_NAME" >/dev/null 2>&1 || true
fi
mkdir -p "$APP_BUNDLE/Contents/MacOS"
if [[ "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" == 1 ]]; then
  proof_slices=()
  for proof_arch in arm64 x86_64; do
    # Swift Build currently ignores --triple for this executable on the hosted
    # runner. The native engine honors it; verify the output before combining.
    proof_flags=(--build-system native --scratch-path "$ROOT_DIR/.build/universal-$proof_arch" --triple "$proof_arch-apple-macosx27.0" -Xswiftc -DSLICCY_NATIVE_SCREEN_PROOF -Xswiftc -DSLICCY_UNIVERSAL_SLICE_PROOF)
    "$SWIFT" build "${proof_flags[@]}" --product "$APP_NAME"
    proof_bin="$("$SWIFT" build "${proof_flags[@]}" --show-bin-path)"
    [[ "$(/usr/bin/lipo -archs "$proof_bin/$APP_NAME")" == "$proof_arch" ]] || { echo 'Unexpected proof slice architecture.' >&2; exit 2; }
    proof_slices+=("$proof_bin/$APP_NAME")
  done
  /usr/bin/lipo -create "${proof_slices[@]}" -output "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
  proof_archs="$(/usr/bin/lipo -archs "$APP_BUNDLE/Contents/MacOS/$APP_NAME")"
  [[ "$proof_archs" == 'arm64 x86_64' || "$proof_archs" == 'x86_64 arm64' ]] || { echo 'Unexpected universal architecture set.' >&2; exit 2; }
else
  "$SWIFT" build "${SWIFT_FLAGS[@]}" --product "$APP_NAME"
  BUILD_DIR="$("$SWIFT" build "${SWIFT_FLAGS[@]}" --show-bin-path)"
  cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
fi
if [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" == 1 && "${SLICCY_UNIVERSAL_SLICE_PROOF:-0}" != 1 && "${SLICCY_SNAPSHOT_PROOF:-0}" != 1 ]]; then
  mkdir -p "$APP_BUNDLE/Contents/Helpers"
  /usr/bin/xcrun clang -Wall -Wextra -Werror Tests/NativeScreenFilterProbe/exec-helper.c \
    -framework Security -framework CoreFoundation -o "$APP_BUNDLE/Contents/Helpers/ScreenProofExecHelper"
  /usr/bin/xcrun clang -Wall -Wextra -Werror -I Sources/ScreenSystem/include \
    Sources/ScreenSystem/ScreenSystem.c Tests/NativeScreenFilterProbe/handoff-helper.c \
    -framework Security -framework CoreFoundation -o "$APP_BUNDLE/Contents/Helpers/ScreenProofHandoffHelper"
  for helper_name in ScreenProofExecHelper ScreenProofHandoffHelper; do
    /usr/bin/codesign --force --sign - --identifier ai.sliccy.proof-helper "$APP_BUNDLE/Contents/Helpers/$helper_name"
  done
elif [[ "${SLICCY_CAPTURE_RUNNER_PROOF:-0}" == 1 ]]; then
  surface_app="$APP_BUNDLE/Contents/Helpers/ScreenProofSurface.app"
  [[ ! -e "$APP_BUNDLE/Contents/Helpers" ]] || { echo 'Use a fresh capture fixture bundle.' >&2; exit 2; }
  mkdir -p "$surface_app/Contents/MacOS"
  /usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macos27.0 Tests/NativeCaptureSurface/surface-app.swift -o "$surface_app/Contents/MacOS/ScreenProofSurface"
  /usr/bin/python3 - "$surface_app/Contents/Info.plist" <<'PYPLIST'
import plistlib
import sys
with open(sys.argv[1], 'xb') as output:
    plistlib.dump({'CFBundleIdentifier': 'ai.sliccy.proof-helper', 'CFBundleExecutable': 'ScreenProofSurface',
                  'CFBundleName': 'ScreenProofSurface', 'CFBundlePackageType': 'APPL',
                  'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '11',
                  'LSMinimumSystemVersion': '27.0', 'NSPrincipalClass': 'NSApplication',
                  'NSHighResolutionCapable': True, 'LSUIElement': True}, output)
PYPLIST
  /usr/bin/codesign --force --sign - --identifier ai.sliccy.proof-helper "$surface_app"
else
  [[ ! -e "$APP_BUNDLE/Contents/Helpers" ]] || { echo 'Diagnostic helper must not be in a production bundle.' >&2; exit 2; }
fi
if [[ -x "$ROOT_DIR/.build/tools/slicc" ]]; then
  mkdir -p "$APP_BUNDLE/Contents/Resources"
  cp "$ROOT_DIR/.build/tools/slicc" "$APP_BUNDLE/Contents/Resources/slicc"
  # Preserve the upstream Developer ID signature and CodeDirectory identity.
  /usr/bin/codesign --verify --strict "$APP_BUNDLE/Contents/Resources/slicc"
fi
if [[ "${SLICCY_SNAPSHOT_PROOF:-0}" == 1 ]]; then
  [[ -f "$ROOT_DIR/.build/tools/slicc-snapshot-amd64" ]] || { echo 'Fixed snapshot resource missing.' >&2; exit 2; }
  cp "$ROOT_DIR/.build/tools/slicc-snapshot-amd64" "$APP_BUNDLE/Contents/Resources/slicc-snapshot-amd64"
  /usr/bin/codesign --verify --strict "$APP_BUNDLE/Contents/Resources/slicc-snapshot-amd64"
fi
cat > "$APP_BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$APP_NAME</string>
<key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
<key>CFBundleName</key><string>$APP_NAME</string>
<key>CFBundleDisplayName</key><string>Sliccy</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>$BUILD_NUMBER</string>
<key>LSMinimumSystemVersion</key><string>27.0</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$APP_BUNDLE"

case "$MODE" in
  --build) echo "Built $APP_BUNDLE" ;;
  --debug) /usr/bin/xcrun lldb -- "$APP_BUNDLE/Contents/MacOS/$APP_NAME" ;;
  --logs|--telemetry)
    /usr/bin/open -n "$APP_BUNDLE"
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --verify)
    /usr/bin/open -n "$APP_BUNDLE"
    /usr/bin/pgrep -x "$APP_NAME" >/dev/null
    echo "Launched $APP_BUNDLE"
    ;;
  run) /usr/bin/open -n "$APP_BUNDLE" ;;
esac
