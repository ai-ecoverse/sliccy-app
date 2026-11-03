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
if [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" == 1 ]]; then
  [[ "$MODE" == --build && "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main ]] || { echo 'Build the diagnostic bundle through upstream main CI.' >&2; exit 2; }
  SWIFT_FLAGS=(--scratch-path "$ROOT_DIR/.build/native-proof" -Xswiftc -DSLICCY_NATIVE_SCREEN_PROOF)
  APP_BUNDLE="$ROOT_DIR/dist-proof/$APP_NAME.app"
  BUILD_NUMBER=5
fi
SWIFT="${SLICCY_SWIFT:-$(/usr/bin/xcrun --find swift)}"
cd "$ROOT_DIR"
export CLANG_MODULE_CACHE_PATH="$ROOT_DIR/.build/ModuleCache"

if [[ "$MODE" != "--build" ]]; then
  /usr/bin/pkill -x "$APP_NAME" >/dev/null 2>&1 || true
fi
"$SWIFT" build "${SWIFT_FLAGS[@]}" --product "$APP_NAME"
BUILD_DIR="$("$SWIFT" build "${SWIFT_FLAGS[@]}" --show-bin-path)"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
cp "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
if [[ "${SLICCY_NATIVE_SCREEN_PROOF:-0}" == 1 ]]; then
  mkdir -p "$APP_BUNDLE/Contents/Helpers"
  /usr/bin/xcrun clang -Wall -Wextra -Werror Tests/NativeScreenFilterProbe/exec-helper.c \
    -framework Security -framework CoreFoundation -o "$APP_BUNDLE/Contents/Helpers/ScreenProofExecHelper"
  /usr/bin/xcrun clang -Wall -Wextra -Werror -I Sources/ScreenSystem/include \
    Sources/ScreenSystem/ScreenSystem.c Tests/NativeScreenFilterProbe/handoff-helper.c \
    -framework Security -framework CoreFoundation -o "$APP_BUNDLE/Contents/Helpers/ScreenProofHandoffHelper"
  for helper_name in ScreenProofExecHelper ScreenProofHandoffHelper; do
    /usr/bin/codesign --force --sign - --identifier ai.sliccy.proof-helper "$APP_BUNDLE/Contents/Helpers/$helper_name"
  done
else
  [[ ! -e "$APP_BUNDLE/Contents/Helpers" ]] || { echo 'Diagnostic helper must not be in a production bundle.' >&2; exit 2; }
fi
if [[ -x "$ROOT_DIR/.build/tools/slicc" ]]; then
  mkdir -p "$APP_BUNDLE/Contents/Resources"
  cp "$ROOT_DIR/.build/tools/slicc" "$APP_BUNDLE/Contents/Resources/slicc"
  # Preserve the upstream Developer ID signature and CodeDirectory identity.
  /usr/bin/codesign --verify --strict "$APP_BUNDLE/Contents/Resources/slicc"
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
