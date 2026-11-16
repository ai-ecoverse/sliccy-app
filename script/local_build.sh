#!/usr/bin/env bash
# Production UI build only: no proof variant, signing upload or app launch.
set -euo pipefail

case "${1:-}" in
  --help|-h)
    echo "Usage: $0 [--check]"
    echo 'Check prerequisites, fetch the pinned CLI, and build dist/Sliccy.app without launching it.'
    echo '--check checks prerequisites only; it does not download, compile or sign.'
    exit 0 ;;
  ''|--check) ;;
  *) echo "Usage: $0 [--check]" >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { echo 'Expected at most one argument.' >&2; exit 2; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for flag in SLICCY_NATIVE_SCREEN_PROOF SLICCY_UNIVERSAL_SLICE_PROOF SLICCY_SNAPSHOT_PROOF SLICCY_HOSTED_PID_PROOF SLICCY_CAPTURE_RUNNER_PROOF; do
  value="${!flag:-0}"
  [[ "$value" == 0 ]] || { echo "Unset $flag for a local app build." >&2; exit 2; }
done
[[ "$(uname -s)" == Darwin ]] || { echo 'Sliccy requires macOS 27 or newer.' >&2; exit 2; }
os_version="$(/usr/bin/sw_vers -productVersion)"
[[ "${os_version%%.*}" -ge 27 ]] || { echo "macOS 27 or newer is required (found $os_version)." >&2; exit 2; }
/usr/bin/xcrun --find swift >/dev/null || { echo 'Select Xcode 27 or newer in Xcode Settings → Locations.' >&2; exit 2; }
sdk_version="$(/usr/bin/xcrun --sdk macosx --show-sdk-version)"
[[ "${sdk_version%%.*}" -ge 27 ]] || { echo "Select Xcode 27 or newer (selected macOS SDK: $sdk_version)." >&2; exit 2; }
echo "Prerequisites: macOS $os_version, macOS SDK $sdk_version. Native capture disabled."
[[ "${1:-}" != --check ]] || exit 0

"$ROOT_DIR/script/fetch_cli.sh"
"$ROOT_DIR/script/build_and_run.sh" --build
echo 'Build finished. Launch when ready:'
printf '  open "%s/dist/Sliccy.app"\n' "$ROOT_DIR"
echo 'Or preview without loading saved sessions:'
printf '  open -n "%s/dist/Sliccy.app" --args --preview --show-overview\n' "$ROOT_DIR"
