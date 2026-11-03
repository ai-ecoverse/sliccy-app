#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main && "$(uname -m)" == arm64 ]] || { echo 'Snapshot fixture resources require upstream arm64 CI.' >&2; exit 2; }
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT_DIR/.build/tools"
SNAPSHOT_TEMP=$(mktemp "$ROOT_DIR/.build/tools/snapshot.XXXXXX")
trap 'rm -f "$SNAPSHOT_TEMP"' EXIT
curl --fail --location --silent --show-error --max-time 120 \
  https://github.com/ai-ecoverse/slicc-cli/releases/download/v1.59.0/slicc-darwin-amd64 -o "$SNAPSHOT_TEMP"
printf '%s  %s\n' 9ff520697095ce930cc25d4a5e208a72eb82a072211fd7b9bbd6da2b9b78278e "$SNAPSHOT_TEMP" | shasum -a 256 --check
/usr/bin/codesign --verify --strict \
  -R '=anchor apple generic and identifier "ai.sliccy.slicc" and certificate leaf[subject.OU] = "S8LB56P782"' "$SNAPSHOT_TEMP"
chmod 755 "$SNAPSHOT_TEMP"
mv "$SNAPSHOT_TEMP" "$ROOT_DIR/.build/tools/slicc-snapshot-amd64"
echo 'Fixed signed snapshot resource verified; it is never executed.'
