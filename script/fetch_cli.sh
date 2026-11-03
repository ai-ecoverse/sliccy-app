#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  arm64) ARCH=arm64; SHA=0055c051f48364dbf6d3744c637a06353305a392d06edbedd96bd6764adb5a73 ;;
  x86_64) ARCH=amd64; SHA=9ff520697095ce930cc25d4a5e208a72eb82a072211fd7b9bbd6da2b9b78278e ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
mkdir -p "$ROOT_DIR/.build/tools"
CLI_TEMP="$(mktemp "$ROOT_DIR/.build/tools/slicc.XXXXXX")"
trap 'rm -f "$CLI_TEMP"' EXIT
curl --fail --location --silent --show-error --max-time 120 \
  "https://github.com/ai-ecoverse/slicc-cli/releases/download/v1.59.0/slicc-darwin-$ARCH" -o "$CLI_TEMP"
printf '%s  %s\n' "$SHA" "$CLI_TEMP" | shasum -a 256 --check
/usr/bin/codesign --verify --strict \
  -R '=anchor apple generic and identifier "ai.sliccy.slicc" and certificate leaf[subject.OU] = "S8LB56P782"' "$CLI_TEMP"
chmod 755 "$CLI_TEMP"
mv "$CLI_TEMP" "$ROOT_DIR/.build/tools/slicc"
echo 'slicc v1.59.0 ready for bundling. The system CLI is unchanged.'
