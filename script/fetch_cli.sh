#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  arm64) ARCH=arm64; SHA=471451a0e66319f43797c487caaccf7a70242c89aac3e676fc2adc1e892fa618 ;;
  x86_64) ARCH=amd64; SHA=05fc5a5b7364086b4a846807d4e69959c5da8d29eec9a4bd84b35ef725464832 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
mkdir -p "$ROOT_DIR/.build/tools"
CLI_TEMP="$(mktemp "$ROOT_DIR/.build/tools/slicc.XXXXXX")"
trap 'rm -f "$CLI_TEMP"' EXIT
curl --fail --location --silent --show-error --max-time 120 \
  "https://github.com/ai-ecoverse/slicc-cli/releases/download/v1.58.1/slicc-darwin-$ARCH" -o "$CLI_TEMP"
printf '%s  %s\n' "$SHA" "$CLI_TEMP" | shasum -a 256 --check
/usr/bin/codesign --verify --strict \
  -R '=anchor apple generic and identifier "ai.sliccy.slicc" and certificate leaf[subject.OU] = "S8LB56P782"' "$CLI_TEMP"
chmod 755 "$CLI_TEMP"
mv "$CLI_TEMP" "$ROOT_DIR/.build/tools/slicc"
echo 'slicc v1.58.1 ready for bundling. The system CLI is unchanged.'
