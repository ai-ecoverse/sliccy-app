#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  arm64) ARCH=arm64; SHA=64d0088b0bca15750199a0d99c3a8afecbefce6948172b07360739cc5bebc2ed ;;
  x86_64) ARCH=amd64; SHA=13359981b549a900249f38bf7ddf6391661fd4f2aba83742dd8a8992c59663c4 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
mkdir -p "$ROOT_DIR/.build/tools"
CLI_TEMP="$(mktemp "$ROOT_DIR/.build/tools/slicc.XXXXXX")"
trap 'rm -f "$CLI_TEMP"' EXIT
curl --fail --location --silent --show-error --max-time 120 \
  "https://github.com/ai-ecoverse/slicc-cli/releases/download/v1.57.0/slicc-darwin-$ARCH" -o "$CLI_TEMP"
printf '%s  %s\n' "$SHA" "$CLI_TEMP" | shasum -a 256 --check
chmod 755 "$CLI_TEMP"
mv "$CLI_TEMP" "$ROOT_DIR/.build/tools/slicc"
echo 'slicc v1.57.0 ready for bundling. The system CLI is unchanged.'
