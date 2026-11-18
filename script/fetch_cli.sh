#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  arm64) ARCH=arm64; SHA=c92ee233e56f136f217a40c6444221d31ce3e68cde63745ba0cb3ab1321bf4a2 ;;
  x86_64) ARCH=amd64; SHA=b85d0ed26b877d80ec5105a0a30d472c1b8dc12df04abd5040d9c5cd30c8ff07 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
mkdir -p "$ROOT_DIR/.build/tools"
CLI_TEMP="$(mktemp "$ROOT_DIR/.build/tools/slicc.XXXXXX")"
trap 'rm -f "$CLI_TEMP"' EXIT
curl --fail --location --silent --show-error --max-time 120 \
  "https://github.com/ai-ecoverse/slicc-cli/releases/download/v1.68.0/slicc-darwin-$ARCH" -o "$CLI_TEMP"
printf '%s  %s\n' "$SHA" "$CLI_TEMP" | shasum -a 256 --check
/usr/bin/codesign --verify --strict \
  -R '=anchor apple generic and identifier "ai.sliccy.slicc" and certificate leaf[subject.OU] = "S8LB56P782"' "$CLI_TEMP"
chmod 755 "$CLI_TEMP"
mv "$CLI_TEMP" "$ROOT_DIR/.build/tools/slicc"
echo 'slicc v1.68.0 ready for bundling. The system CLI is unchanged.'
