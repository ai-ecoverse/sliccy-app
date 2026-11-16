#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  arm64) ARCH=arm64; SHA=32f509932c22f540564eda51ba490260e38c855d9f139b5028b08050969dcb76 ;;
  x86_64) ARCH=amd64; SHA=d64b1db858dec4ebca9bf0f4595b99ccda380222793ef0757c02ed63f8a03a78 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
mkdir -p "$ROOT_DIR/.build/tools"
CLI_TEMP="$(mktemp "$ROOT_DIR/.build/tools/slicc.XXXXXX")"
trap 'rm -f "$CLI_TEMP"' EXIT
curl --fail --location --silent --show-error --max-time 120 \
  "https://github.com/ai-ecoverse/slicc-cli/releases/download/v1.67.12/slicc-darwin-$ARCH" -o "$CLI_TEMP"
printf '%s  %s\n' "$SHA" "$CLI_TEMP" | shasum -a 256 --check
/usr/bin/codesign --verify --strict \
  -R '=anchor apple generic and identifier "ai.sliccy.slicc" and certificate leaf[subject.OU] = "S8LB56P782"' "$CLI_TEMP"
chmod 755 "$CLI_TEMP"
mv "$CLI_TEMP" "$ROOT_DIR/.build/tools/slicc"
echo 'slicc v1.67.12 ready for bundling. The system CLI is unchanged.'
