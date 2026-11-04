#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
probe_root=$(mktemp -d /private/tmp/sliccy-surface-unit.XXXXXX)
trap 'rm -rf "$probe_root"' EXIT
/usr/bin/xcrun swiftc -parse-as-library -target arm64-apple-macos27.0 \
  Tests/NativeCaptureSurface/surface-presence.swift Tests/NativeCaptureSurface/presence-tests.swift \
  -o "$probe_root/presence-tests"
"$probe_root/presence-tests"
