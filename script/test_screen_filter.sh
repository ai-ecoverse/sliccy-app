#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
probe_root=$(mktemp -d /private/tmp/sliccy-filter-probe.XXXXXX)
trap 'rm -rf "$probe_root"' EXIT
probe_app="$probe_root/Sliccy Filter Probe.app"
mkdir -p "$probe_app/Contents/MacOS"
cat > "$probe_app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>ai.sliccy.filter-probe</string>
<key>CFBundleExecutable</key><string>FilterProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>Sliccy Filter Probe</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
/usr/bin/xcrun swiftc -swift-version 6 -o "$probe_app/Contents/MacOS/FilterProbe" \
  Sources/Sliccy/Screen/ScreenFailure.swift Sources/Sliccy/Screen/ScreenFilterBuilder.swift \
  Tests/NativeScreenFilterProbe/main.swift
/usr/bin/codesign --force --sign - "$probe_app"
"$probe_app/Contents/MacOS/FilterProbe" "${1:-Tests/SliccyTests/Fixtures/screen/filter-builder.json}"
