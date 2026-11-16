#!/bin/bash
set +x
set -euo pipefail
umask 077
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main ]] || { echo 'DMG signing requires upstream main CI.' >&2; exit 2; }
[[ $# == 2 && "${APPLE_TEAM_ID:-}" == S8LB56P782 ]] || exit 2
: "${RUNNER_TEMP:?}"
: "${APPLE_API_KEY_P8_BASE64:?}"
: "${APPLE_API_KEY_ID:?}"
: "${APPLE_API_KEY_ISSUER_ID:?}"
app="$1"
output="$2"
version=$(python3 "$(dirname "$0")/release_metadata.py" --version)
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")" == "$version" ]] || { echo 'DMG app version mismatch.' >&2; exit 2; }
/usr/bin/codesign --verify --deep --strict -R '=anchor apple generic and identifier "ai.sliccy.mac" and certificate leaf[subject.OU] = "S8LB56P782"' "$app"
/usr/bin/xcrun stapler validate "$app"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
dmg="$output/Sliccy-$version.dmg"
python3 "$(dirname "$0")/build_dmg.py" "$app" "$dmg"
/usr/bin/codesign --force --timestamp --sign "Developer ID Application: Lars Trieloff ($APPLE_TEAM_ID)" "$dmg"
private_dir=$(mktemp -d "$RUNNER_TEMP/sliccy-dmg-notary.XXXXXX")
trap 'rm -rf "$private_dir"' EXIT
printf '%s' "$APPLE_API_KEY_P8_BASE64" | /usr/bin/base64 --decode > "$private_dir/key.p8"
unset APPLE_API_KEY_P8_BASE64
/usr/bin/xcrun notarytool submit "$dmg" --key "$private_dir/key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_KEY_ISSUER_ID" --wait --timeout 30m --output-format json > "$output/dmg-notarization.json" 2> "$private_dir/notary.log"
/usr/bin/plutil -extract status raw -o - "$output/dmg-notarization.json" | /usr/bin/grep -qx Accepted
/usr/bin/xcrun stapler staple "$dmg"
/usr/bin/xcrun stapler validate "$dmg"
/usr/bin/codesign --verify --strict "$dmg"
/usr/sbin/spctl --assess --type open --context context:primary-signature "$dmg"
(cd "$output" && shasum -a 256 "Sliccy-$version.dmg" > DMG-SHA256SUMS)
