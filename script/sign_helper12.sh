#!/bin/bash
set +x
set -euo pipefail
umask 077
[[ $# == 0 && "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/proof/helper12-signing-v1 && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == macOS && "${RUNNER_ARCH:-}" == ARM64 ]] || { echo 'Helper12 signing requires its reviewed hosted branch.' >&2; exit 2; }
: "${APPLE_TEAM_ID:?}"
: "${APPLE_API_KEY_ID:?}"
: "${APPLE_API_KEY_ISSUER_ID:?}"
: "${APPLE_API_KEY_P8_BASE64:?}"
: "${RUNNER_TEMP:?}"
[[ "$APPLE_TEAM_ID" == S8LB56P782 ]] || exit 2
cd "$(dirname "$0")/.."
[[ "$(/usr/bin/git rev-parse HEAD)" == "$GITHUB_SHA" ]] || exit 2
input=dist-helper12/ScreenProofSurface.app
plist="$input/Contents/Info.plist"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")" == ai.sliccy.proof-helper && "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist")" == 12 && "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist")" == 0.1.0 ]] || exit 2
[[ "$(/usr/bin/lipo -archs "$input/Contents/MacOS/ScreenProofSurface")" == arm64 && ! -e artifacts/helper12 ]] || exit 2
mkdir -p artifacts/helper12
artifact_dir="$(cd artifacts/helper12 && pwd)"
signed_app="$artifact_dir/ScreenProofSurface.app"
/usr/bin/ditto "$input" "$signed_app"
private_dir=$(mktemp -d "$RUNNER_TEMP/sliccy-helper12-notary.XXXXXX")
trap 'rm -rf "$private_dir"' EXIT
cat > "$private_dir/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>
PLIST
identity="Developer ID Application: Lars Trieloff ($APPLE_TEAM_ID)"
requirement='anchor apple generic and identifier "ai.sliccy.proof-helper" and certificate leaf[subject.OU] = "S8LB56P782" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
/usr/bin/codesign --force --options runtime --timestamp --sign "$identity" --identifier ai.sliccy.proof-helper --entitlements "$private_dir/entitlements.plist" "$signed_app"
/usr/bin/codesign --verify --all-architectures --deep --strict -R "=$requirement" "$signed_app"
set +e
/usr/bin/codesign --verify --strict -R '=identifier "ai.sliccy.mac"' "$signed_app" > "$private_dir/role.stdout" 2> "$private_dir/role.stderr"
role_status=$?
set -e
[[ "$role_status" == 3 ]] || { echo 'Helper app-role refusal absent.' >&2; exit 1; }
/usr/bin/codesign -d --entitlements :- "$signed_app" > "$artifact_dir/entitlements.plist" 2> "$private_dir/entitlements.log"
/usr/bin/python3 - "$artifact_dir/entitlements.plist" <<'PY'
import plistlib,sys
assert plistlib.load(open(sys.argv[1],'rb'))=={}
PY
/usr/bin/ditto -c -k --keepParent "$signed_app" "$private_dir/ScreenProofSurface-notarize.zip"
printf '%s' "$APPLE_API_KEY_P8_BASE64" | /usr/bin/base64 --decode > "$private_dir/key.p8"
unset APPLE_API_KEY_P8_BASE64
if ! /usr/bin/xcrun notarytool submit "$private_dir/ScreenProofSurface-notarize.zip" --key "$private_dir/key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_KEY_ISSUER_ID" --wait --timeout 30m --output-format json > "$artifact_dir/notarization.json" 2> "$private_dir/notary.log"; then
  echo 'Helper12 notarization failed or timed out.' >&2
  exit 1
fi
/usr/bin/plutil -extract status raw -o - "$artifact_dir/notarization.json" | /usr/bin/grep -qx Accepted
/usr/bin/xcrun stapler staple "$signed_app"
/usr/bin/xcrun stapler validate "$signed_app"
/usr/bin/codesign --verify --all-architectures --deep --strict -R "=$requirement" "$signed_app"
/usr/sbin/spctl --assess --type execute "$signed_app"
/usr/bin/codesign -d --verbose=4 "$signed_app" 2> "$artifact_dir/signing.txt"
/usr/bin/ditto -c -k --keepParent "$signed_app" "$artifact_dir/ScreenProofSurface-0.1.0.zip"
python3 -B script/helper12_manifest.py
(cd "$artifact_dir" && /usr/bin/shasum -a 256 ScreenProofSurface-0.1.0.zip > SHA256SUMS)
printf 'Verified helper12 artifact.\n'
