#!/bin/bash
# Run after the approved release workflow imports its Developer ID certificate.
# Uses the same secret names as ai-ecoverse/slicc; never copies signing secrets.
set +x
set -euo pipefail
umask 077

if [[ "${GITHUB_ACTIONS:-}" != true || "${GITHUB_REPOSITORY:-}" != ai-ecoverse/sliccy-app || "${GITHUB_EVENT_NAME:-}" != push || "${GITHUB_REF:-}" != refs/heads/main ]]; then
  echo 'Run signing through the approved GitHub Actions signing workflow.' >&2
  exit 2
fi
if [[ $# != 2 ]]; then
  echo 'usage: sign_and_notarize.sh <built-Sliccy.app> <new-artifact-directory>' >&2
  exit 2
fi
: "${APPLE_TEAM_ID:?Signing workflow must supply APPLE_TEAM_ID}"
: "${APPLE_API_KEY_ID:?Signing workflow must supply APPLE_API_KEY_ID}"
: "${APPLE_API_KEY_ISSUER_ID:?Signing workflow must supply APPLE_API_KEY_ISSUER_ID}"
: "${APPLE_API_KEY_P8_BASE64:?Signing workflow must supply APPLE_API_KEY_P8_BASE64}"
: "${RUNNER_TEMP:?Runner temporary directory is required}"
[[ "$APPLE_TEAM_ID" == S8LB56P782 ]] || { echo 'Unexpected signing team.' >&2; exit 2; }

input_app="$1"
artifact_dir="$2"
plist="$input_app/Contents/Info.plist"
[[ -d "$input_app" && -f "$plist" ]] || { echo 'Built app bundle is missing.' >&2; exit 2; }
[[ ! -e "$artifact_dir" ]] || { echo 'Use a new artifact directory.' >&2; exit 2; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")" == ai.sliccy.mac ]] || { echo 'Unexpected app identifier.' >&2; exit 2; }
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist")" == 0.1.0 ]] || { echo 'Proof build must use approved version 0.1.0.' >&2; exit 2; }
[[ -x "$input_app/Contents/MacOS/Sliccy" ]] || { echo 'App executable is missing.' >&2; exit 2; }
[[ -x "$input_app/Contents/Resources/slicc" ]] || { echo 'Bundled CLI is missing.' >&2; exit 2; }
/usr/bin/codesign --verify --strict "$input_app/Contents/Resources/slicc"

mkdir -p "$artifact_dir"
artifact_dir="$(cd "$artifact_dir" && pwd)"
signed_app="$artifact_dir/Sliccy.app"
/usr/bin/ditto "$input_app" "$signed_app"
# No debug, injection, JIT, capture, or accessibility entitlement is inherited.
# OS recording consent is separate and this script never requests it.
cat > "$artifact_dir/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>
PLIST
identity="Developer ID Application: Lars Trieloff ($APPLE_TEAM_ID)"
for helper_name in ScreenProofExecHelper ScreenProofHandoffHelper; do
helper="$signed_app/Contents/Helpers/$helper_name"
if [[ -e "$helper" ]]; then
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist")" == 6 ]] || { echo 'Unexpected diagnostic helper.' >&2; exit 2; }
  /usr/bin/codesign --force --options runtime --timestamp --sign "$identity" \
    --identifier ai.sliccy.proof-helper --entitlements "$artifact_dir/entitlements.plist" "$helper"
  /usr/bin/codesign --verify --strict -R '=anchor apple generic and identifier "ai.sliccy.proof-helper" and certificate leaf[subject.OU] = "S8LB56P782"' "$helper"
  if /usr/bin/codesign --verify --strict -R '=identifier "ai.sliccy.mac"' "$helper" >/dev/null 2>&1; then
    echo 'Diagnostic helper must not have app peer identity.' >&2; exit 2
  fi
fi
done
/usr/bin/codesign --force --options runtime --timestamp --sign "$identity" \
  --entitlements "$artifact_dir/entitlements.plist" "$signed_app"
# Preserve the upstream CLI signature and exact artifact bytes; never re-sign it.
/usr/bin/cmp "$input_app/Contents/Resources/slicc" "$signed_app/Contents/Resources/slicc"
if [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist")" == 8 ]]; then
  /usr/bin/cmp "$input_app/Contents/Resources/slicc-snapshot-amd64" "$signed_app/Contents/Resources/slicc-snapshot-amd64"
  python3 "$(dirname "$0")/snapshot_manifest.py" "$signed_app" "$artifact_dir/snapshot-manifest.json"
fi
requirement='anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[subject.OU] = "S8LB56P782" and identifier "ai.sliccy.mac"'
/usr/bin/codesign --verify --deep --strict -R "=$requirement" "$signed_app"
if [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist")" == 7 ]]; then
  /usr/bin/codesign --verify --deep --strict --all-architectures -R "=$requirement" "$signed_app"
  python3 "$(dirname "$0")/universal_manifest.py" "$signed_app" "$artifact_dir/universal-manifest.json"
fi
/usr/bin/ditto -c -k --keepParent "$signed_app" "$artifact_dir/Sliccy-notarize.zip"
private_dir=$(mktemp -d "$RUNNER_TEMP/sliccy-notary.XXXXXX")
trap 'rm -rf "$private_dir"' EXIT
printf '%s' "$APPLE_API_KEY_P8_BASE64" | /usr/bin/base64 --decode > "$private_dir/key.p8"
unset APPLE_API_KEY_P8_BASE64
if ! /usr/bin/xcrun notarytool submit "$artifact_dir/Sliccy-notarize.zip" \
  --key "$private_dir/key.p8" --key-id "$APPLE_API_KEY_ID" \
  --issuer "$APPLE_API_KEY_ISSUER_ID" --wait --timeout 30m \
  --output-format json > "$artifact_dir/notarization.json" 2> "$private_dir/notary.log"; then
  echo 'Notarization submission failed or timed out.' >&2
  exit 1
fi
/usr/bin/plutil -extract status raw -o - "$artifact_dir/notarization.json" | /usr/bin/grep -qx Accepted
/usr/bin/xcrun stapler staple "$signed_app"
/usr/bin/xcrun stapler validate "$signed_app"
/usr/bin/codesign --verify --deep --strict -R "=$requirement" "$signed_app"
/usr/sbin/spctl --assess --type execute "$signed_app"
/usr/bin/ditto -c -k --keepParent "$signed_app" "$artifact_dir/Sliccy-0.1.0.zip"
/usr/bin/codesign -dvvv "$signed_app" 2> "$artifact_dir/signing.txt"
for helper_name in ScreenProofExecHelper ScreenProofHandoffHelper; do
  helper="$signed_app/Contents/Helpers/$helper_name"
  if [[ -e "$helper" ]]; then /usr/bin/codesign -dvvv "$helper" 2>> "$artifact_dir/signing.txt"; fi
done
(cd "$artifact_dir" && /usr/bin/shasum -a 256 Sliccy-0.1.0.zip > SHA256SUMS)
printf 'Verified signed app: %s\n' "$signed_app"
