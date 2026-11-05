#!/bin/bash
set +x
set -euo pipefail
umask 077
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == ai-ecoverse/sliccy-app && "${GITHUB_EVENT_NAME:-}" == workflow_dispatch && "${GITHUB_REF:-}" == refs/heads/main ]] || { echo 'Signing requires a push to the reviewed helper12 signing branch.' >&2; exit 2; }
: "${RUNNER_TEMP:?Runner temporary directory is required}"
: "${APPLE_CERTIFICATE_BASE64:?Developer ID certificate secret is required}"
: "${APPLE_DEVELOPER_CERTIFICATE_PASSWORD:?Certificate password secret is required}"
private_dir=$(mktemp -d "$RUNNER_TEMP/sliccy-signing.XXXXXX")
keychain="$private_dir/signing.keychain-db"
cleanup() {
  /usr/bin/security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$private_dir"
}
trap cleanup EXIT
export SLICCY_P12_PASSWORD
SLICCY_P12_PASSWORD=$(openssl rand -hex 32)
import_certificate() {
  printf '%s' "$APPLE_CERTIFICATE_BASE64" | /usr/bin/base64 --decode > "$private_dir/raw.p12" || return 1
  /usr/bin/security create-keychain -p "$SLICCY_P12_PASSWORD" "$keychain" || return 1
  /usr/bin/security set-keychain-settings -lut 3600 "$keychain" || return 1
  /usr/bin/security unlock-keychain -p "$SLICCY_P12_PASSWORD" "$keychain" || return 1
  if ! openssl pkcs12 -in "$private_dir/raw.p12" -nodes -out "$private_dir/certificate.pem" -passin env:APPLE_DEVELOPER_CERTIFICATE_PASSWORD; then
    openssl pkcs12 -legacy -in "$private_dir/raw.p12" -nodes -out "$private_dir/certificate.pem" -passin env:APPLE_DEVELOPER_CERTIFICATE_PASSWORD || return 1
  fi
  openssl pkcs12 -export -in "$private_dir/certificate.pem" -out "$private_dir/normalized.p12" \
    -passout env:SLICCY_P12_PASSWORD -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 || return 1
  /usr/bin/security import "$private_dir/normalized.p12" -k "$keychain" -P "$SLICCY_P12_PASSWORD" \
    -t cert -f pkcs12 -T /usr/bin/codesign -T /usr/bin/security || return 1
  /usr/bin/security set-key-partition-list -S apple-tool:,apple:,codesign: -k "$SLICCY_P12_PASSWORD" "$keychain" || return 1
  /usr/bin/security list-keychains -d user -s "$keychain" || return 1
}
if ! import_certificate > "$private_dir/import.log" 2>&1; then
  echo 'Developer ID certificate import failed.' >&2
  exit 1
fi
unset APPLE_CERTIFICATE_BASE64 APPLE_DEVELOPER_CERTIFICATE_PASSWORD SLICCY_P12_PASSWORD
"$(dirname "$0")/sign_helper12.sh" "$@"
