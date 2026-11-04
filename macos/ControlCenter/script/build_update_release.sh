#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-}"
build="${2:-}"
sequence="${3:-}"
artifact_url="${4:-}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ \
    && "$build" =~ ^[1-9][0-9]*$ && "$sequence" =~ ^[1-9][0-9]*$ \
    && "$artifact_url" == https://* ]] || {
  echo "usage: $0 VERSION BUILD SEQUENCE HTTPS_ARTIFACT_URL" >&2
  exit 2
}
[[ "${SECURE_SANDBOX_DEVELOPER_ID:-}" == "Developer ID Application:"* \
    || "${SECURE_SANDBOX_DEVELOPER_ID:-}" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo "SECURE_SANDBOX_DEVELOPER_ID must name or SHA1-pin a Developer ID Application identity." >&2
  exit 2
}
[[ -n "${SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE:-}" ]] || {
  echo "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE is required." >&2
  exit 2
}
[[ -n "${SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64:-}" \
    && "${SECURE_SANDBOX_UPDATE_KEY_ID:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || {
  echo "Run through op-agents with the update signing key and key ID configured." >&2
  exit 2
}
[[ -n "${SECURE_SANDBOX_UPDATE_SECURITY_SUMMARY:-}" \
    && -n "${SECURE_SANDBOX_UPDATE_CONTROL_CENTER_COMPATIBILITY:-}" \
    && -n "${SECURE_SANDBOX_UPDATE_PROTECTED_ENVIRONMENT_COMPATIBILITY:-}" ]] || {
  echo "Security and compatibility summaries are required." >&2
  exit 2
}

output_dir="$root_dir/dist/update/$version-$build"
[[ ! -e "$output_dir" ]] || {
  echo "Release output already exists: $output_dir" >&2
  exit 1
}
mkdir -p "$output_dir"

"$root_dir/../../scripts/build-native-credential-components.sh" >/dev/null

SECURE_SANDBOX_BUILD_CONFIGURATION=release \
SECURE_SANDBOX_APP_VERSION="$version" \
SECURE_SANDBOX_APP_BUILD="$build" \
SECURE_SANDBOX_UPDATE_SEQUENCE="$sequence" \
  "$root_dir/script/build_and_run.sh" --build-only >/dev/null
"$root_dir/script/validate_bundle.sh" "$root_dir/dist/SecureSandboxControlCenter.app" --distribution >/dev/null

submission="$output_dir/notary-submission.zip"
/usr/bin/ditto -c -k --keepParent "$root_dir/dist/SecureSandboxControlCenter.app" "$submission"
xcrun notarytool submit "$submission" \
  --keychain-profile "$SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE" --wait
xcrun stapler staple "$root_dir/dist/SecureSandboxControlCenter.app"
xcrun stapler validate "$root_dir/dist/SecureSandboxControlCenter.app"
"$root_dir/script/validate_bundle.sh" "$root_dir/dist/SecureSandboxControlCenter.app" --distribution >/dev/null

artifact="$output_dir/SecureSandbox-$version-$build.zip"
/usr/bin/ditto -c -k --keepParent "$root_dir/dist/SecureSandboxControlCenter.app" "$artifact"
artifact_size="$(stat -f %z "$artifact")"
artifact_sha256="$(shasum -a 256 "$artifact" | awk '{print $1}')"
release_commit="$(git -C "$root_dir/../.." rev-parse HEAD)"
published_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
classification="${SECURE_SANDBOX_UPDATE_SECURITY_CLASSIFICATION:-maintenance}"
manifest="$output_dir/manifest.json"
envelope="$output_dir/stable.json"

jq -n -S \
  --arg schema secure-sandbox-control-center-update-manifest-v1 \
  --arg channel stable \
  --argjson sequence "$sequence" \
  --arg version "$version" \
  --argjson build "$build" \
  --arg published_at "$published_at" \
  --arg minimum_macos 27.0 \
  --argjson minimum_current_sequence "${SECURE_SANDBOX_UPDATE_MINIMUM_CURRENT_SEQUENCE:-1}" \
  --arg release_commit "$release_commit" \
  --arg artifact_url "$artifact_url" \
  --argjson artifact_size "$artifact_size" \
  --arg artifact_sha256 "$artifact_sha256" \
  --arg classification "$classification" \
  --arg security_summary "$SECURE_SANDBOX_UPDATE_SECURITY_SUMMARY" \
  --arg control_center "$SECURE_SANDBOX_UPDATE_CONTROL_CENTER_COMPATIBILITY" \
  --arg protected_environment "$SECURE_SANDBOX_UPDATE_PROTECTED_ENVIRONMENT_COMPATIBILITY" \
  '{schema:$schema,channel:$channel,sequence:$sequence,version:$version,build:$build,
    published_at:$published_at,minimum_macos:$minimum_macos,
    minimum_current_sequence:$minimum_current_sequence,release_commit:$release_commit,
    artifact:{url:$artifact_url,size:$artifact_size,sha256:$artifact_sha256},
    security:{classification:$classification,summary:$security_summary},
    compatibility:{control_center:$control_center,protected_environment:$protected_environment}}' >"$manifest"

swift run -c release --package-path "$root_dir" SecureSandboxUpdateSigner \
  sign "$manifest" "$envelope" "$SECURE_SANDBOX_UPDATE_KEY_ID"
rm "$submission"
printf '{"schema":"secure-sandbox-control-center-release-build-v1","status":"verified","version":"%s","build":%s,"sequence":%s,"artifact":"%s","envelope":"%s"}\n' \
  "$version" "$build" "$sequence" "$artifact" "$envelope"
