#!/bin/bash -p
set -euo pipefail
set +x
set +a
umask 077
[[ "$-" == *p* ]] || {
  echo "Execute this release builder directly so privileged Bash ignores startup injection." >&2
  exit 2
}

update_signing_key="${SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64:-}"
export -n update_signing_key
unset SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
IFS=$' \t\n'
unset BASH_ENV CDPATH ENV TAR_OPTIONS
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG_COUNT
unset GIT_CONFIG_PARAMETERS GIT_EXEC_PATH GIT_TEMPLATE_DIR GIT_ATTR_NOSYSTEM
unset GIT_SSL_NO_VERIFY GIT_SSL_CAINFO GIT_PROXY_COMMAND GIT_ASKPASS SSH_ASKPASS
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_ATTR_NOSYSTEM=1
unset DEVELOPER_DIR TOOLCHAINS SDKROOT SWIFT_EXEC SWIFTC_EXEC
unset SWIFT_DRIVER_SWIFT_EXEC MACOSX_DEPLOYMENT_TARGET
unset CC CXX LD AR NM CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR LLVM_PROFILE_FILE
unset CODESIGN_ALLOCATE
unset SECURE_SANDBOX_SWIFT_HERMETIC SECURE_SANDBOX_SWIFT_SCRATCH_PATH
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONBREAKPOINT
for inherited_name in "${!DYLD_@}" "${!LD_@}"; do
  unset "$inherited_name"
done

root_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
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
[[ -n "$update_signing_key" \
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

release_repo="$root_dir/../.."
release_branch="$(/usr/bin/git -C "$release_repo" symbolic-ref --quiet --short HEAD)" || {
  echo "Release construction requires an attached Git branch." >&2
  exit 1
}
release_commit="$(/usr/bin/git -C "$release_repo" rev-parse --verify 'HEAD^{commit}')" || {
  echo "Release construction could not resolve the source commit." >&2
  exit 1
}
if ! release_status="$(/usr/bin/git -C "$release_repo" \
    status --porcelain=v1 --untracked-files=all)"; then
  echo "Release construction could not inspect the Git worktree." >&2
  exit 1
fi
[[ "$release_commit" =~ ^[0-9a-f]{40}$ && -z "$release_status" ]] || {
  echo "Release construction requires a clean SHA-1 Git worktree." >&2
  exit 1
}
require_unchanged_release_source() {
  local current_branch current_commit current_status
  current_branch="$(/usr/bin/git -C "$release_repo" symbolic-ref --quiet --short HEAD)" || {
    echo "The release source branch became detached." >&2
    return 1
  }
  current_commit="$(/usr/bin/git -C "$release_repo" rev-parse --verify 'HEAD^{commit}')" || {
    echo "The release source commit became unreadable." >&2
    return 1
  }
  if ! current_status="$(/usr/bin/git -C "$release_repo" \
      status --porcelain=v1 --untracked-files=all)"; then
    echo "The release source status became unreadable." >&2
    return 1
  fi
  [[ "$current_branch" == "$release_branch" \
      && "$current_commit" == "$release_commit" \
      && -z "$current_status" ]] || {
    echo "The release source changed after construction began." >&2
    return 1
  }
}

dist_dir="$root_dir/dist"
update_dir="$dist_dir/update"
output_dir="$update_dir/$version-$build"
publish_target="$dist_dir/SecureSandboxControlCenter.app"
publish_previous="$dist_dir/.SecureSandboxControlCenter.release-previous.app"
release_workspace=""
publish_stage=""
publish_moved_existing=false
publish_installed_new=false
publish_complete=false
cleanup_release() {
  local status=$?
  set +e
  unset update_signing_key
  if [[ "$publish_complete" != true ]]; then
    if [[ "$publish_installed_new" == true \
        && -d "$publish_target" && ! -L "$publish_target" ]]; then
      /bin/rm -rf -- "$publish_target"
    fi
    if [[ "$publish_moved_existing" == true \
        && -d "$publish_previous" && ! -L "$publish_previous" ]]; then
      /bin/mv "$publish_previous" "$publish_target" || true
    fi
  fi
  if [[ -n "$publish_stage" && -d "$publish_stage" && ! -L "$publish_stage" ]]; then
    /bin/rm -rf -- "$publish_stage"
  fi
  if [[ -n "$release_workspace" \
      && -d "$release_workspace" && ! -L "$release_workspace" ]]; then
    /bin/rm -rf -- "$release_workspace"
  fi
  exit "$status"
}
trap cleanup_release EXIT

if [[ ! -e "$dist_dir" ]]; then
  /bin/mkdir -m 755 "$dist_dir"
fi
[[ -d "$dist_dir" && ! -L "$dist_dir" \
    && "$(/usr/bin/stat -f %u "$dist_dir")" == "$EUID" ]] || {
  echo "The release output directory is not trusted." >&2
  exit 1
}
if [[ ! -e "$update_dir" ]]; then
  /bin/mkdir -m 700 "$update_dir"
fi
[[ -d "$update_dir" && ! -L "$update_dir" \
    && "$(/usr/bin/stat -f %u "$update_dir")" == "$EUID" ]] || {
  echo "The release evidence directory is not trusted." >&2
  exit 1
}
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || {
  echo "Release output already exists: $output_dir" >&2
  exit 1
}
/bin/mkdir -p "$output_dir"

release_workspace="$(/usr/bin/mktemp \
  -d /tmp/secure-sandbox-control-center-release.XXXXXX)"
source_archive="$release_workspace/source.tar"
source_root="$release_workspace/source"
/bin/mkdir "$source_root"
/usr/bin/git -C "$release_repo" archive --format=tar \
  --output="$source_archive" "$release_commit"
/usr/bin/tar -xf "$source_archive" -C "$source_root"
candidate_control="$source_root/macos/ControlCenter"
candidate_validator="$candidate_control/script/validate_bundle.sh"
for required_source in \
  "$candidate_control/Package.swift" \
  "$candidate_control/Package.resolved" \
  "$candidate_control/script/build_and_run.sh" \
  "$candidate_validator" \
  "$candidate_control/Sources/SecureSandboxUpdateSigner/main.swift" \
  "$source_root/scripts/build-native-credential-components.sh"; do
  [[ -f "$required_source" && ! -L "$required_source" ]] || {
    echo "The committed release source archive is incomplete." >&2
    exit 1
  }
done

swift_scratch="$release_workspace/swift-scratch"
/bin/mkdir -p \
  "$swift_scratch/cache" "$swift_scratch/config" "$swift_scratch/security"
swift_options=(
  --package-path "$candidate_control"
  --scratch-path "$swift_scratch"
  --cache-path "$swift_scratch/cache"
  --config-path "$swift_scratch/config"
  --security-path "$swift_scratch/security"
  --disable-dependency-cache
  --disable-build-manifest-caching
  --manifest-cache none
  --disable-netrc
  --disable-keychain
  --only-use-versions-from-resolved-file
  --skip-update
  --disable-prefetching
  --disable-experimental-prebuilts
  --disable-index-store
)
SECURE_SANDBOX_SWIFT_HERMETIC=1 \
SECURE_SANDBOX_SWIFT_SCRATCH_PATH="$swift_scratch" \
  "$source_root/scripts/build-native-credential-components.sh" >/dev/null

SECURE_SANDBOX_SWIFT_HERMETIC=1 \
SECURE_SANDBOX_SWIFT_SCRATCH_PATH="$swift_scratch" \
SECURE_SANDBOX_BUILD_CONFIGURATION=release \
SECURE_SANDBOX_APP_VERSION="$version" \
SECURE_SANDBOX_APP_BUILD="$build" \
SECURE_SANDBOX_UPDATE_SEQUENCE="$sequence" \
  "$candidate_control/script/build_and_run.sh" --build-only >/dev/null
candidate_app="$candidate_control/dist/SecureSandboxControlCenter.app"
"$candidate_validator" "$candidate_app" --pre-notarization >/dev/null

/usr/bin/swift build -c release "${swift_options[@]}" \
  --product SecureSandboxUpdateSigner >/dev/null
signer_bin_path="$(/usr/bin/swift build -c release \
  "${swift_options[@]}" --show-bin-path)"
signer_binary="$signer_bin_path/SecureSandboxUpdateSigner"
[[ -f "$signer_binary" && ! -L "$signer_binary" && -x "$signer_binary" ]] || {
  echo "The archived-source update signer build is invalid." >&2
  exit 1
}

submission="$output_dir/notary-submission.zip"
notary_result="$output_dir/notary-result.json"
notary_log="$output_dir/notary-log.json"
/usr/bin/ditto -c -k --keepParent "$candidate_app" "$submission"
/usr/bin/xcrun notarytool submit "$submission" \
  --keychain-profile "$SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE" --wait \
  --output-format json >"$notary_result"
/usr/bin/python3 -I -c '
import json,re,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
if value.get("status") != "Accepted" or re.fullmatch(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    value.get("id", ""),
) is None:
    raise SystemExit("control_center_notarization_not_accepted")
' "$notary_result"
submission_id="$(/usr/bin/python3 -I -c '
import json,pathlib,sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["id"])
' "$notary_result")"
/usr/bin/xcrun notarytool log "$submission_id" \
  --keychain-profile "$SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE" "$notary_log"
/usr/bin/python3 -I -c '
import json,pathlib,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if (
    value.get("status") != "Accepted"
    or not isinstance(value.get("statusCode"), int)
    or isinstance(value["statusCode"], bool)
    or value["statusCode"] != 0
    or "issues" not in value
    or value["issues"] not in (None, [])
):
    raise SystemExit("control_center_notary_log_not_clean")
' "$notary_log"
/usr/bin/xcrun stapler staple "$candidate_app"
/usr/bin/xcrun stapler validate "$candidate_app"
"$candidate_validator" "$candidate_app" --distribution >/dev/null

artifact="$output_dir/SecureSandbox-$version-$build.zip"
artifact_stage="$release_workspace/artifact-stage"
artifact_app="$artifact_stage/SecureSandbox.app"
/bin/mkdir "$artifact_stage"
/usr/bin/ditto "$candidate_app" "$artifact_app"
"$candidate_validator" "$artifact_app" --distribution >/dev/null
/usr/bin/ditto -c -k --keepParent "$artifact_app" "$artifact"
roundtrip_dir="$release_workspace/artifact-roundtrip"
/bin/mkdir "$roundtrip_dir"
/usr/bin/ditto -x -k "$artifact" "$roundtrip_dir"
/usr/bin/python3 -I -c '
import pathlib,sys
root=pathlib.Path(sys.argv[1]); expected=root/"SecureSandbox.app"
if list(root.iterdir()) != [expected] or not expected.is_dir() or expected.is_symlink():
    raise SystemExit("control_center_artifact_layout_invalid")
' "$roundtrip_dir"
"$candidate_validator" \
  "$roundtrip_dir/SecureSandbox.app" --distribution >/dev/null
artifact_size="$(/usr/bin/stat -f %z "$artifact")"
artifact_sha256="$(/usr/bin/shasum -a 256 "$artifact" \
  | /usr/bin/awk '{print $1}')"
require_unchanged_release_source
published_at="$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
classification="${SECURE_SANDBOX_UPDATE_SECURITY_CLASSIFICATION:-maintenance}"
manifest="$output_dir/manifest.json"
envelope="$output_dir/stable.json"

/usr/bin/jq -n -S \
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

signer_status=0
SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64="$update_signing_key" \
  "$signer_binary" sign \
    "$manifest" "$envelope" "$SECURE_SANDBOX_UPDATE_KEY_ID" \
  || signer_status=$?
unset update_signing_key
[[ "$signer_status" == 0 \
    && -f "$envelope" && ! -L "$envelope" && -s "$envelope" ]] || {
  echo "The isolated update-manifest signer failed." >&2
  exit 1
}
require_unchanged_release_source

[[ ! -e "$publish_previous" && ! -L "$publish_previous" ]] || {
  echo "A prior release publication needs inspection." >&2
  exit 1
}
if [[ -e "$publish_target" || -L "$publish_target" ]]; then
  [[ -d "$publish_target" && ! -L "$publish_target" ]] || {
    echo "The existing Control Center distribution path is unsafe." >&2
    exit 1
  }
fi
publish_stage="$(/usr/bin/mktemp \
  -d "$dist_dir/.SecureSandboxControlCenter.release.XXXXXX")"
/usr/bin/ditto "$candidate_app" \
  "$publish_stage/SecureSandboxControlCenter.app"
"$candidate_validator" \
  "$publish_stage/SecureSandboxControlCenter.app" --distribution >/dev/null
if [[ -d "$publish_target" ]]; then
  /bin/mv "$publish_target" "$publish_previous"
  publish_moved_existing=true
fi
/bin/mv "$publish_stage/SecureSandboxControlCenter.app" "$publish_target"
publish_installed_new=true
"$candidate_validator" "$publish_target" --distribution >/dev/null
require_unchanged_release_source
if [[ "$publish_moved_existing" == true ]]; then
  /bin/rm -rf -- "$publish_previous"
fi
publish_complete=true
/bin/rm "$submission"
printf '{"schema":"secure-sandbox-control-center-release-build-v1","status":"verified","version":"%s","build":%s,"sequence":%s,"artifact":"%s","envelope":"%s"}\n' \
  "$version" "$build" "$sequence" "$artifact" "$envelope"
