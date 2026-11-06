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
notary_keychain_profile="${SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE:-}"
notary_keychain="${SECURE_SANDBOX_NOTARY_KEYCHAIN:-}"
export -n notary_keychain_profile notary_keychain
unset SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE SECURE_SANDBOX_NOTARY_KEYCHAIN
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

release_mode=update
if [[ "${1:-}" == --notarized-app-only ]]; then
  release_mode=notarized-app-only
  shift
fi
version="${1:-}"
build="${2:-}"
sequence="${3:-}"
artifact_url="${4:-}"

usage() {
  echo "usage: $0 VERSION BUILD SEQUENCE HTTPS_ARTIFACT_URL" >&2
  echo "       $0 --notarized-app-only VERSION BUILD SEQUENCE" >&2
}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ \
    && "$build" =~ ^[1-9][0-9]*$ && "$sequence" =~ ^[1-9][0-9]*$ ]] || {
  usage
  exit 2
}
if [[ "$release_mode" == update ]]; then
  [[ "$#" == 4 && "$artifact_url" == https://* ]] || {
    usage
    exit 2
  }
else
  [[ "$#" == 3 ]] || {
    usage
    exit 2
  }
fi
if [[ "$release_mode" == notarized-app-only && -n "$update_signing_key" ]]; then
  echo "The notarized-app-only path must not receive the update signing key." >&2
  exit 2
fi
if [[ "$release_mode" == notarized-app-only ]]; then
  for inherited_name in "${!SECURE_SANDBOX_UPDATE_@}"; do
    unset "$inherited_name"
  done
fi
/usr/bin/python3 -I -c '
import re,sys
limit=(1 << 64) - 1
for label,raw in (("build",sys.argv[1]),("sequence",sys.argv[2])):
    if re.fullmatch(r"[1-9][0-9]*",raw) is None or int(raw) > limit:
        raise SystemExit(f"control_center_{label}_outside_uint64")
' "$build" "$sequence"
if [[ "$release_mode" == notarized-app-only ]]; then
  [[ "${SECURE_SANDBOX_DEVELOPER_ID:-}" =~ ^[0-9A-Fa-f]{40}$ ]] || {
    echo "The notarized-app-only path requires a SHA1-pinned Developer ID identity." >&2
    exit 2
  }
else
  [[ "${SECURE_SANDBOX_DEVELOPER_ID:-}" == "Developer ID Application:"* \
      || "${SECURE_SANDBOX_DEVELOPER_ID:-}" =~ ^[0-9A-Fa-f]{40}$ ]] || {
    echo "SECURE_SANDBOX_DEVELOPER_ID must name or SHA1-pin a Developer ID Application identity." >&2
    exit 2
  }
fi
[[ "$notary_keychain_profile" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || {
  echo "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE is required." >&2
  exit 2
}
[[ -n "$notary_keychain" && "$notary_keychain" == /* \
    && "$notary_keychain" != *$'\n'* && "$notary_keychain" != *$'\r'* ]] || {
  echo "SECURE_SANDBOX_NOTARY_KEYCHAIN must be an absolute path." >&2
  exit 2
}
if [[ "$release_mode" == update ]]; then
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
fi

root_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

operator_home="$(/usr/bin/python3 -I -c '
import os,pwd
print(pwd.getpwuid(os.geteuid()).pw_dir)
')"
[[ "$operator_home" == /* && "$operator_home" != *$'\n'* \
    && -d "$operator_home" && ! -L "$operator_home" \
    && "$(/usr/bin/stat -f %u "$operator_home")" == "$EUID" ]] || {
  echo "The operator home directory is not trusted." >&2
  exit 1
}

require_trusted_notary_keychain() {
  /usr/bin/python3 -I -c '
import os,stat,sys

path,home=sys.argv[1:]
failure="control_center_notary_keychain_untrusted"
fds=[]

def reject():
    raise SystemExit(failure)

def same_inode(*records):
    return len({(item.st_dev,item.st_ino) for item in records}) == 1

def trusted_directory(item,euid):
    return (stat.S_ISDIR(item.st_mode) and item.st_uid == euid
            and not item.st_mode & 0o022)

try:
    euid=os.geteuid()
    if (not path or not home or "\n" in path or "\r" in path
            or not os.path.isabs(path) or not os.path.isabs(home)
            or os.path.normpath(path) != path
            or os.path.realpath(path) != path
            or os.path.realpath(home) != home):
        reject()
    keychains=os.path.join(home,"Library","Keychains")
    basename=os.path.basename(path)
    if (os.path.dirname(path) != keychains
            or basename in {"",".",".."}):
        reject()
    nofollow=getattr(os,"O_NOFOLLOW",None)
    directory=getattr(os,"O_DIRECTORY",None)
    nonblock=getattr(os,"O_NONBLOCK",None)
    if nofollow is None or directory is None or nonblock is None:
        reject()
    directory_flags=os.O_RDONLY | directory | nofollow
    file_flags=os.O_RDONLY | nofollow | nonblock

    home_before=os.lstat(home)
    home_fd=os.open(home,directory_flags); fds.append(home_fd)
    home_opened=os.fstat(home_fd)
    library_before=os.stat("Library",dir_fd=home_fd,follow_symlinks=False)
    library_fd=os.open("Library",directory_flags,dir_fd=home_fd)
    fds.append(library_fd)
    library_opened=os.fstat(library_fd)
    keychains_before=os.stat(
        "Keychains",dir_fd=library_fd,follow_symlinks=False,
    )
    keychains_fd=os.open("Keychains",directory_flags,dir_fd=library_fd)
    fds.append(keychains_fd)
    keychains_opened=os.fstat(keychains_fd)
    keychain_before=os.lstat(basename,dir_fd=keychains_fd)
    if not stat.S_ISREG(keychain_before.st_mode):
        reject()
    keychain_fd=os.open(basename,file_flags,dir_fd=keychains_fd)
    fds.append(keychain_fd)
    keychain_opened=os.fstat(keychain_fd)

    home_after=os.lstat(home)
    library_after=os.stat("Library",dir_fd=home_fd,follow_symlinks=False)
    keychains_after=os.stat(
        "Keychains",dir_fd=library_fd,follow_symlinks=False,
    )
    keychain_after=os.lstat(basename,dir_fd=keychains_fd)
    if (not same_inode(home_before,home_opened,home_after)
            or not same_inode(
                library_before,library_opened,library_after,
            )
            or not same_inode(
                keychains_before,keychains_opened,keychains_after,
            )
            or not same_inode(
                keychain_before,keychain_opened,keychain_after,
            )
            or not all(trusted_directory(item,euid) for item in (
                home_opened,library_opened,keychains_opened,
            ))
            or not stat.S_ISREG(keychain_opened.st_mode)
            or keychain_opened.st_uid != euid
            or keychain_opened.st_nlink != 1
            or keychain_opened.st_mode & 0o022):
        reject()
except (OSError,ValueError):
    reject()
finally:
    for descriptor in reversed(fds):
        os.close(descriptor)
' "$notary_keychain" "$operator_home" || {
    echo "The explicit notarization Keychain is not trusted." >&2
    return 1
  }
}

notary_keychain_args=(
  --keychain-profile "$notary_keychain_profile"
  --keychain "$notary_keychain"
)
require_trusted_notary_keychain
if ! /usr/bin/xcrun notarytool history \
    "${notary_keychain_args[@]}" --output-format json >/dev/null; then
  echo "The explicit notarization Keychain profile is unavailable; no release artifact work began." >&2
  exit 1
fi

require_app_only_manual_admission() {
  local sequence_floor installed_app installed_sequence
  [[ "$release_mode" == notarized-app-only ]] || return 0
  sequence_floor="$operator_home/Library/Application Support/SecureSandbox/Updates/sequence-floor.json"
  [[ ! -e "$sequence_floor" && ! -L "$sequence_floor" ]] || {
    echo "The in-app update sequence floor exists; use the in-app update path." >&2
    return 1
  }
  installed_app="$operator_home/Applications/SecureSandbox.app"
  if [[ ! -e "$installed_app" && ! -L "$installed_app" ]]; then
    return 0
  fi
  [[ -d "$installed_app" && ! -L "$installed_app" \
      && "$(/usr/bin/stat -f %u "$installed_app")" == "$EUID" ]] || {
    echo "The installed Control Center path is not trusted." >&2
    return 1
  }
  "$root_dir/script/validate_bundle.sh" \
    "$installed_app" --distribution >/dev/null
  installed_sequence="$(/usr/libexec/PlistBuddy \
    -c 'Print :SSUpdateSequence' "$installed_app/Contents/Info.plist")"
  /usr/bin/python3 -I -c '
import re,sys
limit=(1 << 64) - 1
def parsed(raw,label):
    if re.fullmatch(r"[1-9][0-9]*",raw) is None:
        raise SystemExit(f"{label}_sequence_invalid")
    value=int(raw)
    if value > limit:
        raise SystemExit(f"{label}_sequence_outside_uint64")
    return value
candidate=parsed(sys.argv[1],"candidate")
installed=parsed(sys.argv[2],"installed")
if candidate <= installed:
    raise SystemExit("notarized_app_sequence_must_advance")
' "$sequence" "$installed_sequence"
}
require_app_only_manual_admission

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
if [[ "$release_mode" == update ]]; then
  evidence_dir="$dist_dir/update"
  output_dir="$evidence_dir/$version-$build"
else
  evidence_dir="$dist_dir/notarized-app"
  output_dir="$evidence_dir/$version-$build-$sequence"
fi
publish_target="$dist_dir/SecureSandboxControlCenter.app"
publish_previous="$dist_dir/.SecureSandboxControlCenter.release-previous.app"
release_workspace=""
publish_stage=""
publish_moved_existing=false
publish_installed_new=false
publish_complete=false
receipt=""
cleanup_release() {
  local status=$?
  set +e
  unset update_signing_key
  if [[ "$publish_complete" != true ]]; then
    if [[ -n "$receipt" && -f "$receipt" && ! -L "$receipt" ]]; then
      /bin/rm -f -- "$receipt"
    fi
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
if [[ ! -e "$evidence_dir" ]]; then
  /bin/mkdir -m 700 "$evidence_dir"
fi
[[ -d "$evidence_dir" && ! -L "$evidence_dir" \
    && "$(/usr/bin/stat -f %u "$evidence_dir")" == "$EUID" ]] || {
  echo "The release evidence directory is not trusted." >&2
  exit 1
}
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || {
  echo "Release output already exists: $output_dir" >&2
  exit 1
}
/bin/mkdir -m 700 "$output_dir"
[[ -d "$output_dir" && ! -L "$output_dir" \
    && "$(/usr/bin/stat -f %u "$output_dir")" == "$EUID" ]] || {
  echo "The release evidence tuple directory is not trusted." >&2
  exit 1
}

release_workspace="$(/usr/bin/mktemp \
  -d /tmp/secure-sandbox-control-center-release.XXXXXX)"
source_archive="$release_workspace/source.tar"
source_root="$release_workspace/source"
/bin/mkdir "$source_root"
/usr/bin/git -C "$release_repo" archive --format=tar \
  --output="$source_archive" "$release_commit"
source_archive_sha256="$(/usr/bin/shasum -a 256 "$source_archive" \
  | /usr/bin/awk '{print $1}')"
/usr/bin/tar -xf "$source_archive" -C "$source_root"
candidate_control="$source_root/macos/ControlCenter"
candidate_validator="$candidate_control/script/validate_bundle.sh"
required_sources=(
  "$candidate_control/Package.swift" \
  "$candidate_control/Package.resolved" \
  "$candidate_control/Resources/Update/UpdatePolicy.json" \
  "$candidate_control/script/build_and_run.sh" \
  "$candidate_validator"
)
if [[ "$release_mode" == update ]]; then
  required_sources+=(
    "$candidate_control/Sources/SecureSandboxUpdateSigner/main.swift"
    "$source_root/scripts/build-native-credential-components.sh"
  )
fi
for required_source in "${required_sources[@]}"; do
  [[ -f "$required_source" && ! -L "$required_source" ]] || {
    echo "The committed release source archive is incomplete." >&2
    exit 1
  }
done
require_disabled_update_policy() {
  local policy="$1"
  [[ -f "$policy" && ! -L "$policy" ]] || {
    echo "The notarized-app-only update policy is not a regular file." >&2
    return 1
  }
  /usr/bin/python3 -I -c '
import json,pathlib,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_keys={
    "artifact_origin","artifact_redirect_hosts","bundle_identifier","channel",
    "disabled_reason","enabled","key_id","manifest_url",
    "maximum_artifact_bytes","maximum_manifest_bytes","public_key_base64",
    "schema","team_identifier",
}
if (
    not isinstance(value,dict)
    or set(value) != expected_keys
    or value.get("schema") != "secure-sandbox-control-center-update-policy-v1"
    or value.get("enabled") is not False
    or not isinstance(value.get("disabled_reason"),str)
    or not value["disabled_reason"].strip()
    or value.get("channel") != "stable"
    or value.get("manifest_url") is not None
    or value.get("key_id") is not None
    or value.get("public_key_base64") is not None
    or value.get("artifact_origin") is not None
    or value.get("artifact_redirect_hosts") != []
    or value.get("team_identifier") is not None
    or value.get("bundle_identifier") != "org.zebeth.SecureSandbox.ControlCenter"
    or type(value.get("maximum_manifest_bytes")) is not int
    or value["maximum_manifest_bytes"] != 131072
    or type(value.get("maximum_artifact_bytes")) is not int
    or value["maximum_artifact_bytes"] != 268435456
):
    raise SystemExit("notarized_app_only_requires_disabled_update_policy")
' "$policy"
}
if [[ "$release_mode" == notarized-app-only ]]; then
  require_disabled_update_policy \
    "$candidate_control/Resources/Update/UpdatePolicy.json"
fi

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
if [[ "$release_mode" == update ]]; then
  SECURE_SANDBOX_SWIFT_HERMETIC=1 \
  SECURE_SANDBOX_SWIFT_SCRATCH_PATH="$swift_scratch" \
    "$source_root/scripts/build-native-credential-components.sh" >/dev/null
fi

SECURE_SANDBOX_SWIFT_HERMETIC=1 \
SECURE_SANDBOX_SWIFT_SCRATCH_PATH="$swift_scratch" \
SECURE_SANDBOX_BUILD_CONFIGURATION=release \
SECURE_SANDBOX_APP_VERSION="$version" \
SECURE_SANDBOX_APP_BUILD="$build" \
SECURE_SANDBOX_UPDATE_SEQUENCE="$sequence" \
SECURE_SANDBOX_RELEASE_COMMIT="$release_commit" \
  "$candidate_control/script/build_and_run.sh" --build-only >/dev/null
candidate_app="$candidate_control/dist/SecureSandboxControlCenter.app"
"$candidate_validator" "$candidate_app" --pre-notarization >/dev/null
if [[ "$release_mode" == notarized-app-only ]]; then
  require_disabled_update_policy \
    "$candidate_app/Contents/Resources/UpdatePolicy.json"
fi
[[ "$(/usr/libexec/PlistBuddy -c 'Print :SSReleaseCommit' \
    "$candidate_app/Contents/Info.plist")" == "$release_commit" ]] || {
  echo "The signed candidate is not bound to the captured release commit." >&2
  exit 1
}

signer_binary=""
if [[ "$release_mode" == update ]]; then
  /usr/bin/swift build -c release "${swift_options[@]}" \
    --product SecureSandboxUpdateSigner >/dev/null
  signer_bin_path="$(/usr/bin/swift build -c release \
    "${swift_options[@]}" --show-bin-path)"
  signer_binary="$signer_bin_path/SecureSandboxUpdateSigner"
  [[ -f "$signer_binary" && ! -L "$signer_binary" && -x "$signer_binary" ]] || {
    echo "The archived-source update signer build is invalid." >&2
    exit 1
  }
fi

submission="$output_dir/notary-submission.zip"
notary_result="$output_dir/notary-result.json"
notary_log="$output_dir/notary-log.json"
/usr/bin/ditto -c -k --keepParent "$candidate_app" "$submission"
submission_sha256="$(/usr/bin/shasum -a 256 "$submission" \
  | /usr/bin/awk '{print $1}')"
require_trusted_notary_keychain
/usr/bin/xcrun notarytool submit "$submission" \
  "${notary_keychain_args[@]}" --wait \
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
require_trusted_notary_keychain
/usr/bin/xcrun notarytool log "$submission_id" \
  "${notary_keychain_args[@]}" "$notary_log"
/usr/bin/python3 -I -c '
import json,pathlib,re,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if (
    value.get("status") != "Accepted"
    or not isinstance(value.get("statusCode"), int)
    or isinstance(value["statusCode"], bool)
    or value["statusCode"] != 0
    or "issues" not in value
    or value["issues"] not in (None, [])
    or str(value.get("jobId", "")).lower() != sys.argv[2].lower()
    or re.fullmatch(r"[0-9a-fA-F]{64}",str(value.get("sha256", ""))) is None
    or str(value["sha256"]).lower() != sys.argv[3].lower()
):
    raise SystemExit("control_center_notary_log_not_clean")
' "$notary_log" "$submission_id" "$submission_sha256"
/usr/bin/xcrun stapler staple "$candidate_app"
/usr/bin/xcrun stapler validate "$candidate_app"
"$candidate_validator" "$candidate_app" --distribution >/dev/null
require_unchanged_release_source
candidate_app_details="$(/usr/bin/codesign -dv --verbose=4 \
  "$candidate_app" 2>&1)"
candidate_helper="$candidate_app/Contents/Helpers/SecureSandboxUpdateInstaller"
candidate_helper_details="$(/usr/bin/codesign -dv --verbose=4 \
  "$candidate_helper" 2>&1)"
candidate_app_identifier="$(/usr/bin/printf '%s\n' "$candidate_app_details" \
  | /usr/bin/sed -n 's/^Identifier=//p')"
candidate_helper_identifier="$(/usr/bin/printf '%s\n' "$candidate_helper_details" \
  | /usr/bin/sed -n 's/^Identifier=//p')"
candidate_app_team="$(/usr/bin/printf '%s\n' "$candidate_app_details" \
  | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
candidate_helper_team="$(/usr/bin/printf '%s\n' "$candidate_helper_details" \
  | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
candidate_app_cdhash="$(/usr/bin/printf '%s\n' "$candidate_app_details" \
  | /usr/bin/sed -n 's/^CDHash=//p')"
candidate_helper_cdhash="$(/usr/bin/printf '%s\n' "$candidate_helper_details" \
  | /usr/bin/sed -n 's/^CDHash=//p')"
[[ "$candidate_app_identifier" == org.zebeth.SecureSandbox.ControlCenter \
    && "$candidate_helper_identifier" == SecureSandboxUpdateInstaller \
    && "$candidate_app_team" == 389K3H8Y32 \
    && "$candidate_helper_team" == 389K3H8Y32 \
    && "$candidate_app_cdhash" =~ ^[0-9A-Fa-f]{40}$ \
    && "$candidate_helper_cdhash" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo "The notarized candidate signing evidence is incomplete." >&2
  exit 1
}

artifact=""
envelope=""
if [[ "$release_mode" == update ]]; then
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
fi

require_app_only_manual_admission
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
[[ "$(/usr/libexec/PlistBuddy -c 'Print :SSReleaseCommit' \
    "$publish_target/Contents/Info.plist")" == "$release_commit" \
    && "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$publish_target/Contents/Info.plist")" == "$version" \
    && "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
    "$publish_target/Contents/Info.plist")" == "$build" \
    && "$(/usr/libexec/PlistBuddy -c 'Print :SSUpdateSequence' \
    "$publish_target/Contents/Info.plist")" == "$sequence" ]] || {
  echo "The published Control Center is not bound to the release tuple." >&2
  exit 1
}
published_app_details="$(/usr/bin/codesign -dv --verbose=4 \
  "$publish_target" 2>&1)"
published_helper="$publish_target/Contents/Helpers/SecureSandboxUpdateInstaller"
published_helper_details="$(/usr/bin/codesign -dv --verbose=4 \
  "$published_helper" 2>&1)"
published_app_identifier="$(/usr/bin/printf '%s\n' "$published_app_details" \
  | /usr/bin/sed -n 's/^Identifier=//p')"
published_helper_identifier="$(/usr/bin/printf '%s\n' "$published_helper_details" \
  | /usr/bin/sed -n 's/^Identifier=//p')"
published_app_team="$(/usr/bin/printf '%s\n' "$published_app_details" \
  | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
published_helper_team="$(/usr/bin/printf '%s\n' "$published_helper_details" \
  | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
published_app_cdhash="$(/usr/bin/printf '%s\n' "$published_app_details" \
  | /usr/bin/sed -n 's/^CDHash=//p')"
published_helper_cdhash="$(/usr/bin/printf '%s\n' "$published_helper_details" \
  | /usr/bin/sed -n 's/^CDHash=//p')"
[[ "$published_app_identifier" == "$candidate_app_identifier" \
    && "$published_helper_identifier" == "$candidate_helper_identifier" \
    && "$published_app_team" == "$candidate_app_team" \
    && "$published_helper_team" == "$candidate_helper_team" \
    && "$published_app_cdhash" == "$candidate_app_cdhash" \
    && "$published_helper_cdhash" == "$candidate_helper_cdhash" ]] || {
  echo "The published Control Center signing evidence changed in transit." >&2
  exit 1
}
require_unchanged_release_source
if [[ "$release_mode" == notarized-app-only ]]; then
notary_log_sha256="$(/usr/bin/shasum -a 256 "$notary_log" \
  | /usr/bin/awk '{print $1}')"
receipt="$output_dir/notarized-app-receipt.json"
/usr/bin/python3 -I -c '
import json,os,sys
path=sys.argv[1]
value={
    "build":int(sys.argv[4]),
    "dist_published":True,
    "gatekeeper_assessed":True,
    "helper":{"cdhash":sys.argv[13],"identifier":sys.argv[12]},
    "main":{"cdhash":sys.argv[11],"identifier":sys.argv[10]},
    "notary_log_sha256":sys.argv[8],
    "notary_submission_id":sys.argv[6],
    "notary_submission_sha256":sys.argv[7],
    "release_commit":sys.argv[2],
    "release_mode":sys.argv[9],
    "schema":"secure-sandbox-control-center-notarized-app-receipt-v1",
    "sequence":int(sys.argv[5]),
    "source_archive_sha256":sys.argv[14],
    "stapler_validated":True,
    "status":"verified",
    "team_id":"389K3H8Y32",
    "version":sys.argv[3],
}
data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"wb") as stream:
    stream.write(data)
' "$receipt" "$release_commit" "$version" "$build" "$sequence" \
  "$submission_id" "$submission_sha256" "$notary_log_sha256" \
  "$release_mode" "$published_app_identifier" "$published_app_cdhash" \
  "$published_helper_identifier" "$published_helper_cdhash" \
  "$source_archive_sha256"
/usr/bin/python3 -I -c '
import json,os,re,stat,sys
path=sys.argv[1]
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,"r",encoding="utf-8") as stream:
    evidence=os.fstat(stream.fileno())
    if (
        not stat.S_ISREG(evidence.st_mode)
        or evidence.st_uid != os.geteuid()
        or evidence.st_nlink != 1
        or stat.S_IMODE(evidence.st_mode) != 0o600
    ):
        raise SystemExit("notarized_app_receipt_identity_invalid")
    value=json.load(stream)
expected={
    "build":int(sys.argv[4]),
    "dist_published":True,
    "gatekeeper_assessed":True,
    "helper":{"cdhash":sys.argv[13],"identifier":sys.argv[12]},
    "main":{"cdhash":sys.argv[11],"identifier":sys.argv[10]},
    "notary_log_sha256":sys.argv[8],
    "notary_submission_id":sys.argv[6],
    "notary_submission_sha256":sys.argv[7],
    "release_commit":sys.argv[2],
    "release_mode":sys.argv[9],
    "schema":"secure-sandbox-control-center-notarized-app-receipt-v1",
    "sequence":int(sys.argv[5]),
    "source_archive_sha256":sys.argv[14],
    "stapler_validated":True,
    "status":"verified",
    "team_id":"389K3H8Y32",
    "version":sys.argv[3],
}
if value != expected:
    raise SystemExit("notarized_app_receipt_readback_mismatch")
for cdhash in (value["main"]["cdhash"],value["helper"]["cdhash"]):
    if re.fullmatch(r"[0-9a-fA-F]{40}",cdhash) is None:
        raise SystemExit("notarized_app_receipt_cdhash_invalid")
for digest in (
    value["notary_log_sha256"],value["notary_submission_sha256"],
    value["source_archive_sha256"],
):
    if re.fullmatch(r"[0-9a-f]{64}",digest) is None:
        raise SystemExit("notarized_app_receipt_sha256_invalid")
' "$receipt" "$release_commit" "$version" "$build" "$sequence" \
  "$submission_id" "$submission_sha256" "$notary_log_sha256" \
  "$release_mode" "$published_app_identifier" "$published_app_cdhash" \
  "$published_helper_identifier" "$published_helper_cdhash" \
  "$source_archive_sha256"
fi
publish_complete=true
if [[ "$publish_moved_existing" == true ]]; then
  /bin/rm -rf -- "$publish_previous"
fi
/bin/rm "$submission"
if [[ "$release_mode" == update ]]; then
  printf '{"schema":"secure-sandbox-control-center-release-build-v1","status":"verified","version":"%s","build":%s,"sequence":%s,"artifact":"%s","envelope":"%s"}\n' \
    "$version" "$build" "$sequence" "$artifact" "$envelope"
else
  /usr/bin/python3 -I -c '
import json,sys
print(json.dumps({
    "app":sys.argv[5],
    "build":int(sys.argv[2]),
    "receipt":sys.argv[6],
    "schema":"secure-sandbox-control-center-notarized-app-build-v1",
    "sequence":int(sys.argv[3]),
    "status":"verified",
    "version":sys.argv[1],
},sort_keys=True,separators=(",",":")))
' "$version" "$build" "$sequence" "$release_mode" "$publish_target" "$receipt"
fi
