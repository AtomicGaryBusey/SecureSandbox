#!/bin/bash -p
set -euo pipefail
set +x
set +a
umask 077
[[ "$-" == *p* ]] || {
  echo native_component_builder_requires_direct_privileged_bash_execution >&2
  exit 2
}

fixed_team="389K3H8Y32"
identity="${SECURE_SANDBOX_DEVELOPER_ID:-}"
swift_scratch_path="${SECURE_SANDBOX_SWIFT_SCRATCH_PATH:-}"
swift_hermetic="${SECURE_SANDBOX_SWIFT_HERMETIC:-0}"
release_candidate="${SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY:-0}"
release_output_root="${SECURE_SANDBOX_RELEASE_OUTPUT_ROOT:-}"
release_commit="${SECURE_SANDBOX_RELEASE_COMMIT:-}"
source_archive_sha256="${SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256:-}"
expected_team_input="${SECURE_SANDBOX_EXPECTED_TEAM_ID:-}"
signing_config_sha256_input="${SECURE_SANDBOX_SIGNING_CONFIG_SHA256:-}"
release_source_root="${SECURE_SANDBOX_RELEASE_SOURCE_ROOT:-}"

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
unset SWIFT_DRIVER_SWIFT_EXEC SWIFTFLAGS OTHER_SWIFT_FLAGS SWIFT_INCLUDE_PATHS
unset MACOSX_DEPLOYMENT_TARGET ARCHS VALID_ARCHS EXCLUDED_ARCHS ONLY_ACTIVE_ARCH
unset CC CXX LD AR NM CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR LLVM_PROFILE_FILE
unset CODESIGN_ALLOCATE XCODE_XCCONFIG_FILE OTHER_CODE_SIGN_FLAGS
unset CODE_SIGN_IDENTITY CODE_SIGN_STYLE DEVELOPMENT_TEAM
unset PROVISIONING_PROFILE PROVISIONING_PROFILE_SPECIFIER
unset CODE_SIGNING_ALLOWED CODE_SIGNING_REQUIRED CODE_SIGN_ENTITLEMENTS
unset CODE_SIGN_INJECT_BASE_ENTITLEMENTS ENABLE_HARDENED_RUNTIME
unset EXPANDED_CODE_SIGN_IDENTITY PRODUCT_BUNDLE_IDENTIFIER
unset CONFIGURATION ACTION SYMROOT OBJROOT DSTROOT BUILD_DIR TARGET_BUILD_DIR
unset CONFIGURATION_BUILD_DIR BUILT_PRODUCTS_DIR PROJECT_TEMP_DIR TEMP_DIR
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONBREAKPOINT
unset SECURE_SANDBOX_DEVELOPER_ID SECURE_SANDBOX_SWIFT_SCRATCH_PATH
unset SECURE_SANDBOX_SWIFT_HERMETIC SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY
unset SECURE_SANDBOX_RELEASE_OUTPUT_ROOT SECURE_SANDBOX_RELEASE_COMMIT
unset SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256 SECURE_SANDBOX_SIGNING_CONFIG
unset SECURE_SANDBOX_EXPECTED_TEAM_ID SECURE_SANDBOX_SIGNING_CONFIG_SHA256
unset SECURE_SANDBOX_RELEASE_SOURCE_ROOT
for inherited_name in "${!DYLD_@}" "${!LD_@}" \
    "${!SWIFTPM_@}" "${!XCODE_@}"; do
  unset "$inherited_name"
done

if [[ "$release_candidate" == 1 && -n "$release_source_root" ]]; then
  repo="$release_source_root"
else
  repo="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
fi
source_package="$repo/macos/ControlCenter"
release_package_template="$source_package/NativeHostComponents.Package.swift"
helper_name="SecureSandboxNativeCredentialHelper.app"
backend_name="SecureSandboxNativeStackBackend"
consumer_name="SecureSandboxNativeProjectionConsumer"
manifest_name="SecureSandboxNativeComponents.bundle.json"
helper_identifier="org.zebeth.SecureSandbox.NativeCredentialHelper"
backend_identifier="org.zebeth.SecureSandbox.NativeStackBackend"
consumer_identifier="org.zebeth.SecureSandbox.NativeProjectionConsumer"

directory_record() {
  /usr/bin/python3 -I -c '
import json,os,stat,sys
path=sys.argv[1]; private=sys.argv[2]=="1"; expected_uid=int(sys.argv[3])
before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    opened=os.fstat(fd); named=os.lstat(path)
finally:
    os.close(fd)
mode=stat.S_IMODE(opened.st_mode)
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or opened.st_uid!=expected_uid or (private and mode&0o077)):
    raise SystemExit("native_component_directory_untrusted")
print(json.dumps({"dev":opened.st_dev,"gid":opened.st_gid,
    "ino":opened.st_ino,"mode":mode,"uid":opened.st_uid},
    sort_keys=True,separators=(",",":")))
' "$1" "$2" "$EUID"
}

validate_directory_record() {
  /usr/bin/python3 -I -c '
import json,os,stat,sys
path=sys.argv[1]; expected=json.loads(sys.argv[2]); failure=sys.argv[3]
before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    opened=os.fstat(fd); named=os.lstat(path)
finally:
    os.close(fd)
record={"dev":opened.st_dev,"gid":opened.st_gid,"ino":opened.st_ino,
        "mode":stat.S_IMODE(opened.st_mode),"uid":opened.st_uid}
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or record!=expected):
    raise SystemExit(failure)
' "$1" "$2" "$3"
}

run_in_recorded_directory() {
  local directory="$1" record="$2" failure="$3"
  shift 3
  /usr/bin/python3 -I -c '
import json,os,stat,sys
path=sys.argv[1]; expected=json.loads(sys.argv[2]); failure=sys.argv[3]
command=sys.argv[4:]
before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
opened=os.fstat(fd); named=os.lstat(path)
record={"dev":opened.st_dev,"gid":opened.st_gid,"ino":opened.st_ino,
        "mode":stat.S_IMODE(opened.st_mode),"uid":opened.st_uid}
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or record!=expected or not command or not command[0].startswith("/")):
    os.close(fd); raise SystemExit(failure)
os.fchdir(fd)
os.set_inheritable(fd,False)
os.execve(command[0],command,os.environ)
' "$directory" "$record" "$failure" "$@"
}

retain_existing_entry() {
  /usr/bin/python3 -I -c '
import ctypes,errno,json,os,stat,sys
path,encoded,name,failure=sys.argv[1:]
expected=json.loads(encoded)
if not name or name in {".",".."} or "/" in name:
    raise SystemExit(failure)
before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    opened=os.fstat(fd); named=os.lstat(path)
    record={"dev":opened.st_dev,"gid":opened.st_gid,"ino":opened.st_ino,
        "mode":stat.S_IMODE(opened.st_mode),"uid":opened.st_uid}
    if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
            or record!=expected):
        raise SystemExit(failure)
    libc=ctypes.CDLL(None,use_errno=True); rename=libc.renameatx_np
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,
        ctypes.c_char_p,ctypes.c_uint); rename.restype=ctypes.c_int
    for attempt in range(16):
        retained=(".secure-sandbox-retained-"+str(os.getpid())+"-"
            +os.urandom(12).hex())
        if rename(fd,os.fsencode(name),fd,os.fsencode(retained),4)==0:
            os.fsync(fd); break
        value=ctypes.get_errno()
        if value==errno.ENOENT: break
        if value!=errno.EEXIST: raise OSError(value,os.strerror(value),name)
    else: raise SystemExit(failure)
finally:
    os.close(fd)
' "$1" "$2" "$3" "$4"
}

closed_component_source_record() {
  /usr/bin/python3 -I -c '
import hashlib,json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); expected_uid=int(sys.argv[2]); layout=sys.argv[3]
if layout not in {"source","snapshot"}:
    raise SystemExit("native_component_source_layout_invalid")
package=("NativeHostComponents.Package.swift" if layout=="source" else "Package.swift")
roots=[
 (package,"Package.swift"),
 ("Sources/SecureSandboxNativeAuthCore","Sources/SecureSandboxNativeAuthCore"),
 ("Sources/SecureSandboxNativeXPCTransport","Sources/SecureSandboxNativeXPCTransport"),
 ("Sources/SecureSandboxNativeCredentialHelper","Sources/SecureSandboxNativeCredentialHelper"),
 ("Sources/SecureSandboxNativeCredentialXPCService","Sources/SecureSandboxNativeCredentialXPCService"),
 ("Sources/SecureSandboxNativeStackBackend","Sources/SecureSandboxNativeStackBackend"),
 ("Sources/SecureSandboxNativeProjectionConsumer","Sources/SecureSandboxNativeProjectionConsumer"),
]
entries={}
for relative_root,canonical_root in roots:
    start=root/relative_root
    if not start.exists() or start.is_symlink():
        raise SystemExit("native_component_source_inventory_invalid")
    paths=[start]
    if start.is_dir(): paths.extend(sorted(start.rglob("*")))
    for path in paths:
        suffix=path.relative_to(start)
        relative=(pathlib.PurePosixPath(canonical_root)/suffix).as_posix()
        info=path.lstat()
        if info.st_uid!=expected_uid or stat.S_IMODE(info.st_mode)&0o022:
            raise SystemExit("native_component_source_untrusted:"+relative)
        if stat.S_ISDIR(info.st_mode):
            entries[relative]={"kind":"directory","mode":0o555}
        elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
            data=path.read_bytes()
            current=path.lstat()
            if ((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
                    !=(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns)
                    or len(data)!=info.st_size):
                raise SystemExit("native_component_source_changed:"+relative)
            entries[relative]={"kind":"file",
                "mode":0o555 if stat.S_IMODE(info.st_mode)&0o111 else 0o444,
                "sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
        else:
            raise SystemExit("native_component_source_entry_invalid:"+relative)
raw=(json.dumps(entries,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
print(hashlib.sha256(raw).hexdigest())
' "$1" "$EUID" "$2"
}

closed_tree_record() {
  /usr/bin/python3 -I -c '
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); expected_uid=int(sys.argv[2]); entries={}
if not root.is_dir() or root.is_symlink(): raise SystemExit("native_component_snapshot_invalid")
for path in sorted(root.rglob("*")):
    relative=path.relative_to(root).as_posix(); info=path.lstat()
    if info.st_uid!=expected_uid or stat.S_IMODE(info.st_mode)&0o022:
        raise SystemExit("native_component_snapshot_untrusted:"+relative)
    if stat.S_ISDIR(info.st_mode):
        entries[relative]={"kind":"directory","mode":stat.S_IMODE(info.st_mode)}
    elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
        data=path.read_bytes(); current=path.lstat()
        if ((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
                !=(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns)
                or len(data)!=info.st_size):
            raise SystemExit("native_component_snapshot_changed:"+relative)
        entries[relative]={"kind":"file","mode":stat.S_IMODE(info.st_mode),
            "sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
    else: raise SystemExit("native_component_snapshot_entry_invalid:"+relative)
raw=(json.dumps(entries,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
print(hashlib.sha256(raw).hexdigest())
' "$1" "$EUID"
}

[[ "$identity" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo SECURE_SANDBOX_DEVELOPER_ID_must_be_an_exact_SHA1_fingerprint >&2
  exit 2
}
identity="$(/bin/echo "$identity" | /usr/bin/tr '[:lower:]' '[:upper:]')"
[[ "$release_candidate" == 0 || "$release_candidate" == 1 ]] || {
  echo SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY_must_be_0_or_1 >&2
  exit 2
}
[[ "$swift_hermetic" == 1 ]] || {
  echo SECURE_SANDBOX_SWIFT_HERMETIC_must_be_1 >&2
  exit 2
}
if [[ "$release_candidate" == 1 ]]; then
  [[ "$release_source_root" == /* && -d "$release_source_root" \
      && ! -L "$release_source_root" \
      && "$(cd "$release_source_root" && pwd -P)" == "$release_source_root" \
      && "$release_output_root" == /* \
      && "$release_commit" =~ ^[0-9a-f]{40}$ \
      && "$source_archive_sha256" =~ ^[0-9a-f]{64}$ \
      && "$expected_team_input" == "$fixed_team" \
      && "$signing_config_sha256_input" =~ ^[0-9a-f]{64}$ ]] || {
    echo native_component_release_contract_invalid >&2
    exit 2
  }
  artifact_root="$release_output_root"
else
  [[ -z "$release_output_root" && -z "$release_commit" \
      && -z "$source_archive_sha256" && -z "$expected_team_input" \
      && -z "$signing_config_sha256_input" \
      && -z "$release_source_root" ]] || {
    echo native_component_nonrelease_contract_invalid >&2
    exit 2
  }
  artifact_root="$repo/artifacts/host"
fi

if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then
  [[ -d "$artifact_root" && ! -L "$artifact_root" \
      && "$artifact_root" == /* \
      && "$(/usr/bin/stat -f %u "$artifact_root")" == "$EUID" ]] || {
    echo native_component_output_root_untrusted >&2
    exit 1
  }
else
  [[ "$release_candidate" == 0 ]] || {
    echo native_component_release_output_root_untrusted >&2
    exit 1
  }
  /bin/mkdir -p "$artifact_root"
fi
if [[ "$release_candidate" == 1 ]]; then
  artifact_mode="$(/usr/bin/stat -f %Lp "$artifact_root")"
  [[ "$artifact_mode" =~ ^[0-7]00$ ]] || {
    echo native_component_release_output_permissions_invalid >&2
    exit 1
  }
  for candidate in \
    "$artifact_root/$helper_name" \
    "$artifact_root/$backend_name" \
    "$artifact_root/$consumer_name" \
    "$artifact_root/$manifest_name"; do
    [[ ! -e "$candidate" && ! -L "$candidate" ]] || {
      echo native_component_release_output_already_exists >&2
      exit 1
    }
  done
fi
artifact_root_record="$(directory_record \
  "$artifact_root" "$release_candidate")" \
  || { echo native_component_output_root_untrusted >&2; exit 1; }
release_source_root_record=""
if [[ "$release_candidate" == 1 ]]; then
  release_source_root_record="$(directory_record "$repo" 1)" \
    || { echo native_component_release_source_root_untrusted >&2; exit 1; }
fi
source_record="$(closed_component_source_record "$source_package" source)" \
  || { echo native_component_source_inventory_invalid >&2; exit 1; }

[[ "$swift_scratch_path" == /* && -d "$swift_scratch_path" \
    && ! -L "$swift_scratch_path" \
    && "$(/usr/bin/stat -f %u "$swift_scratch_path")" == "$EUID" \
    && "$(/usr/bin/stat -f %Lp "$swift_scratch_path")" =~ ^[0-7]00$ \
    && -f "$release_package_template" \
    && ! -L "$release_package_template" ]] || {
  echo hermetic_Swift_build_requires_private_scratch_and_closed_package >&2
  exit 2
}
/usr/bin/python3 -I -c '
import os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); expected_uid=int(sys.argv[2])
allowed={"cache","config","security"}
for path in root.iterdir():
    info=path.lstat()
    if (path.name not in allowed or not stat.S_ISDIR(info.st_mode)
            or path.is_symlink() or info.st_uid!=expected_uid
            or stat.S_IMODE(info.st_mode)&0o077 or any(path.iterdir())):
        raise SystemExit("native_component_swift_scratch_not_fresh")
' "$swift_scratch_path" "$EUID"
for swift_directory in cache config security; do
  if [[ ! -e "$swift_scratch_path/$swift_directory" ]]; then
    /bin/mkdir -m 700 "$swift_scratch_path/$swift_directory"
  fi
done

/usr/bin/python3 -I -c '
import re,subprocess,sys
fingerprint,team=sys.argv[1:]
output=subprocess.run(
    ["/usr/bin/security","find-identity","-v","-p","codesigning"],
    check=True,capture_output=True,text=True,
).stdout
pattern=re.compile(r"^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+\"([^\"]+)\"\s*$",re.M)
matches=[name for digest,name in pattern.findall(output)
         if digest.upper()==fingerprint
         and name.startswith("Developer ID Application:")
         and name.endswith(" ("+team+")")]
if len(matches)!=1:
    raise SystemExit("native_component_requested_developer_id_unavailable")
' "$identity" "$fixed_team"

if [[ "$release_candidate" == 1 ]]; then
  build_temp_parent="$(/usr/bin/dirname "$artifact_root")"
else
  build_temp_parent=/private/tmp
fi
build_root="$(/usr/bin/mktemp -d \
  "$build_temp_parent/.secure-sandbox-native-components.XXXXXX")"
build_root_record="$(directory_record "$build_root" 1)" \
  || { echo native_component_build_root_untrusted >&2; exit 1; }
stage="$build_root/stage"
build_package="$build_root/package"
helper="$stage/$helper_name"
backend="$stage/$backend_name"
consumer="$stage/$consumer_name"
manifest="$stage/$manifest_name"
cleanup() {
  # Darwin cannot condition unlink/rmdir on an already-open inode.  Retain the
  # whole tree under a no-replace quarantine name so a raced object is never
  # destroyed; /tmp owns eventual lifecycle cleanup.
  local status=$?
  if [[ -e "$build_root" || -L "$build_root" ]]; then
    /usr/bin/python3 -I -c '
import ctypes,errno,json,os,stat,sys
path=sys.argv[1]; expected=json.loads(sys.argv[2])
parent=os.path.dirname(path); name=os.path.basename(path)
pfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
def identity(value):
    return {"dev":value.st_dev,"gid":value.st_gid,"ino":value.st_ino,
        "mode":stat.S_IMODE(value.st_mode),"uid":value.st_uid}
fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=pfd)
try:
    opened=os.fstat(fd); named=os.stat(name,dir_fd=pfd,follow_symlinks=False)
    if (identity(opened)!=expected or (named.st_dev,named.st_ino)!=(opened.st_dev,opened.st_ino)):
        raise SystemExit("native_component_cleanup_root_changed")
    libc=ctypes.CDLL(None,use_errno=True); rename=libc.renameatx_np
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,
        ctypes.c_char_p,ctypes.c_uint); rename.restype=ctypes.c_int
    for attempt in range(16):
        retained=(".secure-sandbox-retained-"+str(os.getpid())+"-"
            +os.urandom(12).hex())
        if rename(pfd,os.fsencode(name),pfd,os.fsencode(retained),4)==0:
            break
        value=ctypes.get_errno()
        if value!=errno.EEXIST: raise OSError(value,os.strerror(value),name)
    else: raise SystemExit("native_component_cleanup_quarantine_collision")
    os.fsync(pfd)
    moved=os.stat(retained,dir_fd=pfd,follow_symlinks=False)
    if identity(moved)!=expected or identity(os.fstat(fd))!=expected:
        raise SystemExit("native_component_cleanup_root_changed:retained="+retained)
finally:
    os.close(fd); os.close(pfd)
' "$build_root" "$build_root_record" || {
      echo native_component_cleanup_refused >&2
      [[ "$status" -ne 0 ]] || status=1
    }
  fi
  return "$status"
}
trap cleanup EXIT
/bin/mkdir -p "$stage" "$helper/Contents/MacOS" "$build_package/Sources"

/bin/cp "$release_package_template" "$build_package/Package.swift"
for target in \
    SecureSandboxNativeAuthCore \
    SecureSandboxNativeXPCTransport \
    SecureSandboxNativeCredentialHelper \
    SecureSandboxNativeCredentialXPCService \
    SecureSandboxNativeStackBackend \
    SecureSandboxNativeProjectionConsumer; do
  /usr/bin/ditto --noqtn \
    "$source_package/Sources/$target" "$build_package/Sources/$target"
done
[[ "$(closed_component_source_record "$source_package" source)" == "$source_record" \
    && "$(closed_component_source_record "$build_package" snapshot)" == "$source_record" ]] \
  || { echo native_component_snapshot_not_source_equivalent >&2; exit 1; }
build_package_record="$(closed_tree_record "$build_package")" \
  || { echo native_component_snapshot_invalid >&2; exit 1; }

swift_options=(--package-path "$build_package")
swift_options+=(
  --disable-sandbox
  --scratch-path "$swift_scratch_path"
  --cache-path "$swift_scratch_path/cache"
  --config-path "$swift_scratch_path/config"
  --security-path "$swift_scratch_path/security"
  --disable-dependency-cache
  --disable-build-manifest-caching
  --manifest-cache none
  --disable-netrc
  --disable-keychain
  --disable-automatic-resolution
  --skip-update
  --disable-prefetching
  --disable-experimental-prebuilts
  --disable-index-store
)
network_denied_profile='(version 1)(allow default)(deny network*)'

/usr/bin/sandbox-exec -p "$network_denied_profile" \
  /usr/bin/swift build -c release "${swift_options[@]}" \
  --product SecureSandboxNativeCredentialXPCService
/usr/bin/sandbox-exec -p "$network_denied_profile" \
  /usr/bin/swift build -c release "${swift_options[@]}" \
  --product SecureSandboxNativeStackBackend
/usr/bin/sandbox-exec -p "$network_denied_profile" \
  /usr/bin/swift build -c release "${swift_options[@]}" \
  --product SecureSandboxNativeProjectionConsumer
bin_path="$(/usr/bin/sandbox-exec -p "$network_denied_profile" \
  /usr/bin/swift build -c release \
  "${swift_options[@]}" --show-bin-path)"
[[ "$(closed_component_source_record "$source_package" source)" == "$source_record" \
    && "$(closed_component_source_record "$build_package" snapshot)" == "$source_record" \
    && "$(closed_tree_record "$build_package")" == "$build_package_record" ]] \
  || { echo native_component_source_changed_during_build >&2; exit 1; }
/usr/bin/python3 -I -c '
import pathlib,stat,sys
root=pathlib.Path(sys.argv[1])
for name in ("checkouts","repositories","artifacts","registry"):
    path=root/name
    if not path.exists() and not path.is_symlink(): continue
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
            or any(path.iterdir())):
        raise SystemExit("native_component_external_dependency_material_present")
' "$swift_scratch_path"

/bin/cp \
  "$bin_path/SecureSandboxNativeCredentialXPCService" \
  "$helper/Contents/MacOS/SecureSandboxNativeCredentialXPCService"
/bin/cp \
  "$build_package/Sources/SecureSandboxNativeCredentialHelper/SecureSandboxNativeCredentialHelper-Info.plist" \
  "$helper/Contents/Info.plist"
/bin/cp "$bin_path/$backend_name" "$backend"
/bin/cp "$bin_path/$consumer_name" "$consumer"
/bin/chmod 0555 \
  "$helper/Contents/MacOS/SecureSandboxNativeCredentialXPCService" \
  "$backend" "$consumer"
/bin/chmod 0444 "$helper/Contents/Info.plist"

entitlements="$build_package/Sources/SecureSandboxNativeCredentialHelper/SecureSandboxNativeCredentialHelper.entitlements"
/usr/bin/codesign --force --options runtime --timestamp \
  --entitlements "$entitlements" --sign "$identity" "$helper"
/usr/bin/codesign --force --options runtime --timestamp \
  --identifier "$backend_identifier" --sign "$identity" "$backend"
/usr/bin/codesign --force --options runtime --timestamp \
  --identifier "$consumer_identifier" --sign "$identity" "$consumer"

for item in "$helper" "$backend" "$consumer"; do
  /usr/bin/codesign --verify --strict --verbose=2 "$item"
done
verify_signed_component() {
  local item="$1" identifier="$2" label="$3" requirement details
  local observed_identifier observed_team authority timestamp fingerprint
  requirement="identifier \"$identifier\" and anchor apple generic and certificate leaf = H\"$identity\" and certificate leaf[subject.OU] = \"$fixed_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --strict --verbose=2 -R="$requirement" "$item"
  details="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1)"
  observed_identifier="$(/bin/echo "$details" \
    | /usr/bin/sed -n 's/^Identifier=//p')"
  observed_team="$(/bin/echo "$details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  authority="$(/bin/echo "$details" \
    | /usr/bin/sed -n 's/^Authority=//p' | /usr/bin/sed -n '1p')"
  timestamp="$(/bin/echo "$details" \
    | /usr/bin/sed -n 's/^Timestamp=//p')"
  [[ "$observed_identifier" == "$identifier" \
      && "$observed_team" == "$fixed_team" \
      && "$authority" == "Developer ID Application:"*" ($fixed_team)" \
      && -n "$timestamp" \
      && "$details" == *"flags=0x10000(runtime)"* \
      && "$details" != *"Signature=adhoc"* ]] || {
    echo native_component_signing_policy_invalid >&2
    return 1
  }
  /usr/bin/codesign -d \
    "--extract-certificates=$build_root/$label-leaf" \
    "$item" >/dev/null 2>&1
  fingerprint="$(/usr/bin/openssl x509 -inform DER \
    -in "$build_root/$label-leaf0" -noout -fingerprint -sha1 \
    | /usr/bin/sed -n 's/^SHA1 Fingerprint=//p' \
    | /usr/bin/tr -d ':' \
    | /usr/bin/tr '[:lower:]' '[:upper:]')"
  [[ "$fingerprint" == "$identity" ]] || {
    echo native_component_leaf_fingerprint_mismatch >&2
    return 1
  }
}

team="$fixed_team"
for specification in \
  "$helper|$helper_identifier|helper" \
  "$backend|$backend_identifier|backend" \
  "$consumer|$consumer_identifier|consumer"; do
  item="${specification%%|*}"
  remainder="${specification#*|}"
  identifier="${remainder%%|*}"
  label="${remainder#*|}"
  verify_signed_component "$item" "$identifier" "$label"
done

/usr/bin/python3 -I -c '
import subprocess,sys
for path in sys.argv[1:]:
    result=subprocess.run(
        ["/usr/bin/codesign","-d","--entitlements",":-",path],
        check=True,capture_output=True,
    )
    if result.stdout:
        raise SystemExit("native_component_unexpected_entitlements")
' "$backend" "$consumer"

/usr/bin/find "$helper" -type d -exec /bin/chmod 0555 {} +
/usr/bin/find "$helper" -type f -exec /bin/chmod 0444 {} +
/bin/chmod 0555 "$helper/Contents/MacOS/SecureSandboxNativeCredentialXPCService"
/bin/chmod 0555 "$backend" "$consumer"
/usr/bin/python3 -I -c '
import hashlib,json,pathlib,plistlib,stat,subprocess,sys
helper=pathlib.Path(sys.argv[1]); backend=pathlib.Path(sys.argv[2]); consumer=pathlib.Path(sys.argv[3])
output=pathlib.Path(sys.argv[4]); team=sys.argv[5]
files={}
for root,label in ((helper,helper.name),):
    for path in sorted(root.rglob("*")):
        relative=path.relative_to(root).as_posix(); info=path.lstat()
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise SystemExit("native_component_entry_invalid:"+relative)
        if path.is_file():
            data=path.read_bytes()
            files[relative]={"mode":stat.S_IMODE(info.st_mode),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
def record(path):
    info=path.lstat(); data=path.read_bytes()
    return {"mode":stat.S_IMODE(info.st_mode),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
entitlements=plistlib.loads(subprocess.run(
    ["/usr/bin/codesign","-d","--entitlements",":-",str(helper)],
    check=True,capture_output=True,
).stdout)
expected_entitlements={
    "com.apple.security.app-sandbox":True,
    "com.apple.security.network.client":True,
    "com.apple.security.network.server":True,
    "com.apple.security.temporary-exception.files.absolute-path.read-only":[
        "/usr/local/libexec/secure-sandbox-host/",
        "/usr/local/var/lib/secure-sandbox/native-credential-tickets/",
    ],
}
if entitlements != expected_entitlements:
    raise SystemExit("native_helper_entitlements_invalid")
value={
    "backend":{"identifier":"org.zebeth.SecureSandbox.NativeStackBackend",**record(backend)},
    "consumer":{"identifier":"org.zebeth.SecureSandbox.NativeProjectionConsumer",**record(consumer)},
    "helper":{"bundle":"SecureSandboxNativeCredentialHelper.app","files":files,"identifier":"org.zebeth.SecureSandbox.NativeCredentialHelper"},
    "schema":"secure-sandbox-native-components-bundle-v1",
    "signing_policy":{"team_id":team},
}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="ascii")
' "$helper" "$backend" "$consumer" "$manifest" "$team"
/bin/chmod 0444 "$manifest"

validate_directory_record "$artifact_root" "$artifact_root_record" \
  native_component_output_root_changed
for target in \
  "$artifact_root/$helper_name" \
  "$artifact_root/$backend_name" \
  "$artifact_root/$consumer_name" \
  "$artifact_root/$manifest_name"; do
  if [[ -e "$target" || -L "$target" ]]; then
    [[ "$release_candidate" == 0 ]] || {
      echo native_component_release_output_changed >&2
      exit 1
    }
    retain_existing_entry "$artifact_root" "$artifact_root_record" \
      "${target##*/}" native_component_existing_output_retention_failed
  fi
done
if [[ "$release_candidate" == 1 ]]; then
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed \
    /usr/bin/ditto --noqtn "$helper" "$helper_name"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed /bin/cp "$backend" "$backend_name"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed /bin/cp "$consumer" "$consumer_name"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed /bin/cp "$manifest" "$manifest_name"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed \
    /usr/bin/find "$helper_name" -type d -exec /bin/chmod 0555 '{}' +
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed \
    /usr/bin/find "$helper_name" -type f -exec /bin/chmod 0444 '{}' +
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed /bin/chmod 0555 \
      "$helper_name/Contents/MacOS/SecureSandboxNativeCredentialXPCService" \
      "$backend_name" "$consumer_name"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed /bin/chmod 0444 "$manifest_name"
else
  /usr/bin/ditto "$helper" "$artifact_root/$helper_name"
  /bin/cp "$backend" "$artifact_root/$backend_name"
  /bin/cp "$consumer" "$artifact_root/$consumer_name"
  /bin/cp "$manifest" "$artifact_root/$manifest_name"
  /usr/bin/find "$artifact_root/$helper_name" -type d -exec /bin/chmod 0555 {} +
  /usr/bin/find "$artifact_root/$helper_name" -type f -exec /bin/chmod 0444 {} +
  /bin/chmod 0555 \
    "$artifact_root/$helper_name/Contents/MacOS/SecureSandboxNativeCredentialXPCService" \
    "$artifact_root/$backend_name" "$artifact_root/$consumer_name"
  /bin/chmod 0444 "$artifact_root/$manifest_name"
fi
validate_directory_record "$artifact_root" "$artifact_root_record" \
  native_component_output_root_changed
for specification in \
  "$artifact_root/$helper_name|$helper_identifier|published-helper" \
  "$artifact_root/$backend_name|$backend_identifier|published-backend" \
  "$artifact_root/$consumer_name|$consumer_identifier|published-consumer"; do
  item="${specification%%|*}"
  remainder="${specification#*|}"
  identifier="${remainder%%|*}"
  label="${remainder#*|}"
  /usr/bin/codesign --verify --strict --verbose=2 "$item"
  verify_signed_component "$item" "$identifier" "$label"
  validate_directory_record "$artifact_root" "$artifact_root_record" \
    native_component_output_root_changed
done
[[ "$(closed_component_source_record "$source_package" source)" == "$source_record" \
    && "$(closed_component_source_record "$build_package" snapshot)" == "$source_record" \
    && "$(closed_tree_record "$build_package")" == "$build_package_record" ]] \
  || { echo native_component_source_changed_before_completion >&2; exit 1; }
validate_directory_record "$artifact_root" "$artifact_root_record" \
  native_component_output_root_changed
if [[ "$release_candidate" == 1 ]]; then
  validate_directory_record "$repo" "$release_source_root_record" \
    native_component_release_source_root_changed
fi
printf "%s\n" "$artifact_root/$manifest_name"
