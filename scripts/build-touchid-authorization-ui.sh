#!/bin/bash -p
set -euo pipefail
set +x
set +a
umask 077
[[ "$-" == *p* ]] || {
  echo touchid_builder_requires_direct_privileged_bash_execution >&2
  exit 2
}

fixed_team="389K3H8Y32"
fixed_identifier="org.zebeth.SecureSandbox.AuthorizationUI"
developer_id="${SECURE_SANDBOX_DEVELOPER_ID:-}"
signing_config_override="${SECURE_SANDBOX_SIGNING_CONFIG:-}"
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
unset SECURE_SANDBOX_DEVELOPER_ID SECURE_SANDBOX_SIGNING_CONFIG
unset SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY
unset SECURE_SANDBOX_RELEASE_OUTPUT_ROOT SECURE_SANDBOX_RELEASE_COMMIT
unset SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256
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
source_package="$repo/macos/TouchIDAuthorization"
package="$source_package"
signing_config="${signing_config_override:-$source_package/Signing.local.xcconfig}"
derived=""
derived_record=""

directory_record() {
  /usr/bin/python3 -I -c '
import json,os,stat,sys
path=sys.argv[1]; private=sys.argv[2]=="1"; expected_uid=int(sys.argv[3])
before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try: opened=os.fstat(fd); named=os.lstat(path)
finally: os.close(fd)
mode=stat.S_IMODE(opened.st_mode)
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or opened.st_uid!=expected_uid or (private and mode&0o077)):
    raise SystemExit("touchid_directory_untrusted")
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
try: opened=os.fstat(fd); named=os.lstat(path)
finally: os.close(fd)
record={"dev":opened.st_dev,"gid":opened.st_gid,"ino":opened.st_ino,
        "mode":stat.S_IMODE(opened.st_mode),"uid":opened.st_uid}
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or record!=expected): raise SystemExit(failure)
' "$1" "$2" "$3"
}

run_in_recorded_directory() {
  local directory="$1" record="$2" failure="$3"
  shift 3
  /usr/bin/python3 -I -c '
import json,os,stat,sys
path=sys.argv[1]; expected=json.loads(sys.argv[2]); failure=sys.argv[3]
command=sys.argv[4:]; before=os.lstat(path)
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
opened=os.fstat(fd); named=os.lstat(path)
record={"dev":opened.st_dev,"gid":opened.st_gid,"ino":opened.st_ino,
        "mode":stat.S_IMODE(opened.st_mode),"uid":opened.st_uid}
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or record!=expected or not command or not command[0].startswith("/")):
    os.close(fd); raise SystemExit(failure)
os.fchdir(fd); os.set_inheritable(fd,False); os.execve(command[0],command,os.environ)
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

touchid_source_record() {
  /usr/bin/python3 -I -c '
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); signing_config=pathlib.Path(sys.argv[2])
expected_uid=int(sys.argv[3])
names=[
 "Package.swift","AuthorizationUI.entitlements","Info.plist",
 "Artwork/AppIcon.icon/icon.json",
 "Artwork/AppIcon.icon/Assets/AuthorizationLock.svg",
 "Artwork/AppIcon.icon/Assets/ControlStack.svg",
 "Artwork/AppIcon.icon/Assets/DiagonalAccent.svg",
 "SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj",
 "Sources/AuthorizationCore/AuthorizationRequest.swift",
 "Sources/AuthorizationCore/ExecutionApprovalCrypto.swift",
 "Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift",
 "Sources/SecureSandboxAuthorizationUI/main.swift",
 "Signing.local.xcconfig",
]
entries={}
for name in names:
    path=signing_config if name=="Signing.local.xcconfig" else root/name
    before=path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid!=expected_uid or before.st_nlink!=1
            or stat.S_IMODE(before.st_mode)&0o022):
        raise SystemExit("touchid_source_entry_untrusted:"+name)
    data=path.read_bytes(); after=path.lstat()
    if ((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            or len(data)!=before.st_size):
        raise SystemExit("touchid_source_changed:"+name)
    entries[name]={"mode":stat.S_IMODE(before.st_mode),
        "sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
raw=(json.dumps(entries,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
print(hashlib.sha256(raw).hexdigest())
' "$1" "$2" "$EUID"
}
cleanup() {
  # Darwin cannot condition unlink/rmdir on an already-open inode.  Retain the
  # whole tree under a no-replace quarantine name so a raced object is never
  # destroyed; /tmp owns eventual lifecycle cleanup.
  local status=$?
  if [[ -n "$derived" ]]; then
    if [[ "$(/usr/bin/dirname "$derived")" != "$build_temp_parent" \
        || "$(/usr/bin/basename "$derived")" \
          != .secure-sandbox-touchid-build.* \
        || -z "$derived_record" ]]; then
      echo touchid_build_cleanup_root_invalid >&2
      [[ "$status" -ne 0 ]] || status=1
    else
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
        raise SystemExit("touchid_cleanup_root_changed")
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
    else: raise SystemExit("touchid_cleanup_quarantine_collision")
    os.fsync(pfd)
    moved=os.stat(retained,dir_fd=pfd,follow_symlinks=False)
    if identity(moved)!=expected or identity(os.fstat(fd))!=expected:
        raise SystemExit("touchid_cleanup_root_changed:retained="+retained)
finally:
    os.close(fd); os.close(pfd)
' "$derived" "$derived_record" || {
        echo touchid_build_cleanup_refused >&2
        [[ "$status" -ne 0 ]] || status=1
      }
    fi
  fi
  return "$status"
}
trap cleanup EXIT

[[ "$release_candidate" == 0 || "$release_candidate" == 1 ]] || {
  echo SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY_must_be_0_or_1 >&2
  exit 2
}
[[ -z "$developer_id" || "$release_candidate" == 1 ]] || {
  echo touchid_developer_id_requires_release_candidate_contract >&2
  exit 2
}
if [[ -n "$developer_id" || "$release_candidate" == 1 ]]; then
  [[ "$developer_id" =~ ^[0-9A-Fa-f]{40}$ ]] || {
    echo SECURE_SANDBOX_DEVELOPER_ID_must_be_an_exact_SHA1_fingerprint >&2
    exit 2
  }
  developer_id="$(/bin/echo "$developer_id" \
    | /usr/bin/tr '[:lower:]' '[:upper:]')"
else
  [[ -z "$release_output_root" && -z "$release_commit" \
      && -z "$source_archive_sha256" && -z "$expected_team_input" \
      && -z "$signing_config_sha256_input" \
      && -z "$release_source_root" ]] || {
    echo touchid_local_build_rejects_release_contract_variables >&2
    exit 2
  }
fi

validate_private_directory() {
  local path="$1" mode
  [[ "$path" == /* && -d "$path" && ! -L "$path" \
      && "$(/usr/bin/stat -f %u "$path")" == "$EUID" ]] || {
    echo touchid_release_output_root_untrusted >&2
    return 1
  }
  mode="$(/usr/bin/stat -f %Lp "$path")"
  [[ "$mode" =~ ^[0-7]00$ ]] || {
    echo touchid_release_output_root_permissions_invalid >&2
    return 1
  }
}

if [[ "$release_candidate" == 1 ]]; then
  [[ "$release_source_root" == /* && -d "$release_source_root" \
      && ! -L "$release_source_root" \
      && "$(cd "$release_source_root" && pwd -P)" == "$release_source_root" \
      && -n "$signing_config_override" && "$signing_config" == /* \
      && "$release_commit" =~ ^[0-9a-f]{40}$ \
      && "$source_archive_sha256" =~ ^[0-9a-f]{64}$ \
      && "$expected_team_input" == "$fixed_team" \
      && "$signing_config_sha256_input" =~ ^[0-9a-f]{64}$ ]] || {
    echo touchid_release_contract_invalid >&2
    exit 2
  }
  validate_private_directory "$release_output_root"
  artifact_root="$release_output_root"
  for candidate in \
    "$artifact_root/SecureSandboxAuthorizationUI.app" \
    "$artifact_root/SecureSandboxAuthorizationUI.bundle.json" \
    "$artifact_root/SecureSandboxAuthorizationUI.sources.json"; do
    [[ ! -e "$candidate" && ! -L "$candidate" ]] || {
      echo touchid_release_output_already_exists >&2
      exit 1
    }
  done
else
  artifact_root="$repo/artifacts/host"
  /bin/mkdir -p "$artifact_root"
fi
output="$artifact_root/SecureSandboxAuthorizationUI.app"
bundle_manifest="$artifact_root/SecureSandboxAuthorizationUI.bundle.json"
source_manifest="$artifact_root/SecureSandboxAuthorizationUI.sources.json"
artifact_root_record="$(directory_record \
  "$artifact_root" "$release_candidate")" \
  || { echo touchid_release_output_root_untrusted >&2; exit 1; }
release_source_root_record=""
if [[ "$release_candidate" == 1 ]]; then
  release_source_root_record="$(directory_record "$repo" 1)" \
    || { echo touchid_release_source_root_untrusted >&2; exit 1; }
fi

if [[ "$release_candidate" == 1 ]]; then
  build_temp_parent="$(/usr/bin/dirname "$artifact_root")"
else
  build_temp_parent=/private/tmp
fi
derived="$(/usr/bin/mktemp -d \
  "$build_temp_parent/.secure-sandbox-touchid-build.XXXXXX")"
derived_record="$(directory_record "$derived" 1)" \
  || { echo touchid_build_root_untrusted >&2; exit 1; }
pinned_signing_config="$derived/Signing.release.xcconfig"

signing_config_state="$(/usr/bin/python3 -I -c '
import hashlib,json,os,stat,sys
source,destination=sys.argv[1],sys.argv[2]
expected_uid=int(sys.argv[3]); release=sys.argv[4]=="1"
expected=b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
before=os.lstat(source)
flags=os.O_RDONLY | os.O_CLOEXEC
if hasattr(os,"O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor=os.open(source,flags)
try:
    opened=os.fstat(descriptor)
    raw=b""
    while len(raw) <= 4096:
        chunk=os.read(descriptor,4097-len(raw))
        if not chunk:
            break
        raw += chunk
    after=os.fstat(descriptor)
finally:
    os.close(descriptor)
named=os.lstat(source)
def identity(value):
    return (value.st_dev,value.st_ino,value.st_uid,value.st_gid,
        stat.S_IMODE(value.st_mode),value.st_nlink,value.st_size,
        value.st_mtime_ns,value.st_ctime_ns)
mode=stat.S_IMODE(opened.st_mode)
if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
        or identity(before)!=identity(opened) or identity(opened)!=identity(after)
        or identity(after)!=identity(named) or opened.st_uid!=expected_uid
        or opened.st_nlink!=1 or mode & (0o222 if release else 0o022)
        or (release and os.access(source,os.W_OK))
        or raw!=expected or len(raw)!=opened.st_size):
    raise SystemExit("touchid_signing_config_untrusted")
out=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o400)
try:
    if os.write(out,raw)!=len(raw):
        raise SystemExit("touchid_signing_config_copy_failed")
    os.fsync(out)
    pinned=os.fstat(out)
finally:
    os.close(out)
record={
    "identity":identity(opened),
    "pinned_identity":identity(pinned),
    "sha256":hashlib.sha256(raw).hexdigest(),
}
print(json.dumps(record,separators=(",",":"),sort_keys=True))
' "$signing_config" "$pinned_signing_config" "$EUID" "$release_candidate")"
if [[ "$release_candidate" == 1 ]]; then
  observed_signing_config_sha256="$(/usr/bin/python3 -I -c \
    'import json,sys; print(json.loads(sys.argv[1])["sha256"])' \
    "$signing_config_state")"
  [[ "$observed_signing_config_sha256" == "$signing_config_sha256_input" ]] || {
    echo touchid_signing_config_digest_mismatch >&2
    exit 1
  }
fi

validate_pinned_signing_config() {
  /usr/bin/python3 -I -c '
import hashlib,json,os,stat,sys
path=sys.argv[1]; expected=json.loads(sys.argv[2]); before=os.lstat(path)
flags=os.O_RDONLY | os.O_CLOEXEC
if hasattr(os,"O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor=os.open(path,flags)
try:
    opened=os.fstat(descriptor); raw=os.read(descriptor,4097)
    after=os.fstat(descriptor)
finally:
    os.close(descriptor)
named=os.lstat(path)
def identity(value):
    return [value.st_dev,value.st_ino,value.st_uid,value.st_gid,
        stat.S_IMODE(value.st_mode),value.st_nlink,value.st_size,
        value.st_mtime_ns,value.st_ctime_ns]
if (identity(before)!=expected["pinned_identity"]
        or identity(opened)!=expected["pinned_identity"]
        or identity(after)!=expected["pinned_identity"]
        or identity(named)!=expected["pinned_identity"]
        or len(raw)!=opened.st_size
        or hashlib.sha256(raw).hexdigest()!=expected["sha256"]):
    raise SystemExit("touchid_pinned_signing_config_changed")
' "$pinned_signing_config" "$signing_config_state"
}
validate_pinned_signing_config
source_record="$(touchid_source_record "$source_package" "$signing_config")" \
  || { echo touchid_source_inventory_invalid >&2; exit 1; }
if [[ "$release_candidate" == 1 ]]; then
  package="$derived/source-package"
  /bin/mkdir -m 0700 "$package"
  /usr/bin/python3 -I -c '
import os,pathlib,shutil,stat,sys
source=pathlib.Path(sys.argv[1]); destination=pathlib.Path(sys.argv[2])
signing_config=pathlib.Path(sys.argv[3])
names=[
 "Package.swift","AuthorizationUI.entitlements","Info.plist",
 "Artwork/AppIcon.icon/icon.json",
 "Artwork/AppIcon.icon/Assets/AuthorizationLock.svg",
 "Artwork/AppIcon.icon/Assets/ControlStack.svg",
 "Artwork/AppIcon.icon/Assets/DiagonalAccent.svg",
 "SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj",
 "Sources/AuthorizationCore/AuthorizationRequest.swift",
 "Sources/AuthorizationCore/ExecutionApprovalCrypto.swift",
 "Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift",
 "Sources/SecureSandboxAuthorizationUI/main.swift",
 "Signing.local.xcconfig",
]
for name in names:
    origin=signing_config if name=="Signing.local.xcconfig" else source/name
    info=origin.lstat()
    if not stat.S_ISREG(info.st_mode) or origin.is_symlink() or info.st_nlink!=1:
        raise SystemExit("touchid_source_snapshot_entry_invalid:"+name)
    target=destination/name; target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(origin,target,follow_symlinks=False)
' "$source_package" "$package" "$signing_config"
  [[ "$(touchid_source_record "$source_package" "$signing_config")" == "$source_record" \
      && "$(touchid_source_record "$package" "$package/Signing.local.xcconfig")" == "$source_record" ]] \
    || { echo touchid_source_changed_during_snapshot >&2; exit 1; }
fi

validate_signing_config_unchanged() {
  /usr/bin/python3 -I -c '
import hashlib,json,os,stat,sys
source=sys.argv[1]; expected=json.loads(sys.argv[2]); before=os.lstat(source)
flags=os.O_RDONLY | os.O_CLOEXEC
if hasattr(os,"O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor=os.open(source,flags)
try:
    opened=os.fstat(descriptor)
    raw=b""
    while len(raw) <= 4096:
        chunk=os.read(descriptor,4097-len(raw))
        if not chunk:
            break
        raw += chunk
    after=os.fstat(descriptor)
finally:
    os.close(descriptor)
named=os.lstat(source)
def identity(value):
    return [value.st_dev,value.st_ino,value.st_uid,value.st_gid,
        stat.S_IMODE(value.st_mode),value.st_nlink,value.st_size,
        value.st_mtime_ns,value.st_ctime_ns]
if (identity(before)!=expected["identity"]
        or identity(opened)!=expected["identity"]
        or identity(after)!=expected["identity"]
        or identity(named)!=expected["identity"]
        or len(raw)!=opened.st_size
        or hashlib.sha256(raw).hexdigest()!=expected["sha256"]):
    raise SystemExit("touchid_signing_config_changed")
' "$signing_config" "$signing_config_state"
}

if [[ -n "$developer_id" ]]; then
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
    raise SystemExit("touchid_requested_developer_id_unavailable")
' "$developer_id" "$fixed_team"
fi

if [[ -n "$developer_id" ]]; then
  archive="$derived/SecureSandboxAuthorizationUI.xcarchive"
  export_root="$derived/export"
  export_options="$derived/ExportOptions.plist"
  /usr/bin/xcodebuild -quiet \
    -project "$package/SecureSandboxAuthorizationUI.xcodeproj" \
    -scheme SecureSandboxAuthorizationUI \
    -configuration Release \
    -xcconfig "$pinned_signing_config" \
    -derivedDataPath "$derived/DerivedData" \
    -archivePath "$archive" \
    -allowProvisioningUpdates \
    "DEVELOPMENT_TEAM=$fixed_team" \
    "CODE_SIGN_STYLE=Automatic" \
    "CODE_SIGN_IDENTITY=$developer_id" \
    "PRODUCT_BUNDLE_IDENTIFIER=$fixed_identifier" \
    "ENABLE_HARDENED_RUNTIME=YES" \
    "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO" \
    archive
  /usr/bin/plutil -create xml1 "$export_options"
  /usr/bin/plutil -insert destination -string export "$export_options"
  /usr/bin/plutil -insert method -string developer-id "$export_options"
  /usr/bin/plutil -insert signingStyle -string automatic "$export_options"
  /usr/bin/plutil -insert signingCertificate -string "$developer_id" "$export_options"
  /usr/bin/plutil -insert teamID -string "$fixed_team" "$export_options"
  /usr/bin/xcodebuild -quiet \
    -exportArchive \
    -archivePath "$archive" \
    -exportPath "$export_root" \
    -exportOptionsPlist "$export_options" \
    -allowProvisioningUpdates \
    "DEVELOPMENT_TEAM=$fixed_team" \
    "CODE_SIGN_IDENTITY=$developer_id"
  built="$export_root/SecureSandboxAuthorizationUI.app"
else
  /usr/bin/xcodebuild -quiet \
    -project "$package/SecureSandboxAuthorizationUI.xcodeproj" \
    -scheme SecureSandboxAuthorizationUI \
    -configuration Release \
    -xcconfig "$pinned_signing_config" \
    -derivedDataPath "$derived" \
    -allowProvisioningUpdates \
    "DEVELOPMENT_TEAM=$fixed_team" \
    "PRODUCT_BUNDLE_IDENTIFIER=$fixed_identifier" \
    "ENABLE_HARDENED_RUNTIME=YES" \
    "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO" \
    build
  built="$derived/Build/Products/Release/SecureSandboxAuthorizationUI.app"
fi
validate_signing_config_unchanged
validate_pinned_signing_config
[[ "$(touchid_source_record "$source_package" "$signing_config")" == "$source_record" ]] \
  || { echo touchid_source_changed_during_build >&2; exit 1; }
if [[ "$release_candidate" == 1 ]]; then
  [[ "$(touchid_source_record "$package" "$package/Signing.local.xcconfig")" == "$source_record" ]] \
    || { echo touchid_build_snapshot_changed >&2; exit 1; }
fi
/usr/bin/codesign --verify --deep --strict --verbose=2 "$built"
if [[ -n "$developer_id" ]]; then
  requirement="identifier \"$fixed_identifier\" and anchor apple generic and certificate leaf = H\"$developer_id\" and certificate leaf[subject.OU] = \"$fixed_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --deep --strict --verbose=2 \
    -R="$requirement" "$built"
  certificate_prefix="$derived/touchid-leaf-certificate-"
  /usr/bin/codesign -d --extract-certificates "$certificate_prefix" \
    "$built" >/dev/null 2>&1
  observed_fingerprint="$(/usr/bin/openssl x509 -inform DER \
    -in "${certificate_prefix}0" -noout -fingerprint -sha1 \
    | /usr/bin/sed -n 's/^SHA1 Fingerprint=//p' \
    | /usr/bin/tr -d ':' \
    | /usr/bin/tr '[:lower:]' '[:upper:]')"
  [[ "$observed_fingerprint" == "$developer_id" ]] || {
    echo touchid_developer_id_fingerprint_mismatch >&2
    exit 1
  }
fi
[[ -f "$built/Contents/embedded.provisionprofile" ]] \
  || { echo touchid_macos_provisioning_profile_missing >&2; exit 1; }
/usr/bin/python3 -I -c '
import datetime,hashlib,os,pathlib,plistlib,stat,subprocess,sys
app=pathlib.Path(sys.argv[1]); expected_identifier=sys.argv[2]
expected_team=sys.argv[3]; expected_fingerprint=sys.argv[4]
release=bool(expected_fingerprint)
info=plistlib.loads((app/"Contents/Info.plist").read_bytes())
if (info.get("CFBundleIdentifier")!=expected_identifier
        or info.get("CFBundleExecutable")!="SecureSandboxAuthorizationUI"):
    raise SystemExit("touchid_bundle_identity_invalid")
details=subprocess.run(
    ["/usr/bin/codesign","-dv","--verbose=4",str(app)],
    check=True,capture_output=True,text=True,
).stderr.splitlines()
def values(prefix):
    return [line[len(prefix):] for line in details if line.startswith(prefix)]
if (values("Identifier=")!=[expected_identifier]
        or values("TeamIdentifier=")!=[expected_team]
        or not any("flags=0x10000(runtime)" in line for line in details)
        or any(line=="Signature=adhoc" for line in details)):
    raise SystemExit("touchid_developer_id_signing_policy_invalid")
if release:
    authorities=values("Authority=")
    if (not authorities or not authorities[0].startswith("Developer ID Application:")
            or not authorities[0].endswith(" ("+expected_team+")")
            or len(values("Timestamp="))!=1 or not values("Timestamp=")[0]):
        raise SystemExit("touchid_developer_id_signing_policy_invalid")
entitlements=plistlib.loads(subprocess.run(
    ["/usr/bin/codesign","-d","--entitlements",":-",str(app)],
    check=True,capture_output=True,
).stdout)
application_identifier=expected_team+"."+expected_identifier
expected_entitlements={
    "com.apple.application-identifier":application_identifier,
    "com.apple.developer.team-identifier":expected_team,
    "keychain-access-groups":[application_identifier],
}
if entitlements!=expected_entitlements:
    raise SystemExit("touchid_entitlements_invalid")
profile_path=app/"Contents/embedded.provisionprofile"
profile_info=profile_path.lstat()
if (not stat.S_ISREG(profile_info.st_mode) or profile_info.st_nlink!=1):
    raise SystemExit("touchid_provisioning_profile_invalid")
profile=plistlib.loads(subprocess.run(
    ["/usr/bin/security","cms","-D","-i",str(profile_path)],
    check=True,capture_output=True,
).stdout)
if (profile.get("ApplicationIdentifierPrefix")!=[expected_team]
        or profile.get("TeamIdentifier")!=[expected_team]
        or profile.get("Platform")!=["OSX"]):
    raise SystemExit("touchid_provisioning_profile_identity_invalid")
profile_entitlements=profile.get("Entitlements")
if (not isinstance(profile_entitlements,dict)
        or profile_entitlements.get("com.apple.application-identifier")
            != application_identifier
        or profile_entitlements.get("com.apple.developer.team-identifier")
            != expected_team
        or profile_entitlements.get("keychain-access-groups")
            not in ([expected_team+".*"],[application_identifier])):
    raise SystemExit("touchid_provisioning_profile_entitlements_invalid")
expiration=profile.get("ExpirationDate")
if not isinstance(expiration,datetime.datetime):
    raise SystemExit("touchid_provisioning_profile_expiration_invalid")
if expiration.tzinfo is None:
    expiration=expiration.replace(tzinfo=datetime.timezone.utc)
minimum=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=52)
if expiration <= minimum:
    raise SystemExit("touchid_provisioning_profile_headroom_insufficient")
if release:
    if (set(profile_entitlements)!={
            "com.apple.application-identifier",
            "com.apple.developer.team-identifier",
            "keychain-access-groups",
        } or profile.get("ProvisionsAllDevices") is not True):
        raise SystemExit("touchid_developer_id_profile_scope_invalid")
    certificates=profile.get("DeveloperCertificates")
    if (not isinstance(certificates,list)
            or expected_fingerprint.lower() not in {
                hashlib.sha1(value).hexdigest()
                for value in certificates if isinstance(value,bytes)
            }):
        raise SystemExit("touchid_developer_id_profile_certificate_mismatch")
' "$built" "$fixed_identifier" "$fixed_team" "$developer_id"

validate_directory_record "$artifact_root" "$artifact_root_record" \
  touchid_release_output_root_changed
if [[ "$release_candidate" == 0 ]]; then
  if [[ -e "$output" || -L "$output" ]]; then
    retain_existing_entry "$artifact_root" "$artifact_root_record" \
      "${output##*/}" touchid_existing_output_retention_failed
  fi
else
  [[ ! -e "$output" && ! -L "$output" ]] || {
    echo touchid_release_output_changed >&2
    exit 1
  }
fi
if [[ "$release_candidate" == 1 ]]; then
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed \
    /usr/bin/ditto --noqtn "$built" "SecureSandboxAuthorizationUI.app"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed /usr/bin/find \
    "SecureSandboxAuthorizationUI.app" -type d -exec /bin/chmod 0555 '{}' +
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed /usr/bin/find \
    "SecureSandboxAuthorizationUI.app" -type f -exec /bin/chmod 0444 '{}' +
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed /bin/chmod 0555 \
    "SecureSandboxAuthorizationUI.app/Contents/MacOS/SecureSandboxAuthorizationUI"
else
  /usr/bin/ditto "$built" "$output"
  /usr/bin/find "$output" -type d -exec /bin/chmod 0555 {} +
  /usr/bin/find "$output" -type f -exec /bin/chmod 0444 {} +
  /bin/chmod 0555 "$output/Contents/MacOS/SecureSandboxAuthorizationUI"
fi
validate_directory_record "$artifact_root" "$artifact_root_record" \
  touchid_release_output_root_changed
/usr/bin/codesign --verify --deep --strict --verbose=2 "$output"
if [[ -n "$developer_id" ]]; then
  /usr/bin/codesign --verify --deep --strict --verbose=2 \
    -R="$requirement" "$output"
  installed_certificate_prefix="$derived/published-touchid-leaf"
  /usr/bin/codesign -d --extract-certificates \
    "$installed_certificate_prefix" "$output" >/dev/null 2>&1
  installed_fingerprint="$(/usr/bin/openssl x509 -inform DER \
    -in "${installed_certificate_prefix}0" -noout -fingerprint -sha1 \
    | /usr/bin/sed -n 's/^SHA1 Fingerprint=//p' \
    | /usr/bin/tr -d ':' \
    | /usr/bin/tr '[:lower:]' '[:upper:]')"
  [[ "$installed_fingerprint" == "$developer_id" ]] || {
    echo touchid_published_developer_id_fingerprint_mismatch >&2
    exit 1
  }
fi
validate_directory_record "$artifact_root" "$artifact_root_record" \
  touchid_release_output_root_changed
generated_bundle_manifest="$derived/SecureSandboxAuthorizationUI.bundle.json"
/usr/bin/python3 -I -c '
import hashlib,json,pathlib,plistlib,stat,subprocess,sys
root=pathlib.Path(sys.argv[1]); output=pathlib.Path(sys.argv[2])
expected_team=sys.argv[3]; expected_bundle_id=sys.argv[4]
files={}
for path in sorted(root.rglob("*")):
    relative=path.relative_to(root).as_posix()
    info=path.lstat()
    if path.is_symlink() or (not path.is_dir() and not path.is_file()):
        raise SystemExit("touchid_bundle_entry_invalid:"+relative)
    if path.is_file():
        data=path.read_bytes()
        files[relative]={"mode":stat.S_IMODE(info.st_mode),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
entitlements=plistlib.loads(subprocess.run(
    ["/usr/bin/codesign","-d","--entitlements",":-",str(root)],
    check=True,capture_output=True,
).stdout)
profile=plistlib.loads(subprocess.run(
    ["/usr/bin/security","cms","-D","-i",str(root/"Contents/embedded.provisionprofile")],
    check=True,capture_output=True,
).stdout)
team=entitlements.get("com.apple.developer.team-identifier")
application_identifier=entitlements.get("com.apple.application-identifier")
groups=entitlements.get("keychain-access-groups")
bundle_id=plistlib.loads((root/"Contents/Info.plist").read_bytes()).get("CFBundleIdentifier")
if (team != expected_team or bundle_id != expected_bundle_id
        or application_identifier != team+"."+bundle_id
        or groups != [application_identifier]
        or profile.get("ApplicationIdentifierPrefix") != [team]
        or profile.get("TeamIdentifier") != [team]):
    raise SystemExit("touchid_signing_policy_invalid")
value={
    "bundle":"SecureSandboxAuthorizationUI.app",
    "files":files,
    "schema":"secure-sandbox-touchid-ui-bundle-v2",
    "signing_policy":{
        "access_group":application_identifier,
        "application_identifier":application_identifier,
        "bundle_id":bundle_id,
        "team_id":team,
    },
}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
' "$output" "$generated_bundle_manifest" "$fixed_team" "$fixed_identifier"
/bin/chmod 0444 "$generated_bundle_manifest"
generated_source_manifest="$derived/SecureSandboxAuthorizationUI.sources.json"
/usr/bin/python3 -I -c '
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); output=pathlib.Path(sys.argv[2])
names=["Package.swift","AuthorizationUI.entitlements","Info.plist","Artwork/AppIcon.icon/icon.json","Artwork/AppIcon.icon/Assets/AuthorizationLock.svg","Artwork/AppIcon.icon/Assets/ControlStack.svg","Artwork/AppIcon.icon/Assets/DiagonalAccent.svg","SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj","Sources/AuthorizationCore/AuthorizationRequest.swift","Sources/AuthorizationCore/ExecutionApprovalCrypto.swift","Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift","Sources/SecureSandboxAuthorizationUI/main.swift"]
value={"schema":"secure-sandbox-touchid-ui-source-v1","sources":{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
' "$source_package" "$generated_source_manifest"
/bin/chmod 0444 "$generated_source_manifest"
for target in "$bundle_manifest" "$source_manifest"; do
  if [[ -e "$target" || -L "$target" ]]; then
    [[ "$release_candidate" == 0 ]] \
      || { echo touchid_release_output_changed >&2; exit 1; }
    retain_existing_entry "$artifact_root" "$artifact_root_record" \
      "${target##*/}" touchid_existing_manifest_retention_failed
  fi
done
if [[ "$release_candidate" == 1 ]]; then
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed /bin/cp \
    "$generated_bundle_manifest" "SecureSandboxAuthorizationUI.bundle.json"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed /bin/cp \
    "$generated_source_manifest" "SecureSandboxAuthorizationUI.sources.json"
  run_in_recorded_directory "$artifact_root" "$artifact_root_record" \
    touchid_release_output_root_changed /bin/chmod 0444 \
    "SecureSandboxAuthorizationUI.bundle.json" \
    "SecureSandboxAuthorizationUI.sources.json"
else
  /bin/cp "$generated_bundle_manifest" "$bundle_manifest"
  /bin/cp "$generated_source_manifest" "$source_manifest"
  /bin/chmod 0444 "$bundle_manifest" "$source_manifest"
fi
[[ "$(touchid_source_record "$source_package" "$signing_config")" == "$source_record" ]] \
  || { echo touchid_source_changed_before_completion >&2; exit 1; }
if [[ "$release_candidate" == 1 ]]; then
  [[ "$(touchid_source_record "$package" "$package/Signing.local.xcconfig")" == "$source_record" ]] \
    || { echo touchid_build_snapshot_changed >&2; exit 1; }
fi
validate_directory_record "$artifact_root" "$artifact_root_record" \
  touchid_release_output_root_changed
if [[ "$release_candidate" == 1 ]]; then
  validate_directory_record "$repo" "$release_source_root_record" \
    touchid_release_source_root_changed
fi
echo "$output"
