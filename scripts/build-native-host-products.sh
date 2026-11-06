#!/bin/bash -p
set -euo pipefail
set +x
set +a
umask 077
[[ "$-" == *p* ]] || {
  echo native_host_release_requires_privileged_bash >&2
  exit 2
}

# Capture the small public release input surface, then remove inherited build
# authority before resolving any source or invoking any toolchain process.
argument_count=$#
requested_mode="${1:-}"
requested_output="${2:-}"
developer_id_input="${SECURE_SANDBOX_DEVELOPER_ID:-}"
notary_profile_input="${SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE:-}"
notary_keychain_input="${SECURE_SANDBOX_NOTARY_KEYCHAIN:-}"
unset SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE SECURE_SANDBOX_NOTARY_KEYCHAIN
candidate_authority="${SECURE_SANDBOX_NATIVE_HOST_CANDIDATE_ONLY:-}"
release_commit_input="${SECURE_SANDBOX_RELEASE_COMMIT:-}"
source_archive_sha256_input="${SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256:-}"
source_archive_path_input="${SECURE_SANDBOX_SOURCE_ARCHIVE_PATH:-}"
source_tree_sha256_input="${SECURE_SANDBOX_SOURCE_TREE_SHA256:-}"
signing_config_sha256_input="${SECURE_SANDBOX_SIGNING_CONFIG_SHA256:-}"
signing_config_input="${SECURE_SANDBOX_SIGNING_CONFIG:-}"
release_source_root_input="${SECURE_SANDBOX_RELEASE_SOURCE_ROOT:-}"
host_release_preimage_path_input="${SECURE_SANDBOX_HOST_RELEASE_PREIMAGE_PATH:-}"
host_release_preimage_sha256_input="${SECURE_SANDBOX_HOST_RELEASE_PREIMAGE_SHA256:-}"
release_build_parent_identity_input="${SECURE_SANDBOX_RELEASE_BUILD_PARENT_IDENTITY:-}"
source_helper_sha256_input="${SECURE_SANDBOX_RELEASE_SOURCE_HELPER_SHA256:-}"
touchid_builder_sha256_input="${SECURE_SANDBOX_RELEASE_TOUCHID_BUILDER_SHA256:-}"
component_builder_sha256_input="${SECURE_SANDBOX_RELEASE_COMPONENT_BUILDER_SHA256:-}"
export -n argument_count requested_mode requested_output developer_id_input
export -n notary_profile_input notary_keychain_input candidate_authority
export -n release_commit_input
export -n source_archive_sha256_input signing_config_sha256_input
export -n source_archive_path_input source_tree_sha256_input
export -n signing_config_input
export -n release_source_root_input
export -n host_release_preimage_path_input host_release_preimage_sha256_input
export -n release_build_parent_identity_input
export -n source_helper_sha256_input touchid_builder_sha256_input
export -n component_builder_sha256_input

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
export GIT_NO_REPLACE_OBJECTS=1
unset DEVELOPER_DIR TOOLCHAINS SDKROOT SWIFT_EXEC SWIFTC_EXEC
unset SWIFT_DRIVER_SWIFT_EXEC MACOSX_DEPLOYMENT_TARGET
unset CC CXX LD AR NM RANLIB STRIP CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR LLVM_PROFILE_FILE CODESIGN_ALLOCATE
unset XCODE_XCCONFIG_FILE CODE_SIGN_IDENTITY CODE_SIGN_STYLE
unset DEVELOPMENT_TEAM PROVISIONING_PROFILE PROVISIONING_PROFILE_SPECIFIER
unset OTHER_CFLAGS OTHER_CPLUSPLUSFLAGS OTHER_LDFLAGS OTHER_SWIFT_FLAGS
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONBREAKPOINT
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy
unset all_proxy no_proxy
for inherited_name in "${!DYLD_@}" "${!LD_@}" \
    "${!SECURE_SANDBOX_@}"; do
  unset "$inherited_name"
done

LC_ALL=C
LANG=C
TMPDIR=/tmp
export LC_ALL LANG TMPDIR
fixed_team=389K3H8Y32
container_identifier=org.zebeth.SecureSandbox.NativeHostProducts
if [[ "$requested_mode" == --candidate-only ]]; then
  repo="$release_source_root_input"
else
  repo="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
fi
source_helper="$repo/scripts/native_host_release_source.py"
operator_record="$(/usr/bin/python3 -I -c '
import json,os,pwd
record=pwd.getpwuid(os.geteuid())
print(json.dumps({"home":record.pw_dir,"name":record.pw_name},sort_keys=True))
')"
operator_home="$(/usr/bin/python3 -I -c \
  'import json,sys; print(json.loads(sys.argv[1])["home"])' \
  "$operator_record")"
operator_name="$(/usr/bin/python3 -I -c \
  'import json,sys; print(json.loads(sys.argv[1])["name"])' \
  "$operator_record")"
[[ "$operator_home" == /* && "$operator_home" != *$'\n'* \
    && -d "$operator_home" && ! -L "$operator_home" \
    && "$(/usr/bin/stat -f %u "$operator_home")" == "$EUID" ]] || {
  echo native_host_operator_home_untrusted >&2
  exit 1
}
HOME="$operator_home"
USER="$operator_name"
LOGNAME="$operator_name"
export HOME USER LOGNAME

fail() {
  echo "$1" >&2
  exit "${2:-1}"
}

require_acl_free_paths() {
  /usr/bin/python3 -I -c '
import ctypes,errno,os,stat,sys
libc=ctypes.CDLL(None,use_errno=True)
acl_get_fd_np=getattr(libc,"acl_get_fd_np",None)
acl_get_entry=getattr(libc,"acl_get_entry",None)
acl_free=getattr(libc,"acl_free",None)
if acl_get_fd_np is None or acl_get_entry is None or acl_free is None:
    raise SystemExit("native_host_extended_acl_api_unavailable")
acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int]
acl_get_fd_np.restype=ctypes.c_void_p
acl_get_entry.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.POINTER(ctypes.c_void_p)]
acl_get_entry.restype=ctypes.c_int
acl_free.argtypes=[ctypes.c_void_p]
acl_free.restype=ctypes.c_int
for path in sys.argv[1:]:
    before=os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or before.st_uid!=os.geteuid():
        raise SystemExit("native_host_acl_boundary_untrusted")
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
    if stat.S_ISDIR(before.st_mode): flags|=os.O_DIRECTORY
    descriptor=os.open(path,flags)
    try:
        opened=os.fstat(descriptor)
        if ((before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)
                or opened.st_uid!=os.geteuid()):
            raise SystemExit("native_host_acl_boundary_changed")
        ctypes.set_errno(0)
        acl=acl_get_fd_np(descriptor,0x00000100)
        if not acl:
            if ctypes.get_errno()==errno.ENOENT: continue
            raise SystemExit("native_host_acl_boundary_untrusted")
        try:
            entry=ctypes.c_void_p()
            ctypes.set_errno(0)
            result=acl_get_entry(acl,0,ctypes.byref(entry))
            if result==0 or ctypes.get_errno() not in {errno.ENOENT,errno.EINVAL}:
                raise SystemExit("native_host_acl_boundary_untrusted")
        finally:
            if acl_free(acl)!=0:
                raise SystemExit("native_host_acl_boundary_release_failed")
    finally:
        os.close(descriptor)
' "$@"
}

require_release_inputs() {
  [[ "$developer_id_input" =~ ^[0-9A-Fa-f]{40}$ ]] \
    || fail SECURE_SANDBOX_DEVELOPER_ID_requires_SHA1_pin 2
  developer_id_input="$(/usr/bin/printf '%s' "$developer_id_input" \
    | /usr/bin/tr '[:upper:]' '[:lower:]')"
  [[ "$notary_profile_input" =~ ^[A-Za-z0-9][-A-Za-z0-9._\ ]{0,127}$ ]] \
    || fail SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE_is_required 2
  require_notary_keychain
  identity_listing="$(/usr/bin/security find-identity -v -p codesigning)" \
    || fail native_host_codesigning_identity_lookup_failed
  /usr/bin/printf '%s\n' "$identity_listing" | /usr/bin/python3 -I -c '
import re,sys
identity=sys.argv[1].lower(); team=sys.argv[2]
lines=sys.stdin.read().splitlines()
matches=[]
for line in lines:
    match=re.match(r"^\s*[0-9]+\)\s+([0-9A-Fa-f]{40})\s+\"([^\"]+)\"\s*$",line)
    if not match or match.group(1).lower() != identity:
        continue
    subject=match.group(2)
    if subject.startswith("Developer ID Application:") and subject.endswith("("+team+")"):
        matches.append(line)
if len(matches) != 1:
    raise SystemExit("native_host_SHA1_identity_not_unique_Developer_ID_for_fixed_team")
' "$developer_id_input" "$fixed_team"
}

require_notary_keychain() {
  /usr/bin/python3 -I -c '
import os,stat,sys
home,path,expected_uid_raw=sys.argv[1:]
try:
    expected_uid=int(expected_uid_raw)
except ValueError:
    raise SystemExit("native_host_notary_keychain_untrusted")
fds=[]

def reject():
    raise SystemExit("native_host_notary_keychain_untrusted")

def same_inode(*records):
    return len({(item.st_dev,item.st_ino) for item in records}) == 1

def trusted_directory(item):
    return (stat.S_ISDIR(item.st_mode) and item.st_uid==expected_uid
            and not stat.S_IMODE(item.st_mode)&0o022)

def trusted_keychain(item):
    return (stat.S_ISREG(item.st_mode) and item.st_uid==expected_uid
            and item.st_nlink==1 and not stat.S_IMODE(item.st_mode)&0o022)

if (
    not home.startswith("/") or not path.startswith("/")
    or "\n" in home or "\r" in home
    or "\n" in path or "\r" in path
    or os.path.normpath(home)!=home or os.path.normpath(path)!=path
    or os.path.realpath(home)!=home or os.path.realpath(path)!=path
    or expected_uid!=os.geteuid()
):
    reject()
library=os.path.join(home,"Library")
keychains=os.path.join(library,"Keychains")
if os.path.dirname(path)!=keychains or os.path.basename(path) in {"",".",".."}:
    reject()
basename=os.path.basename(path)
directory_flags=(os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
file_flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
try:
    home_before=os.lstat(home)
    if not trusted_directory(home_before): reject()
    home_fd=os.open(home,directory_flags); fds.append(home_fd)
    home_opened=os.fstat(home_fd)
    library_before=os.stat("Library",dir_fd=home_fd,follow_symlinks=False)
    if not trusted_directory(library_before): reject()
    library_fd=os.open("Library",directory_flags,dir_fd=home_fd)
    fds.append(library_fd)
    library_opened=os.fstat(library_fd)
    keychains_before=os.stat(
        "Keychains",dir_fd=library_fd,follow_symlinks=False,
    )
    if not trusted_directory(keychains_before): reject()
    keychains_fd=os.open("Keychains",directory_flags,dir_fd=library_fd)
    fds.append(keychains_fd)
    keychains_opened=os.fstat(keychains_fd)
    keychain_before=os.stat(
        basename,dir_fd=keychains_fd,follow_symlinks=False,
    )
    if not trusted_keychain(keychain_before): reject()
    keychain_fd=os.open(basename,file_flags,dir_fd=keychains_fd)
    fds.append(keychain_fd)
    keychain_opened=os.fstat(keychain_fd)

    home_after=os.lstat(home)
    library_after=os.stat("Library",dir_fd=home_fd,follow_symlinks=False)
    keychains_after=os.stat(
        "Keychains",dir_fd=library_fd,follow_symlinks=False,
    )
    keychain_after=os.stat(
        basename,dir_fd=keychains_fd,follow_symlinks=False,
    )
    if (
        not same_inode(home_before,home_opened,home_after)
        or not same_inode(library_before,library_opened,library_after)
        or not same_inode(keychains_before,keychains_opened,keychains_after)
        or not same_inode(keychain_before,keychain_opened,keychain_after)
        or not all(trusted_directory(item) for item in (
            home_before,home_opened,home_after,
            library_before,library_opened,library_after,
            keychains_before,keychains_opened,keychains_after,
        ))
        or not all(trusted_keychain(item) for item in (
            keychain_before,keychain_opened,keychain_after,
        ))
    ):
        reject()
except OSError:
    reject()
finally:
    for descriptor in reversed(fds):
        os.close(descriptor)
' "$operator_home" "$notary_keychain_input" "$EUID" \
    || fail native_host_notary_keychain_untrusted 2
}

notary_keychain_args=(
  --keychain-profile "$notary_profile_input"
  --keychain "$notary_keychain_input"
)

preflight_notary_credentials() {
  require_notary_keychain
  /usr/bin/xcrun notarytool history \
    "${notary_keychain_args[@]}" --output-format json >/dev/null \
    || fail native_host_notary_credentials_preflight_failed
}

signing_config_record() {
  /usr/bin/python3 -I -c '
import hashlib,json,os,stat,subprocess,sys
path=sys.argv[1]; expected_uid=int(sys.argv[2])
expected=b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    info=os.fstat(fd); data=b""
    while True:
        block=os.read(fd,4096)
        if not block: break
        data+=block
        if len(data)>4096: raise SystemExit("native_host_signing_config_oversize")
finally:
    os.close(fd)
current=os.lstat(path)
listing=subprocess.run(
    ["/bin/ls","-lde",path],check=True,capture_output=True,text=True,
).stdout.splitlines()
mode=stat.S_IMODE(info.st_mode)
if (
    not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(current.st_mode)
    or (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino)
    or info.st_uid!=expected_uid or info.st_nlink!=1
    or mode not in {0o400,0o440,0o444,0o600,0o640,0o644}
    or data!=expected or len(listing)!=1 or "+" in listing[0].split()[0]
):
    raise SystemExit("native_host_signing_config_untrusted")
print(json.dumps({
    "dev":info.st_dev,"gid":info.st_gid,
    "ino":info.st_ino,"mode":mode,"mtime_ns":info.st_mtime_ns,
    "sha256":hashlib.sha256(data).hexdigest(),"size":len(data),
    "uid":info.st_uid,
},sort_keys=True,separators=(",",":")))
' "$1" "$EUID"
}

copy_exact_signing_config() {
  /usr/bin/python3 -I -c '
import hashlib,json,os,stat,sys
source,destination,encoded=sys.argv[1:]
expected_record=json.loads(encoded)
expected=b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    info=os.fstat(fd); data=b""
    while True:
        block=os.read(fd,4096)
        if not block: break
        data+=block
finally:
    os.close(fd)
record={
    "dev":info.st_dev,"gid":info.st_gid,"ino":info.st_ino,
    "mode":stat.S_IMODE(info.st_mode),"mtime_ns":info.st_mtime_ns,
    "sha256":hashlib.sha256(data).hexdigest(),"size":len(data),
    "uid":info.st_uid,
}
if data!=expected or record!=expected_record:
    raise SystemExit("native_host_signing_config_changed")
out=os.open(
    destination,
    os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
    0o444,
)
try:
    view=memoryview(data)
    while view:
        written=os.write(out,view)
        if written<=0: raise SystemExit("native_host_signing_config_copy_failed")
        view=view[written:]
    os.fchmod(out,0o444); os.fsync(out)
finally:
    os.close(out)
' "$1" "$2" "$3"
  require_acl_free_paths "$2"
  /bin/chmod 0444 "$2"
}

validate_archived_signing_config() {
  /usr/bin/python3 -I -c '
import hashlib,os,stat,subprocess,sys
path,digest=sys.argv[1:]
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    info=os.fstat(fd); data=os.read(fd,4097)
finally:
    os.close(fd)
listing=subprocess.run(
    ["/bin/ls","-lde",path],check=True,capture_output=True,text=True,
).stdout.splitlines()
if (
    not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
    or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o444
    or data!=b"SECURE_SANDBOX_DEVELOPMENT_TEAM = 389K3H8Y32\n"
    or hashlib.sha256(data).hexdigest()!=digest
    or len(listing)!=1 or "+" in listing[0].split()[0]
):
    raise SystemExit("native_host_archived_signing_config_invalid")
' "$1" "$2"
}

verify_signed_product() {
  local path="$1" identifier="$2" require_runtime="$3" deep="$4"
  local details observed_identifier observed_team observed_cdhash requirement
  local certificate_root fingerprint
  verify_options=(--verify --strict --verbose=2)
  [[ "$deep" == 1 ]] && verify_options+=(--deep)
  /usr/bin/codesign "${verify_options[@]}" "$path" >/dev/null
  requirement="identifier \"$identifier\" and anchor apple generic and certificate leaf[subject.OU] = \"$fixed_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign "${verify_options[@]}" -R="$requirement" "$path" >/dev/null
  details="$(/usr/bin/codesign -dv --verbose=4 "$path" 2>&1)"
  observed_identifier="$(/usr/bin/printf '%s\n' "$details" \
    | /usr/bin/sed -n 's/^Identifier=//p')"
  observed_team="$(/usr/bin/printf '%s\n' "$details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  observed_cdhash="$(/usr/bin/printf '%s\n' "$details" \
    | /usr/bin/sed -n 's/^CDHash=//p' \
    | /usr/bin/tr '[:upper:]' '[:lower:]')"
  [[ "$observed_identifier" == "$identifier" \
      && "$observed_team" == "$fixed_team" \
      && "$observed_cdhash" =~ ^[0-9a-f]{40}$ \
      && "$details" != *"Signature=adhoc"* ]] \
    || fail native_host_product_signing_identity_invalid
  if [[ "$require_runtime" == 1 ]]; then
    [[ "$details" == *"flags=0x10000(runtime)"* ]] \
      || fail native_host_product_hardened_runtime_missing
  fi
  certificate_root="$(/usr/bin/mktemp -d \
    "$build_root/certificate.XXXXXX")"
  (cd "$certificate_root" \
    && /usr/bin/codesign -d --extract-certificates "$path" >/dev/null 2>&1)
  [[ -f "$certificate_root/codesign0" \
      && ! -L "$certificate_root/codesign0" ]] \
    || fail native_host_product_leaf_certificate_missing
  fingerprint="$(/usr/bin/openssl x509 -inform DER \
    -in "$certificate_root/codesign0" -noout -fingerprint -sha1 \
    | /usr/bin/sed -E 's/^[^=]+=//; s/://g' \
    | /usr/bin/tr '[:upper:]' '[:lower:]')"
  [[ "$fingerprint" == "$developer_id_input" ]] \
    || fail native_host_product_certificate_SHA1_mismatch
  /usr/bin/printf '%s\n' "$observed_cdhash"
}

run_candidate_only() {
  [[ "$argument_count" == 2 && "$requested_mode" == --candidate-only \
      && "$candidate_authority" == 1 ]] \
    || fail native_host_candidate_only_authority_missing 2
  require_release_inputs
  [[ "$release_source_root_input" == "$repo" \
      && "$repo" == /* && -d "$repo" && ! -L "$repo" ]] \
    || fail native_host_candidate_source_root_invalid 2
  /usr/bin/python3 -I -c '
import os,stat,sys
path=sys.argv[1]; info=os.lstat(path)
if (os.path.realpath(path)!=path or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid()
        or stat.S_IMODE(info.st_mode)&0o077):
    raise SystemExit("native_host_candidate_source_root_untrusted")
' "$repo"
  [[ "$release_commit_input" =~ ^[0-9a-f]{40}$ \
      && "$source_archive_sha256_input" =~ ^[0-9a-f]{64}$ \
      && "$source_archive_path_input" == /* \
      && "$source_tree_sha256_input" =~ ^[0-9a-f]{64}$ \
      && "$signing_config_sha256_input" =~ ^[0-9a-f]{64}$ \
      && "$host_release_preimage_path_input" == /* \
      && "$host_release_preimage_sha256_input" =~ ^[0-9a-f]{64}$ ]] \
    || fail native_host_candidate_provenance_invalid 2
  [[ "$requested_output" == /* && -d "$requested_output" \
      && ! -L "$requested_output" ]] \
    || fail native_host_candidate_output_invalid 2
  /usr/bin/python3 -I -c '
import os,stat,sys
path=sys.argv[1]; info=os.lstat(path)
if (
    not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
    or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700
    or os.path.realpath(path)!=path
    or any(os.scandir(path))
):
    raise SystemExit("native_host_candidate_output_untrusted")
' "$requested_output"
  [[ ! -e "$repo/.git" && ! -L "$repo/.git" ]] \
    || fail native_host_candidate_source_must_be_archive
  [[ -f "$source_helper" && ! -L "$source_helper" \
      && -f "$source_archive_path_input" \
      && ! -L "$source_archive_path_input" \
      && -f "$host_release_preimage_path_input" \
      && ! -L "$host_release_preimage_path_input" ]] \
    || fail native_host_candidate_source_evidence_missing
  release_build_parent="$(/usr/bin/dirname "$source_archive_path_input")"
  [[ "$release_build_parent" == /* && "$release_build_parent" != / \
      && "$(/usr/bin/dirname "$host_release_preimage_path_input")" \
        == "$release_build_parent" \
      && "$release_source_root_input" \
        == "$release_build_parent/mounted-source" \
      && -n "$release_build_parent_identity_input" \
      && "$source_helper_sha256_input" =~ ^[0-9a-f]{64}$ \
      && "$touchid_builder_sha256_input" =~ ^[0-9a-f]{64}$ \
      && "$component_builder_sha256_input" =~ ^[0-9a-f]{64}$ ]] \
    || fail native_host_release_build_parent_invalid
  /usr/bin/python3 -I -c '
import os,pathlib,stat,sys
parent_path,candidate_path=sys.argv[1:]
parent=os.lstat(parent_path)
parent_resolved=pathlib.Path(parent_path).resolve(strict=True)
candidate_resolved=pathlib.Path(candidate_path).resolve(strict=True)
if (
    str(parent_resolved)!=parent_path
    or not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
    or parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700
    or parent_resolved==candidate_resolved
    or parent_resolved in candidate_resolved.parents
    or candidate_resolved in parent_resolved.parents
):
    raise SystemExit("native_host_release_build_parent_untrusted")
' "$release_build_parent" "$requested_output"
  expected_signing_config="$repo/macos/TouchIDAuthorization/Signing.local.xcconfig"
  [[ "$signing_config_input" == "$expected_signing_config" ]] \
    || fail native_host_candidate_signing_config_path_invalid
  require_acl_free_paths \
    "$repo" "$release_build_parent" "$requested_output" "$source_helper" \
    "$source_archive_path_input" "$host_release_preimage_path_input" \
    "$expected_signing_config" \
    || fail native_host_candidate_acl_boundary_untrusted
  validate_archived_signing_config \
    "$expected_signing_config" "$signing_config_sha256_input"
  verify_candidate_source() {
    local record observed_tree
    record="$(run_source_helper_fd verify-source \
      --archive "$source_archive_path_input" \
      --source-root "$repo" \
      --archive-sha256 "$source_archive_sha256_input" \
      --signing-config-sha256 "$signing_config_sha256_input")" \
      || fail native_host_candidate_source_changed
    observed_tree="$(/usr/bin/python3 -I -c \
      'import json,sys; print(json.loads(sys.argv[1])["source_tree_sha256"])' \
      "$record")"
    [[ "$observed_tree" == "$source_tree_sha256_input" ]] \
      || fail native_host_candidate_source_tree_mismatch
  }

  exec 20<"$release_build_parent"
  exec 22<"$source_helper"
  run_source_helper_fd() {
    /usr/bin/python3 -I -c '
import hashlib,os,sys
descriptor=int(sys.argv[1]); expected=sys.argv[2]
raw=bytearray(); offset=0
while True:
    block=os.pread(descriptor,65536,offset)
    if not block: break
    raw.extend(block); offset+=len(block)
    if len(raw)>1024*1024:
        raise SystemExit("native_host_source_helper_oversize")
if hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit("native_host_source_helper_digest_mismatch")
sys.argv=["native_host_release_source.py",*sys.argv[3:]]
namespace={"__name__":"__main__","__file__":"<held-native-host-source-helper>","__package__":None}
exec(compile(bytes(raw),namespace["__file__"],"exec"),namespace,namespace)
' 22 "$source_helper_sha256_input" "$@"
  }
  [[ "$(run_source_helper_fd identity --path "$release_build_parent")" \
      == "$release_build_parent_identity_input" ]] \
    || fail native_host_release_build_parent_identity_mismatch
  verify_candidate_source
  build_creation="$(run_source_helper_fd create-build-directory-at \
    --parent-fd 20 --prefix .build. \
    --parent-identity "$release_build_parent_identity_input")" \
    || fail native_host_candidate_build_root_untrusted
  build_name="$(/usr/bin/python3 -I -c '
import json,re,sys
value=json.loads(sys.argv[1]); name=value.get("name","")
if (value.get("schema")!="secure-sandbox-native-host-build-directory-v1"
        or value.get("status")!="verified"
        or re.fullmatch(r"\.build\.[0-9a-f]{24}",name) is None):
    raise SystemExit("native_host_candidate_build_record_invalid")
print(name)
' "$build_creation")"
  build_root_identity="$build_creation"
  build_root="$release_build_parent/$build_name"
  build_descriptor_open=false
  exec 21<"$build_root"
  build_descriptor_open=true
  require_build_custody() {
    run_source_helper_fd verify-build-directory-at \
      --parent-fd 20 --root-fd 21 --name "$build_name" \
      --parent-identity "$release_build_parent_identity_input" \
      --identity "$build_root_identity" \
      --parent-path "$release_build_parent" --root-path "$build_root" \
      >/dev/null || fail native_host_candidate_build_custody_changed
  }
  cleanup_candidate_build() {
    local status=$?
    if [[ "$build_descriptor_open" == true ]]; then
      run_source_helper_fd retire-build-directory-at \
        --parent-fd 20 --root-fd 21 --name "$build_name" \
        --parent-identity "$release_build_parent_identity_input" \
        --identity "$build_root_identity" \
        --parent-path "$release_build_parent" >/dev/null || status=1
      exec 21<&-
      build_descriptor_open=false
    fi
    exec 20<&-
    exec 22<&-
    return "$status"
  }
  trap cleanup_candidate_build EXIT
  require_build_custody

  generation="$requested_output/generation"
  evidence="$requested_output/evidence"
  child_output="$build_root/child-output"
  swift_scratch="$build_root/swift-scratch"
  stage="$build_root/SecureSandboxHostProducts"
  unsigned="$build_root/SecureSandboxNativeHostProducts.dmg"
  /bin/mkdir -m 0755 "$generation" "$stage"
  /usr/bin/python3 -I -c '
import hashlib,os,stat,sys
source,destination,expected=sys.argv[1:]
before=os.lstat(source)
source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
destination_fd=-1
try:
    opened=os.fstat(source_fd)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink!=1
            or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)):
        raise SystemExit("native_host_source_archive_untrusted")
    destination_fd=os.open(
        destination,
        os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
        0o444,
    )
    digest=hashlib.sha256(); size=0
    while True:
        block=os.read(source_fd,1024*1024)
        if not block: break
        digest.update(block); size+=len(block)
        view=memoryview(block)
        while view:
            written=os.write(destination_fd,view)
            if written<=0: raise SystemExit("native_host_source_archive_copy_failed")
            view=view[written:]
    after=os.fstat(source_fd)
    if ((opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            or size!=opened.st_size or digest.hexdigest()!=expected):
        raise SystemExit("native_host_source_archive_changed")
    os.fchmod(destination_fd,0o444); os.fsync(destination_fd)
finally:
    if destination_fd>=0: os.close(destination_fd)
    os.close(source_fd)
' "$source_archive_path_input" \
    "$generation/SecureSandboxNativeHostProducts.source.tar" \
    "$source_archive_sha256_input"
  /bin/mkdir -m 0700 "$evidence" "$child_output" "$swift_scratch"
  /usr/bin/python3 -I -c '
import hashlib,os,stat,sys
source,destination,expected=sys.argv[1:]
before=os.lstat(source)
source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
destination_fd=-1
try:
    opened=os.fstat(source_fd)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid!=os.geteuid() or opened.st_nlink!=1
            or stat.S_IMODE(opened.st_mode) not in {0o400,0o600}
            or (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino)):
        raise SystemExit("native_host_release_preimage_untrusted")
    destination_fd=os.open(
        destination,
        os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
        0o400,
    )
    digest=hashlib.sha256(); size=0
    while True:
        block=os.read(source_fd,1024*1024)
        if not block: break
        digest.update(block); size+=len(block)
        if size>1024*1024*1024:
            raise SystemExit("native_host_release_preimage_oversize")
        view=memoryview(block)
        while view:
            written=os.write(destination_fd,view)
            if written<=0:
                raise SystemExit("native_host_release_preimage_copy_failed")
            view=view[written:]
    after=os.fstat(source_fd)
    if ((opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            or size!=opened.st_size or digest.hexdigest()!=expected):
        raise SystemExit("native_host_release_preimage_changed")
    os.fchmod(destination_fd,0o400); os.fsync(destination_fd)
finally:
    if destination_fd>=0: os.close(destination_fd)
    os.close(source_fd)
directory_fd=os.open(os.path.dirname(destination),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.fsync(directory_fd)
finally: os.close(directory_fd)
' "$host_release_preimage_path_input" \
    "$evidence/SecureSandboxHostReleasePreimage.tar" \
    "$host_release_preimage_sha256_input"
  /bin/mkdir -m 0700 \
    "$swift_scratch/cache" "$swift_scratch/config" "$swift_scratch/security"
  require_build_custody
  child_output_identity="$(run_source_helper_fd identity \
    --path "$child_output")" \
    || fail native_host_child_output_untrusted
  require_child_output_identity() {
    local current
    require_build_custody
    current="$(run_source_helper_fd identity \
      --path "$child_output")" \
      || fail native_host_child_output_changed
    [[ "$current" == "$child_output_identity" ]] \
      || fail native_host_child_output_changed
    require_build_custody
  }

  common_environment=(
    PATH=/usr/bin:/bin:/usr/sbin:/sbin
    HOME="$operator_home"
    USER="$operator_name"
    LOGNAME="$operator_name"
    TMPDIR=/tmp
    LC_ALL=C
    LANG=C
    SECURE_SANDBOX_RELEASE_CANDIDATE_ONLY=1
    SECURE_SANDBOX_RELEASE_OUTPUT_ROOT="$child_output"
    SECURE_SANDBOX_DEVELOPER_ID="$developer_id_input"
    SECURE_SANDBOX_EXPECTED_TEAM_ID="$fixed_team"
    SECURE_SANDBOX_RELEASE_COMMIT="$release_commit_input"
    SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256="$source_archive_sha256_input"
    SECURE_SANDBOX_SIGNING_CONFIG_SHA256="$signing_config_sha256_input"
    SECURE_SANDBOX_RELEASE_SOURCE_ROOT="$repo"
  )
  emit_held_script_fd() {
    /usr/bin/python3 -I -c '
import hashlib,os,sys
descriptor=int(sys.argv[1]); expected=sys.argv[2]
raw=bytearray(); offset=0
while True:
    block=os.pread(descriptor,65536,offset)
    if not block: break
    raw.extend(block); offset+=len(block)
    if len(raw)>1024*1024:
        raise SystemExit("native_host_held_script_oversize")
if hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit("native_host_held_script_digest_mismatch")
sys.stdout.buffer.write(raw)
' "$1" "$2"
  }
  exec 6<"$repo/scripts/build-touchid-authorization-ui.sh"
  emit_held_script_fd 6 "$touchid_builder_sha256_input" \
    | /usr/bin/env -i "${common_environment[@]}" \
      SECURE_SANDBOX_SIGNING_CONFIG="$expected_signing_config" \
      /bin/bash -p -s >/dev/null
  exec 6<&-
  require_child_output_identity
  verify_candidate_source
  exec 7<"$repo/scripts/build-native-credential-components.sh"
  emit_held_script_fd 7 "$component_builder_sha256_input" \
    | /usr/bin/env -i "${common_environment[@]}" \
      SECURE_SANDBOX_SWIFT_HERMETIC=1 \
      SECURE_SANDBOX_SWIFT_SCRATCH_PATH="$swift_scratch" \
      /bin/bash -p -s >/dev/null
  exec 7<&-
  require_child_output_identity
  verify_candidate_source

  /usr/bin/python3 -I -c '
import pathlib,stat,sys
root=pathlib.Path(sys.argv[1])
expected={
 "SecureSandboxAuthorizationUI.app":"directory",
 "SecureSandboxAuthorizationUI.bundle.json":"file",
 "SecureSandboxAuthorizationUI.sources.json":"file",
 "SecureSandboxNativeCredentialHelper.app":"directory",
 "SecureSandboxNativeComponents.bundle.json":"file",
 "SecureSandboxNativeStackBackend":"file",
 "SecureSandboxNativeProjectionConsumer":"file",
}
actual={}
for path in root.iterdir():
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode): raise SystemExit("native_host_child_output_link")
    actual[path.name]="directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "special"
if actual!=expected:
    raise SystemExit("native_host_child_output_inventory_invalid")
' "$child_output"
  require_child_output_identity
  child_output_tree="$(run_source_helper_fd tree \
    --path "$child_output")" \
    || fail native_host_child_output_inventory_untrusted

  /usr/bin/ditto --noqtn \
    "$child_output/SecureSandboxAuthorizationUI.app" \
    "$generation/SecureSandboxAuthorizationUI.app"
  /usr/bin/ditto --noqtn \
    "$child_output/SecureSandboxNativeCredentialHelper.app" \
    "$generation/SecureSandboxNativeCredentialHelper.app"
  for name in \
      SecureSandboxAuthorizationUI.bundle.json \
      SecureSandboxAuthorizationUI.sources.json \
      SecureSandboxNativeComponents.bundle.json \
      SecureSandboxNativeStackBackend \
      SecureSandboxNativeProjectionConsumer; do
    /bin/cp "$child_output/$name" "$generation/$name"
  done
  require_child_output_identity
  [[ "$(run_source_helper_fd tree --path "$child_output")" \
      == "$child_output_tree" ]] \
    || fail native_host_child_output_changed_during_copy
  verify_candidate_source
  /bin/chmod 0444 \
    "$generation/SecureSandboxAuthorizationUI.bundle.json" \
    "$generation/SecureSandboxAuthorizationUI.sources.json" \
    "$generation/SecureSandboxNativeComponents.bundle.json"
  /bin/chmod 0555 \
    "$generation/SecureSandboxNativeStackBackend" \
    "$generation/SecureSandboxNativeProjectionConsumer"

  require_build_custody
  authorization_ui_cdhash="$(verify_signed_product \
    "$generation/SecureSandboxAuthorizationUI.app" \
    org.zebeth.SecureSandbox.AuthorizationUI 1 1)"
  credential_helper_cdhash="$(verify_signed_product \
    "$generation/SecureSandboxNativeCredentialHelper.app" \
    org.zebeth.SecureSandbox.NativeCredentialHelper 1 1)"
  backend_cdhash="$(verify_signed_product \
    "$generation/SecureSandboxNativeStackBackend" \
    org.zebeth.SecureSandbox.NativeStackBackend 1 0)"
  projection_cdhash="$(verify_signed_product \
    "$generation/SecureSandboxNativeProjectionConsumer" \
    org.zebeth.SecureSandbox.NativeProjectionConsumer 1 0)"
  require_build_custody

  /usr/bin/ditto --noqtn \
    "$generation/SecureSandboxAuthorizationUI.app" \
    "$stage/SecureSandboxAuthorizationUI.app"
  /usr/bin/ditto --noqtn \
    "$generation/SecureSandboxNativeCredentialHelper.app" \
    "$stage/SecureSandboxNativeCredentialHelper.app"
  /bin/cp \
    "$generation/SecureSandboxAuthorizationUI.bundle.json" \
    "$generation/SecureSandboxNativeComponents.bundle.json" \
    "$generation/SecureSandboxNativeStackBackend" \
    "$generation/SecureSandboxNativeProjectionConsumer" \
    "$stage/"
  /bin/chmod 0444 \
    "$stage/SecureSandboxAuthorizationUI.bundle.json" \
    "$stage/SecureSandboxNativeComponents.bundle.json"
  /bin/chmod 0555 \
    "$stage/SecureSandboxNativeStackBackend" \
    "$stage/SecureSandboxNativeProjectionConsumer"
  /usr/bin/python3 -I -c '
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); output=root/"SecureSandboxNativeHostProducts.manifest.json"
entries={}
for path in sorted(root.rglob("*")):
    relative=path.relative_to(root).as_posix(); info=path.lstat()
    if path.is_symlink() or (not path.is_dir() and not path.is_file()):
        raise SystemExit("native_host_container_entry_invalid:"+relative)
    if path.is_file():
        data=path.read_bytes(); mode=stat.S_IMODE(info.st_mode)
        if mode not in {0o444,0o555}:
            raise SystemExit("native_host_container_entry_mode_invalid:"+relative)
        entries[relative]={"mode":mode,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
value={"entries":entries,"schema":"secure-sandbox-native-host-products-manifest-v1"}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="ascii")
' "$stage"
  /bin/chmod 0444 "$stage/SecureSandboxNativeHostProducts.manifest.json"

  /usr/bin/hdiutil create -quiet -ov -format UDZO \
    -volname SecureSandboxHostProducts -srcfolder "$stage" "$unsigned"
  require_build_custody
  /usr/bin/codesign --force --timestamp --identifier "$container_identifier" \
    --sign "$developer_id_input" "$unsigned"
  container_cdhash="$(verify_signed_product \
    "$unsigned" "$container_identifier" 0 0)"
  notary_submission_sha256="$(/usr/bin/shasum -a 256 "$unsigned" \
    | /usr/bin/awk '{print $1}')"
  notary_result="$evidence/notary-result.json"
  notary_log="$evidence/notary-log.json"
  require_notary_keychain
  /usr/bin/xcrun notarytool submit "$unsigned" \
    "${notary_keychain_args[@]}" --wait --output-format json \
    >"$notary_result"
  /usr/bin/python3 -I -c '
import json,re,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
if value.get("status")!="Accepted" or re.fullmatch(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    value.get("id",""),
) is None:
    raise SystemExit("native_host_container_notarization_not_accepted")
' "$notary_result"
  submission_id="$(/usr/bin/python3 -I -c '
import json,pathlib,sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["id"].lower())
' "$notary_result")"
  require_notary_keychain
  /usr/bin/xcrun notarytool log "$submission_id" \
    "${notary_keychain_args[@]}" "$notary_log"
  /usr/bin/python3 -I -c '
import json,pathlib,re,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if (
    value.get("status")!="Accepted"
    or not isinstance(value.get("statusCode"),int)
    or isinstance(value["statusCode"],bool) or value["statusCode"]!=0
    or "issues" not in value or value["issues"] not in (None,[])
    or str(value.get("jobId","")).lower()!=sys.argv[2].lower()
    or re.fullmatch(r"[0-9a-fA-F]{64}",str(value.get("sha256",""))) is None
    or str(value["sha256"]).lower()!=sys.argv[3].lower()
):
    raise SystemExit("native_host_container_notary_log_not_clean")
' "$notary_log" "$submission_id" "$notary_submission_sha256"
  /bin/chmod 0600 "$notary_result" "$notary_log"
  require_build_custody

  /usr/bin/xcrun stapler staple "$unsigned"
  /usr/bin/xcrun stapler validate "$unsigned"
  /usr/sbin/spctl --assess --type open \
    --context context:primary-signature --verbose=4 "$unsigned"
  /usr/bin/hdiutil verify "$unsigned" >/dev/null
  final_container_cdhash="$(verify_signed_product \
    "$unsigned" "$container_identifier" 0 0)"
  [[ "$final_container_cdhash" == "$container_cdhash" ]] \
    || fail native_host_container_cdhash_changed_after_staple
  require_build_custody

  container="$generation/SecureSandboxNativeHostProducts.dmg"
  container_manifest="$generation/SecureSandboxNativeHostProducts.manifest.json"
  container_receipt="$generation/SecureSandboxNativeHostProducts.notarization.json"
  container_receipt_signature="$generation/SecureSandboxNativeHostProducts.notarization.sig"
  /usr/bin/ditto --noqtn "$unsigned" "$container"
  /bin/cp "$stage/SecureSandboxNativeHostProducts.manifest.json" \
    "$container_manifest"
  /bin/chmod 0444 "$container" "$container_manifest"
  /usr/bin/xcrun stapler validate "$container"
  /usr/sbin/spctl --assess --type open \
    --context context:primary-signature --verbose=4 "$container"
  /usr/bin/hdiutil verify "$container" >/dev/null
  published_container_cdhash="$(verify_signed_product \
    "$container" "$container_identifier" 0 0)"
  [[ "$published_container_cdhash" == "$container_cdhash" ]] \
    || fail native_host_container_cdhash_changed_in_candidate_copy

  container_manifest_sha256="$(/usr/bin/shasum -a 256 "$container_manifest" \
    | /usr/bin/awk '{print $1}')"
  container_sha256="$(/usr/bin/shasum -a 256 "$container" \
    | /usr/bin/awk '{print $1}')"
  container_size="$(/usr/bin/stat -f %z "$container")"
  notary_log_sha256="$(/usr/bin/shasum -a 256 "$notary_log" \
    | /usr/bin/awk '{print $1}')"
  /usr/bin/python3 -I -c '
import json,os,sys
path=sys.argv[1]
value={
 "build_custody":"trusted-login-principal-v1",
 "container_cdhash":sys.argv[2],
 "container_identifier":"org.zebeth.SecureSandbox.NativeHostProducts",
 "container_manifest_sha256":sys.argv[3],
 "container_sha256":sys.argv[4],
 "container_size":int(sys.argv[5]),
 "developer_id_certificate_sha1":sys.argv[6],
 "gatekeeper_assessed":True,
 "host_release_preimage_sha256":sys.argv[18],
 "notary_log_sha256":sys.argv[7],
 "notary_status":"accepted",
 "notary_submission_id":sys.argv[8],
 "notary_submission_sha256":sys.argv[9],
 "products":{
   "authorization_ui":{"cdhash":sys.argv[10],"identifier":"org.zebeth.SecureSandbox.AuthorizationUI"},
   "credential_helper":{"cdhash":sys.argv[11],"identifier":"org.zebeth.SecureSandbox.NativeCredentialHelper"},
   "native_projection_consumer":{"cdhash":sys.argv[13],"identifier":"org.zebeth.SecureSandbox.NativeProjectionConsumer"},
   "native_stack_backend":{"cdhash":sys.argv[12],"identifier":"org.zebeth.SecureSandbox.NativeStackBackend"},
 },
 "release_commit":sys.argv[14],
 "schema":"secure-sandbox-native-host-products-notarization-v3",
 "signing_config_sha256":sys.argv[15],
 "source_archive_sha256":sys.argv[16],
 "source_tree_sha256":sys.argv[17],
 "stapler_validated":True,
 "team_id":"389K3H8Y32",
}
raw=(json.dumps(value,indent=2,sort_keys=True)+"\n").encode("ascii")
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
try:
    view=memoryview(raw)
    while view:
        written=os.write(fd,view)
        if written<=0: raise SystemExit("native_host_receipt_write_failed")
        view=view[written:]
    os.fchmod(fd,0o444); os.fsync(fd)
finally:
    os.close(fd)
' "$container_receipt" "$container_cdhash" "$container_manifest_sha256" \
    "$container_sha256" "$container_size" "$developer_id_input" \
    "$notary_log_sha256" "$submission_id" "$notary_submission_sha256" \
    "$authorization_ui_cdhash" "$credential_helper_cdhash" \
    "$backend_cdhash" "$projection_cdhash" "$release_commit_input" \
    "$signing_config_sha256_input" "$source_archive_sha256_input" \
    "$source_tree_sha256_input" "$host_release_preimage_sha256_input"

  /usr/bin/python3 -I -c '
import json,pathlib,re,sys
path=pathlib.Path(sys.argv[1]); value=json.loads(path.read_bytes())
expected_keys={
 "build_custody","container_cdhash","container_identifier","container_manifest_sha256",
 "container_sha256","container_size","developer_id_certificate_sha1",
 "gatekeeper_assessed","host_release_preimage_sha256",
 "notary_log_sha256","notary_status",
 "notary_submission_id","notary_submission_sha256","products",
 "release_commit","schema","signing_config_sha256",
 "source_archive_sha256","source_tree_sha256","stapler_validated","team_id",
}
if set(value)!=expected_keys or value.get("schema")!="secure-sandbox-native-host-products-notarization-v3":
    raise SystemExit("native_host_receipt_schema_invalid")
if value.get("build_custody")!="trusted-login-principal-v1":
    raise SystemExit("native_host_receipt_build_custody_invalid")
if set(value.get("products",{}))!={"authorization_ui","credential_helper","native_stack_backend","native_projection_consumer"}:
    raise SystemExit("native_host_receipt_products_invalid")
for product in value["products"].values():
    if set(product)!={"identifier","cdhash"} or re.fullmatch(r"[0-9a-f]{40}",product["cdhash"]) is None:
        raise SystemExit("native_host_receipt_product_invalid")
for name in (
 "container_manifest_sha256","container_sha256","notary_log_sha256",
 "notary_submission_sha256","signing_config_sha256","source_archive_sha256",
 "host_release_preimage_sha256",
 "source_tree_sha256",
):
    if re.fullmatch(r"[0-9a-f]{64}",str(value.get(name,""))) is None:
        raise SystemExit("native_host_receipt_digest_invalid")
if re.fullmatch(r"[0-9a-f]{40}",value.get("developer_id_certificate_sha1","")) is None:
    raise SystemExit("native_host_receipt_certificate_invalid")
' "$container_receipt"
  receipt_identifier=org.zebeth.SecureSandbox.NativeHostProductsReceipt
  /usr/bin/codesign --force --timestamp \
    --identifier "$receipt_identifier" \
    --sign "$developer_id_input" \
    --detached "$container_receipt_signature" "$container_receipt"
  /bin/chmod 0444 "$container_receipt_signature"
  receipt_requirement="identifier \"$receipt_identifier\" and anchor apple generic and certificate leaf = H\"$developer_id_input\" and certificate leaf[subject.OU] = \"$fixed_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --strict --verbose=2 \
    --detached "$container_receipt_signature" \
    -R="$receipt_requirement" "$container_receipt"
  receipt_signature_details="$(/usr/bin/codesign -d --verbose=4 \
    --detached "$container_receipt_signature" "$container_receipt" 2>&1)"
  [[ "$receipt_signature_details" == *"Identifier=$receipt_identifier"* \
      && "$receipt_signature_details" == *"TeamIdentifier=$fixed_team"* \
      && "$receipt_signature_details" == *"Timestamp="* \
      && "$receipt_signature_details" != *"Signature=adhoc"* ]] \
    || fail native_host_receipt_signature_invalid
  verify_candidate_source
  require_child_output_identity
  [[ "$(run_source_helper_fd tree --path "$child_output")" \
      == "$child_output_tree" ]] \
    || fail native_host_child_output_changed_after_signing
  require_build_custody
  [[ -f "$evidence/SecureSandboxHostReleasePreimage.tar" \
      && ! -L "$evidence/SecureSandboxHostReleasePreimage.tar" \
      && "$(/usr/bin/stat -f %Lp \
        "$evidence/SecureSandboxHostReleasePreimage.tar")" == 400 \
      && "$(/usr/bin/shasum -a 256 \
        "$evidence/SecureSandboxHostReleasePreimage.tar" \
        | /usr/bin/awk '{print $1}')" \
        == "$host_release_preimage_sha256_input" ]] \
    || fail native_host_release_preimage_changed
  /bin/chmod 0755 "$generation"
  /usr/bin/python3 -I -c '
import json,sys
print(json.dumps({
 "evidence":sys.argv[2],"generation":sys.argv[1],
 "receipt":sys.argv[3],"receipt_signature":sys.argv[4],
 "schema":"secure-sandbox-native-host-products-candidate-v2",
 "status":"verified",
},sort_keys=True,separators=(",",":")))
' "$generation" "$evidence" "$container_receipt" "$container_receipt_signature"
}

run_driver() {
  [[ "$argument_count" == 0 ]] || fail 'usage: build-native-host-products.sh' 2
  require_release_inputs
  preflight_notary_credentials
  [[ "$repo" == /* && -d "$repo/.git" && ! -L "$repo/.git" ]] \
    || fail native_host_release_repository_invalid
  release_branch="$(/usr/bin/git -C "$repo" \
    symbolic-ref --quiet --short HEAD)" \
    || fail native_host_release_requires_attached_branch
  [[ "$release_branch" == public-release ]] \
    || fail native_host_release_requires_public_release_branch
  release_commit="$(/usr/bin/git -C "$repo" \
    rev-parse --verify 'HEAD^{commit}')" \
    || fail native_host_release_commit_unreadable
  release_status="$(/usr/bin/git -C "$repo" \
    status --porcelain=v1 --untracked-files=all)" \
    || fail native_host_release_status_unreadable
  [[ "$release_commit" =~ ^[0-9a-f]{40}$ && -z "$release_status" ]] \
    || fail native_host_release_requires_clean_SHA1_worktree
  source_helper_object="$(/usr/bin/git -C "$repo" ls-tree \
    "$release_commit" -- scripts/native_host_release_source.py \
    | /usr/bin/python3 -I -c '
import re,sys
raw=sys.stdin.read()
match=re.fullmatch(r"100755 blob ([0-9a-f]{40})\tscripts/native_host_release_source.py\n",raw)
if match is None: raise SystemExit("native_host_release_source_blob_invalid")
print(match.group(1))
')" || fail native_host_release_source_helper_missing
  source_helper_sha256="$(/usr/bin/git -C "$repo" cat-file blob \
    "$source_helper_object" | /usr/bin/shasum -a 256 \
    | /usr/bin/awk '{print $1}')"
  [[ "$source_helper_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail native_host_release_source_helper_digest_invalid
  tracked_executable_sha256() {
    local relative object digest
    relative="$1"
    object="$(/usr/bin/git -C "$repo" ls-tree "$release_commit" -- "$relative" \
      | /usr/bin/python3 -I -c '
import re,sys
relative=sys.argv[1]; raw=sys.stdin.read()
match=re.fullmatch(
    r"100755 blob ([0-9a-f]{40})\t"+re.escape(relative)+r"\n",raw,
)
if match is None: raise SystemExit("native_host_release_executable_blob_invalid")
print(match.group(1))
' "$relative")" || fail native_host_release_executable_missing
    digest="$(/usr/bin/git -C "$repo" cat-file blob "$object" \
      | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
      || fail native_host_release_executable_digest_invalid
    /usr/bin/printf '%s\n' "$digest"
  }
  candidate_script_sha256="$(tracked_executable_sha256 \
    scripts/build-native-host-products.sh)"
  touchid_builder_sha256="$(tracked_executable_sha256 \
    scripts/build-touchid-authorization-ui.sh)"
  component_builder_sha256="$(tracked_executable_sha256 \
    scripts/build-native-credential-components.sh)"
  run_committed_source_helper() {
    /usr/bin/git -C "$repo" cat-file blob "$source_helper_object" \
      | /usr/bin/python3 -I -c '
import hashlib,sys
expected=sys.argv[1]; raw=sys.stdin.buffer.read()
header=b"blob "+str(len(raw)).encode("ascii")+b"\0"
if hashlib.sha1(header+raw).hexdigest()!=expected:
    raise SystemExit("native_host_release_source_blob_changed")
sys.argv=["native_host_release_source.py",*sys.argv[2:]]
namespace={"__name__":"__main__","__file__":"<committed-native-host-source-helper>","__package__":None}
exec(compile(raw,namespace["__file__"],"exec"),namespace,namespace)
' "$source_helper_object" "$@"
  }
  run_committed_source_helper verify-repo \
    --repo "$repo" --commit "$release_commit" >/dev/null \
    || fail native_host_release_repository_untrusted

  signing_config="$repo/macos/TouchIDAuthorization/Signing.local.xcconfig"
  signing_record="$(signing_config_record "$signing_config")" \
    || fail native_host_signing_config_untrusted
  signing_config_sha256="$(/usr/bin/python3 -I -c \
    'import json,sys; print(json.loads(sys.argv[1])["sha256"])' \
    "$signing_record")"
  require_unchanged_release_source() {
    local branch commit status record
    branch="$(/usr/bin/git -C "$repo" \
      symbolic-ref --quiet --short HEAD)" || return 1
    commit="$(/usr/bin/git -C "$repo" \
      rev-parse --verify 'HEAD^{commit}')" || return 1
    status="$(/usr/bin/git -C "$repo" \
      status --porcelain=v1 --untracked-files=all)" || return 1
    record="$(signing_config_record "$signing_config")" || return 1
    [[ "$branch" == "$release_branch" && "$commit" == "$release_commit" \
        && -z "$status" && "$record" == "$signing_record" ]] || {
      echo native_host_release_source_changed >&2
      return 1
    }
    run_committed_source_helper verify-repo \
      --repo "$repo" --commit "$release_commit" >/dev/null || {
      echo native_host_release_source_changed >&2
      return 1
    }
  }

  private_root="$repo/.private"
  [[ -d "$private_root" && ! -L "$private_root" \
      && "$(/usr/bin/stat -f %u "$private_root")" == "$EUID" \
      && "$(/usr/bin/stat -f %Lp "$private_root")" == 700 ]] \
    || fail native_host_private_root_untrusted
  candidate_records="$private_root/native-host-product-candidates"
  if [[ ! -e "$candidate_records" && ! -L "$candidate_records" ]]; then
    /bin/mkdir -m 0700 "$candidate_records"
  fi
  [[ -d "$candidate_records" && ! -L "$candidate_records" \
      && "$(/usr/bin/stat -f %u "$candidate_records")" == "$EUID" \
      && "$(/usr/bin/stat -f %Lp "$candidate_records")" == 700 ]] \
    || fail native_host_candidate_records_untrusted
  workspace_records="$private_root/native-host-release-workspaces"
  if [[ ! -e "$workspace_records" && ! -L "$workspace_records" ]]; then
    /bin/mkdir -m 0700 "$workspace_records"
  fi
  [[ -d "$workspace_records" && ! -L "$workspace_records" \
      && "$(/usr/bin/stat -f %u "$workspace_records")" == "$EUID" \
      && "$(/usr/bin/stat -f %Lp "$workspace_records")" == 700 ]] \
    || fail native_host_workspace_records_untrusted
  candidate_temp="$(/usr/bin/mktemp \
    -d "$candidate_records/.candidate.XXXXXX")"
  candidate_temp_identity="$(run_committed_source_helper identity \
    --path "$candidate_temp")" \
    || fail native_host_candidate_temp_untrusted
  release_workspace="$(/usr/bin/mktemp \
    -d "$workspace_records/.release.XXXXXX")"
  release_workspace_identity="$(run_committed_source_helper identity \
    --path "$release_workspace")" \
    || fail native_host_release_workspace_untrusted
  source_device=""
  source_mount_descriptor_open=false
  source_mount_identity=""
  candidate_retained=false
  cleanup_driver() {
    local status=$?
    if [[ "$source_mount_descriptor_open" == true ]]; then
      exec 9<&-
      source_mount_descriptor_open=false
    fi
    if [[ -n "${source_device:-}" ]]; then
      if /usr/bin/hdiutil detach "$source_device" >/dev/null 2>&1; then
        source_device=""
      else
        status=1
      fi
    fi
    if [[ "$candidate_retained" != true && -n "${candidate_temp:-}" \
        && "$candidate_temp" == "$candidate_records/.candidate."* ]]; then
      run_committed_source_helper remove-tree \
        --path "$candidate_temp" --parent "$candidate_records" \
        --prefix .candidate. --identity "$candidate_temp_identity" \
        >/dev/null || status=1
    fi
    if [[ -z "${source_device:-}" && -n "${release_workspace:-}" \
        && "$release_workspace" == "$workspace_records/.release."* ]]; then
      run_committed_source_helper remove-tree \
        --path "$release_workspace" --parent "$workspace_records" \
        --prefix .release. --identity "$release_workspace_identity" \
        >/dev/null || status=1
    fi
    return "$status"
  }
  trap cleanup_driver EXIT

  source_archive="$release_workspace/source.tar"
  source_root="$release_workspace/source"
  /bin/mkdir -m 0700 "$source_root"
  source_preparation="$(run_committed_source_helper prepare \
    --repo "$repo" --archive "$source_archive" \
    --source-root "$source_root")" \
    || fail native_host_release_source_preparation_failed
  prepared_commit="$(/usr/bin/python3 -I -c \
    'import json,sys; print(json.loads(sys.argv[1])["commit"])' \
    "$source_preparation")"
  source_archive_sha256="$(/usr/bin/python3 -I -c \
    'import json,sys; print(json.loads(sys.argv[1])["archive_sha256"])' \
    "$source_preparation")"
  [[ "$prepared_commit" == "$release_commit" \
      && "$source_archive_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail native_host_release_source_preparation_mismatch
  for required in \
      "$source_root/scripts/build-native-host-products.sh" \
      "$source_root/scripts/build-touchid-authorization-ui.sh" \
      "$source_root/scripts/build-native-credential-components.sh" \
      "$source_root/scripts/host-controller-release.py" \
      "$source_root/scripts/native_host_release_source.py" \
      "$source_root/scripts/native_host_generation_publication.py" \
      "$source_root/macos/ControlCenter/Package.resolved"; do
    [[ -f "$required" && ! -L "$required" ]] \
      || fail native_host_release_archive_incomplete
  done
  archived_signing_config="$source_root/macos/TouchIDAuthorization/Signing.local.xcconfig"
  copy_exact_signing_config \
    "$signing_config" "$archived_signing_config" "$signing_record"
  validate_archived_signing_config \
    "$archived_signing_config" "$signing_config_sha256"
  source_verification="$(run_committed_source_helper verify-source \
    --archive "$source_archive" --source-root "$source_root" \
    --archive-sha256 "$source_archive_sha256" \
    --signing-config-sha256 "$signing_config_sha256")" \
    || fail native_host_release_source_verification_failed
  source_tree_sha256="$(/usr/bin/python3 -I -c \
    'import json,sys; print(json.loads(sys.argv[1])["source_tree_sha256"])' \
    "$source_verification")"
  [[ "$source_tree_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail native_host_release_source_tree_invalid
  require_unchanged_release_source

  source_image="$release_workspace/source.dmg"
  source_mount="$release_workspace/mounted-source"
  source_attach_record="$release_workspace/source-attach.plist"
  /bin/mkdir -m 0700 "$source_mount"
  /usr/bin/hdiutil create -quiet -format UDRO \
    -volname SecureSandboxReleaseSource -srcfolder "$source_root" \
    "$source_image"
  /usr/bin/hdiutil verify "$source_image" >/dev/null
  /usr/bin/hdiutil attach -readonly -nobrowse -noautoopen \
    -mountpoint "$source_mount" -plist "$source_image" \
    >"$source_attach_record"
  source_device="$(/usr/bin/python3 -I -c '
import os,pathlib,plistlib,re,sys
record=plistlib.loads(pathlib.Path(sys.argv[1]).read_bytes())
expected=os.path.realpath(sys.argv[2])
entities=record.get("system-entities") if isinstance(record,dict) else None
mounted=[value for value in entities or []
         if isinstance(value,dict) and "mount-point" in value]
if (len(mounted)!=1 or os.path.realpath(str(mounted[0].get("mount-point","")))!=expected
        or re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)?",str(mounted[0].get("dev-entry",""))) is None):
    raise SystemExit("native_host_release_source_mount_invalid")
print(mounted[0]["dev-entry"])
' "$source_attach_record" "$source_mount")" \
    || fail native_host_release_source_mount_invalid
  exec 9<"$source_mount"
  source_mount_descriptor_open=true
  source_mount_record() {
    /usr/bin/python3 -I -c '
import json,os,stat,sys
path=sys.argv[1]
try:
    opened=os.fstat(9); named=os.lstat(path); filesystem=os.statvfs(path)
except OSError as error:
    raise SystemExit("native_host_release_source_mount_changed") from error
identity=lambda value: (
    value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
    value.st_nlink,value.st_mtime_ns,value.st_ctime_ns,
)
if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(named.st_mode)
        or identity(opened)!=identity(named)
        or not filesystem.f_flag & getattr(os,"ST_RDONLY",1)):
    raise SystemExit("native_host_release_source_mount_changed")
print(json.dumps(identity(opened),separators=(",",":")))
' "$source_mount"
  }
  source_mount_identity="$(source_mount_record)" \
    || fail native_host_release_source_mount_invalid
  require_immutable_source_mount() {
    local current
    current="$(source_mount_record)" || return 1
    [[ "$current" == "$source_mount_identity" ]] || {
      echo native_host_release_source_mount_changed >&2
      return 1
    }
  }
  immutable_source_verification="$(run_committed_source_helper verify-source \
    --archive "$source_archive" --source-root "$source_mount" \
    --archive-sha256 "$source_archive_sha256" \
    --signing-config-sha256 "$signing_config_sha256")" \
    || fail native_host_release_source_mount_invalid
  [[ "$immutable_source_verification" == "$source_verification" ]] \
    || fail native_host_release_source_mount_mismatch
  require_immutable_source_mount \
    || fail native_host_release_source_mount_changed

  host_release_preimage="$release_workspace/SecureSandboxHostReleasePreimage.tar"
  host_release_preimage_record="$(/usr/bin/python3 -I \
    "$source_mount/scripts/host-controller-release.py" \
    prepare-native-host-release-preimage \
    --repo "$repo" --source-archive "$source_archive" \
    --expected-source-archive-sha256 "$source_archive_sha256" \
    --output "$host_release_preimage" --gpgv-binary /opt/homebrew/bin/gpgv \
    --json)" || fail native_host_release_preimage_failed
  host_release_preimage_sha256="$(/usr/bin/python3 -I -c '
import json,re,sys
value=json.loads(sys.argv[1])
digest=value.get("sha256","")
if (value.get("schema")!="secure-sandbox-native-host-release-preimage-v1"
        or value.get("status")!="sealed"
        or re.fullmatch(r"[0-9a-f]{64}",digest) is None):
    raise SystemExit("native_host_release_preimage_record_invalid")
print(digest)
' "$host_release_preimage_record")" \
    || fail native_host_release_preimage_record_invalid
  require_immutable_source_mount \
    || fail native_host_release_source_mount_changed
  require_unchanged_release_source

  publication_helper="$source_mount/scripts/native_host_generation_publication.py"
  publication_state="$private_root/native-host-publication"
  /usr/bin/python3 -I "$publication_helper" reconcile \
    --target "$repo/artifacts/host" --state-root "$publication_state" \
    >/dev/null
  emit_candidate_script_fd() {
    /usr/bin/python3 -I -c '
import hashlib,os,sys
descriptor=int(sys.argv[1]); expected=sys.argv[2]
raw=bytearray(); offset=0
while True:
    block=os.pread(descriptor,65536,offset)
    if not block: break
    raw.extend(block); offset+=len(block)
    if len(raw)>1024*1024:
        raise SystemExit("native_host_candidate_script_oversize")
if hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit("native_host_candidate_script_digest_mismatch")
sys.stdout.buffer.write(raw)
' "$1" "$2"
  }
  exec 8<"$source_mount/scripts/build-native-host-products.sh"
  emit_candidate_script_fd 8 "$candidate_script_sha256" \
    | /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    HOME="$operator_home" USER="$operator_name" LOGNAME="$operator_name" \
    TMPDIR=/tmp LC_ALL=C LANG=C \
    SECURE_SANDBOX_NATIVE_HOST_CANDIDATE_ONLY=1 \
    SECURE_SANDBOX_DEVELOPER_ID="$developer_id_input" \
    SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE="$notary_profile_input" \
    SECURE_SANDBOX_NOTARY_KEYCHAIN="$notary_keychain_input" \
    SECURE_SANDBOX_RELEASE_COMMIT="$release_commit" \
    SECURE_SANDBOX_SOURCE_ARCHIVE_SHA256="$source_archive_sha256" \
    SECURE_SANDBOX_SOURCE_ARCHIVE_PATH="$source_archive" \
    SECURE_SANDBOX_SOURCE_TREE_SHA256="$source_tree_sha256" \
    SECURE_SANDBOX_SIGNING_CONFIG_SHA256="$signing_config_sha256" \
    SECURE_SANDBOX_SIGNING_CONFIG="$source_mount/macos/TouchIDAuthorization/Signing.local.xcconfig" \
    SECURE_SANDBOX_RELEASE_SOURCE_ROOT="$source_mount" \
    SECURE_SANDBOX_HOST_RELEASE_PREIMAGE_PATH="$host_release_preimage" \
    SECURE_SANDBOX_HOST_RELEASE_PREIMAGE_SHA256="$host_release_preimage_sha256" \
    SECURE_SANDBOX_RELEASE_BUILD_PARENT_IDENTITY="$release_workspace_identity" \
    SECURE_SANDBOX_RELEASE_SOURCE_HELPER_SHA256="$source_helper_sha256" \
    SECURE_SANDBOX_RELEASE_TOUCHID_BUILDER_SHA256="$touchid_builder_sha256" \
    SECURE_SANDBOX_RELEASE_COMPONENT_BUILDER_SHA256="$component_builder_sha256" \
    /bin/bash -p -s -- --candidate-only "$candidate_temp" >/dev/null
  exec 8<&-
  require_immutable_source_mount \
    || fail native_host_release_source_mount_changed
  [[ "$(run_committed_source_helper verify-source \
      --archive "$source_archive" --source-root "$source_mount" \
      --archive-sha256 "$source_archive_sha256" \
      --signing-config-sha256 "$signing_config_sha256")" \
      == "$source_verification" ]] \
    || fail native_host_release_source_changed_after_build
  require_unchanged_release_source

  candidate_receipt="$candidate_temp/generation/SecureSandboxNativeHostProducts.notarization.json"
  candidate_receipt_signature="$candidate_temp/generation/SecureSandboxNativeHostProducts.notarization.sig"
  candidate_source_archive="$candidate_temp/generation/SecureSandboxNativeHostProducts.source.tar"
  candidate_preimage="$candidate_temp/evidence/SecureSandboxHostReleasePreimage.tar"
  [[ -f "$candidate_receipt" && ! -L "$candidate_receipt" \
      && -f "$candidate_receipt_signature" \
      && ! -L "$candidate_receipt_signature" \
      && -f "$candidate_source_archive" \
      && ! -L "$candidate_source_archive" \
      && -f "$candidate_preimage" && ! -L "$candidate_preimage" \
      && "$(/usr/bin/shasum -a 256 "$candidate_preimage" \
        | /usr/bin/awk '{print $1}')" == "$host_release_preimage_sha256" \
      && "$(/usr/bin/shasum -a 256 "$candidate_source_archive" \
        | /usr/bin/awk '{print $1}')" == "$source_archive_sha256" ]] \
    || fail native_host_candidate_receipt_evidence_missing
  submission_id="$(/usr/bin/python3 -I -c '
import json,pathlib,re,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
if (
    value.get("schema")!="secure-sandbox-native-host-products-notarization-v3"
    or value.get("build_custody")!="trusted-login-principal-v1"
    or value.get("release_commit")!=sys.argv[2]
    or value.get("source_archive_sha256")!=sys.argv[3]
    or value.get("signing_config_sha256")!=sys.argv[4]
    or value.get("source_tree_sha256")!=sys.argv[5]
    or value.get("developer_id_certificate_sha1")!=sys.argv[6]
    or value.get("host_release_preimage_sha256")!=sys.argv[7]
    or value.get("team_id")!="389K3H8Y32"
    or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",str(value.get("notary_submission_id",""))) is None
):
    raise SystemExit("native_host_candidate_receipt_provenance_mismatch")
print(value["notary_submission_id"])
' "$candidate_receipt" "$release_commit" "$source_archive_sha256" \
    "$signing_config_sha256" "$source_tree_sha256" \
    "$developer_id_input" "$host_release_preimage_sha256")"
  receipt_identifier=org.zebeth.SecureSandbox.NativeHostProductsReceipt
  receipt_requirement="identifier \"$receipt_identifier\" and anchor apple generic and certificate leaf = H\"$developer_id_input\" and certificate leaf[subject.OU] = \"$fixed_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --strict --verbose=2 \
    --detached "$candidate_receipt_signature" \
    -R="$receipt_requirement" "$candidate_receipt"
  /usr/bin/python3 -I -c '
import ctypes,errno,os,stat,sys
root_path=sys.argv[1]
expected_uid=os.geteuid()
libc=ctypes.CDLL(None,use_errno=True)
acl_get_fd_np=getattr(libc,"acl_get_fd_np",None)
acl_get_entry=getattr(libc,"acl_get_entry",None)
acl_free=getattr(libc,"acl_free",None)
if acl_get_fd_np is None or acl_get_entry is None or acl_free is None:
    raise SystemExit("native_host_candidate_durability_acl_api_unavailable")
acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int]
acl_get_fd_np.restype=ctypes.c_void_p
acl_get_entry.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.POINTER(ctypes.c_void_p)]
acl_get_entry.restype=ctypes.c_int
acl_free.argtypes=[ctypes.c_void_p]
acl_free.restype=ctypes.c_int
def reject_acl(descriptor):
    ctypes.set_errno(0)
    acl=acl_get_fd_np(descriptor,0x00000100)
    if not acl:
        if ctypes.get_errno()==errno.ENOENT:
            return
        raise SystemExit("native_host_candidate_durability_acl_untrusted")
    try:
        entry=ctypes.c_void_p()
        ctypes.set_errno(0)
        result=acl_get_entry(acl,0,ctypes.byref(entry))
        if result==0 or ctypes.get_errno() not in {errno.ENOENT,errno.EINVAL}:
            raise SystemExit("native_host_candidate_durability_acl_untrusted")
    finally:
        if acl_free(acl)!=0:
            raise SystemExit("native_host_candidate_durability_acl_release_failed")
identity=lambda value:(
    value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
    value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns,
)
before=os.lstat(root_path)
root_fd=os.open(
    root_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
)
def sync_tree(directory,prefix=()):
    reject_acl(directory)
    directory_before=os.fstat(directory)
    names=sorted(os.listdir(directory))
    if len(names)>4096:
        raise SystemExit("native_host_candidate_durability_inventory_invalid")
    for name in names:
        if not name or name in {".",".."} or "/" in name or "\0" in name:
            raise SystemExit("native_host_candidate_durability_inventory_invalid")
        named=os.stat(name,dir_fd=directory,follow_symlinks=False)
        if (stat.S_ISLNK(named.st_mode) or named.st_uid!=expected_uid
                or named.st_mode&(stat.S_IWGRP|stat.S_IWOTH)):
            raise SystemExit("native_host_candidate_durability_entry_untrusted")
        if stat.S_ISDIR(named.st_mode):
            child=os.open(
                name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                dir_fd=directory,
            )
            try:
                opened=os.fstat(child)
                reject_acl(child)
                if identity(opened)!=identity(named):
                    raise SystemExit("native_host_candidate_durability_entry_changed")
                sync_tree(child,(*prefix,name))
                os.fsync(child)
                after=os.fstat(child)
                current=os.stat(name,dir_fd=directory,follow_symlinks=False)
                if identity(opened)!=identity(after) or identity(after)!=identity(current):
                    raise SystemExit("native_host_candidate_durability_entry_changed")
            finally:
                os.close(child)
        elif stat.S_ISREG(named.st_mode) and named.st_nlink==1:
            child=os.open(
                name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,
                dir_fd=directory,
            )
            try:
                opened=os.fstat(child)
                reject_acl(child)
                if identity(opened)!=identity(named):
                    raise SystemExit("native_host_candidate_durability_entry_changed")
                os.fsync(child)
                after=os.fstat(child)
                current=os.stat(name,dir_fd=directory,follow_symlinks=False)
                if identity(opened)!=identity(after) or identity(after)!=identity(current):
                    raise SystemExit("native_host_candidate_durability_entry_changed")
            finally:
                os.close(child)
        else:
            raise SystemExit("native_host_candidate_durability_entry_untrusted")
    os.fsync(directory)
    if names!=sorted(os.listdir(directory)) or identity(directory_before)!=identity(os.fstat(directory)):
        raise SystemExit("native_host_candidate_durability_inventory_changed")
try:
    opened=os.fstat(root_fd)
    reject_acl(root_fd)
    if (identity(before)!=identity(opened) or not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode)!=0o700
            or sorted(os.listdir(root_fd))!=["evidence","generation"]):
        raise SystemExit("native_host_candidate_durability_root_untrusted")
    evidence=os.open(
        "evidence",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
        dir_fd=root_fd,
    )
    try:
        reject_acl(evidence)
        if sorted(os.listdir(evidence))!=[
            "SecureSandboxHostReleasePreimage.tar",
            "notary-log.json","notary-result.json",
        ]:
            raise SystemExit("native_host_candidate_durability_evidence_invalid")
        for name,mode in (
            ("SecureSandboxHostReleasePreimage.tar",0o400),
            ("notary-log.json",0o600),("notary-result.json",0o600),
        ):
            info=os.stat(name,dir_fd=evidence,follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)!=mode
                    or info.st_dev!=opened.st_dev
                    or info.st_uid!=expected_uid):
                raise SystemExit("native_host_candidate_durability_evidence_invalid")
    finally:
        os.close(evidence)
    sync_tree(root_fd)
    os.fsync(root_fd)
    after=os.fstat(root_fd)
    named=os.lstat(root_path)
    if identity(opened)!=identity(after) or identity(after)!=identity(named):
        raise SystemExit("native_host_candidate_durability_root_changed")
finally:
    os.close(root_fd)
' "$candidate_temp"
  candidate_final="$candidate_records/$release_commit-$submission_id"
  [[ ! -e "$candidate_final" && ! -L "$candidate_final" ]] \
    || fail native_host_candidate_evidence_collision
  /bin/mv "$candidate_temp" "$candidate_final"
  candidate_retained=true
  /usr/bin/python3 -I -c '
import os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.fsync(fd)
finally: os.close(fd)
' "$candidate_records"
  require_unchanged_release_source
  require_immutable_source_mount \
    || fail native_host_release_source_mount_changed

  /usr/bin/python3 -I "$publication_helper" publish \
    --candidate "$candidate_final/generation" \
    --target "$repo/artifacts/host" \
    --state-root "$publication_state" >/dev/null
  require_immutable_source_mount \
    || fail native_host_release_source_mount_changed
  require_unchanged_release_source
  /usr/bin/python3 -I -c '
import json,sys
print(json.dumps({
 "build_custody":"trusted-login-principal-v1",
 "candidate_evidence":sys.argv[1],"release_commit":sys.argv[2],
 "developer_id_certificate_sha1":sys.argv[6],
 "host_release_preimage_sha256":sys.argv[8],
 "schema":"secure-sandbox-native-host-products-build-v3",
 "signing_config_sha256":sys.argv[4],
 "source_archive_sha256":sys.argv[3],"source_tree_sha256":sys.argv[5],
 "status":"verified",
 "target":sys.argv[7],
},sort_keys=True,separators=(",",":")))
' "$candidate_final" "$release_commit" "$source_archive_sha256" \
    "$signing_config_sha256" "$source_tree_sha256" \
    "$developer_id_input" "$repo/artifacts/host" \
    "$host_release_preimage_sha256"
}

if [[ "$requested_mode" == --candidate-only ]]; then
  run_candidate_only
else
  run_driver
fi
