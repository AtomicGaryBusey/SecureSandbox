#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
package="$repo/macos/ControlCenter"
artifact_root="$repo/artifacts/host"
helper_name="SecureSandboxNativeCredentialHelper.app"
backend_name="SecureSandboxNativeStackBackend"
consumer_name="SecureSandboxNativeProjectionConsumer"
manifest_name="SecureSandboxNativeComponents.bundle.json"
helper_identifier="org.zebeth.SecureSandbox.NativeCredentialHelper"
backend_identifier="org.zebeth.SecureSandbox.NativeStackBackend"
consumer_identifier="org.zebeth.SecureSandbox.NativeProjectionConsumer"
identity="${SECURE_SANDBOX_DEVELOPER_ID:-}"

[[ -n "$identity" ]] || {
  echo SECURE_SANDBOX_DEVELOPER_ID_is_required >&2
  exit 2
}
[[ "$identity" == "Developer ID Application:"* \
    || "$identity" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo SECURE_SANDBOX_DEVELOPER_ID_must_be_a_Developer_ID_name_or_SHA1 >&2
  exit 2
}

build_root="$(mktemp -d /tmp/secure-sandbox-native-components.XXXXXX)"
stage="$build_root/stage"
helper="$stage/$helper_name"
backend="$stage/$backend_name"
consumer="$stage/$consumer_name"
manifest="$stage/$manifest_name"
cleanup() { /bin/rm -rf -- "$build_root"; }
trap cleanup EXIT
/bin/mkdir -p "$stage" "$helper/Contents/MacOS"

/usr/bin/swift build -c release --package-path "$package" \
  --product SecureSandboxNativeCredentialXPCService
/usr/bin/swift build -c release --package-path "$package" \
  --product SecureSandboxNativeStackBackend
/usr/bin/swift build -c release --package-path "$package" \
  --product SecureSandboxNativeProjectionConsumer
bin_path="$(/usr/bin/swift build -c release --package-path "$package" --show-bin-path)"

/bin/cp \
  "$bin_path/SecureSandboxNativeCredentialXPCService" \
  "$helper/Contents/MacOS/SecureSandboxNativeCredentialXPCService"
/bin/cp \
  "$package/Sources/SecureSandboxNativeCredentialHelper/SecureSandboxNativeCredentialHelper-Info.plist" \
  "$helper/Contents/Info.plist"
/bin/cp "$bin_path/$backend_name" "$backend"
/bin/cp "$bin_path/$consumer_name" "$consumer"
/bin/chmod 0555 \
  "$helper/Contents/MacOS/SecureSandboxNativeCredentialXPCService" \
  "$backend" "$consumer"
/bin/chmod 0444 "$helper/Contents/Info.plist"

entitlements="$package/Sources/SecureSandboxNativeCredentialHelper/SecureSandboxNativeCredentialHelper.entitlements"
/usr/bin/codesign --force --options runtime --timestamp \
  --entitlements "$entitlements" --sign "$identity" "$helper"
/usr/bin/codesign --force --options runtime --timestamp \
  --identifier "$backend_identifier" --sign "$identity" "$backend"
/usr/bin/codesign --force --options runtime --timestamp \
  --identifier "$consumer_identifier" --sign "$identity" "$consumer"

for item in "$helper" "$backend" "$consumer"; do
  /usr/bin/codesign --verify --strict --verbose=2 "$item"
done
team="$(/usr/bin/codesign -dv --verbose=4 "$helper" 2>&1 \
  | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
[[ "$team" =~ ^[A-Z0-9]{10}$ ]] || {
  echo native_component_team_identifier_invalid >&2
  exit 1
}
for specification in \
  "$helper:$helper_identifier" \
  "$backend:$backend_identifier" \
  "$consumer:$consumer_identifier"; do
  item="${specification%%:*}"
  identifier="${specification#*:}"
  requirement="identifier \"$identifier\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --strict --verbose=2 -R="$requirement" "$item"
  details="$(/usr/bin/codesign -dv --verbose=4 "$item" 2>&1)"
  [[ "$details" == *"flags=0x10000(runtime)"* \
      && "$details" == *"TeamIdentifier=$team"* \
      && "$details" != *"Signature=adhoc"* ]] || {
    echo native_component_signing_policy_invalid >&2
    exit 1
  }
done

/usr/bin/find "$helper" -type d -exec /bin/chmod 0555 {} +
/usr/bin/find "$helper" -type f -exec /bin/chmod 0444 {} +
/bin/chmod 0555 "$helper/Contents/MacOS/SecureSandboxNativeCredentialXPCService"
/bin/chmod 0555 "$backend" "$consumer"
/usr/bin/python3 -c '
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

/bin/mkdir -p "$artifact_root"
for target in \
  "$artifact_root/$helper_name" \
  "$artifact_root/$backend_name" \
  "$artifact_root/$consumer_name" \
  "$artifact_root/$manifest_name"; do
  if [[ -e "$target" || -L "$target" ]]; then
    /bin/chmod -R u+w "$target" 2>/dev/null || true
    /bin/rm -rf -- "$target"
  fi
done
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
for item in \
  "$artifact_root/$helper_name" \
  "$artifact_root/$backend_name" \
  "$artifact_root/$consumer_name"; do
  /usr/bin/codesign --verify --strict --verbose=2 "$item"
done
printf "%s\n" "$artifact_root/$manifest_name"
