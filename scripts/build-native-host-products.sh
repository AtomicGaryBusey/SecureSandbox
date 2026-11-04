#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
artifact_root="$repo/artifacts/host"
identity="${SECURE_SANDBOX_DEVELOPER_ID:-}"
notary_profile="${SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE:-}"
container="$artifact_root/SecureSandboxNativeHostProducts.dmg"
container_manifest="$artifact_root/SecureSandboxNativeHostProducts.manifest.json"
container_receipt="$artifact_root/SecureSandboxNativeHostProducts.notarization.json"
container_identifier="org.zebeth.SecureSandbox.NativeHostProducts"

[[ "$identity" == "Developer ID Application:"* \
    || "$identity" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo SECURE_SANDBOX_DEVELOPER_ID_must_name_or_SHA1_pin_a_Developer_ID_Application_identity >&2
  exit 2
}
[[ "$notary_profile" =~ ^[A-Za-z0-9][A-Za-z0-9._[:space:]-]{0,127}$ ]] || {
  echo SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE_is_required >&2
  exit 2
}

"$repo/scripts/build-touchid-authorization-ui.sh" >/dev/null
"$repo/scripts/build-native-credential-components.sh" >/dev/null

build_root="$(mktemp -d /tmp/secure-sandbox-native-host-products.XXXXXX)"
stage="$build_root/SecureSandboxHostProducts"
unsigned="$build_root/SecureSandboxNativeHostProducts.dmg"
notary_result="$build_root/notary-result.json"
notary_log="$build_root/notary-log.json"
cleanup() { /bin/rm -rf -- "$build_root"; }
trap cleanup EXIT
/bin/mkdir -p "$stage"

/usr/bin/ditto --noqtn \
  "$artifact_root/SecureSandboxAuthorizationUI.app" \
  "$stage/SecureSandboxAuthorizationUI.app"
/usr/bin/ditto --noqtn \
  "$artifact_root/SecureSandboxNativeCredentialHelper.app" \
  "$stage/SecureSandboxNativeCredentialHelper.app"
/bin/cp \
  "$artifact_root/SecureSandboxAuthorizationUI.bundle.json" \
  "$stage/SecureSandboxAuthorizationUI.bundle.json"
/bin/cp \
  "$artifact_root/SecureSandboxNativeComponents.bundle.json" \
  "$stage/SecureSandboxNativeComponents.bundle.json"
/bin/cp \
  "$artifact_root/SecureSandboxNativeStackBackend" \
  "$stage/SecureSandboxNativeStackBackend"
/bin/cp \
  "$artifact_root/SecureSandboxNativeProjectionConsumer" \
  "$stage/SecureSandboxNativeProjectionConsumer"

/usr/bin/python3 -c '
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); output=root/"SecureSandboxNativeHostProducts.manifest.json"
entries={}
for path in sorted(root.rglob("*")):
    relative=path.relative_to(root).as_posix(); info=path.lstat()
    if path.is_symlink() or (not path.is_dir() and not path.is_file()):
        raise SystemExit("native_host_container_entry_invalid:"+relative)
    if path.is_file():
        data=path.read_bytes()
        entries[relative]={"mode":stat.S_IMODE(info.st_mode),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
value={"entries":entries,"schema":"secure-sandbox-native-host-products-manifest-v1"}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="ascii")
' "$stage"
/bin/chmod 0444 "$stage/SecureSandboxNativeHostProducts.manifest.json"

/usr/bin/hdiutil create -quiet -ov -format UDZO \
  -volname SecureSandboxHostProducts -srcfolder "$stage" "$unsigned"
/usr/bin/codesign --force --timestamp --identifier "$container_identifier" \
  --sign "$identity" "$unsigned"
/usr/bin/codesign --verify --strict --verbose=2 "$unsigned"
team="$(/usr/bin/codesign -dv --verbose=4 "$unsigned" 2>&1 \
  | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
[[ "$team" =~ ^[A-Z0-9]{10}$ ]] || {
  echo native_host_container_team_invalid >&2
  exit 1
}
requirement="identifier \"$container_identifier\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
/usr/bin/codesign --verify --strict --verbose=2 -R="$requirement" "$unsigned"

/usr/bin/xcrun notarytool submit "$unsigned" \
  --keychain-profile "$notary_profile" --wait --output-format json \
  >"$notary_result"
/usr/bin/python3 -c '
import json,re,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
if value.get("status") != "Accepted" or re.fullmatch(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    value.get("id", ""),
) is None:
    raise SystemExit("native_host_container_notarization_not_accepted")
' "$notary_result"
submission_id="$(/usr/bin/python3 -c '
import json,pathlib,sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["id"])
' "$notary_result")"
/usr/bin/xcrun notarytool log "$submission_id" \
  --keychain-profile "$notary_profile" "$notary_log"
/usr/bin/python3 -c '
import json,pathlib,sys
value=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("status") != "Accepted" or value.get("issues") != []:
    raise SystemExit("native_host_container_notary_log_not_clean")
' "$notary_log"
/usr/bin/xcrun stapler staple "$unsigned"
/usr/bin/xcrun stapler validate "$unsigned"
/usr/sbin/spctl --assess --type open \
  --context context:primary-signature --verbose=4 "$unsigned"
/usr/bin/hdiutil verify "$unsigned" >/dev/null
/usr/bin/codesign --verify --strict --verbose=2 -R="$requirement" "$unsigned"

/bin/mkdir -p "$artifact_root"
for target in "$container" "$container_manifest" "$container_receipt"; do
  if [[ -e "$target" || -L "$target" ]]; then
    /bin/chmod u+w "$target" 2>/dev/null || true
    /bin/rm -f -- "$target"
  fi
done
/bin/cp "$unsigned" "$container"
/bin/cp \
  "$stage/SecureSandboxNativeHostProducts.manifest.json" \
  "$container_manifest"
/usr/bin/python3 -c '
import hashlib,json,pathlib,sys
result=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
notary_log=pathlib.Path(sys.argv[2]).read_bytes()
container=pathlib.Path(sys.argv[3]); output=pathlib.Path(sys.argv[4]); team=sys.argv[5]
data=container.read_bytes()
value={
    "container_sha256":hashlib.sha256(data).hexdigest(),
    "container_size":len(data),
    "gatekeeper_assessed":True,
    "notary_submission_id":result["id"].lower(),
    "notary_log_sha256":hashlib.sha256(notary_log).hexdigest(),
    "notary_status":"accepted",
    "schema":"secure-sandbox-native-host-products-notarization-v1",
    "stapler_validated":True,
    "team_id":team,
}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="ascii")
' "$notary_result" "$notary_log" "$container" "$container_receipt" "$team"
/bin/chmod 0444 "$container" "$container_manifest" "$container_receipt"
/usr/bin/codesign --verify --strict --verbose=2 -R="$requirement" "$container"
/usr/bin/xcrun stapler validate "$container"
/usr/sbin/spctl --assess --type open \
  --context context:primary-signature --verbose=4 "$container"
/usr/bin/hdiutil verify "$container" >/dev/null
printf '%s\n' "$container"
