#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
package="$repo/macos/TouchIDAuthorization"
output="$repo/artifacts/host/SecureSandboxAuthorizationUI.app"
bundle_manifest="$repo/artifacts/host/SecureSandboxAuthorizationUI.bundle.json"
source_manifest="$repo/artifacts/host/SecureSandboxAuthorizationUI.sources.json"
signing_config="${SECURE_SANDBOX_SIGNING_CONFIG:-$package/Signing.local.xcconfig}"
derived="$(mktemp -d /tmp/secure-sandbox-touchid-build.XXXXXX)"
trap '/bin/rm -rf -- "$derived"' EXIT

[[ -f "$signing_config" && ! -L "$signing_config" ]] \
  || { echo touchid_signing_config_missing >&2; exit 1; }

/usr/bin/xcodebuild -quiet \
  -project "$package/SecureSandboxAuthorizationUI.xcodeproj" \
  -scheme SecureSandboxAuthorizationUI \
  -configuration Release \
  -xcconfig "$signing_config" \
  -derivedDataPath "$derived" \
  -allowProvisioningUpdates \
  build
built="$derived/Build/Products/Release/SecureSandboxAuthorizationUI.app"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$built"
[[ -f "$built/Contents/embedded.provisionprofile" ]] \
  || { echo touchid_macos_provisioning_profile_missing >&2; exit 1; }
/usr/bin/python3 -c '
import datetime,plistlib,subprocess,sys
profile=sys.argv[1]
value=plistlib.loads(subprocess.run(
    ["/usr/bin/security","cms","-D","-i",profile],
    check=True,capture_output=True,
).stdout)
expiration=value.get("ExpirationDate")
if not isinstance(expiration,datetime.datetime):
    raise SystemExit("touchid_provisioning_profile_expiration_invalid")
if expiration.tzinfo is None:
    expiration=expiration.replace(tzinfo=datetime.timezone.utc)
minimum=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=52)
if expiration <= minimum:
    raise SystemExit("touchid_provisioning_profile_headroom_insufficient")
' "$built/Contents/embedded.provisionprofile"

/bin/mkdir -p "$(dirname "$output")"
if [[ -e "$output" || -L "$output" ]]; then
  /bin/chmod -R u+w "$output" 2>/dev/null || true
  /bin/rm -rf -- "$output"
fi
/usr/bin/ditto "$built" "$output"
/usr/bin/find "$output" -type d -exec /bin/chmod 0555 {} +
/usr/bin/find "$output" -type f -exec /bin/chmod 0444 {} +
/bin/chmod 0555 "$output/Contents/MacOS/SecureSandboxAuthorizationUI"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$output"
if [[ -e "$bundle_manifest" ]]; then
  /bin/chmod u+w "$bundle_manifest"
fi
/usr/bin/python3 -c '
import hashlib,json,os,pathlib,plistlib,re,stat,subprocess,sys
root=pathlib.Path(sys.argv[1]); output=pathlib.Path(sys.argv[2])
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
if (not isinstance(team,str) or re.fullmatch(r"[A-Z0-9]{10}",team) is None
        or not isinstance(bundle_id,str) or not bundle_id
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
' "$output" "$bundle_manifest"
/bin/chmod 0444 "$bundle_manifest"
if [[ -e "$source_manifest" ]]; then
  /bin/chmod u+w "$source_manifest"
fi
/usr/bin/python3 -c '
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); output=pathlib.Path(sys.argv[2])
names=["Package.swift","AuthorizationUI.entitlements","Info.plist","SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj","Sources/AuthorizationCore/AuthorizationRequest.swift","Sources/AuthorizationCore/ExecutionApprovalCrypto.swift","Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift","Sources/SecureSandboxAuthorizationUI/main.swift"]
value={"schema":"secure-sandbox-touchid-ui-source-v1","sources":{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}}
output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
' "$package" "$source_manifest"
/bin/chmod 0444 "$source_manifest"
echo "$output"
