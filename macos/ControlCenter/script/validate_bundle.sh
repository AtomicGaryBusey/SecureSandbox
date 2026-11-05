#!/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset BASH_ENV CDPATH ENV

root_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
bundle="${1:-$root_dir/dist/SecureSandboxControlCenter.app}"
mode="${2:---local}"
authorized_team="389K3H8Y32"
[[ "$mode" == --local || "$mode" == --pre-notarization \
    || "$mode" == --distribution ]] || {
  echo "Usage: $0 [APP_BUNDLE] [--local|--pre-notarization|--distribution]" >&2
  exit 2
}
[[ -d "$bundle/Contents/MacOS" && -d "$bundle/Contents/Resources" ]] || {
  echo "Control Center app bundle is incomplete." >&2
  exit 1
}
/usr/bin/plutil -lint "$bundle/Contents/Info.plist" >/dev/null
identifier="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$bundle/Contents/Info.plist")"
executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$bundle/Contents/Info.plist")"
minimum="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$bundle/Contents/Info.plist")"
icon_name="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconName' "$bundle/Contents/Info.plist")"
update_sequence="$(/usr/libexec/PlistBuddy -c 'Print :SSUpdateSequence' "$bundle/Contents/Info.plist")"
[[ "$identifier" == org.zebeth.SecureSandbox.ControlCenter \
    && "$executable" == SecureSandboxControlCenter && "$minimum" == 27.0 \
    && "$icon_name" == AppIcon && "$update_sequence" =~ ^[1-9][0-9]*$ \
    && -x "$bundle/Contents/MacOS/$executable" \
    && -x "$bundle/Contents/Helpers/SecureSandboxUpdateInstaller" \
    && -s "$bundle/Contents/Resources/UpdatePolicy.json" \
    && -s "$bundle/Contents/Resources/AppIcon.icns" \
    && -s "$bundle/Contents/Resources/Assets.car" \
    && -s "$bundle/Contents/Resources/Licenses/SwiftTerm.txt" ]] || {
  echo "Control Center bundle identity or required resources are invalid." >&2
  exit 1
}
/usr/bin/codesign --verify --deep --strict "$bundle"
helper="$bundle/Contents/Helpers/SecureSandboxUpdateInstaller"
/usr/bin/codesign --verify --strict "$helper"
app_details="$(/usr/bin/codesign -dv --verbose=4 "$bundle" 2>&1)"
helper_details="$(/usr/bin/codesign -dv --verbose=4 "$helper" 2>&1)"
if [[ "$mode" != --local ]]; then
  app_requirement="identifier \"org.zebeth.SecureSandbox.ControlCenter\" and anchor apple generic and certificate leaf[subject.OU] = \"$authorized_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  helper_requirement="identifier \"SecureSandboxUpdateInstaller\" and anchor apple generic and certificate leaf[subject.OU] = \"$authorized_team\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
  /usr/bin/codesign --verify --strict --verbose=2 \
    -R="$app_requirement" "$bundle"
  /usr/bin/codesign --verify --strict --verbose=2 \
    -R="$helper_requirement" "$helper"
  app_identifier="$(/usr/bin/printf '%s\n' "$app_details" \
    | /usr/bin/sed -n 's/^Identifier=//p')"
  helper_identifier="$(/usr/bin/printf '%s\n' "$helper_details" \
    | /usr/bin/sed -n 's/^Identifier=//p')"
  app_team="$(/usr/bin/printf '%s\n' "$app_details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  helper_team="$(/usr/bin/printf '%s\n' "$helper_details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  app_timestamp="$(/usr/bin/printf '%s\n' "$app_details" \
    | /usr/bin/sed -n 's/^Timestamp=//p')"
  helper_timestamp="$(/usr/bin/printf '%s\n' "$helper_details" \
    | /usr/bin/sed -n 's/^Timestamp=//p')"
  [[ "$app_identifier" == org.zebeth.SecureSandbox.ControlCenter \
      && "$app_details" == *"Authority=Developer ID Application:"* \
      && "$app_details" == *"flags=0x10000(runtime)"* \
      && "$app_details" != *"Signature=adhoc"* \
      && "$helper_identifier" == SecureSandboxUpdateInstaller \
      && "$helper_details" == *"Authority=Developer ID Application:"* \
      && "$helper_details" == *"flags=0x10000(runtime)"* \
      && "$helper_details" != *"Signature=adhoc"* \
      && "$app_team" == "$authorized_team" \
      && "$helper_team" == "$authorized_team" \
      && -n "$app_timestamp" && "$app_timestamp" != none \
      && "$app_timestamp" != *$'\n'* \
      && -n "$helper_timestamp" && "$helper_timestamp" != none \
      && "$helper_timestamp" != *$'\n'* ]] || {
    echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"rejected","reason":"developer_id_hardened_runtime_required"}'
    exit 1
  }
fi
if [[ "$mode" == --distribution ]]; then
  /usr/bin/xcrun stapler validate "$bundle" >/dev/null 2>&1 || {
    echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"rejected","reason":"stapled_ticket_invalid"}'
    exit 1
  }
  /usr/sbin/spctl -a -vv "$bundle" >/dev/null 2>&1 || {
    echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"rejected","reason":"gatekeeper_rejected"}'
    exit 1
  }
  echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"verified","scope":"distribution"}'
elif [[ "$mode" == --pre-notarization ]]; then
  echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"verified","scope":"pre-notarization"}'
else
  echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"verified","scope":"local"}'
fi
