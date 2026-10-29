#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle="${1:-$root_dir/dist/SecureSandboxControlCenter.app}"
mode="${2:---local}"
[[ "$mode" == --local || "$mode" == --distribution ]] || {
  echo "Usage: $0 [APP_BUNDLE] [--local|--distribution]" >&2
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
[[ "$identifier" == org.zebeth.SecureSandbox.ControlCenter \
    && "$executable" == SecureSandboxControlCenter && "$minimum" == 27.0 \
    && "$icon_name" == AppIcon \
    && -x "$bundle/Contents/MacOS/$executable" \
    && -s "$bundle/Contents/Resources/AppIcon.icns" \
    && -s "$bundle/Contents/Resources/Assets.car" \
    && -s "$bundle/Contents/Resources/Licenses/SwiftTerm.txt" ]] || {
  echo "Control Center bundle identity or required resources are invalid." >&2
  exit 1
}
/usr/bin/codesign --verify --deep --strict "$bundle"
details="$(/usr/bin/codesign -dv --verbose=4 "$bundle" 2>&1)"
if [[ "$mode" == --distribution ]]; then
  [[ "$details" == *"Authority=Developer ID Application:"* \
      && "$details" == *"flags=0x10000(runtime)"* \
      && "$details" != *"Signature=adhoc"* ]] || {
    echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"rejected","reason":"developer_id_hardened_runtime_required"}'
    exit 1
  }
  /usr/sbin/spctl -a -vv "$bundle" >/dev/null 2>&1 || {
    echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"rejected","reason":"gatekeeper_rejected"}'
    exit 1
  }
  echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"verified","scope":"distribution"}'
else
  echo '{"schema":"secure-sandbox-control-center-bundle-v1","status":"verified","scope":"local"}'
fi
