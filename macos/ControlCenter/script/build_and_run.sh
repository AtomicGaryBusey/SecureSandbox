#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="SecureSandboxControlCenter"
BUNDLE_ID="org.zebeth.SecureSandbox.ControlCenter"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_BUNDLE="$ROOT_DIR/dist/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true
swift build --package-path "$ROOT_DIR"
BUILD_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/$APP_NAME"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
cp "$BUILD_BINARY" "$APP_BINARY"
chmod +x "$APP_BINARY"
mkdir -p "$APP_BUNDLE/Contents/Resources/Licenses"
cp "$ROOT_DIR/.build/checkouts/SwiftTerm/LICENSE" \
  "$APP_BUNDLE/Contents/Resources/Licenses/SwiftTerm.txt"
icon_path="$($ROOT_DIR/script/build_icon.sh)"
cp "$icon_path" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
cat >"$APP_BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleName</key><string>SecureSandbox</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>27.0</string>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSRemovableVolumesUsageDescription</key><string>SecureSandbox verifies operator-selected backup destinations and exports selected evidence.</string>
</dict></plist>
PLIST
if [[ -n "${SECURE_SANDBOX_DEVELOPER_ID:-}" ]]; then
  [[ "$SECURE_SANDBOX_DEVELOPER_ID" == "Developer ID Application:"* ]] || {
    echo "SECURE_SANDBOX_DEVELOPER_ID must name a Developer ID Application certificate." >&2
    exit 2
  }
  codesign --force --options runtime --timestamp --sign "$SECURE_SANDBOX_DEVELOPER_ID" "$APP_BUNDLE" >/dev/null
else
  codesign --force --sign - "$APP_BUNDLE" >/dev/null
fi
"$ROOT_DIR/script/validate_bundle.sh" "$APP_BUNDLE" >/dev/null

open_app() { /usr/bin/open -n "$APP_BUNDLE"; }
case "$MODE" in
  run) open_app ;;
  --debug|debug) lldb -- "$APP_BINARY" ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    sleep 2
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
