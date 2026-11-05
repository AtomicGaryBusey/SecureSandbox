#!/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset BASH_ENV CDPATH ENV

MODE="${1:-run}"
APP_NAME="SecureSandboxControlCenter"
BUNDLE_ID="org.zebeth.SecureSandbox.ControlCenter"
BUILD_CONFIGURATION="${SECURE_SANDBOX_BUILD_CONFIGURATION:-debug}"
APP_VERSION="${SECURE_SANDBOX_APP_VERSION:-0.1.0}"
APP_BUILD="${SECURE_SANDBOX_APP_BUILD:-1}"
UPDATE_SEQUENCE="${SECURE_SANDBOX_UPDATE_SEQUENCE:-1}"
ROOT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
APP_BUNDLE="$ROOT_DIR/dist/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
UPDATE_HELPER_NAME="SecureSandboxUpdateInstaller"
SWIFT_SCRATCH_PATH="${SECURE_SANDBOX_SWIFT_SCRATCH_PATH:-}"
SWIFT_HERMETIC="${SECURE_SANDBOX_SWIFT_HERMETIC:-0}"

[[ "$BUILD_CONFIGURATION" == debug || "$BUILD_CONFIGURATION" == release ]] || {
  echo "SECURE_SANDBOX_BUILD_CONFIGURATION must be debug or release." >&2
  exit 2
}
[[ "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ \
    && "$APP_BUILD" =~ ^[1-9][0-9]*$ && "$UPDATE_SEQUENCE" =~ ^[1-9][0-9]*$ ]] || {
  echo "Version, build, or update sequence is invalid." >&2
  exit 2
}
[[ "$SWIFT_HERMETIC" == 0 || "$SWIFT_HERMETIC" == 1 ]] || {
  echo "SECURE_SANDBOX_SWIFT_HERMETIC must be 0 or 1." >&2
  exit 2
}
swift_options=(--package-path "$ROOT_DIR")
if [[ -n "$SWIFT_SCRATCH_PATH" ]]; then
  [[ "$SWIFT_SCRATCH_PATH" == /* ]] || {
    echo "SECURE_SANDBOX_SWIFT_SCRATCH_PATH must be absolute." >&2
    exit 2
  }
  swift_options+=(--scratch-path "$SWIFT_SCRATCH_PATH")
fi
if [[ "$SWIFT_HERMETIC" == 1 ]]; then
  [[ -n "$SWIFT_SCRATCH_PATH" \
      && -f "$ROOT_DIR/Package.resolved" && ! -L "$ROOT_DIR/Package.resolved" ]] || {
    echo "Hermetic Swift builds require a fresh scratch path and Package.resolved." >&2
    exit 2
  }
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL=/dev/null
  unset GIT_CONFIG_COUNT
  swift_options+=(
    --cache-path "$SWIFT_SCRATCH_PATH/cache"
    --config-path "$SWIFT_SCRATCH_PATH/config"
    --security-path "$SWIFT_SCRATCH_PATH/security"
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
fi
swift_build_root="${SWIFT_SCRATCH_PATH:-$ROOT_DIR/.build}"

if [[ "$MODE" != --build-only && "$MODE" != build-only ]]; then
  /usr/bin/pkill -x "$APP_NAME" >/dev/null 2>&1 || true
fi
/usr/bin/swift build -c "$BUILD_CONFIGURATION" "${swift_options[@]}"
bin_path="$(/usr/bin/swift build -c "$BUILD_CONFIGURATION" \
  "${swift_options[@]}" --show-bin-path)"
BUILD_BINARY="$bin_path/$APP_NAME"
UPDATE_HELPER_BINARY="$bin_path/$UPDATE_HELPER_NAME"
/bin/rm -rf "$APP_BUNDLE"
/bin/mkdir -p "$APP_BUNDLE/Contents/MacOS"
/bin/cp "$BUILD_BINARY" "$APP_BINARY"
/bin/chmod +x "$APP_BINARY"
/bin/mkdir -p "$APP_BUNDLE/Contents/Helpers"
/bin/cp "$UPDATE_HELPER_BINARY" "$APP_BUNDLE/Contents/Helpers/$UPDATE_HELPER_NAME"
/bin/chmod +x "$APP_BUNDLE/Contents/Helpers/$UPDATE_HELPER_NAME"
/bin/mkdir -p "$APP_BUNDLE/Contents/Resources/Licenses"
/bin/cp "$swift_build_root/checkouts/SwiftTerm/LICENSE" \
  "$APP_BUNDLE/Contents/Resources/Licenses/SwiftTerm.txt"
/bin/cp "$ROOT_DIR/Resources/Update/UpdatePolicy.json" \
  "$APP_BUNDLE/Contents/Resources/UpdatePolicy.json"
icon_info="$swift_build_root/AppIcon.partial-info.plist"
/usr/bin/xcrun actool --compile "$APP_BUNDLE/Contents/Resources" \
  --platform macosx --minimum-deployment-target 27.0 --app-icon AppIcon \
  --output-partial-info-plist "$icon_info" \
  "$ROOT_DIR/Artwork/AppIcon.icon" >/dev/null
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconName' "$icon_info")" == AppIcon ]] || {
  echo "Icon Composer asset compilation did not select AppIcon." >&2
  exit 1
}
/bin/cat >"$APP_BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleName</key><string>SecureSandbox</string>
  <key>CFBundleShortVersionString</key><string>$APP_VERSION</string>
  <key>CFBundleVersion</key><string>$APP_BUILD</string>
  <key>SSUpdateSequence</key><integer>$UPDATE_SEQUENCE</integer>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleIconName</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>27.0</string>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSRemovableVolumesUsageDescription</key><string>SecureSandbox verifies operator-selected backup destinations and exports selected evidence.</string>
</dict></plist>
PLIST
if [[ -n "${SECURE_SANDBOX_DEVELOPER_ID:-}" ]]; then
  [[ "$SECURE_SANDBOX_DEVELOPER_ID" == "Developer ID Application:"* \
      || "$SECURE_SANDBOX_DEVELOPER_ID" =~ ^[0-9A-Fa-f]{40}$ ]] || {
    echo "SECURE_SANDBOX_DEVELOPER_ID must name or SHA1-pin a Developer ID Application certificate." >&2
    exit 2
  }
  /usr/bin/codesign --force --options runtime --timestamp --sign "$SECURE_SANDBOX_DEVELOPER_ID" \
    "$APP_BUNDLE/Contents/Helpers/$UPDATE_HELPER_NAME" >/dev/null
  /usr/bin/codesign --force --options runtime --timestamp --sign "$SECURE_SANDBOX_DEVELOPER_ID" "$APP_BUNDLE" >/dev/null
else
  /usr/bin/codesign --force --sign - "$APP_BUNDLE/Contents/Helpers/$UPDATE_HELPER_NAME" >/dev/null
  /usr/bin/codesign --force --sign - "$APP_BUNDLE" >/dev/null
fi
"$ROOT_DIR/script/validate_bundle.sh" "$APP_BUNDLE" >/dev/null

open_app() { /usr/bin/open -n "$APP_BUNDLE"; }
case "$MODE" in
  --build-only|build-only) printf '%s\n' "$APP_BUNDLE" ;;
  run) open_app ;;
  --debug|debug) /usr/bin/lldb -- "$APP_BINARY" ;;
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
    /bin/sleep 2
    /usr/bin/pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--build-only|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
