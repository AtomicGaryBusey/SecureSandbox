#!/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset BASH_ENV CDPATH ENV

root_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_app="$root_dir/dist/SecureSandboxControlCenter.app"
apps_dir="$HOME/Applications"
installed_app="$apps_dir/SecureSandbox.app"
previous_app="$apps_dir/.SecureSandbox.previous.app"
validation_mode="${1:---local}"

[[ "$validation_mode" == --local \
    || "$validation_mode" == --distribution ]] || {
  echo "Usage: $0 [--local|--distribution]" >&2
  exit 2
}
require_control_center_stopped() {
  if [[ "$validation_mode" == --distribution ]] \
      && /usr/bin/pgrep -x SecureSandboxControlCenter >/dev/null 2>&1; then
    echo "Quit SecureSandbox before installing a distribution build." >&2
    return 1
  fi
}
require_local_mode_ad_hoc() {
  local candidate="$1"
  local details signature team
  [[ "$validation_mode" == --local ]] || return 0
  details="$(/usr/bin/codesign -dv --verbose=4 "$candidate" 2>&1)" || {
    echo "Local installation requires a valid ad-hoc signature." >&2
    return 1
  }
  signature="$(/usr/bin/printf '%s\n' "$details" \
    | /usr/bin/sed -n 's/^Signature=//p')"
  team="$(/usr/bin/printf '%s\n' "$details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  [[ "$signature" == adhoc && "$team" == "not set" ]] || {
    echo "Local installation admits ad-hoc builds only; use --distribution for release software." >&2
    return 1
  }
}
require_control_center_stopped

[[ -d "$source_app" && ! -L "$source_app" ]] || {
  echo "Build the Control Center app before installing it." >&2
  exit 1
}
"$root_dir/script/validate_bundle.sh" "$source_app" "$validation_mode" >/dev/null
require_local_mode_ad_hoc "$source_app"
require_control_center_stopped
if [[ ! -e "$apps_dir" ]]; then
  /bin/mkdir -m 755 "$apps_dir"
fi
[[ -d "$apps_dir" && ! -L "$apps_dir" \
    && "$(/usr/bin/stat -f %u "$apps_dir")" == "$EUID" ]] || {
  echo "The user Applications directory is not trusted." >&2
  exit 1
}
if [[ -e "$previous_app" || -L "$previous_app" ]]; then
  [[ ! -e "$installed_app" && ! -L "$installed_app"
     && -d "$previous_app" && ! -L "$previous_app" ]] || {
    echo "An interrupted prior installation needs inspection." >&2
    exit 1
  }
  "$root_dir/script/validate_bundle.sh" "$previous_app" "$validation_mode" >/dev/null
  require_local_mode_ad_hoc "$previous_app"
  require_control_center_stopped
  /bin/mv "$previous_app" "$installed_app"
fi
if [[ -e "$installed_app" || -L "$installed_app" ]]; then
  [[ -d "$installed_app" && ! -L "$installed_app" ]] || {
    echo "The installed app path is not a regular app bundle." >&2
    exit 1
  }
  "$root_dir/script/validate_bundle.sh" "$installed_app" "$validation_mode" >/dev/null
  require_local_mode_ad_hoc "$installed_app"
fi

stage="$(/usr/bin/mktemp -d "$apps_dir/.SecureSandbox.install.XXXXXX")"
had_existing=false
moved_existing=false
installed_new=false
complete=false
cleanup() {
  local status=$?
  set +e
  if [[ "$complete" != true ]]; then
    if [[ "$installed_new" == true ]]; then
      /bin/rm -rf -- "$installed_app"
    fi
    if [[ "$moved_existing" == true && -d "$previous_app" && ! -L "$previous_app" ]]; then
      /bin/mv "$previous_app" "$installed_app" || true
    fi
  fi
  /bin/rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT

/usr/bin/ditto "$source_app" "$stage/SecureSandbox.app"
"$root_dir/script/validate_bundle.sh" "$stage/SecureSandbox.app" "$validation_mode" >/dev/null
require_local_mode_ad_hoc "$stage/SecureSandbox.app"
require_control_center_stopped
if [[ -d "$installed_app" ]]; then
  had_existing=true
  /bin/mv "$installed_app" "$previous_app"
  moved_existing=true
fi
require_control_center_stopped
/bin/mv "$stage/SecureSandbox.app" "$installed_app"
installed_new=true
"$root_dir/script/validate_bundle.sh" "$installed_app" "$validation_mode" >/dev/null
require_local_mode_ad_hoc "$installed_app"
if [[ "$had_existing" == true ]]; then
  /bin/rm -rf -- "$previous_app"
fi
complete=true
printf '{"schema":"secure-sandbox-control-center-install-v1","status":"verified","scope":"user-applications","path":"%s"}\n' "$installed_app"
