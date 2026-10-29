#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_app="$root_dir/dist/SecureSandboxControlCenter.app"
apps_dir="$HOME/Applications"
installed_app="$apps_dir/SecureSandbox.app"
previous_app="$apps_dir/.SecureSandbox.previous.app"

[[ -d "$source_app" && ! -L "$source_app" ]] || {
  echo "Build the Control Center app before installing it." >&2
  exit 1
}
"$root_dir/script/validate_bundle.sh" "$source_app" --local >/dev/null
if [[ ! -e "$apps_dir" ]]; then
  mkdir -m 755 "$apps_dir"
fi
[[ -d "$apps_dir" && ! -L "$apps_dir" && "$(stat -f %u "$apps_dir")" == "$EUID" ]] || {
  echo "The user Applications directory is not trusted." >&2
  exit 1
}
if [[ -e "$previous_app" || -L "$previous_app" ]]; then
  [[ ! -e "$installed_app" && ! -L "$installed_app"
     && -d "$previous_app" && ! -L "$previous_app" ]] || {
    echo "An interrupted prior installation needs inspection." >&2
    exit 1
  }
  "$root_dir/script/validate_bundle.sh" "$previous_app" --local >/dev/null
  mv "$previous_app" "$installed_app"
fi
if [[ -e "$installed_app" || -L "$installed_app" ]]; then
  [[ -d "$installed_app" && ! -L "$installed_app" ]] || {
    echo "The installed app path is not a regular app bundle." >&2
    exit 1
  }
fi

stage="$(mktemp -d "$apps_dir/.SecureSandbox.install.XXXXXX")"
had_existing=false
moved_existing=false
installed_new=false
complete=false
cleanup() {
  local status=$?
  if [[ "$complete" != true ]]; then
    if [[ "$installed_new" == true ]]; then
      rm -rf -- "$installed_app"
    fi
    if [[ "$moved_existing" == true && -d "$previous_app" && ! -L "$previous_app" ]]; then
      mv "$previous_app" "$installed_app" || true
    fi
  fi
  rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT

/usr/bin/ditto "$source_app" "$stage/SecureSandbox.app"
"$root_dir/script/validate_bundle.sh" "$stage/SecureSandbox.app" --local >/dev/null
if [[ -d "$installed_app" ]]; then
  had_existing=true
  mv "$installed_app" "$previous_app"
  moved_existing=true
fi
mv "$stage/SecureSandbox.app" "$installed_app"
installed_new=true
"$root_dir/script/validate_bundle.sh" "$installed_app" --local >/dev/null
complete=true
if [[ "$had_existing" == true ]]; then
  rm -rf -- "$previous_app"
fi
printf '{"schema":"secure-sandbox-control-center-install-v1","status":"verified","scope":"user-applications","path":"%s"}\n' "$installed_app"
