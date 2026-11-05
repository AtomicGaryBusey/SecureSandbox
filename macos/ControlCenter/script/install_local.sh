#!/bin/bash -p
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset BASH_ENV CDPATH ENV

root_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_app="$root_dir/dist/SecureSandboxControlCenter.app"
operator_home="$(/usr/bin/python3 -I -c '
import os,pwd
print(pwd.getpwuid(os.geteuid()).pw_dir)
')"
[[ "$operator_home" == /* && "$operator_home" != *$'\n'* \
    && -d "$operator_home" && ! -L "$operator_home" \
    && "$(/usr/bin/stat -f %u "$operator_home")" == "$EUID" ]] || {
  echo "The operator home directory is not trusted." >&2
  exit 1
}
apps_dir="$operator_home/Applications"
installed_app="$apps_dir/SecureSandbox.app"
previous_app="$apps_dir/.SecureSandbox.previous.app"
sequence_floor="$operator_home/Library/Application Support/SecureSandbox/Updates/sequence-floor.json"
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
require_distribution_floor_absent() {
  [[ "$validation_mode" == --distribution ]] || return 0
  [[ ! -e "$sequence_floor" && ! -L "$sequence_floor" ]] || {
    echo "The in-app update sequence floor exists; use the in-app update path." >&2
    return 1
  }
}
require_distribution_sequence_valid() {
  local candidate="$1" candidate_sequence
  [[ "$validation_mode" == --distribution ]] || return 0
  candidate_sequence="$(/usr/libexec/PlistBuddy \
    -c 'Print :SSUpdateSequence' "$candidate/Contents/Info.plist")"
  /usr/bin/python3 -I -c '
import re,sys
raw=sys.argv[1]
if re.fullmatch(r"[1-9][0-9]*",raw) is None or int(raw) > (1 << 64) - 1:
    raise SystemExit("distribution_sequence_outside_uint64")
' "$candidate_sequence"
}
require_distribution_sequence_advance() {
  local candidate="$1" predecessor="$2" candidate_sequence predecessor_sequence
  [[ "$validation_mode" == --distribution ]] || return 0
  candidate_sequence="$(/usr/libexec/PlistBuddy \
    -c 'Print :SSUpdateSequence' "$candidate/Contents/Info.plist")"
  predecessor_sequence="$(/usr/libexec/PlistBuddy \
    -c 'Print :SSUpdateSequence' "$predecessor/Contents/Info.plist")"
  /usr/bin/python3 -I -c '
import re,sys
limit=(1 << 64) - 1
def parsed(raw,label):
    if re.fullmatch(r"[1-9][0-9]*",raw) is None:
        raise SystemExit(f"distribution_{label}_sequence_invalid")
    value=int(raw)
    if value > limit:
        raise SystemExit(f"distribution_{label}_sequence_outside_uint64")
    return value
if parsed(sys.argv[1],"candidate") <= parsed(sys.argv[2],"predecessor"):
    raise SystemExit("distribution_sequence_must_advance")
' "$candidate_sequence" "$predecessor_sequence"
}
distribution_bundle_evidence() {
  local candidate="$1" info helper app_details helper_details
  local version build sequence release_commit app_identifier helper_identifier
  local app_team helper_team app_cdhash helper_cdhash
  [[ "$validation_mode" == --distribution ]] || return 0
  info="$candidate/Contents/Info.plist"
  helper="$candidate/Contents/Helpers/SecureSandboxUpdateInstaller"
  version="$(/usr/libexec/PlistBuddy -c \
    'Print :CFBundleShortVersionString' "$info")"
  build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$info")"
  sequence="$(/usr/libexec/PlistBuddy -c 'Print :SSUpdateSequence' "$info")"
  release_commit="$(/usr/libexec/PlistBuddy -c 'Print :SSReleaseCommit' "$info")"
  app_details="$(/usr/bin/codesign -dv --verbose=4 "$candidate" 2>&1)"
  helper_details="$(/usr/bin/codesign -dv --verbose=4 "$helper" 2>&1)"
  app_identifier="$(/usr/bin/printf '%s\n' "$app_details" \
    | /usr/bin/sed -n 's/^Identifier=//p')"
  helper_identifier="$(/usr/bin/printf '%s\n' "$helper_details" \
    | /usr/bin/sed -n 's/^Identifier=//p')"
  app_team="$(/usr/bin/printf '%s\n' "$app_details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  helper_team="$(/usr/bin/printf '%s\n' "$helper_details" \
    | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  app_cdhash="$(/usr/bin/printf '%s\n' "$app_details" \
    | /usr/bin/sed -n 's/^CDHash=//p')"
  helper_cdhash="$(/usr/bin/printf '%s\n' "$helper_details" \
    | /usr/bin/sed -n 's/^CDHash=//p')"
  /usr/bin/python3 -I -c '
import re,sys
version,build,sequence,commit,app_id,helper_id,app_team,helper_team,app_cd,helper_cd=sys.argv[1:]
limit=(1 << 64) - 1
if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?",version) is None:
    raise SystemExit("distribution_version_invalid")
for label,raw in (("build",build),("sequence",sequence)):
    if re.fullmatch(r"[1-9][0-9]*",raw) is None or int(raw) > limit:
        raise SystemExit(f"distribution_{label}_outside_uint64")
if re.fullmatch(r"[0-9a-f]{40}",commit) is None:
    raise SystemExit("distribution_release_commit_invalid")
if app_id != "org.zebeth.SecureSandbox.ControlCenter" or helper_id != "SecureSandboxUpdateInstaller":
    raise SystemExit("distribution_identifier_invalid")
if app_team != "389K3H8Y32" or helper_team != "389K3H8Y32":
    raise SystemExit("distribution_team_invalid")
if re.fullmatch(r"[0-9A-Fa-f]{40}",app_cd) is None or re.fullmatch(r"[0-9A-Fa-f]{40}",helper_cd) is None:
    raise SystemExit("distribution_cdhash_invalid")
print("\n".join((version,build,sequence,commit,app_id,helper_id,app_team,helper_team,app_cd.lower(),helper_cd.lower())))
' "$version" "$build" "$sequence" "$release_commit" \
    "$app_identifier" "$helper_identifier" "$app_team" "$helper_team" \
    "$app_cdhash" "$helper_cdhash"
}
source_distribution_evidence=""
require_distribution_evidence_matches_source() {
  local candidate="$1" evidence
  [[ "$validation_mode" == --distribution ]] || return 0
  evidence="$(distribution_bundle_evidence "$candidate")"
  [[ -n "$source_distribution_evidence" \
      && "$evidence" == "$source_distribution_evidence" ]] || {
    echo "The distribution candidate identity changed while staging." >&2
    return 1
  }
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
require_distribution_floor_absent

[[ -d "$source_app" && ! -L "$source_app" ]] || {
  echo "Build the Control Center app before installing it." >&2
  exit 1
}
"$root_dir/script/validate_bundle.sh" "$source_app" "$validation_mode" >/dev/null
require_local_mode_ad_hoc "$source_app"
require_distribution_sequence_valid "$source_app"
if [[ "$validation_mode" == --distribution ]]; then
  source_distribution_evidence="$(distribution_bundle_evidence "$source_app")"
fi
require_control_center_stopped
require_distribution_floor_absent
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
  require_distribution_sequence_advance "$source_app" "$previous_app"
  require_control_center_stopped
  require_distribution_floor_absent
  /bin/mv "$previous_app" "$installed_app"
fi
if [[ -e "$installed_app" || -L "$installed_app" ]]; then
  [[ -d "$installed_app" && ! -L "$installed_app" ]] || {
    echo "The installed app path is not a regular app bundle." >&2
    exit 1
  }
  "$root_dir/script/validate_bundle.sh" "$installed_app" "$validation_mode" >/dev/null
  require_local_mode_ad_hoc "$installed_app"
  require_distribution_sequence_advance "$source_app" "$installed_app"
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
require_distribution_sequence_valid "$stage/SecureSandbox.app"
require_distribution_evidence_matches_source "$stage/SecureSandbox.app"
require_control_center_stopped
require_distribution_floor_absent
if [[ -d "$installed_app" ]]; then
  require_distribution_sequence_advance "$stage/SecureSandbox.app" "$installed_app"
  had_existing=true
  /bin/mv "$installed_app" "$previous_app"
  moved_existing=true
fi
require_control_center_stopped
require_distribution_floor_absent
if [[ "$moved_existing" == true ]]; then
  require_distribution_sequence_advance "$stage/SecureSandbox.app" "$previous_app"
else
  require_distribution_sequence_valid "$stage/SecureSandbox.app"
fi
require_distribution_evidence_matches_source "$stage/SecureSandbox.app"
/bin/mv "$stage/SecureSandbox.app" "$installed_app"
installed_new=true
"$root_dir/script/validate_bundle.sh" "$installed_app" "$validation_mode" >/dev/null
require_local_mode_ad_hoc "$installed_app"
require_distribution_sequence_valid "$installed_app"
require_distribution_evidence_matches_source "$installed_app"
complete=true
if [[ "$had_existing" == true ]]; then
  /bin/rm -rf -- "$previous_app"
fi
printf '{"schema":"secure-sandbox-control-center-install-v1","status":"verified","scope":"user-applications","path":"%s"}\n' "$installed_app"
