#!/bin/zsh
set -u
set -o pipefail

umask 077
export PATH=/opt/local/bin:/opt/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin

script_path=${0:A}
repo_root=${script_path:h:h}
diagnostic_root="$HOME/SecureSandbox-Native-Host-Transfer"

fail() {
  /usr/bin/printf 'SecureSandbox bootstrap diagnostic launcher: %s\n' "$1" >&2
  exit 1
}

if [[ -L "$diagnostic_root" ]]; then
  fail "diagnostic root must not be a symlink"
fi
if [[ ! -e "$diagnostic_root" ]]; then
  /bin/mkdir -m 700 -- "$diagnostic_root" || fail "cannot create diagnostic root"
fi
[[ -d "$diagnostic_root" ]] || fail "diagnostic root is not a directory"

root_uid=$(/usr/bin/stat -f '%u' -- "$diagnostic_root") || fail "cannot inspect diagnostic root owner"
root_mode=$(/usr/bin/stat -f '%Lp' -- "$diagnostic_root") || fail "cannot inspect diagnostic root mode"
[[ "$root_uid" == "$(/usr/bin/id -u)" ]] || fail "diagnostic root is not operator-owned"
[[ "$root_mode" == "700" ]] || fail "diagnostic root mode must be 700"
root_acl=$(/bin/ls -lde "$diagnostic_root") || fail "cannot inspect diagnostic root ACL"
[[ "$root_acl" != *$'\n'* && "${root_acl%% *}" != *+* ]] \
  || fail "diagnostic root must not have an extended ACL"

diagnostic_log=$(/usr/bin/mktemp "$diagnostic_root/bootstrap-authorization.XXXXXX") \
  || fail "cannot create diagnostic log"
/bin/chmod 600 "$diagnostic_log" || fail "cannot protect diagnostic log"

# FD 3 remains a direct append path even if the terminal or tee disappears.
exec 3>>"$diagnostic_log"
exec 4>&1

validate_log_identity() {
  /usr/bin/python3 -I -c '
import os, stat, sys
path = sys.argv[1]
named = os.lstat(path)
opened = os.fstat(3)
valid = (
    stat.S_ISREG(named.st_mode)
    and named.st_dev == opened.st_dev
    and named.st_ino == opened.st_ino
    and named.st_uid == os.getuid()
    and named.st_gid == os.getgid()
    and stat.S_IMODE(named.st_mode) == 0o600
    and named.st_nlink == 1
)
raise SystemExit(0 if valid else 1)
' "$diagnostic_log"
}
validate_log_identity || fail "diagnostic log identity is unsafe"

sync_log() {
  /usr/bin/python3 -I -c 'import os; os.fsync(3)'
}
sync_log_and_parent() {
  /usr/bin/python3 -I -c '
import os, sys
os.fsync(3)
directory = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
' "$diagnostic_root"
}
sync_log_and_parent || fail "cannot durably create diagnostic log"

event() {
  local name=$1
  shift
  local timestamp
  timestamp=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')
  /usr/bin/printf \
    'secure-sandbox-bootstrap-diagnostic-v1 timestamp=%s pid=%s event=%s%s\n' \
    "$timestamp" "$$" "$name" "${*:+ $*}" >&3 || return 1
  sync_log || return 1
  /usr/bin/printf \
    'secure-sandbox-bootstrap-diagnostic-v1 timestamp=%s pid=%s event=%s%s\n' \
    "$timestamp" "$$" "$name" "${*:+ $*}" >&4 || true
}

termination_reason=preflight
on_signal() {
  local signal_name=$1
  local signal_status=$2
  termination_reason="signal-$signal_name"
  event signal-received "signal=$signal_name status=$signal_status"
  trap - HUP INT TERM
  exit "$signal_status"
}
on_exit() {
  local exit_code=$?
  event launcher-exit "status=$exit_code reason=$termination_reason log=$diagnostic_log"
  exec 3>&-
  exec 4>&-
}
trap on_exit EXIT
trap 'on_signal HUP 129' HUP
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

if [[ -x /opt/local/bin/python3 ]]; then
  python_bin=/opt/local/bin/python3
elif [[ -x /usr/bin/python3 ]]; then
  python_bin=/usr/bin/python3
else
  event preflight-rejected "reason=python-unavailable" || true
  fail "no approved Python interpreter is available"
fi

terminal=$(/usr/bin/tty 2>/dev/null) || terminal=unavailable
event launcher-start "terminal=$terminal log=$diagnostic_log" \
  || fail "cannot record launcher start"

branch=$(/usr/bin/git -C "$repo_root" branch --show-current 2>/dev/null) || {
  event preflight-rejected "reason=source-branch-unavailable" || true
  fail "cannot identify source branch"
}
if [[ "$branch" != public-release ]]; then
  event preflight-rejected "reason=source-branch-invalid branch=$branch" || true
  fail "source branch must be public-release"
fi
source_state=$(
  /usr/bin/git -C "$repo_root" status --porcelain --untracked-files=all 2>/dev/null
) || {
  event preflight-rejected "reason=source-status-unavailable" || true
  fail "cannot inspect source checkout"
}
if [[ -n "$source_state" ]]; then
  event preflight-rejected "reason=source-checkout-dirty" || true
  fail "source checkout must be clean"
fi
source_commit=$(
  /usr/bin/git -C "$repo_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null
) || {
  event preflight-rejected "reason=source-commit-unavailable" || true
  fail "cannot identify source commit"
}
if [[ ! "$source_commit" =~ '^[0-9a-f]{40}$' ]]; then
  event preflight-rejected "reason=source-commit-invalid" || true
  fail "source commit is invalid"
fi

event source-verified "source_commit=$source_commit branch=$branch" \
  || fail "cannot record verified source"
event command-start \
  "command=bootstrap-authorization requesting_agent=Codex requesting_session=DISPOSABLE_MAC_ACCEPTANCE" \
  || fail "cannot record command start"
termination_reason=command-return

cd "$repo_root" || fail "cannot enter repository"
"$python_bin" scripts/deploy-host-controller.py \
  bootstrap-authorization \
  --requesting-agent Codex \
  --requesting-session DISPOSABLE_MAC_ACCEPTANCE \
  2>&1 | /usr/bin/tee -a /dev/fd/3
pipeline_statuses=("${pipestatus[@]}")
command_status=${pipeline_statuses[1]}
tee_status=${pipeline_statuses[2]}
validate_log_identity || {
  event diagnostic-log-rejected "reason=identity-changed"
  exit 1
}
event command-exit "status=$command_status" || fail "cannot record command exit"
if [[ "$tee_status" != 0 ]]; then
  event diagnostic-copy-exit "status=$tee_status" || true
  exit 1
fi
exit "$command_status"
