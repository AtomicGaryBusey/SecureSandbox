#!/bin/bash
set -euo pipefail

release_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
ssh_config="$release_dir/ssh_config"
control_client="$release_dir/control_client"
active_marker="${SECURE_SANDBOX_ACTIVE_MARKER:-}"
release_id="${SECURE_SANDBOX_RELEASE_ID:-}"
state_root="${SECURE_SANDBOX_STATE_ROOT:-}"
run_interrupted=false
session_failed=false
approval_relay_pid=""
lifecycle_armed=false
session_pid=""

control() {
  local host="$1"
  shift
  "$control_client" client --ssh-config "$ssh_config" "$host" run "$@"
}

control_pipe() {
  local host="$1"
  shift
  "$control_client" client --ssh-config "$ssh_config" "$host" pipe "$@"
}

cleanup_marker() {
  if [[ -n "$state_root" && "$state_root" == /* && -n "$active_marker" \
      && "$active_marker" == "$state_root/active/"* ]]; then
    /bin/rm -f -- "$active_marker"
  fi
}
trap cleanup_marker EXIT

expected_marker_root="$state_root/active/"
[[ -n "$state_root" && "$state_root" == /* && ! -L "$state_root" ]] || {
  echo "controller_state_directory_invalid" >&2
  exit 1
}
[[ -n "$active_marker" && "$active_marker" == "$expected_marker_root"* && -f "$active_marker" && ! -L "$active_marker" ]] || {
  echo "controller_active_marker_missing" >&2
  exit 1
}
[[ "$release_id" =~ ^[0-9a-f]{64}$ ]] || {
  echo "controller_release_id_invalid" >&2
  exit 1
}
[[ "$(/usr/bin/jq -er .pid "$active_marker")" == "$$" && "$(/usr/bin/jq -er .release_id "$active_marker")" == "$release_id" ]] || {
  echo "controller_active_marker_invalid" >&2
  exit 1
}

interrupt_run() {
  local exit_status="$1"
  run_interrupted=true
  if [[ -n "$session_pid" ]]; then
    /bin/kill -HUP "$session_pid" 2>/dev/null || true
  fi
  exit "$exit_status"
}
trap 'interrupt_run 129' HUP
trap 'interrupt_run 130' INT
trap 'interrupt_run 143' TERM

claude_args=()
resume_requested=false
lease_profile=standard
lease_profile_given=false
source_id=""
acceptance_run_id="${SECURE_SANDBOX_ACCEPTANCE_RUN_ID:-}"
acceptance_session_id="${SECURE_SANDBOX_ACCEPTANCE_SESSION_ID:-}"
if [[ -n "$acceptance_run_id" || -n "$acceptance_session_id" ]]; then
  [[ "$acceptance_run_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ \
      && "$acceptance_session_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || { echo "Invalid bounded acceptance context." >&2; exit 2; }
fi
usage_error() { echo "Usage: secure-sandbox-claude [--lease-profile short|standard|extended] [--resume SESSION_UUID | --source SOURCE_UUID]" >&2; exit 2; }
while (( $# )); do
  (( $# >= 2 )) || usage_error
  case "$1" in
    --resume)
      [[ "$resume_requested" == false && -z "$source_id" && "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || usage_error
      claude_args=(--resume "$2"); resume_requested=true;;
    --source)
      [[ -z "$source_id" && "$resume_requested" == false && "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || usage_error
      source_id="$2";;
    --lease-profile)
      [[ "$lease_profile_given" == false ]] || usage_error
      lease_profile="$2"; lease_profile_given=true;;
    *) usage_error;;
  esac
  shift 2
done
case "$lease_profile" in short|standard|extended) ;; *) echo "Unknown lease profile: $lease_profile" >&2; exit 2;; esac

read_epoch() {
  local host="$1"
  local value
  value="$(/usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$host" 'date -u +%s')"
  [[ "$value" =~ ^[0-9]{10,}$ ]] || { echo "Invalid UTC epoch returned by $host." >&2; return 1; }
  printf '%s\n' "$value"
}

parse_lease_response() {
  local payload="$1"
  local now maximum
  now="$(/bin/date -u +%s)"
  maximum=$((now + 86400))
  /usr/bin/jq -er --argjson minimum "$((now - 60))" --argjson maximum "$maximum" '
    if type == "object"
       and (.lease_id | type) == "string"
       and (.lease_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
       and (.expires_at | type) == "number"
       and (.expires_at | floor == .)
       and .expires_at >= $minimum
       and .expires_at <= $maximum
    then [.lease_id, (.expires_at | tostring)] | @tsv
    else error("invalid lease response")
    end
  ' <<<"$payload"
}

canonicalize_gateway_summary() {
  local payload="$1" expected_run_id="$2" expected_lease_id="$3" expected_reason="$4" issued_lease="$5"
  /usr/bin/jq -ceS --arg run_id "$expected_run_id" --arg lease_id "$expected_lease_id" --arg reason "$expected_reason" --argjson issued "$issued_lease" '
    def nonnegative_integer: type == "number" and floor == . and . >= 0;
    if type == "object"
       and .schema == "secure-sandbox-run-lease-summary-v1"
       and .reason == $reason
       and (.finalized_at | nonnegative_integer)
       and (.lease | type) == "object"
       and .lease.schema == "secure-sandbox-run-lease-v1"
       and .lease.run_id == $run_id and .lease.lease_id == $lease_id
       and (.lease | del(.expires_at, .renewals)) == ($issued | del(.expires_at, .renewals))
       and (.lease.expires_at | nonnegative_integer)
       and .lease.expires_at >= $issued.expires_at
       and .lease.expires_at <= $issued.maximum_expires_at
       and (.lease.renewals | nonnegative_integer)
       and .lease.renewals >= $issued.renewals
       and (.lease.relay_sha256 | test("^[0-9a-f]{64}$"))
       and (.lease.policy_sha256 | test("^[0-9a-f]{64}$"))
       and (.lease.model | type) == "string" and (.lease.model | length) > 0
       and (.lease.profile | type) == "string" and (.lease.profile | length) > 0
       and (.final_counters | type) == "object"
       and .final_counters.schema == "secure-sandbox-run-lease-counter-v1"
       and .final_counters.run_id == $run_id and .final_counters.lease_id == $lease_id
       and all(.final_counters.requests, .final_counters.input_tokens,
               .final_counters.output_tokens, .final_counters.cost_microusd,
               .final_counters.updated_at; nonnegative_integer)
    then . else error("invalid Gateway summary") end
  ' <<<"$payload"
}

record_session_run() {
  /usr/bin/python3 -I - "$state_root/session-runs.json" "$session_binding_id" "$run_id" <<'PY'
import fcntl
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

path = Path(sys.argv[1])
session_id = sys.argv[2]
run_id = sys.argv[3]
uuid = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
run_uuid = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
if uuid.fullmatch(session_id) is None or run_uuid.fullmatch(run_id) is None:
    raise SystemExit("session_run_id_invalid")
parent = path.parent
parent_info = parent.lstat()
if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700):
    raise SystemExit("session_run_directory_untrusted")
lock_path = parent / ".session-runs.lock"
lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
temporary = None
try:
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
            or lock_info.st_uid != os.geteuid() or stat.S_IMODE(lock_info.st_mode) != 0o600):
        raise SystemExit("session_run_lock_untrusted")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        value = {"schema": "secure-sandbox-session-runs-v2", "sessions": {}}
    else:
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 1024 * 1024):
                raise SystemExit("session_run_catalog_untrusted")
            raw = handle.read(1024 * 1024 + 1)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SystemExit("session_run_catalog_invalid") from error
    if not isinstance(value, dict) or value.get("schema") not in {
            "secure-sandbox-session-runs-v1", "secure-sandbox-session-runs-v2"}:
        raise SystemExit("session_run_catalog_invalid")
    legacy = value["schema"] == "secure-sandbox-session-runs-v1"
    sessions = value.get("sessions")
    if not isinstance(sessions, dict) or len(sessions) > 10_000:
        raise SystemExit("session_run_catalog_invalid")
    for key, record in sessions.items():
        if (not isinstance(key, str) or uuid.fullmatch(key) is None
                or not isinstance(record, dict)
                or set(record) not in ({"last_started_at", "runs"},
                                       {"last_started_at", "runs", "run_ids"})
                or (legacy and "run_ids" in record)
                or not isinstance(record["last_started_at"], int)
                or isinstance(record["last_started_at"], bool) or record["last_started_at"] < 0
                or not isinstance(record["runs"], int) or isinstance(record["runs"], bool)
                or not 1 <= record["runs"] <= 1_000_000
                or ("run_ids" in record and (not isinstance(record["run_ids"], list)
                    or len(record["run_ids"]) > 1000
                    or len(record["run_ids"]) > record["runs"]
                    or any(not isinstance(item, str) or run_uuid.fullmatch(item) is None
                           for item in record["run_ids"])
                    or len(set(record["run_ids"])) != len(record["run_ids"])))):
            raise SystemExit("session_run_catalog_invalid")
    for record in sessions.values():
        record.setdefault("run_ids", [])
    if session_id not in sessions and len(sessions) >= 10_000:
        raise SystemExit("session_run_catalog_full")
    prior = sessions.get(session_id, {"runs": 0})["runs"]
    if prior >= 1_000_000:
        raise SystemExit("session_run_counter_exhausted")
    prior_ids = sessions[session_id]["run_ids"] if session_id in sessions else []
    if run_id in prior_ids:
        raise SystemExit("session_run_duplicate")
    sessions[session_id] = {"last_started_at": int(time.time()), "runs": prior + 1,
                            "run_ids": (prior_ids + [run_id])[-1000:]}
    value["schema"] = "secure-sandbox-session-runs-v2"
    payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    if len(payload) > 1024 * 1024:
        for old_id, old_record in sorted(sessions.items(), key=lambda item: item[1]["last_started_at"]):
            if old_id == session_id:
                continue
            old_record["run_ids"] = []
            payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
            if len(payload) <= 1024 * 1024:
                break
    if len(payload) > 1024 * 1024:
        sessions[session_id]["run_ids"] = sessions[session_id]["run_ids"][-100:]
        payload = (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    if len(payload) > 1024 * 1024:
        raise SystemExit("session_run_catalog_full")
    descriptor, name = tempfile.mkstemp(prefix=".session-runs.", dir=parent)
    temporary = Path(name)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    temporary = None
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if temporary is not None:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    os.close(lock_fd)
PY
}

for guest in sandbox-gateway sandbox-research-admin sandbox-target-admin; do
  host_epoch="$(/bin/date -u +%s)"
  guest_epoch="$(read_epoch "$guest")"
  skew=$((host_epoch - guest_epoch)); (( skew < 0 )) && skew=$((-skew))
  if (( skew > 5 )); then
    echo "$guest exceeds the 5s clock-skew limit." >&2
    echo "Refusing to launch with stale guest clocks." >&2
    exit 1
  fi
done

if [[ "$resume_requested" == true ]]; then
  session_uuid="${claude_args[1]}"
  set +e
  control sandbox-research-control session-refresh-contains "$session_uuid"
  registry_status=$?
  set -e
  case "$registry_status" in
    0) ;;
    1) echo "Refusing to resume an unregistered Claude session UUID: $session_uuid" >&2; exit 2;;
    *) echo "Unable to verify the Claude session registry on Research (status $registry_status)." >&2; exit 1;;
  esac
fi

run_id="${acceptance_run_id:-$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')}"
if [[ -n "$acceptance_session_id" ]]; then
  [[ "$resume_requested" == false ]] || { echo "Acceptance cannot resume an existing session." >&2; exit 2; }
  session_binding_id="$acceptance_session_id"
elif [[ "$resume_requested" == true ]]; then
  session_binding_id="$session_uuid"
else
  session_binding_id="$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')"
fi
lease_json="$(control sandbox-gateway-control lease-issue "$run_id" "$lease_profile")"
issued_lease="$(/usr/bin/jq -ceS --arg run_id "$run_id" '
  def nonnegative_integer: type == "number" and floor == . and . >= 0;
  if type == "object" and .schema == "secure-sandbox-run-lease-v1"
     and .run_id == $run_id
     and (.lease_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
     and (.relay_sha256 | test("^[0-9a-f]{64}$"))
     and (.policy_sha256 | test("^[0-9a-f]{64}$"))
     and (.profile | type) == "string" and (.profile | length) > 0
     and (.model | type) == "string" and (.model | length) > 0
     and all(.issued_at, .expires_at, .maximum_expires_at, .renewals; nonnegative_integer)
     and .issued_at <= .expires_at and .expires_at <= .maximum_expires_at
     and (.limits | type) == "object" and (.pricing | type) == "object"
  then . else error("invalid issued lease") end
' <<<"$lease_json")" || { echo "Invalid Gateway lease." >&2; exit 1; }
lease_fields="$(parse_lease_response "$lease_json")"
IFS=$'\t' read -r lease_id lease_expires_at <<<"$lease_fields"
[[ "$lease_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ \
    && "$lease_expires_at" =~ ^[0-9]{10}$ ]] || { echo "Invalid lease response." >&2; exit 1; }
run_started=false

cleanup_run() {
  cleanup_status=$?
  trap - EXIT
  if [[ -n "$session_pid" ]]; then
    /bin/kill -HUP "$session_pid" 2>/dev/null || true
    wait "$session_pid" 2>/dev/null || true
    session_pid=""
  fi
  if [[ -n "$approval_relay_pid" ]]; then
    /bin/kill "$approval_relay_pid" 2>/dev/null || true
    wait "$approval_relay_pid" 2>/dev/null || true
    approval_relay_pid=""
  fi
  now="$(/bin/date -u +%s)"
  if (( now >= lease_expires_at )); then lease_reason=expired
  elif [[ "$run_interrupted" == true ]]; then lease_reason=operator_closed
  elif [[ "$session_failed" == true ]]; then lease_reason=session_failed
  elif [[ "$run_started" == true ]]; then lease_reason=completed
  else lease_reason=launch_failed
  fi
  cleanup_failed=false
  if [[ "$lifecycle_armed" == true ]]; then
    if ! control sandbox-research-control watchdog-close "$run_id" >/dev/null; then
      echo "Research lifecycle close failed; admission remains closed and recovery is required." >&2
      cleanup_failed=true
    fi
  fi
  gateway_summary=""
  if [[ "$cleanup_failed" == false ]]; then
    if ! gateway_summary="$(control sandbox-gateway-control lease-finalize "$run_id" "$lease_reason")"; then
      echo "Gateway lease finalization failed; Research lifecycle was not committed." >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false ]]; then
    gateway_summary="$(canonicalize_gateway_summary "$gateway_summary" "$run_id" "$lease_id" "$lease_reason" "$issued_lease")" || cleanup_failed=true
    if [[ "$cleanup_failed" == true ]]; then
      echo "Gateway returned an invalid final summary; Research lifecycle was not committed." >&2
    fi
  fi
  if [[ "$cleanup_failed" == false && "$lifecycle_armed" == true ]]; then
    # Gateway atomic_json persists canonical JSON followed by exactly one LF.
    # Bind Research's commit to those exact durable bytes, not merely to an
    # equivalent JSON value transported through command substitution.
    gateway_summary_sha256="$(/usr/bin/printf '%s\n' "$gateway_summary" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    if ! control sandbox-research-control watchdog-commit "$run_id" "$gateway_summary_sha256" >/dev/null; then
      echo "Research lifecycle commit failed; recovery is required." >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false && "$lifecycle_armed" == true ]]; then
    if ! control sandbox-research-control session-refresh >/dev/null; then
      echo "Session registry refresh failed after committed teardown." >&2
      cleanup_failed=true
    fi
  fi
  cleanup_marker
  if [[ "$cleanup_failed" == true ]]; then
    return 70
  fi
  return "$cleanup_status"
}
trap cleanup_run EXIT

control sandbox-research-control watchdog-arm "$run_id" "$lease_id" "$lease_expires_at" "$session_binding_id" >/dev/null
lifecycle_armed=true
control sandbox-research-control capture-ready

approval_relay() {
  local pending status signed response approval_id broker_stderr broker_error failures=0
  relay_event() {
    local stage="$1" result="$2" request_id="${3:-}" event_path
    [[ "$stage" =~ ^[a-z_]{1,48}$ && "$result" =~ ^[a-z0-9_]{1,80}$ ]] || return 1
    [[ -z "$request_id" || "$request_id" =~ ^[0-9a-f-]{36}$ ]] || return 1
    event_path="$state_root/approval-relay-last.json"
    /usr/bin/python3 -I -c '
import json, os, sys, time

path, stage, result, approval_id, run_id, session_id = sys.argv[1:]
record = {
    "approval_id": approval_id,
    "created_at": int(time.time()),
    "result": result,
    "run_id": run_id,
    "schema": "secure-sandbox-approval-relay-event-v1",
    "session_id": session_id,
    "stage": stage,
}
payload = (json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
temporary = path + "." + str(os.getpid()) + ".new"
descriptor = None
try:
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    offset = 0
    while offset < len(payload):
        offset += os.write(descriptor, payload[offset:])
    os.fchmod(descriptor, 0o600)
    os.fsync(descriptor)
    os.close(descriptor)
    descriptor = None
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
except Exception:
    if descriptor is not None:
        os.close(descriptor)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
' "$event_path" "$stage" "$result" "${request_id:-none}" "$run_id" "$session_binding_id" || return 1
    /usr/bin/logger -p user.notice -t secure-sandbox-approval-relay \
      "stage=$stage result=$result approval_id=${request_id:-none} run_id=$run_id session_id=$session_binding_id"
  }
  while true; do
    set +e
    pending="$(control sandbox-research-control execution-approval-next "$run_id" "$session_binding_id" 2>/dev/null)"
    status=$?
    set -e
    if (( status == 3 )); then
      failures=0
      continue
    fi
    if (( status != 0 )); then
      failures=$((failures + 1))
      if (( failures >= 3 )); then
        relay_event poll transport_failed || true
        echo "Execution approval relay failed closed after repeated polling errors." >&2
        /bin/kill -TERM "$controller_pid" 2>/dev/null || true
        return "$status"
      fi
      /bin/sleep 1
      continue
    fi
    failures=0
    if ! approval_id="$(/usr/bin/jq -er '.approval_id' <<<"$pending")"; then
      relay_event request invalid || true
      echo "Execution approval relay received an invalid pending request." >&2
      /bin/kill -TERM "$controller_pid" 2>/dev/null || true
      return 1
    fi
    relay_event claim acquired "$approval_id" || true
    broker_stderr="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/secure-sandbox-approval.XXXXXX")" || {
      relay_event authorization stderr_capture_failed "$approval_id" || true
      /bin/kill -TERM "$controller_pid" 2>/dev/null || true
      return 1
    }
    set +e
    signed="$("$release_dir/authorization_broker" request \
      --agent "Claude Code" --session "$session_binding_id" \
      --purpose "Authorize this exact disposable execution request" \
      --resource "Disposable execution in SecureSandbox-Target" \
      --operation execution-approval-sign --parameters-json "$pending" 2>"$broker_stderr")"
    status=$?
    set -e
    if (( status == 0 )); then
      relay_event authorization approved "$approval_id" || true
      if ! response="$(/usr/bin/jq -ncS --arg approval_id "$approval_id" --argjson envelope "$signed" \
          '{schema:"secure-sandbox-execution-approval-response-v1",approval_id:$approval_id,status:"approved",envelope:$envelope}')"; then
        /bin/rm -f -- "$broker_stderr"
        relay_event response invalid_signed_envelope "$approval_id" || true
        /bin/kill -TERM "$controller_pid" 2>/dev/null || true
        return 1
      fi
    else
      broker_error="$(/usr/bin/tail -n 1 "$broker_stderr" \
        | /usr/bin/jq -er '.error | select(type == "string" and test("^[a-z0-9_]{1,80}$"))' 2>/dev/null \
        || /usr/bin/printf '%s' authorization_failed)"
      relay_event authorization "$broker_error" "$approval_id" || true
      if ! response="$(/usr/bin/jq -ncS --arg approval_id "$approval_id" \
          '{schema:"secure-sandbox-execution-approval-response-v1",approval_id:$approval_id,status:"cancelled"}')"; then
        /bin/rm -f -- "$broker_stderr"
        relay_event response cancellation_encoding_failed "$approval_id" || true
        /bin/kill -TERM "$controller_pid" 2>/dev/null || true
        return 1
      fi
    fi
    /bin/rm -f -- "$broker_stderr"
    relay_event response delivering "$approval_id" || true
    if ! /usr/bin/printf '%s\n' "$response" \
      | control_pipe sandbox-research-control execution-approval-deliver >/dev/null; then
      relay_event response delivery_failed "$approval_id" || true
      echo "Execution approval relay failed closed while delivering a response." >&2
      /bin/kill -TERM "$controller_pid" 2>/dev/null || true
      return 1
    fi
    relay_event response delivered "$approval_id" || true
  done
}

controller_pid="$$"
approval_relay &
approval_relay_pid=$!
host_pki="$($release_dir/pki_anchor verify)"
gateway_pki="$(control sandbox-gateway-control pki-verify)"
research_pki="$(control sandbox-research-control pki-verify)"
host_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$host_pki")"
gateway_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$gateway_pki")"
research_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$research_pki")"
[[ "$host_generation" == "$gateway_generation" && "$host_generation" == "$research_generation" ]] || {
  echo "pki_generation_boundary_mismatch" >&2
  exit 1
}
echo "SecureSandbox controller release: $release_id"
echo "SecureSandbox run ID: $run_id"
echo "SecureSandbox session binding: $session_binding_id"
echo "Run lease: $lease_id ($lease_profile; expires $(/bin/date -r "$lease_expires_at" -u '+%Y-%m-%dT%H:%M:%SZ'))"
record_session_run
run_started=true
set +e
if [[ "$resume_requested" == true ]]; then
  /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --resume "$session_uuid" <&0 &
else
  if [[ -n "$source_id" ]]; then
    /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --session-id "$session_binding_id" --source "$source_id" <&0 &
  else
    /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --session-id "$session_binding_id" <&0 &
  fi
fi
session_pid=$!
wait "$session_pid"
session_status=$?
session_pid=""
set -e
if (( session_status != 0 )); then
  session_failed=true
  exit "$session_status"
fi

