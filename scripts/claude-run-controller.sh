#!/bin/bash
set -euo pipefail

release_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
ssh_config="$release_dir/ssh_config"
op_agents="$release_dir/op_agents"
active_marker="${SECURE_SANDBOX_ACTIVE_MARKER:-}"
release_id="${SECURE_SANDBOX_RELEASE_ID:-}"
state_root="${SECURE_SANDBOX_STATE_ROOT:-}"
run_interrupted=false
session_failed=false

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

trap 'run_interrupted=true; exit 129' HUP
trap 'run_interrupted=true; exit 130' INT
trap 'run_interrupted=true; exit 143' TERM

claude_args=()
resume_requested=false
lease_profile=standard
case "$#:${1:-}:${3:-}" in
  0::) ;;
  2:--resume:)
    [[ "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Invalid session UUID." >&2; exit 2; }
    claude_args=(--resume "$2"); resume_requested=true;;
  2:--lease-profile:)
    lease_profile="$2";;
  4:--lease-profile:--resume)
    lease_profile="$2"; [[ "$4" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 2
    claude_args=(--resume "$4"); resume_requested=true;;
  4:--resume:--lease-profile)
    [[ "$2" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 2
    claude_args=(--resume "$2"); resume_requested=true; lease_profile="$4";;
  *) echo "Usage: secure-sandbox-claude [--lease-profile short|standard|extended] [--resume SESSION_UUID]" >&2; exit 2;;
esac
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
       and .lease == $issued
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
  "$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
    | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
      "sudo -S -p '' sh -c '/usr/local/libexec/secure-sandbox/session_registry.py refresh || exit 70; /usr/local/libexec/secure-sandbox/session_registry.py contains \"\$1\"; status=\$?; if test \"\$status\" -eq 0; then exit 0; elif test \"\$status\" -eq 1; then exit 42; else exit 70; fi' sh '$session_uuid'"
  registry_status=$?
  set -e
  case "$registry_status" in
    0) ;;
    42) echo "Refusing to resume an unregistered Claude session UUID: $session_uuid" >&2; exit 2;;
    *) echo "Unable to verify the Claude session registry on Research (status $registry_status)." >&2; exit 1;;
  esac
fi

run_id="$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')"
lease_json="$("$op_agents" read 'op://Agents/SecureSandbox-Gateway/password' \
  | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-gateway \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease.py issue '$run_id' '$lease_profile'")"
issued_lease="$(/usr/bin/jq -ceS --arg run_id "$run_id" '
  if type == "object" and .schema == "secure-sandbox-run-lease-v1"
     and .run_id == $run_id
     and (.lease_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
     and (.relay_sha256 | test("^[0-9a-f]{64}$"))
     and (.policy_sha256 | test("^[0-9a-f]{64}$"))
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
  now="$(/bin/date -u +%s)"
  if (( now >= lease_expires_at )); then lease_reason=expired
  elif [[ "$run_interrupted" == true ]]; then lease_reason=operator_closed
  elif [[ "$session_failed" == true ]]; then lease_reason=session_failed
  elif [[ "$run_started" == true ]]; then lease_reason=completed
  else lease_reason=launch_failed
  fi
  cleanup_failed=false
  if ! "$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
    | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=15 sandbox-research-admin \
      "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease_watchdog.py close '$run_id'" >/dev/null; then
    echo "Research lifecycle close failed; admission remains closed and recovery is required." >&2
    cleanup_failed=true
  fi
  gateway_summary=""
  if [[ "$cleanup_failed" == false ]]; then
    if ! gateway_summary="$("$op_agents" read 'op://Agents/SecureSandbox-Gateway/password' \
      | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=15 sandbox-gateway \
        "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease.py finalize '$run_id' '$lease_reason'")"; then
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
  if [[ "$cleanup_failed" == false ]]; then
    # Gateway atomic_json persists canonical JSON followed by exactly one LF.
    # Bind Research's commit to those exact durable bytes, not merely to an
    # equivalent JSON value transported through command substitution.
    gateway_summary_sha256="$(/usr/bin/printf '%s\n' "$gateway_summary" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    if ! "$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
      | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=15 sandbox-research-admin \
        "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease_watchdog.py commit '$run_id' '$gateway_summary_sha256'" >/dev/null; then
      echo "Research lifecycle commit failed; recovery is required." >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false ]]; then
    if ! "$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
      | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=15 sandbox-research-admin \
        "sudo -S -p '' /usr/local/libexec/secure-sandbox/session_registry.py refresh" >/dev/null; then
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

"$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
  | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease_watchdog.py arm '$run_id' '$lease_id' '$lease_expires_at'" >/dev/null
"$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
  | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
    "sudo -S -p '' sh -c 'test -f /run/secure-sandbox/conversation-capture-ready && test ! -e /run/secure-sandbox/conversation-capture-fatal && test -f /run/secure-sandbox/artifact-capture-ready && test ! -e /run/secure-sandbox/artifact-capture-fatal && systemctl is-active --quiet conversation-capture.service conversation-shipper.service artifact-collector.service'"
host_pki="$($release_dir/pki_anchor verify)"
gateway_pki="$("$op_agents" read 'op://Agents/SecureSandbox-Gateway/password' \
  | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-gateway \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/pki_generation.py verify")"
research_pki="$("$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
  | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/pki_generation.py verify")"
host_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$host_pki")"
gateway_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$gateway_pki")"
research_generation="$(/usr/bin/jq -er '.generation_id + ":" + .manifest_sha256' <<<"$research_pki")"
[[ "$host_generation" == "$gateway_generation" && "$host_generation" == "$research_generation" ]] || {
  echo "pki_generation_boundary_mismatch" >&2
  exit 1
}
echo "SecureSandbox controller release: $release_id"
echo "SecureSandbox run ID: $run_id"
echo "Run lease: $lease_id ($lease_profile; expires $(/bin/date -r "$lease_expires_at" -u '+%Y-%m-%dT%H:%M:%SZ'))"
run_started=true
set +e
if [[ "$resume_requested" == true ]]; then
  /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude --resume "$session_uuid"
else
  /usr/bin/ssh -tt -F "$ssh_config" sandbox-research /usr/local/bin/research-claude
fi
session_status=$?
set -e
if (( session_status != 0 )); then
  session_failed=true
  exit "$session_status"
fi

