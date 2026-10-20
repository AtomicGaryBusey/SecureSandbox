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
lease_id="$(/usr/bin/jq -er .lease_id <<<"$lease_json")"
lease_expires_at="$(/usr/bin/jq -er .expires_at <<<"$lease_json")"
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
  "$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
    | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
      "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease_watchdog.py disarm '$run_id'" >/dev/null 2>&1 || true
  "$op_agents" read 'op://Agents/SecureSandbox-Gateway/password' \
    | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-gateway \
      "sudo -S -p '' /usr/local/libexec/secure-sandbox/run_lease.py finalize '$run_id' '$lease_reason'" >/dev/null 2>&1 || true
  /bin/sleep 2
  "$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
    | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
      "sudo -S -p '' sh -c '/usr/local/libexec/secure-sandbox/session_registry.py refresh && /usr/local/libexec/secure-sandbox/manage_run_id.py clear \"\$1\"' sh '$run_id'" >/dev/null 2>&1 || true
  cleanup_marker
  return "$cleanup_status"
}
trap cleanup_run EXIT

"$op_agents" read 'op://Agents/SecureSandbox-Research/password' \
  | /usr/bin/ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/manage_run_id.py set '$run_id'"
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

