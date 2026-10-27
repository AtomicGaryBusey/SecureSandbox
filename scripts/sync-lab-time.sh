#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
mode="${1:---check}"
maximum_skew_seconds=5

[[ "$mode" == "--check" || "$mode" == "--apply" ]] || {
  echo "Usage: sync-lab-time.sh [--check|--apply]" >&2
  exit 2
}

read_epoch() {
  local host="$1"
  local value
  value="$(ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=1 "$host" 'date -u +%s')"
  [[ "$value" =~ ^[0-9]{10,}$ ]] || {
    echo "Invalid UTC epoch returned by $host." >&2
    return 1
  }
  printf '%s\n' "$value"
}

host_epoch="$(date -u +%s)"
[[ "$host_epoch" =~ ^[0-9]{10,}$ ]] || {
  echo "Invalid UTC epoch returned by the Mac host." >&2
  exit 1
}

if [[ "$mode" == "--apply" ]]; then
  active_run="$(ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=1 \
    sandbox-research-admin \
    'if test -f /run/secure-sandbox/run-id; then cat /run/secure-sandbox/run-id; fi')"
  if [[ -n "$active_run" ]]; then
    echo "Refusing to change guest clocks while Claude run $active_run is active." >&2
    exit 1
  fi

  while IFS= read -r guest; do
    set_epoch="$(date -u +%s)"
    "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
      --timeout-seconds 15 \
      "$guest" run set-time "@$set_epoch" >/dev/null
  done <<'EOF'
sandbox-gateway-control
sandbox-research-control
sandbox-target-control
EOF
fi

failed=0
for guest in sandbox-gateway sandbox-research-admin sandbox-target-admin; do
  host_epoch="$(date -u +%s)"
  guest_epoch="$(read_epoch "$guest")"
  skew=$((host_epoch - guest_epoch))
  (( skew < 0 )) && skew=$((-skew))
  printf '%s: skew=%ss\n' "$guest" "$skew"
  if (( skew > maximum_skew_seconds )); then
    echo "$guest exceeds the ${maximum_skew_seconds}s clock-skew limit." >&2
    failed=1
  fi
done

(( failed == 0 )) || exit 1
echo "SecureSandbox guest clocks are within ${maximum_skew_seconds}s of the Mac."
