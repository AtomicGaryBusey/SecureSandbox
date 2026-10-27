#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
typeset -a stop_order start_order control_hosts
stop_order=(SecureSandbox-Target SecureSandbox-Research SecureSandbox-Gateway)
start_order=(SecureSandbox-Gateway SecureSandbox-Research SecureSandbox-Target)
control_hosts=(sandbox-gateway-control sandbox-research-control sandbox-target-control)

[[ -x "$prlctl" && -x "$control_client" && -f "$ssh_config" ]] || {
  print -u2 'protected_host_prerequisite_missing'
  exit 1
}
if /usr/bin/pgrep -x prl_client_app >/dev/null 2>&1; then
  print -u2 'parallels_gui_must_be_closed_before_vm_lifecycle_transition'
  exit 1
fi
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control run lifecycle-idle >/dev/null

for name in "${stop_order[@]}"; do
  state="$($prlctl list -a -i -j "$name" | jq -r 'select(length == 1) | .[0].State')"
  [[ "$state" == running ]] || { print -u2 "vm_not_running:$name:$state"; exit 1; }
done
for index in {1..3}; do
  host="${control_hosts[4-$index]}"
  name="${stop_order[$index]}"
  "$control_client" client --ssh-config "$ssh_config" "$host" run poweroff >/dev/null 2>&1 || true
  stopped=false
  for _ in {1..60}; do
    state="$($prlctl list -a -i -j "$name" | jq -r 'select(length == 1) | .[0].State')"
    if [[ "$state" == stopped ]]; then stopped=true; break; fi
    sleep 2
  done
  [[ "$stopped" == true ]] || { print -u2 "graceful_poweroff_timeout:$name"; exit 1; }
done
for name in "${start_order[@]}"; do
  if (( $($prlctl list -a -i -j "$name" | jq '[.[0].Hardware | keys[] | select(startswith("cdrom"))] | length') > 0 )); then
    "$root_dir/scripts/remove-installer-media.sh" "$name"
  else
    "$prlctl" set "$name" --auto-share-gamepad off >/dev/null
  fi
done
for name in "${start_order[@]}"; do "$prlctl" start "$name"; done

for host in "${control_hosts[@]}"; do
  ready=false
  for _ in {1..90}; do
    if "$control_client" client --ssh-config "$ssh_config" "$host" run control-status >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 2
  done
  [[ "$ready" == true ]] || { print -u2 "cold_boot_control_unavailable:$host"; exit 1; }
done

"$root_dir/scripts/sync-lab-time.sh" --apply
"$root_dir/scripts/verify-boundaries.sh"
echo cold-boot-acceptance:passed
