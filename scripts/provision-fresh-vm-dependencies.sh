#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
deadline="$root_dir/scripts/run-with-deadline.py"
apply=false
gateway_uuid= research_uuid= target_uuid=
usage() { print -u2 "Usage: $0 [--apply --gateway-uuid UUID --research-uuid UUID --target-uuid UUID]"; exit 2; }
while (( $# > 0 )); do
  case "$1" in
    --apply) apply=true; shift ;;
    --gateway-uuid) (( $# >= 2 )) || usage; gateway_uuid="$2"; shift 2 ;;
    --research-uuid) (( $# >= 2 )) || usage; research_uuid="$2"; shift 2 ;;
    --target-uuid) (( $# >= 2 )) || usage; target_uuid="$2"; shift 2 ;;
    *) usage ;;
  esac
done
if [[ "$apply" == true ]]; then
  for value in "$gateway_uuid" "$research_uuid" "$target_uuid"; do
    [[ "$value" =~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' ]] || usage
  done
  [[ "$gateway_uuid" != "$research_uuid" && "$gateway_uuid" != "$target_uuid" && "$research_uuid" != "$target_uuid" ]] \
    || { print -u2 'expected_vm_uuid_duplicate'; exit 2; }
fi

typeset -a names hosts handles installers payloads
names=(SecureSandbox-Research SecureSandbox-Target)
hosts=(sandbox-research-control sandbox-target-control)
handles=("$research_uuid" "$target_uuid")
installers=(install-research-auditd.sh install-target-rootless-docker-provisioning.sh)
payloads=("$root_dir/scripts/install-research-auditd.sh" "$root_dir/scripts/install-target-rootless-docker-provisioning.sh")

[[ -x "$prlctl" && -x "$control_client" && -x "$deadline" && -f "$ssh_config" ]] || {
  print -u2 'protected_host_prerequisite_missing'
  exit 1
}

expected_adapters_for_role() {
  case "$1" in
    SecureSandbox-Gateway)
      print -r -- '[{"key":"net0","enabled":true,"type":"shared","iface":null,"card":"virtio"},{"key":"net1","enabled":true,"type":"host","iface":"control-net","card":"virtio"}]'
      ;;
    SecureSandbox-Research)
      print -r -- '[{"key":"net1","enabled":true,"type":"host","iface":"control-net","card":"virtio"},{"key":"net2","enabled":true,"type":"host","iface":"lab-net","card":"virtio"}]'
      ;;
    SecureSandbox-Target)
      print -r -- '[{"key":"net1","enabled":true,"type":"host","iface":"lab-net","card":"virtio"}]'
      ;;
    *) return 1 ;;
  esac
}

verify_vm_policy() {
  local info="$1" name="$2" expected_uuid="$3" expected_home expected_adapters home actual_uuid
  [[ "$(print -r -- "$info" | jq -r 'length')" == 1 ]] \
    || { print -u2 "vm_identity_ambiguous:$name"; return 1; }
  [[ "$(print -r -- "$info" | jq -r '.[0].Name')" == "$name" ]] \
    || { print -u2 "vm_name_mismatch:$name"; return 1; }
  actual_uuid="$(print -r -- "$info" | jq -r '.[0].ID | gsub("[{}]"; "")')"
  [[ -z "$expected_uuid" || "$actual_uuid" == "$expected_uuid" ]] \
    || { print -u2 "vm_uuid_mismatch:$name"; return 1; }
  home="$(print -r -- "$info" | jq -r '.[0].Home' | sed 's:/*$::')"
  expected_home="$root_dir/vms/$name.pvm"
  [[ -d "$home" && ! -L "$home" && "${home:A}" == "${expected_home:A}" ]] \
    || { print -u2 "vm_home_invalid:$name"; return 1; }
  expected_adapters="$(expected_adapters_for_role "$name")" \
    || { print -u2 "vm_role_invalid:$name"; return 1; }
  print -r -- "$info" | jq -e --argjson expected "$expected_adapters" '
    ([.[0].Hardware | to_entries[] | select(.key | startswith("net"))
      | {key,enabled:.value.enabled,type:.value.type,iface:(.value.iface // null),card:.value.card}]
     | sort_by(.key)) == $expected
  ' >/dev/null || { print -u2 "unexpected_adapter_inventory:$name"; return 1; }
  print -r -- "$info" | jq -e '
    .[0]["USB and Bluetooth"]["Automatic sharing cameras"] == "off"
    and .[0]["USB and Bluetooth"]["Automatic sharing bluetooth"] == "off"
    and .[0]["USB and Bluetooth"]["Automatic sharing smart cards"] == "off"
    and .[0]["USB and Bluetooth"]["Automatic sharing gamepads"] == "off"
    and .[0]["USB and Bluetooth"]["Support USB 3.0"] == "off"
  ' >/dev/null || { print -u2 "unexpected_device_sharing:$name"; return 1; }
}

verify_transition_policy() {
  local info="$1" name="$2" vm_id="$3" before_adapters="$4"
  local expected_net_key="${5:-}" expected_mac="${6:-}"
  local home expected_home
  home="$(print -r -- "$info" | jq -r 'select(length == 1) | .[0].Home' | sed 's:/*$::')"
  expected_home="$root_dir/vms/$name.pvm"
  [[ -d "$home" && ! -L "$home" && "${home:A}" == "${expected_home:A}" ]] || return 1
  print -r -- "$info" | jq -e --arg name "$name" --arg uuid "$vm_id" --argjson before "$before_adapters" \
    --arg expected_net_key "$expected_net_key" --arg expected_mac "$expected_mac" '
    length == 1
    and .[0].Name == $name
    and (.[0].ID | gsub("[{}]"; "")) == $uuid
    and .[0]["USB and Bluetooth"]["Automatic sharing cameras"] == "off"
    and .[0]["USB and Bluetooth"]["Automatic sharing bluetooth"] == "off"
    and .[0]["USB and Bluetooth"]["Automatic sharing smart cards"] == "off"
    and .[0]["USB and Bluetooth"]["Automatic sharing gamepads"] == "off"
    and .[0]["USB and Bluetooth"]["Support USB 3.0"] == "off"
    and (([.[0].Hardware | to_entries[] | select(.key | startswith("net"))] | sort_by(.key)) as $current
      | ([$current[] | select(.key as $key | $before | map(.key) | index($key))] | sort_by(.key)) == ($before | sort_by(.key))
      and ([$current[] | select(.key as $key | $before | map(.key) | index($key) | not)]) as $new
      | ($new | length) == 1
      and $new[0].value.enabled == true
      and $new[0].value.type == "shared"
      and ($new[0].value.iface // null) == null
      and $new[0].value.card == "virtio"
      and (if $expected_net_key == "" then true
           else $new[0].key == $expected_net_key and $new[0].value.mac == $expected_mac end))
  ' >/dev/null
}

state_dir="$root_dir/.private/restoration"
state_file="$state_dir/temporary-package-provisioning.json"
mkdir -p "$state_dir"
chmod 0700 "$state_dir"
[[ ! -L "$state_dir" && "$(stat -f '%u:%Lp' "$state_dir")" == "$(id -u):700" ]] || {
  print -u2 'temporary_adapter_state_directory_untrusted'
  exit 1
}

wait_control() {
  local host="$1"
  local attempt
  for attempt in {1..60}; do
    if "$control_client" client --ssh-config "$ssh_config" --timeout-seconds 20 "$host" run control-status >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

wait_stopped() {
  local handle="$1"
  local attempt state
  for attempt in {1..60}; do
    state="$($prlctl list -a -i -j "$handle" | jq -r 'select(length == 1) | .[0].State')"
    [[ "$state" == stopped ]] && return 0
    sleep 2
  done
  return 1
}

request_poweroff() {
  local host="$1" handle="$2" attempt poll state
  for attempt in {1..3}; do
    if "$control_client" client --ssh-config "$ssh_config" --timeout-seconds 20 "$host" run poweroff >/dev/null 2>&1; then
      return 0
    fi
    for poll in {1..30}; do
      state="$($prlctl list -a -i -j "$handle" | jq -r 'select(length == 1) | .[0].State')"
      [[ "$state" == stopped ]] && return 0
      sleep 1
    done
  done
  return 1
}

write_adapter_transaction() {
  local stage="$1" name="$2" vm_id="$3" original_state="$4" before_adapters="$5" net_key="${6:-}" mac="${7:-}"
  local temporary
  temporary="$(mktemp "$state_dir/.temporary-package-provisioning.XXXXXX")"
  jq -n --arg stage "$stage" --arg name "$name" --arg vm_id "$vm_id" \
    --arg original_state "$original_state" --argjson before_adapters "$before_adapters" \
    --arg net_key "$net_key" --arg mac "$mac" \
    '{schema:"secure-sandbox-temporary-adapter-transaction-v2",stage:$stage,name:$name,vm_id:$vm_id,original_state:$original_state,before_adapters:$before_adapters,net_key:$net_key,mac:$mac}' \
    > "$temporary"
  chmod 0600 "$temporary"
  sync
  mv -f "$temporary" "$state_file"
  sync
}

clear_adapter_transaction() {
  [[ -e "$state_file" ]] || return 0
  [[ -f "$state_file" && ! -L "$state_file" ]] || return 1
  rm -f -- "$state_file"
  sync
}

verify_adapter_removed() {
  local name="$1" vm_id="$2" before_adapters="$3" info
  info="$($prlctl list -a -i -j "$vm_id")"
  verify_vm_policy "$info" "$name" "$vm_id" || {
    print -u2 "temporary_adapter_removal_policy_invalid:$name"
    return 1
  }
  print -r -- "$info" | jq -e --arg name "$name" --arg vm_id "$vm_id" --argjson before "$before_adapters" '
    length == 1
    and .[0].Name == $name
    and (.[0].ID | gsub("[{}]"; "")) == $vm_id
    and (([.[0].Hardware | to_entries[] | select(.key | startswith("net"))] | sort_by(.key))
         == ($before | sort_by(.key)))
  ' >/dev/null || {
    print -u2 "temporary_adapter_removal_unverified:$name"
    return 1
  }
}

recover_adapter_transaction() {
  [[ -e "$state_file" ]] || return 0
  [[ -f "$state_file" && ! -L "$state_file" && "$(stat -f '%u:%Lp:%l' "$state_file")" == "$(id -u):600:1" ]] || {
    print -u2 'temporary_adapter_state_untrusted'
    return 1
  }
  jq -e '
    .schema == "secure-sandbox-temporary-adapter-transaction-v2"
    and (.stage == "adding" or .stage == "attached")
    and (.name == "SecureSandbox-Research" or .name == "SecureSandbox-Target")
    and (.vm_id | type == "string" and length > 0)
    and (.original_state == "running")
    and (.before_adapters | type == "array"
         and all(.[]; (.key | test("^net[0-9]+$")) and (.value | type == "object")))
    and ((.before_adapters | map(.key) | unique | length) == (.before_adapters | length))
    and (.net_key | type == "string") and (.mac | type == "string")
    and (if .stage == "adding" then (.net_key == "" and .mac == "")
         else (.net_key | test("^net[0-9]+$")) and (.mac | test("^[0-9A-Fa-f]{12}$")) end)
  ' "$state_file" >/dev/null || { print -u2 'temporary_adapter_state_invalid'; return 1; }
  local name vm_id before_adapters normalized_baseline expected_baseline before_keys expected_net expected_mac info state current_adapters current_keys new_keys net_key host
  name="$(jq -r .name "$state_file")"
  vm_id="$(jq -r .vm_id "$state_file" | tr -d '{}')"
  before_adapters="$(jq -c '.before_adapters | sort_by(.key)' "$state_file")"
  expected_baseline="$(expected_adapters_for_role "$name")" || { print -u2 "temporary_adapter_role_invalid:$name"; return 1; }
  normalized_baseline="$(print -r -- "$before_adapters" | jq -c \
    '[.[] | {key,enabled:.value.enabled,type:.value.type,iface:(.value.iface // null),card:.value.card}] | sort_by(.key)')"
  [[ "$(print -r -- "$normalized_baseline" | jq -cS .)" == "$(print -r -- "$expected_baseline" | jq -cS .)" ]] \
    || { print -u2 "temporary_adapter_recovery_baseline_untrusted:$name"; return 1; }
  before_keys="$(print -r -- "$before_adapters" | jq -c 'map(.key)')"
  expected_net="$(jq -r .net_key "$state_file")"
  expected_mac="$(jq -r .mac "$state_file")"
  info="$($prlctl list -a -i -j "$vm_id")"
  [[ "$(print -r -- "$info" | jq -r 'length')" == 1 \
     && "$(print -r -- "$info" | jq -r '.[0].Name')" == "$name" \
     && "$(print -r -- "$info" | jq -r '.[0].ID | gsub("[{}]"; "")')" == "$vm_id" ]] || {
    print -u2 "temporary_adapter_vm_identity_mismatch:$name"
    return 1
  }
  current_adapters="$(print -r -- "$info" | jq -c '[.[0].Hardware | to_entries[] | select(.key | startswith("net"))] | sort_by(.key)')"
  current_keys="$(print -r -- "$current_adapters" | jq -c 'map(.key)')"
  new_keys="$(jq -n -c --argjson current "$current_keys" --argjson before "$before_keys" '$current - $before')"
  print -r -- "$current_adapters" | jq -e --argjson before "$before_adapters" \
    '[.[] | select(.key as $key | $before | map(.key) | index($key))] == $before' >/dev/null || {
      print -u2 "temporary_adapter_recovery_baseline_changed:$name"
      return 1
    }
  if [[ "$(print -r -- "$new_keys" | jq length)" == 0 ]]; then
    [[ "$current_adapters" == "$before_adapters" ]] || { print -u2 "temporary_adapter_recovery_ambiguous:$name"; return 1; }
    state="$(print -r -- "$info" | jq -r '.[0].State')"
    [[ "$state" == running || "$state" == stopped ]] || { print -u2 "temporary_adapter_recovery_state_invalid:$name:$state"; return 1; }
    verify_adapter_removed "$name" "$vm_id" "$before_adapters" || return 1
    if [[ "$state" != running ]]; then
      "$prlctl" start "$vm_id" >/dev/null
    fi
    clear_adapter_transaction
    return 0
  fi
  [[ "$(print -r -- "$new_keys" | jq length)" == 1 ]] || {
    print -u2 "temporary_adapter_recovery_ambiguous:$name"
    return 1
  }
  net_key="$(print -r -- "$new_keys" | jq -r '.[0]')"
  [[ "$(print -r -- "$info" | jq -r --arg key "$net_key" '.[0].Hardware[$key].type')" == shared ]] || {
    print -u2 "temporary_adapter_recovery_unexpected_type:$name:$net_key"
    return 1
  }
  if [[ -n "$expected_net" ]]; then
    [[ "$net_key" == "$expected_net" ]] || { print -u2 "temporary_adapter_recovery_key_mismatch:$name"; return 1; }
    [[ "$(print -r -- "$info" | jq -r --arg key "$net_key" '.[0].Hardware[$key].mac')" == "$expected_mac" ]] || {
      print -u2 "temporary_adapter_recovery_mac_mismatch:$name"
      return 1
    }
  fi
  verify_transition_policy "$info" "$name" "$vm_id" "$before_adapters" "$expected_net" "$expected_mac" \
    || { print -u2 "temporary_adapter_recovery_policy_invalid:$name"; return 1; }
  state="$(print -r -- "$info" | jq -r '.[0].State')"
  if [[ "$state" == running ]]; then
    case "$name" in
      SecureSandbox-Research) host=sandbox-research-control ;;
      SecureSandbox-Target) host=sandbox-target-control ;;
    esac
    request_poweroff "$host" "$vm_id" || { print -u2 "temporary_adapter_recovery_poweroff_failed:$name"; return 1; }
    wait_stopped "$vm_id" || return 1
  elif [[ "$state" != stopped ]]; then
    print -u2 "temporary_adapter_recovery_state_invalid:$name:$state"
    return 1
  fi
  "$prlctl" set "$vm_id" --device-del "$net_key" >/dev/null
  "$prlctl" set "$vm_id" --auto-share-gamepad off >/dev/null
  verify_adapter_removed "$name" "$vm_id" "$before_adapters" || return 1
  "$prlctl" start "$vm_id" >/dev/null
  clear_adapter_transaction
}

finish() {
  local exit_status=$?
  trap - EXIT
  if ! recover_adapter_transaction; then
    print -u2 'temporary_adapter_recovery_incomplete'
    (( exit_status != 0 )) || exit_status=70
  fi
  exit "$exit_status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

recover_adapter_transaction

typeset -a all_names expected_uuids
all_names=(SecureSandbox-Gateway SecureSandbox-Research SecureSandbox-Target)
expected_uuids=("$gateway_uuid" "$research_uuid" "$target_uuid")
for index in {1..3}; do
  name="${all_names[$index]}"
  info="$($prlctl list -a -i -j "$name")"
  verify_vm_policy "$info" "$name" "${expected_uuids[$index]}" || exit 1
  vm_id="$(print -r -- "$info" | jq -r '.[0].ID' | tr -d '{}')"
  state="$(print -r -- "$info" | jq -r '.[0].State')"
  [[ "$state" == running || "$state" == stopped ]] || { print -u2 "vm_state_invalid:$name:$state"; exit 1; }
done

print 'PLAN  provision Research auditd + age through one temporary shared adapter'
print 'PLAN  remove that adapter and prove Research has no default route'
print 'PLAN  provision Target rootless Docker through one temporary shared adapter'
print 'PLAN  remove that adapter and prove Target has no default route'
[[ "$apply" == true ]] || { print 'Dry run only. Re-run with --apply after reviewing this plan.'; exit 0; }

gateway_info="$($prlctl list -a -i -j "$gateway_uuid")"
verify_vm_policy "$gateway_info" SecureSandbox-Gateway "$gateway_uuid" \
  || { print -u2 'vm_policy_changed:SecureSandbox-Gateway'; exit 1; }
gateway_state="$(print -r -- "$gateway_info" | jq -r '.[0].State')"
[[ "$gateway_state" == running || "$gateway_state" == stopped ]] \
  || { print -u2 "vm_state_invalid:SecureSandbox-Gateway:$gateway_state"; exit 1; }
if [[ "$gateway_state" == stopped ]]; then
  "$prlctl" start "$gateway_uuid"
fi
wait_control sandbox-gateway-control \
  || { print -u2 'control_plane_unavailable:SecureSandbox-Gateway'; exit 1; }

for index in {1..2}; do
  info="$($prlctl list -a -i -j "${handles[$index]}")"
  verify_vm_policy "$info" "${names[$index]}" "${handles[$index]}" \
    || { print -u2 "vm_policy_changed:${names[$index]}"; exit 1; }
  state="$(print -r -- "$info" | jq -r '.[0].State')"
  if [[ "$state" == stopped ]]; then
    "$prlctl" start "${handles[$index]}"
  fi
  wait_control "${hosts[$index]}" || { print -u2 "control_plane_unavailable:${names[$index]}"; exit 1; }
done
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control run lifecycle-idle >/dev/null

provision_one() {
  local name="$1" vm_id="$2" host="$3" installer="$4" payload="$5"
  local before after net_key mac state before_adapters before_keys
  before="$($prlctl list -a -i -j "$vm_id")"
  verify_vm_policy "$before" "$name" "$vm_id" \
    || { print -u2 "vm_policy_changed:$name"; return 1; }
  state="$(print -r -- "$before" | jq -r '.[0].State')"
  [[ "$state" == running ]] || { print -u2 "vm_state_invalid:$name:$state"; return 1; }
  before_adapters="$(print -r -- "$before" | jq -c '[.[0].Hardware | to_entries[] | select(.key | startswith("net"))] | sort_by(.key)')"
  before_keys="$(print -r -- "$before_adapters" | jq -c 'map(.key)')"
  request_poweroff "$host" "$vm_id" || { print -u2 "graceful_poweroff_request_failed:$name"; return 1; }
  wait_stopped "$vm_id" || { print -u2 "graceful_poweroff_timeout:$name"; return 1; }
  before="$($prlctl list -a -i -j "$vm_id")"
  verify_vm_policy "$before" "$name" "$vm_id" \
    || { print -u2 "vm_policy_changed:$name"; return 1; }
  print -r -- "$before" | jq -e --argjson adapters "$before_adapters" \
    '([.[0].Hardware | to_entries[] | select(.key | startswith("net"))] | sort_by(.key)) == $adapters' >/dev/null \
    || { print -u2 "vm_topology_changed:$name"; return 1; }
  write_adapter_transaction adding "$name" "$vm_id" "$state" "$before_adapters"
  "$prlctl" set "$vm_id" --device-add net --type shared --adapter-type virtio
  "$prlctl" set "$vm_id" --auto-share-gamepad off
  after="$($prlctl list -a -i -j "$vm_id")"
  verify_transition_policy "$after" "$name" "$vm_id" "$before_adapters" \
    || { print -u2 "temporary_adapter_policy_invalid:$name"; return 1; }
  net_key="$(print -r -- "$after" | jq -r --argjson before "$before" '
    ([.[0].Hardware | to_entries[] | select(.key | startswith("net")) | .key]
     - [$before[0].Hardware | to_entries[] | select(.key | startswith("net")) | .key]) as $new
    | select(($new | length) == 1) | $new[0]')"
  [[ "$net_key" == net<-> ]] || { print -u2 "temporary_adapter_ambiguous:$name"; return 1; }
  mac="$(print -r -- "$after" | jq -r --arg key "$net_key" '.[0].Hardware[$key].mac')"
  [[ "$mac" =~ '^[0-9A-Fa-f]{12}$' ]] || { print -u2 "temporary_adapter_mac_invalid:$name"; return 1; }
  write_adapter_transaction attached "$name" "$vm_id" "$state" "$before_adapters" "$net_key" "$mac"
  after="$($prlctl list -a -i -j "$vm_id")"
  verify_transition_policy "$after" "$name" "$vm_id" "$before_adapters" "$net_key" "$mac" \
    || { print -u2 "temporary_adapter_policy_changed:$name"; return 1; }
  mac="${mac[1,2]}:${mac[3,4]}:${mac[5,6]}:${mac[7,8]}:${mac[9,10]}:${mac[11,12]}"
  "$prlctl" start "$vm_id"
  wait_control "$host" || { print -u2 "control_plane_unavailable:$name"; return 1; }
  if [[ "$name" == SecureSandbox-Research ]]; then
    "$control_client" client --ssh-config "$ssh_config" "$host" deploy "$installer" "$mac" \
      --file "$payload"
  else
    "$control_client" client --ssh-config "$ssh_config" "$host" deploy "$installer" "$mac" \
      --file "$payload" --file "$root_dir/scripts/install-rootless-docker.sh"
  fi
  request_poweroff "$host" "$vm_id" || { print -u2 "graceful_poweroff_request_failed:$name"; return 1; }
  wait_stopped "$vm_id" || { print -u2 "graceful_poweroff_timeout:$name"; return 1; }
  "$prlctl" set "$vm_id" --device-del "$net_key"
  "$prlctl" set "$vm_id" --auto-share-gamepad off
  verify_adapter_removed "$name" "$vm_id" "$before_adapters" || return 1
  "$prlctl" start "$vm_id"
  clear_adapter_transaction
  wait_control "$host" || { print -u2 "control_plane_unavailable_after_cleanup:$name"; return 1; }
  local postcondition_ready=false attempt
  if [[ "$name" == SecureSandbox-Research ]]; then
    for attempt in {1..60}; do
      if "$deadline" 20 ssh -F "$ssh_config" sandbox-research-admin '! ip -4 route show default | grep -q . && systemctl is-active --quiet auditd && test -x /usr/bin/age && test "$(dpkg-query -W -f='"'"'${Version}'"'"' age)" = 1.2.1-1build1 && test "$(dpkg-query -W -f='"'"'${Version}'"'"' auditd)" = 1:4.1.2-1ubuntu0.1 && test -z "$(dpkg -V age)"'; then
        postcondition_ready=true
        break
      fi
      sleep 2
    done
  else
    for attempt in {1..60}; do
      if "$deadline" 20 ssh -F "$ssh_config" sandbox-target-admin '! ip -4 route show default | grep -q . && systemctl --user is-active --quiet docker && for unit in docker.service docker.socket containerd.service; do test "$(systemctl is-enabled "$unit")" = masked && ! systemctl is-active --quiet "$unit" || exit 1; done && test ! -e /var/run/docker.sock'; then
        postcondition_ready=true
        break
      fi
      sleep 2
    done
  fi
  [[ "$postcondition_ready" == true ]] \
    || { print -u2 "contained_dependency_postcondition_timeout:$name"; return 1; }
}

provision_one "${names[1]}" "${handles[1]}" "${hosts[1]}" "${installers[1]}" "${payloads[1]}"
provision_one "${names[2]}" "${handles[2]}" "${hosts[2]}" "${installers[2]}" "${payloads[2]}"
echo fresh-vm-dependencies:provisioned
