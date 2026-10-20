#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
policy="$root_dir/config/snapshot-retention.json"
mode="${1:---dry-run}"

[[ "$mode" == "--dry-run" || "$mode" == "--apply" ]] \
  || { echo "Usage: manage-snapshots.sh [--dry-run|--apply]" >&2; exit 2; }
[[ -x "$prlctl" && -f "$policy" ]] || { echo "Snapshot prerequisites are missing." >&2; exit 1; }
jq -e '.schema == "secure-sandbox-snapshot-retention-v1"
  and (.maximum_snapshots_per_vm | type == "number")
  and (.minimum_free_gib_for_apply | type == "number")
  and (.virtual_machines | length == 3)
  and (.retain_names | length >= 1)' "$policy" >/dev/null

maximum="$(jq -r .maximum_snapshots_per_vm "$policy")"
minimum_gib="$(jq -r .minimum_free_gib_for_apply "$policy")"
mapfile_compat() {
  local target="$1"
  shift
  local line
  eval "$target=()"
  while IFS= read -r line; do
    eval "$target+=(\"\$line\")"
  done < <("$@")
}
mapfile_compat vms jq -r '.virtual_machines[]' "$policy"
mapfile_compat retained jq -r '.retain_names[]' "$policy"

if [[ "$mode" == "--apply" ]]; then
  free_kib="$(df -Pk /System/Volumes/Data | awk 'NR==2 {print $4}')"
  required_kib=$((minimum_gib * 1024 * 1024))
  (( free_kib >= required_kib )) \
    || { echo "Refusing snapshot consolidation below ${minimum_gib} GiB free." >&2; exit 1; }
fi

for vm in "${vms[@]}"; do
  vm_status="$("$prlctl" list -a --no-header --output status,name | awk -v name="$vm" '$2 == name {print $1}')"
  [[ -n "$vm_status" ]] || { echo "Unknown VM in retention policy: $vm" >&2; exit 1; }
  if [[ "$mode" == "--apply" && "$vm_status" != "stopped" ]]; then
    echo "Refusing to consolidate snapshots while $vm is $vm_status." >&2
    exit 1
  fi
  inventory="$("$prlctl" snapshot-list "$vm" -j)"
  count="$(jq 'length' <<<"$inventory")"
  (( count <= 40 )) || { echo "Refusing unexpected snapshot count for $vm: $count" >&2; exit 1; }
  for name in "${retained[@]}"; do
    matches="$(jq --arg name "$name" '[to_entries[] | select(.value.name == $name)] | length' <<<"$inventory")"
    [[ "$matches" == 1 ]] || { echo "Retention milestone missing or duplicated for $vm: $name" >&2; exit 1; }
  done
  current_name="$(jq -r '[to_entries[] | select(.value.current == true)][0].value.name // empty' <<<"$inventory")"
  keep_current=false
  for name in "${retained[@]}"; do [[ "$current_name" == "$name" ]] && keep_current=true; done
  [[ "$keep_current" == true ]] || { echo "Current snapshot is not retained for $vm: $current_name" >&2; exit 1; }
  mapfile_compat delete_ids jq -r --argjson keep "$(jq -c .retain_names "$policy")" \
    'to_entries | sort_by(.value.date)[] | select((.value.name as $n | $keep | index($n)) == null) | .key' <<<"$inventory"
  printf '%s: %s snapshots; retain %s; remove %s\n' "$vm" "$count" "$maximum" "${#delete_ids[@]}"
  if [[ "$mode" == "--apply" ]]; then
    for snapshot_id in "${delete_ids[@]}"; do
      "$prlctl" snapshot-delete "$vm" --id "$snapshot_id"
    done
    remaining="$("$prlctl" snapshot-list "$vm" -j | jq 'length')"
    [[ "$remaining" == "$maximum" ]] \
      || { echo "Unexpected retained snapshot count for $vm: $remaining" >&2; exit 1; }
  fi
done
