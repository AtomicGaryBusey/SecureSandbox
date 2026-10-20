#!/bin/bash
set -euo pipefail

prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
vms=(SecureSandbox-Gateway SecureSandbox-Research SecureSandbox-Target)

[[ -x "$prlctl" ]] || { echo "Parallels prlctl was not found." >&2; exit 1; }

for vm in "${vms[@]}"; do
  state="$($prlctl list -a -i -j "$vm" | jq -r '.[0].State')"
  [[ "$state" == "stopped" ]] || {
    echo "$vm must be stopped before installer-media removal." >&2
    exit 1
  }
done

for vm in "${vms[@]}"; do
  while IFS= read -r device; do
    [[ -n "$device" ]] && "$prlctl" set "$vm" --device-del "$device"
  done < <(
    "$prlctl" list -a -i -j "$vm" \
      | jq -r '.[0].Hardware | keys[] | select(startswith("cdrom"))'
  )

  # Parallels 27.0.3 resets this flag to on when an optical device is deleted.
  "$prlctl" set "$vm" --auto-share-gamepad off
done

echo "Installer media devices removed and automatic gamepad sharing re-disabled."
