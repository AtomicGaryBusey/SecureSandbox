#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
installer="/Library/Application Support/SecureSandbox/installers/c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804.iso"

[[ -x "$prlctl" ]] || { echo "Parallels prlctl was not found." >&2; exit 1; }
[[ $# -eq 1 ]] || {
  echo "Usage: remove-installer-media.sh SecureSandbox-{Gateway|Research|Target}" >&2
  exit 2
}

vm="$1"
case "$vm" in
  SecureSandbox-Gateway) seed="$root_dir/seeds/gateway-cidata.iso" ;;
  SecureSandbox-Research) seed="$root_dir/seeds/research-cidata.iso" ;;
  SecureSandbox-Target) seed="$root_dir/seeds/target-cidata.iso" ;;
  *) echo "Unknown managed VM: $vm" >&2; exit 2 ;;
esac

info="$("$prlctl" list -a -i -j "$vm")"
if ! jq -e --arg vm "$vm" --arg installer "$installer" --arg seed "$seed" '
  type == "array" and length == 1
  and .[0].Name == $vm and .[0].State == "stopped"
  and ([.[0].Hardware | keys[] | select(startswith("cdrom"))]
       | all(. == "cdrom0" or . == "cdrom1"))
  and (.[0].Hardware.cdrom0 == null
       or (.[0].Hardware.cdrom0.enabled == true
           and .[0].Hardware.cdrom0.image == $installer))
  and (.[0].Hardware.cdrom1 == null
       or (.[0].Hardware.cdrom1.enabled == true
           and .[0].Hardware.cdrom1.image == $seed))
' >/dev/null <<<"$info"; then
  echo "$vm is not stopped or has an unexpected optical device or media path." >&2
  exit 1
fi

while IFS= read -r device; do
  [[ -n "$device" ]] && "$prlctl" set "$vm" --device-del "$device"
done < <(
  jq -r '.[0].Hardware | keys[] | select(. == "cdrom0" or . == "cdrom1")' <<<"$info"
)

# Parallels 27.0.3 resets this flag to on when an optical device is deleted.
"$prlctl" set "$vm" --auto-share-gamepad off

info="$("$prlctl" list -a -i -j "$vm")"
jq -e --arg vm "$vm" '
  type == "array" and length == 1
  and .[0].Name == $vm and .[0].State == "stopped"
  and ([.[0].Hardware | keys[] | select(startswith("cdrom"))] | length) == 0
  and .[0]["USB and Bluetooth"]["Automatic sharing cameras"] == "off"
  and .[0]["USB and Bluetooth"]["Automatic sharing bluetooth"] == "off"
  and .[0]["USB and Bluetooth"]["Automatic sharing smart cards"] == "off"
  and .[0]["USB and Bluetooth"]["Automatic sharing gamepads"] == "off"
  and .[0]["USB and Bluetooth"]["Support USB 3.0"] == "off"
' >/dev/null <<<"$info" || {
  echo "$vm installer-media removal could not be verified." >&2
  exit 1
}

echo "$vm installer media removed and automatic gamepad sharing re-disabled."
