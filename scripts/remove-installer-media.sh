#!/bin/bash
set -euo pipefail

prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"
installer="/Library/Application Support/SecureSandbox/installers/c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804.iso"
release_manager="/usr/local/libexec/secure-sandbox-host/current/release_manager"

[[ -x "$prlctl" ]] || { echo "Parallels prlctl was not found." >&2; exit 1; }
[[ $# -eq 1 ]] || {
  echo "Usage: remove-installer-media.sh SecureSandbox-{Gateway|Research|Target}" >&2
  exit 2
}

vm="$1"
case "$vm" in
  SecureSandbox-Gateway) seed_payload="seed_gateway" ;;
  SecureSandbox-Research) seed_payload="seed_research" ;;
  SecureSandbox-Target) seed_payload="seed_target" ;;
  *) echo "Unknown managed VM: $vm" >&2; exit 2 ;;
esac

[[ -x "$release_manager" && ! -L "$release_manager" ]] || {
  echo "The protected Host release verifier is unavailable." >&2
  exit 1
}
release_verification="$($release_manager verify --json)" || {
  echo "The protected Host release could not be verified." >&2
  exit 1
}
release_binding="$(/usr/bin/python3 -I -c '
import json
import re
import sys

value = json.load(sys.stdin)
payload = sys.argv[1]
release_id = value.get("release_id")
digest = value.get("payloads", {}).get(payload)
if (value.get("schema") != "secure-sandbox-host-controller-release-v1"
        or value.get("status") != "verified"
        or not isinstance(release_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", release_id) is None
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
    raise SystemExit(1)
print(f"{release_id}\t{digest}")
' "$seed_payload" <<<"$release_verification")" || {
  echo "The protected Host release or seed binding is invalid." >&2
  exit 1
}
IFS=$'\t' read -r release_id seed_sha256 <<<"$release_binding"
seed="/usr/local/libexec/secure-sandbox-host/releases/$release_id/$seed_payload"
[[ -f "$seed" && ! -L "$seed" && "$(/usr/bin/stat -f '%u:%g:%Lp' "$seed")" == "0:0:444" ]] || {
  echo "The protected seed identity is invalid." >&2
  exit 1
}
[[ "$(/bin/ls -lde "$seed" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] || {
  echo "The protected seed has an extended ACL." >&2
  exit 1
}
[[ "$(/usr/bin/shasum -a 256 "$seed" | /usr/bin/awk '{print $1}')" == "$seed_sha256" ]] || {
  echo "The protected seed digest is invalid." >&2
  exit 1
}

info="$("$prlctl" list -a -i -j "$vm")"
devices="$(/usr/bin/python3 -I -c '
import json
import sys

value = json.load(sys.stdin)
vm, installer, seed = sys.argv[1:]
if not isinstance(value, list) or len(value) != 1:
    raise SystemExit(1)
record = value[0]
hardware = record.get("Hardware")
if record.get("Name") != vm or record.get("State") != "stopped" or not isinstance(hardware, dict):
    raise SystemExit(1)
devices = sorted(name for name in hardware if name.startswith("cdrom"))
if any(name not in {"cdrom0", "cdrom1"} for name in devices):
    raise SystemExit(1)
for name, expected in (("cdrom0", installer), ("cdrom1", seed)):
    device = hardware.get(name)
    if device is not None and (not isinstance(device, dict)
            or device.get("enabled") is not True or device.get("image") != expected):
        raise SystemExit(1)
print("\n".join(devices))
' "$vm" "$installer" "$seed" <<<"$info")" || {
  echo "$vm is not stopped or has an unexpected optical device or media path." >&2
  exit 1
}

while IFS= read -r device; do
  [[ -n "$device" ]] && "$prlctl" set "$vm" --device-del "$device"
done <<<"$devices"

# Parallels 27.0.3 resets this flag to on when an optical device is deleted.
"$prlctl" set "$vm" --auto-share-gamepad off

info="$("$prlctl" list -a -i -j "$vm")"
/usr/bin/python3 -I -c '
import json
import sys

value = json.load(sys.stdin)
vm = sys.argv[1]
if not isinstance(value, list) or len(value) != 1:
    raise SystemExit(1)
record = value[0]
hardware = record.get("Hardware")
usb = record.get("USB and Bluetooth")
required_off = (
    "Automatic sharing cameras", "Automatic sharing bluetooth",
    "Automatic sharing smart cards", "Automatic sharing gamepads",
    "Support USB 3.0",
)
if (record.get("Name") != vm or record.get("State") != "stopped"
        or not isinstance(hardware, dict)
        or any(name.startswith("cdrom") for name in hardware)
        or not isinstance(usb, dict)
        or any(usb.get(name) != "off" for name in required_off)):
    raise SystemExit(1)
' "$vm" <<<"$info" || {
  echo "$vm installer-media removal could not be verified." >&2
  exit 1
}

echo "$vm installer media removed and automatic gamepad sharing re-disabled."
