#!/bin/zsh
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_iso="$workspace_dir/artifacts/ubuntu-26.04.1/ubuntu-26.04.1-live-server-arm64.iso"
output_iso="$workspace_dir/artifacts/ubuntu-26.04.1/ubuntu-26.04.1-autoinstall-arm64.iso"
grub_cfg="$workspace_dir/autoinstall/grub.cfg"
xorriso_bin="/opt/homebrew/bin/xorriso"

for required in "$source_iso" "$grub_cfg" "$xorriso_bin"; do
  if [[ ! -e "$required" ]]; then
    print -u2 "Required input is missing: $required"
    exit 1
  fi
done

umask 077
"$xorriso_bin" \
  -indev "$source_iso" \
  -outdev "$output_iso" \
  -boot_image any replay \
  -map "$grub_cfg" /boot/grub/grub.cfg \
  -end

/bin/chmod 600 "$output_iso"
/usr/bin/shasum -a 256 "$output_iso"
