#!/bin/zsh
set -euo pipefail

workspace_dir="$(cd "$(dirname "$0")/.." && pwd)"
release_directory="$workspace_dir/artifacts/ubuntu-26.04.1"
output_iso="$workspace_dir/artifacts/ubuntu-26.04.1/ubuntu-26.04.1-autoinstall-arm64.iso"
grub_cfg="$workspace_dir/autoinstall/grub.cfg"
xorriso_bin="/opt/homebrew/bin/xorriso"
verifier="/usr/local/libexec/secure-sandbox-host/current/installer_verifier"

for required in "$grub_cfg" "$xorriso_bin" "$verifier"; do
  if [[ ! -e "$required" ]]; then
    print -u2 "Required input is missing: $required"
    exit 1
  fi
done
[[ -x "$verifier" && ! -L "$verifier" ]] || { print -u2 "Installer verifier is unavailable."; exit 1; }
source_iso="$(/usr/bin/sudo /usr/bin/python3 "$verifier" --release-directory "$release_directory" --promote --path-only)"
[[ "$source_iso" == /Library/Application\ Support/SecureSandbox/installers/*.iso ]] || {
  print -u2 "Installer verifier returned an invalid protected path."
  exit 1
}

umask 077
"$xorriso_bin" \
  -indev "$source_iso" \
  -outdev "$output_iso" \
  -boot_image any replay \
  -map "$grub_cfg" /boot/grub/grub.cfg \
  -end

/bin/chmod 600 "$output_iso"
/usr/bin/shasum -a 256 "$output_iso"
