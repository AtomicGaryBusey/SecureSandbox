#!/bin/zsh
set -euo pipefail

workspace_dir="$(cd "$(dirname "$0")/.." && pwd)"
release_directory="$workspace_dir/artifacts/ubuntu-26.04.1"
output_iso="$workspace_dir/artifacts/ubuntu-26.04.1/ubuntu-26.04.1-autoinstall-arm64.iso"
temporary_iso="$workspace_dir/artifacts/ubuntu-26.04.1/.ubuntu-26.04.1-autoinstall-arm64.iso.partial"
grub_cfg="$workspace_dir/autoinstall/grub.cfg"
xorriso_bin="/opt/homebrew/bin/xorriso"
verifier="/usr/local/libexec/secure-sandbox-host/current/installer_verifier"
expected_grub_sha256="cef9d2eb488ba983c1744fa7f4739454c337b5f20dcef4961f1b6614489fb284"
expected_iso_sha256="c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804"
fixed_iso_time="2026082607384200"
fixed_gpt_guid="38c5428a3e2f8746900d92659b7e5d75"
requesting_agent="${SECURE_SANDBOX_REQUESTING_AGENT:-}"
requesting_session="${SECURE_SANDBOX_REQUESTING_SESSION:-}"
while (( $# )); do
  case "$1" in
    --requesting-agent) requesting_agent="${2:-}"; shift 2 ;;
    --requesting-session) requesting_session="${2:-}"; shift 2 ;;
    *) print -u2 "Usage: $0 --requesting-agent NAME --requesting-session ID"; exit 2 ;;
  esac
done
[[ -n "$requesting_agent" && -n "$requesting_session" ]] || {
  print -u2 "Autoinstall publication requires --requesting-agent and --requesting-session."
  exit 2
}

for required in "$grub_cfg" "$xorriso_bin" "$verifier"; do
  if [[ ! -e "$required" ]]; then
    print -u2 "Required input is missing: $required"
    exit 1
  fi
done
[[ -x "$verifier" && ! -L "$verifier" ]] || { print -u2 "Installer verifier is unavailable."; exit 1; }
[[ "$(/usr/bin/shasum -a 256 "$grub_cfg" | /usr/bin/awk '{print $1}')" == "$expected_grub_sha256" ]] || {
  print -u2 "The reviewed autoinstall boot configuration has changed."
  exit 1
}
source_iso="$(/usr/bin/python3 -I "$verifier" --release-directory "$release_directory" --use-promoted --path-only)"
[[ "$source_iso" == /Library/Application\ Support/SecureSandbox/installers/*.iso ]] || {
  print -u2 "Installer verifier returned an invalid protected path."
  exit 1
}

umask 077
[[ ! -L "$output_iso" && ! -L "$temporary_iso" ]] || {
  print -u2 "Refusing an unsafe autoinstall output path."
  exit 1
}
if [[ -e "$output_iso" ]]; then
  [[ -f "$output_iso" && "$(stat -f %u "$output_iso")" == "$EUID" \
    && "$(stat -f %l "$output_iso")" == 1 ]] || {
    print -u2 "Refusing an unsafe existing autoinstall image."
    exit 1
  }
  actual="$(/usr/bin/shasum -a 256 "$output_iso" | /usr/bin/awk '{print $1}')"
  [[ "$actual" == "$expected_iso_sha256" ]] || {
    print -u2 "Existing autoinstall image is not the reviewed derivative."
    exit 1
  }
else
  [[ ! -e "$temporary_iso" ]] || {
    print -u2 "An unreconciled autoinstall build is present."
    exit 1
  }
  trap '/bin/rm -f "$temporary_iso"' EXIT INT TERM
"$xorriso_bin" \
  -indev "$source_iso" \
  -outdev "$temporary_iso" \
  -iso_nowtime "$fixed_iso_time" \
  -boot_image any replay \
  -boot_image any gpt_disk_guid="$fixed_gpt_guid" \
  -map "$grub_cfg" /boot/grub/grub.cfg \
  -chown 0 /boot/grub/grub.cfg -- \
  -chgrp 0 /boot/grub/grub.cfg -- \
  -chmod 0444 /boot/grub/grub.cfg -- \
  -alter_date_r b "$fixed_iso_time" / -- \
  -find / -exec set_to_mtime -- \
  -volume_date c "$fixed_iso_time" \
  -volume_date m "$fixed_iso_time" \
  -volume_date uuid "$fixed_iso_time" \
  -end

  actual="$(/usr/bin/shasum -a 256 "$temporary_iso" | /usr/bin/awk '{print $1}')"
  [[ "$actual" == "$expected_iso_sha256" ]] || {
    print -u2 "Built autoinstall image does not match the reviewed derivative."
    exit 1
  }
  /bin/chmod 600 "$temporary_iso"
  /bin/mv "$temporary_iso" "$output_iso"
  trap - EXIT INT TERM
fi

/bin/chmod 600 "$output_iso"
"$workspace_dir/scripts/installer-operation.py" promote-autoinstall \
  --requesting-agent "$requesting_agent" --requesting-session "$requesting_session"
protected_path="$(/usr/bin/python3 -I "$verifier" \
  --release-directory "$release_directory" --use-promoted-autoinstall --path-only)"
[[ "$protected_path" == "/Library/Application Support/SecureSandbox/installers/$expected_iso_sha256.iso" ]] || {
  print -u2 "Installer verifier returned an invalid protected autoinstall path."
  exit 1
}
/usr/bin/python3 -I "$verifier" --release-directory "$release_directory" \
  --use-promoted-autoinstall --path-only >/dev/null
/bin/rm "$output_iso"
print "Protected autoinstall image verified at $protected_path"
print "Removed the redundant mutable derivative after protected verification."
