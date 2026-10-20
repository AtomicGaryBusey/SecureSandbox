#!/bin/zsh
set -euo pipefail

# Build a NoCloud seed ISO without putting plaintext credentials or private
# keys on disk. The output does contain a password hash and is therefore kept
# outside version control and removed after provisioning.

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seed_dir="$workspace_dir/seeds"
op_cli="$HOME/.local/bin/op-agents"

if (( $# != 1 )); then
  print -u2 "Usage: $0 gateway|research|target"
  exit 2
fi

role="$1"
case "$role" in
  gateway)
    hostname="sandbox-gateway"
    credential_item="SecureSandbox-Gateway"
    ;;
  research)
    hostname="sandbox-research"
    credential_item="SecureSandbox-Research"
    ;;
  target)
    hostname="sandbox-target"
    credential_item="SecureSandbox-Target"
    ;;
  *)
    print -u2 "Unknown role: $role"
    exit 2
    ;;
esac

if [[ ! -x "$op_cli" ]]; then
  print -u2 "1Password wrapper is unavailable: $op_cli"
  exit 1
fi

umask 077
/bin/mkdir -p "$seed_dir"
work_dir="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/secure-sandbox-seed.XXXXXX")"
trap '/bin/rm -rf "$work_dir"' EXIT INT TERM

# The plaintext password flows directly from 1Password to OpenSSL over a pipe.
password_hash="$("$op_cli" read "op://Agents/$credential_item/password" | /opt/homebrew/bin/openssl passwd -6 -stdin)"
public_key="$("$op_cli" read "op://Agents/SecureSandbox-Provisioning/public key")"

/usr/bin/printf '%s\n' \
  "instance-id: secure-sandbox-$role" \
  "local-hostname: $hostname" \
  > "$work_dir/meta-data"

/usr/bin/printf '%s\n' \
  '#cloud-config' \
  'autoinstall:' \
  '  version: 1' \
  '  locale: en_US.UTF-8' \
  '  keyboard:' \
  '    layout: us' \
  '  identity:' \
  "    hostname: $hostname" \
  '    username: labadmin' \
  "    password: '$password_hash'" \
  '  ssh:' \
  '    install-server: true' \
  '    allow-pw: false' \
  '    authorized-keys:' \
  "      - $public_key" \
  '  storage:' \
  '    layout:' \
  '      name: direct' \
  '  packages:' \
  '    - auditd' \
  '    - ca-certificates' \
  '    - curl' \
  '    - nftables' \
  '    - openssh-server' \
  '  updates: security' \
  '  shutdown: poweroff' \
  > "$work_dir/user-data"

output_iso="$seed_dir/$role-cidata.iso"
/usr/bin/hdiutil makehybrid \
  -o "$output_iso" \
  "$work_dir" \
  -iso -joliet \
  -iso-volume-name cidata \
  -joliet-volume-name cidata \
  -ov -quiet
/bin/chmod 600 "$output_iso"

print "Created $output_iso"
