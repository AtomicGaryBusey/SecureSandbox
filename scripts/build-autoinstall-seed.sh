#!/bin/zsh
set -euo pipefail

# Build a NoCloud seed ISO without putting plaintext credentials or private
# keys on disk. The output does contain a password hash and is therefore kept
# outside version control and removed after provisioning.

workspace_dir="${0:A:h:h}"
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
control_public_key="$("$op_cli" read "op://Agents/SecureSandbox-Control/public key")"

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
  '  updates: security' \
  > "$work_dir/user-data"

print '  late-commands:' >> "$work_dir/user-data"
print '    - install -d -m 0700 /target/root/secure-sandbox-control-bootstrap' >> "$work_dir/user-data"
for item in \
  "$workspace_dir/scripts/privileged_control.py:privileged_control.py:0755" \
  "$workspace_dir/scripts/privileged_control_entry.py:privileged_control_entry.py:0755" \
  "$workspace_dir/scripts/install-privileged-control.sh:install-privileged-control.sh:0755" \
  "$workspace_dir/config/privileged-control.sudoers:privileged-control.sudoers:0600" \
  "$workspace_dir/config/sshd-control.conf:sshd-control.conf:0600" \
  "$workspace_dir/config/netplan-$role.yaml:netplan.yaml:0600"; do
  source="${item%%:*}"; remainder="${item#*:}"; name="${remainder%%:*}"; mode="${remainder##*:}"
  encoded="$(base64 < "$source" | tr -d '\n')"
  print "    - /bin/sh -c \"printf '%s' '$encoded' | base64 -d > /target/root/secure-sandbox-control-bootstrap/$name && chmod $mode /target/root/secure-sandbox-control-bootstrap/$name\"" >> "$work_dir/user-data"
done
control_public_key_encoded="$(print -r -- "$control_public_key" | base64 | tr -d '\n')"
print "    - /bin/sh -c \"printf '%s' '$control_public_key_encoded' | base64 -d > /target/root/secure-sandbox-control-bootstrap/control_key.pub && chmod 0600 /target/root/secure-sandbox-control-bootstrap/control_key.pub\"" >> "$work_dir/user-data"
print "    - /bin/sh -c \"if [ -e /target/etc/netplan/00-installer-config.yaml ]; then [ ! -e /target/etc/netplan/00-installer-config.yaml.installer-backup ] && mv -- /target/etc/netplan/00-installer-config.yaml /target/etc/netplan/00-installer-config.yaml.installer-backup; fi\"" >> "$work_dir/user-data"
print "    - install -D -m 0600 /target/root/secure-sandbox-control-bootstrap/netplan.yaml /target/etc/netplan/10-secure-sandbox.yaml" >> "$work_dir/user-data"
print "    - curtin in-target -- netplan generate" >> "$work_dir/user-data"
print "    - curtin in-target -- /root/secure-sandbox-control-bootstrap/install-privileged-control.sh $role /root/secure-sandbox-control-bootstrap/control_key.pub" >> "$work_dir/user-data"
print '    - rm -rf /target/root/secure-sandbox-control-bootstrap' >> "$work_dir/user-data"
print '  shutdown: poweroff' >> "$work_dir/user-data"

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
