#!/bin/bash
set -euo pipefail

role="${1:-}"
public_key_file="${2:-}"
case "$role" in gateway|research|target) ;; *) echo "role_invalid" >&2; exit 2;; esac
[[ -f "$public_key_file" && ! -L "$public_key_file" ]] || { echo "public_key_invalid" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "root_required" >&2; exit 1; }

script_dir="$(cd "$(dirname "$0")" && pwd)"
config_dir="$script_dir"
[[ -f "$config_dir/privileged-control.sudoers" ]] || config_dir="$(cd "$script_dir/../config" && pwd)"
for name in privileged_control.py privileged_control_entry.py privileged-control.sudoers sshd-control.conf; do
  source_dir="$script_dir"
  case "$name" in privileged-control.sudoers|sshd-control.conf) source_dir="$config_dir";; esac
  [[ -f "$source_dir/$name" && ! -L "$source_dir/$name" ]] || { echo "payload_invalid:$name" >&2; exit 2; }
done

public_key="$(cat "$public_key_file")"
[[ "$public_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}(\ [A-Za-z0-9._@+-]+)?$ ]] \
  || { echo "public_key_invalid" >&2; exit 2; }
python3 -m py_compile "$script_dir/privileged_control.py" "$script_dir/privileged_control_entry.py"
visudo -cf "$config_dir/privileged-control.sudoers" >/dev/null

if ! id securectl >/dev/null 2>&1; then
  useradd --system --home-dir /var/empty/securectl --shell /bin/sh securectl
fi
# Keep the account valid for SSH public-key authentication without creating a
# reusable credential. Password authentication is disabled globally.
control_password_hash="$(openssl rand -hex 32 | openssl passwd -6 -stdin)"
printf 'securectl:%s\n' "$control_password_hash" | chpasswd -e
unset control_password_hash
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox /etc/secure-sandbox \
  /etc/ssh/authorized_keys /var/empty/securectl
install -d -o root -g root -m 700 /var/lib/secure-sandbox/control /var/lib/secure-sandbox/control/staging
install -o root -g root -m 755 "$script_dir/privileged_control.py" /usr/local/libexec/secure-sandbox/privileged_control.py
install -o root -g root -m 755 "$script_dir/privileged_control_entry.py" /usr/local/libexec/secure-sandbox/privileged_control_entry.py
install -o root -g root -m 444 "$config_dir/privileged-control.sudoers" /etc/sudoers.d/secure-sandbox-control
install -o root -g root -m 644 "$config_dir/sshd-control.conf" /etc/ssh/sshd_config.d/15-secure-sandbox-control.conf
install -o root -g root -m 644 "$public_key_file" /etc/ssh/authorized_keys/securectl
# Retire the pre-control-plane host automation grants.  All surviving callers
# use the forced-command securectl channel and its typed operation allowlist.
rm -f -- \
  /etc/sudoers.d/secure-sandbox-source-import \
  /etc/sudoers.d/secure-sandbox-dependency-orchestration \
  /etc/sudoers.d/secure-sandbox-codegraph
role_source="$script_dir/.control-role"
umask 077
printf '%s\n' "$role" > "$role_source"
install -o root -g root -m 644 "$role_source" /etc/secure-sandbox/control-role
rm -f -- "$role_source"

if [[ -f /etc/ssh/sshd_config.d/10-secure-sandbox.conf ]] \
    && ! grep -Eq '^AllowUsers([[:space:]].*)?([[:space:]]|^)securectl([[:space:]]|$)' /etc/ssh/sshd_config.d/10-secure-sandbox.conf; then
  sed -Ei 's/^AllowUsers (.*)$/AllowUsers \1 securectl/' /etc/ssh/sshd_config.d/10-secure-sandbox.conf
fi
visudo -c >/dev/null
sshd -t
ssh_state_status=0
ssh_state="$(systemctl is-active ssh.service 2>/dev/null)" || ssh_state_status=$?
case "$ssh_state_status:$ssh_state" in
  0:active)
    systemctl reload ssh.service
    ssh_reloaded=false
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      ssh_state_status=0
      ssh_state="$(systemctl is-active ssh.service 2>/dev/null)" || ssh_state_status=$?
      case "$ssh_state_status:$ssh_state" in
        0:active) ssh_reloaded=true; break ;;
        0:reloading) sleep 0.1 ;;
        *) echo "ssh_service_not_active_after_reload:${ssh_state:-unavailable}" >&2; exit 1 ;;
      esac
    done
    [[ "$ssh_reloaded" == true ]] \
      || { echo "ssh_service_reload_timeout" >&2; exit 1; }
    ;;
  3:inactive) ;;
  *) echo "ssh_service_state_invalid:${ssh_state:-unavailable}" >&2; exit 1 ;;
esac
/usr/local/libexec/secure-sandbox/privileged_control.py internal control-self-check >/dev/null
echo "privileged-control:installed:$role"
