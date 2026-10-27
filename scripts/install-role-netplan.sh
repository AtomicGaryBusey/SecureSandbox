#!/bin/bash
set -euo pipefail

role="${1:-}"
runtime_interface="${2:-}"
runtime_cidr="${3:-}"
role_file="/etc/secure-sandbox/control-role"
source_file="/tmp/netplan.yaml"
installer_config="/etc/netplan/00-installer-config.yaml"
installer_backup="/etc/netplan/00-installer-config.yaml.installer-backup"
managed_config="/etc/netplan/10-secure-sandbox.yaml"

[[ "$(id -u)" -eq 0 ]] || { echo "root_required" >&2; exit 1; }
case "$role" in gateway|research|target) ;; *) echo "role_invalid" >&2; exit 2;; esac
[[ -f "$role_file" && ! -L "$role_file" && "$(cat "$role_file")" == "$role" ]] \
  || { echo "role_binding_invalid" >&2; exit 2; }
[[ "$runtime_interface" =~ ^[a-zA-Z0-9._-]{1,32}$ ]] \
  || { echo "runtime_interface_invalid" >&2; exit 2; }
python3 - "$runtime_cidr" <<'PY' \
  || { echo "runtime_cidr_invalid" >&2; exit 2; }
import ipaddress
import sys

value = ipaddress.ip_interface(sys.argv[1])
if value.version != 4:
    raise SystemExit(1)
PY

[[ -f "$source_file" && ! -L "$source_file" ]] \
  || { echo "netplan_source_invalid" >&2; exit 2; }
read -r source_uid source_mode source_links source_size < <(stat -c '%u %a %h %s' "$source_file")
[[ "$source_uid" == 0 && "$source_links" == 1 && "$source_size" -gt 0 && "$source_size" -le 65536 ]] \
  || { echo "netplan_source_untrusted" >&2; exit 2; }
[[ "$source_mode" == 600 || "$source_mode" == 640 || "$source_mode" == 644 ]] \
  || { echo "netplan_source_mode_invalid" >&2; exit 2; }
/usr/sbin/ip link show dev "$runtime_interface" >/dev/null \
  || { echo "runtime_interface_missing" >&2; exit 2; }

if [[ -e "$managed_config" ]]; then
  cmp -s "$source_file" "$managed_config" \
    || { echo "managed_netplan_conflict" >&2; exit 2; }
else
  if [[ -e "$installer_config" ]]; then
    [[ ! -e "$installer_backup" ]] || { echo "installer_backup_conflict" >&2; exit 2; }
    mv -- "$installer_config" "$installer_backup"
  fi
  install -o root -g root -m 0600 "$source_file" "$managed_config"
  if ! /usr/sbin/netplan generate; then
    rm -f -- "$managed_config"
    if [[ -e "$installer_backup" && ! -e "$installer_config" ]]; then
      mv -- "$installer_backup" "$installer_config"
    fi
    /usr/sbin/netplan generate || true
    echo "netplan_generate_failed" >&2
    exit 1
  fi
fi

if ! /usr/sbin/ip link set dev "$runtime_interface" up \
    || ! /usr/sbin/ip address replace "$runtime_cidr" dev "$runtime_interface"; then
  echo "runtime_network_apply_failed" >&2
  exit 1
fi

echo "role-netplan:installed:$role"
