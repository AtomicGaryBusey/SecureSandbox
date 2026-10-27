#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Target." >&2; exit 1; }
[[ "$(cat /etc/secure-sandbox/control-role 2>/dev/null)" == target ]] || {
  echo "This installer is restricted to Target." >&2
  exit 2
}

provisioning_mac="${1:-}"
installer="${2:-/tmp/install-rootless-docker.sh}"
[[ "$provisioning_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || {
  echo "A provisioning-interface MAC is required." >&2
  exit 2
}
[[ -f "$installer" && ! -L "$installer" ]] || { echo "Rootless Docker installer is missing." >&2; exit 2; }
bash -n "$installer"
provisioning_mac="${provisioning_mac,,}"

interface=""
for address_file in /sys/class/net/*/address; do
  [[ "$(tr '[:upper:]' '[:lower:]' < "$address_file")" == "$provisioning_mac" ]] || continue
  interface="$(basename "$(dirname "$address_file")")"
done
[[ -n "$interface" && "$interface" != lo && "$interface" != lab0 ]] || {
  echo "Provisioning interface is missing or conflicts with a restricted interface." >&2
  exit 2
}

netplan=/etc/netplan/90-secure-sandbox-provisioning.yaml
resolv_backup="$(mktemp /run/secure-sandbox-resolv.XXXXXX)"
maintenance_policy="$(mktemp /run/secure-sandbox-maintenance-nft.XXXXXX)"
cp --no-dereference /etc/resolv.conf "$resolv_backup"
nft -c -f /etc/nftables.conf

cleanup() {
  status=$?
  trap - EXIT INT TERM
  cleanup_failed=0
  if ! nft -c -f /etc/nftables.conf || ! nft -f /etc/nftables.conf; then
    cleanup_failed=1
  fi
  ruleset=""
  if ! ruleset="$(nft list ruleset)"; then
    cleanup_failed=1
  elif [[ "$(grep -c 'policy drop' <<<"$ruleset")" -ne 3 ]] \
      || nft list table inet secure_sandbox_maintenance >/dev/null 2>&1; then
    cleanup_failed=1
  fi
  runtime_interface=""
  for address_file in /sys/class/net/*/address; do
    [[ "$(tr '[:upper:]' '[:lower:]' < "$address_file")" == "$provisioning_mac" ]] || continue
    runtime_interface="$(basename "$(dirname "$address_file")")"
  done
  rm -f -- "$netplan"
  if ! netplan apply >/dev/null 2>&1; then cleanup_failed=1; fi
  if [[ -n "$runtime_interface" ]]; then
    if ! networkctl down "$runtime_interface" >/dev/null 2>&1; then cleanup_failed=1; fi
    if ! ip address flush dev "$runtime_interface" >/dev/null 2>&1; then cleanup_failed=1; fi
    if ! ip link set dev "$runtime_interface" down >/dev/null 2>&1; then cleanup_failed=1; fi
  fi
  if ! cp --no-dereference "$resolv_backup" /etc/resolv.conf; then cleanup_failed=1; fi
  rm -f -- "$resolv_backup" "$maintenance_policy"
  if (( status != 0 )); then return "$status"; fi
  if (( cleanup_failed != 0 )); then return 70; fi
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat > "$maintenance_policy" <<EOF
flush ruleset
table inet secure_sandbox_maintenance {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "$interface" udp sport 67 udp dport 68 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    oifname "$interface" udp sport 68 udp dport 67 accept
    oifname "$interface" ip daddr 10.211.55.1 udp dport 53 accept
    oifname "$interface" ip daddr 10.211.55.1 tcp dport 53 accept
    oifname "$interface" tcp dport { 80, 443 } accept
  }
}
EOF
chmod 0600 "$maintenance_policy"
nft -c -f "$maintenance_policy"
nft -f "$maintenance_policy"

cat > "$netplan" <<EOF
network:
  version: 2
  ethernets:
    provisioning0:
      match:
        macaddress: "$provisioning_mac"
      dhcp4: true
      dhcp6: false
      optional: true
EOF
chmod 0600 "$netplan"
netplan generate
netplan apply
printf 'nameserver 10.211.55.1\noptions timeout:1 attempts:2\n' > /etc/resolv.conf
gpgv --version >/dev/null

/bin/bash "$installer"

cleanup
trap - EXIT INT TERM
! ip -4 route show default | grep -q .
[[ ! -e "$netplan" ]]
echo "target-rootless-docker:installed-contained"
