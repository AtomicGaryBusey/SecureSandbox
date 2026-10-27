#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ "$(cat /etc/secure-sandbox/control-role 2>/dev/null)" == research ]] || {
  echo "This installer is restricted to Research." >&2
  exit 2
}

provisioning_mac="${1:-}"
[[ "$provisioning_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || {
  echo "A provisioning-interface MAC is required." >&2
  exit 2
}
provisioning_mac="${provisioning_mac,,}"

interface=""
for address_file in /sys/class/net/*/address; do
  [[ "$(tr '[:upper:]' '[:lower:]' < "$address_file")" == "$provisioning_mac" ]] || continue
  interface="$(basename "$(dirname "$address_file")")"
done
[[ -n "$interface" && "$interface" != lo && "$interface" != ctl0 && "$interface" != lab0 ]] || {
  echo "Provisioning interface is missing or conflicts with a restricted interface." >&2
  exit 2
}

netplan=/etc/netplan/90-secure-sandbox-provisioning.yaml
resolv_backup="$(mktemp /run/secure-sandbox-resolv.XXXXXX)"
maintenance_policy="$(mktemp /run/secure-sandbox-maintenance-nft.XXXXXX)"
package_staging="$(mktemp -d /var/tmp/secure-sandbox-research-packages.XXXXXX)"
chown _apt:nogroup "$package_staging"
chmod 0700 "$package_staging"
verified_staging="$(mktemp -d /var/tmp/secure-sandbox-research-verified.XXXXXX)"
chmod 0700 "$verified_staging"
audit_config=""
audit_config_backup=""
audit_config_new=""
cp --no-dereference /etc/resolv.conf "$resolv_backup"
nft -c -f /etc/nftables.conf

cleanup() {
  status=$?
  trap - EXIT INT TERM
  cleanup_failed=0
  if [[ -n "$audit_config_backup" && -f "$audit_config_backup" ]]; then
    if ! install -o root -g root -m 0640 "$audit_config_backup" "$audit_config" \
        || ! /usr/sbin/service auditd restart; then
      echo "Failed to restore the prior auditd configuration; backup retained at $audit_config_backup." >&2
      cleanup_failed=1
    else
      rm -f -- "$audit_config_backup"
      audit_config_backup=""
    fi
  fi
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
  rm -f -- "$resolv_backup" "$maintenance_policy" "$audit_config_new"
  rm -rf -- "$package_staging"
  rm -rf -- "$verified_staging"
  if (( cleanup_failed != 0 )); then return 70; fi
  if (( status != 0 )); then return "$status"; fi
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
export DEBIAN_FRONTEND=noninteractive
gpgv --version >/dev/null
apt-get update --error-on=any
verified_debs=()
download_verified_deb() {
  local package="$1" version="$2" expected_sha256="$3" directory deb sealed architecture
  directory="$package_staging/$package"
  install -d -o _apt -g nogroup -m 0700 "$directory"
  (cd "$directory" && apt-get download "$package=$version")
  shopt -s nullglob
  local candidates=("$directory"/*.deb)
  shopt -u nullglob
  [[ "${#candidates[@]}" -eq 1 ]] || { echo "Expected one archive for $package=$version." >&2; exit 2; }
  deb="${candidates[0]}"
  sealed="$verified_staging/$package.deb"
  install -o root -g root -m 0600 "$deb" "$sealed"
  [[ "$(stat -c '%u:%g:%a:%h' "$sealed")" == "0:0:600:1" ]]
  [[ "$(sha256sum "$sealed" | awk '{print $1}')" == "$expected_sha256" ]] || {
    echo "Package digest mismatch for $package=$version." >&2
    exit 2
  }
  architecture="$(dpkg-deb -f "$sealed" Architecture)"
  [[ "$(dpkg-deb -f "$sealed" Package)" == "$package" \
      && "$(dpkg-deb -f "$sealed" Version)" == "$version" \
      && ( "$architecture" == "$(dpkg --print-architecture)" || "$architecture" == all ) ]] || {
    echo "Package identity mismatch for $package=$version." >&2
    exit 2
  }
  verified_debs+=("$sealed")
}
download_verified_deb age 1.2.1-1build1 51b8f2008cb57eddd57ce8038dbdd9409ea9b6ee08459d35c3752e8c87dca7cd
download_verified_deb auditd 1:4.1.2-1ubuntu0.1 297513b0e4f8eed57731f253537e2b918337ee11fc05fc83d627725656b4e284
require_clean_dpkg_state() {
  local audit pending_triggers
  audit="$(dpkg --audit)"
  [[ -z "$audit" ]] || {
    echo "Dirty dpkg state refused before verified package installation: $audit" >&2
    exit 2
  }
  pending_triggers="$(cat /var/lib/dpkg/triggers/Unincorp 2>/dev/null || true)"
  [[ -z "$pending_triggers" ]] || {
    echo "Pending dpkg triggers refused before verified package installation." >&2
    exit 2
  }
}
require_clean_dpkg_state
install_plan="$(apt-get --simulate --no-install-recommends install "${verified_debs[@]}")"
unexpected_packages="$(printf '%s\n' "$install_plan" | awk '
    /^(Inst|Conf|Remv|Purg) / { print $1 " " $2 }
  ' | awk '
    $1 != "Inst" && $1 != "Conf" { print; next }
    $2 !~ /^(age|auditd)$/ { print }
  ')"
[[ -z "$unexpected_packages" ]] || {
  echo "Unbound or destructive package action refused: $unexpected_packages" >&2
  exit 2
}
apt-get install -y --no-install-recommends --no-download "${verified_debs[@]}"
require_clean_dpkg_state
audit_config=/etc/audit/auditd.conf
[[ -f "$audit_config" && ! -L "$audit_config" ]] || {
  echo "auditd configuration is not a trusted regular file" >&2
  exit 2
}
[[ "$(stat -c '%u:%g:%a:%h' "$audit_config")" == "0:0:640:1" ]] || {
  echo "auditd configuration metadata is not trusted" >&2
  exit 2
}
audit_config_new="$(mktemp /etc/audit/.auditd.conf.XXXXXX)"
audit_config_backup="$(mktemp /etc/audit/.auditd.conf.backup.XXXXXX)"
install -o root -g root -m 0640 "$audit_config" "$audit_config_backup"
awk '
  BEGIN { replaced = 0 }
  /^[[:space:]]*log_format[[:space:]]*=/ {
    if (replaced) exit 42
    print "log_format = ENRICHED"
    replaced = 1
    next
  }
  { print }
  END { if (!replaced) print "log_format = ENRICHED" }
' "$audit_config" > "$audit_config_new" || {
  status=$?
  rm -f -- "$audit_config_new" "$audit_config_backup"
  exit "$status"
}
install -o root -g root -m 0640 "$audit_config_new" "$audit_config"
rm -f -- "$audit_config_new"
audit_config_new=""
systemctl enable auditd.service >/dev/null
/usr/sbin/service auditd restart || {
  echo "auditd rejected the ENRICHED configuration; restoring the prior file" >&2
  exit 2
}
command -v auditctl >/dev/null
[[ "$(command -v age)" == /usr/bin/age ]]
[[ "$(stat -c '%u:%g:%a:%h' /usr/bin/age)" == "0:0:755:1" ]]
[[ "$(dpkg-query -W -f='${db:Status-Status}' age)" == installed ]]
[[ "$(dpkg-query -W -f='${Version}' age)" == 1.2.1-1build1 ]]
[[ "$(dpkg-query -W -f='${Version}' auditd)" == 1:4.1.2-1ubuntu0.1 ]]
[[ -z "$(dpkg -V age)" ]]
audit_package_drift="$(dpkg -V auditd | grep -v ' /etc/audit/auditd.conf$' || true)"
[[ -z "$audit_package_drift" ]]
age --version >/dev/null
systemctl is-active --quiet auditd.service
[[ "$(awk -F= '/^[[:space:]]*log_format[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2}' "$audit_config")" == ENRICHED ]]

rm -f -- "$audit_config_backup"
audit_config_backup=""

cleanup
trap - EXIT INT TERM
! ip -4 route show default | grep -q .
[[ ! -e "$netplan" ]]
echo "research-auditd:installed"
