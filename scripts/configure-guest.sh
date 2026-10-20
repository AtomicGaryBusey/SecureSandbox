#!/bin/bash
set -euo pipefail

role="${1:-}"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root." >&2
  exit 1
fi

case "$role" in
  gateway|research|target) ;;
  *)
    echo "Usage: configure-guest.sh gateway|research|target" >&2
    exit 2
    ;;
esac

require_mac() {
  local name="$1" value="${!1:-}"
  if [[ ! "$value" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; then
    echo "$name must be set to a six-octet MAC address." >&2
    exit 2
  fi
}

require_ipv4() {
  local name="$1" value="${!1:-}"
  if ! python3 - "$value" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 else 1)
PY
  then
    echo "$name must be set to one IPv4 address." >&2
    exit 2
  fi
}

case "$role" in
  gateway)
    require_mac SECURE_SANDBOX_UPLINK_MAC
    require_mac SECURE_SANDBOX_CONTROL_MAC
    require_ipv4 SECURE_SANDBOX_ADMIN_SOURCE_IPV4
    ;;
  research)
    require_mac SECURE_SANDBOX_CONTROL_MAC
    require_mac SECURE_SANDBOX_LAB_MAC
    ;;
  target)
    require_mac SECURE_SANDBOX_LAB_MAC
    ;;
esac

if [[ -f /etc/netplan/00-installer-config.yaml && ! -e /etc/netplan/00-installer-config.yaml.installer-backup ]]; then
  mv /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.installer-backup
fi

case "$role" in
  gateway)
    cat > /etc/netplan/10-secure-sandbox.yaml <<EOF
network:
  version: 2
  ethernets:
    uplink0:
      match:
        macaddress: ${SECURE_SANDBOX_UPLINK_MAC}
      set-name: uplink0
      dhcp4: true
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
    ctl0:
      match:
        macaddress: ${SECURE_SANDBOX_CONTROL_MAC}
      set-name: ctl0
      addresses:
        - 172.30.10.1/27
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
EOF
    ;;
  research)
    cat > /etc/netplan/10-secure-sandbox.yaml <<EOF
network:
  version: 2
  ethernets:
    ctl0:
      match:
        macaddress: ${SECURE_SANDBOX_CONTROL_MAC}
      set-name: ctl0
      addresses:
        - 172.30.10.2/27
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
    lab0:
      match:
        macaddress: ${SECURE_SANDBOX_LAB_MAC}
      set-name: lab0
      addresses:
        - 172.30.20.1/27
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
EOF
    ;;
  target)
    cat > /etc/netplan/10-secure-sandbox.yaml <<EOF
network:
  version: 2
  ethernets:
    lab0:
      match:
        macaddress: ${SECURE_SANDBOX_LAB_MAC}
      set-name: lab0
      addresses:
        - 172.30.20.2/27
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
EOF
    ;;
esac
chmod 600 /etc/netplan/10-secure-sandbox.yaml

cat > /etc/sysctl.d/60-secure-sandbox.conf <<'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.io_uring_disabled = 2
EOF

cat > /etc/ssh/sshd_config.d/10-secure-sandbox.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
EOF

case "$role" in
  gateway)
    cat >> /etc/ssh/sshd_config.d/10-secure-sandbox.conf <<'EOF'
AllowUsers labadmin
Match User labadmin
    AllowTcpForwarding yes
    PermitOpen 172.30.10.2:22
Match all
EOF
    install -d -m 0755 /etc/secure-sandbox
    printf '%s\n' "$SECURE_SANDBOX_ADMIN_SOURCE_IPV4" > /etc/secure-sandbox/gateway-admin-source-ipv4
    chmod 600 /etc/secure-sandbox/gateway-admin-source-ipv4
    cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "uplink0" ip saddr ${SECURE_SANDBOX_ADMIN_SOURCE_IPV4} tcp dport 22 accept
    iifname "uplink0" udp sport 67 udp dport 68 accept
    iifname "ctl0" ip saddr 172.30.10.2 icmp type echo-request accept
    iifname "ctl0" ip saddr 172.30.10.2 tcp dport { 8443, 9443 } accept
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-in-deny " flags all counter
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-fwd-deny " flags all counter
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    oifname "uplink0" udp sport 68 udp dport 67 accept
    oifname "ctl0" ip daddr 172.30.10.2 tcp dport 22 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-out-deny " flags all counter
  }
}
EOF
    ;;
  research)
    if ! id agent >/dev/null 2>&1; then
      useradd --create-home --shell /bin/bash agent
    fi
    install -d -m 700 -o agent -g agent /home/agent/.ssh
    install -m 600 -o agent -g agent /home/labadmin/.ssh/authorized_keys /home/agent/.ssh/authorized_keys
    agent_hash="$(openssl rand -base64 48 | openssl passwd -6 -stdin)"
    printf 'agent:%s\n' "$agent_hash" | chpasswd -e
    cat >> /etc/ssh/sshd_config.d/10-secure-sandbox.conf <<'EOF'
AllowUsers labadmin agent
Match User labadmin
    AllowTcpForwarding yes
    PermitOpen 172.30.20.2:22
Match all
EOF
    cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "ctl0" ip saddr 172.30.10.1 tcp dport 22 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-r-in-deny " flags all counter
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-r-fwd-deny " flags all counter
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    oifname "ctl0" ip daddr 172.30.10.1 icmp type echo-request accept
    oifname "ctl0" ip daddr 172.30.10.1 tcp dport { 8443, 9443 } accept
    oifname "lab0" ip daddr 172.30.20.2 icmp type echo-request accept
    oifname "lab0" ip daddr 172.30.20.2 tcp dport { 22, 8080 } accept
    limit rate 5/second burst 10 packets log prefix "sandbox-r-out-deny " flags all counter
  }
}
EOF
    ;;
  target)
    cat >> /etc/ssh/sshd_config.d/10-secure-sandbox.conf <<'EOF'
AllowUsers labadmin
EOF
    cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "lab0" ip saddr 172.30.20.1 icmp type echo-request accept
    iifname "lab0" ip saddr 172.30.20.1 tcp dport { 22, 8080 } accept
    limit rate 5/second burst 10 packets log prefix "sandbox-t-in-deny " flags all counter
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-t-fwd-deny " flags all counter
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    limit rate 5/second burst 10 packets log prefix "sandbox-t-out-deny " flags all counter
  }
}
EOF
    ;;
esac

chmod 600 /etc/ssh/sshd_config.d/10-secure-sandbox.conf /etc/nftables.conf
sshd -t
nft -c -f /etc/nftables.conf
netplan generate

systemctl disable --now ufw.service >/dev/null 2>&1 || true
systemctl enable nftables.service >/dev/null
systemctl disable --now ssh.socket >/dev/null 2>&1 || true
systemctl enable ssh.service >/dev/null
sysctl --system >/dev/null
netplan apply
nft -f /etc/nftables.conf
systemctl restart ssh.service

# These guests deliberately have no package-update path at runtime.  Disable
# discovery/storage helpers and background clients that would otherwise create
# noisy denied traffic or expand the attack surface.  Time remains derived from
# the hypervisor-backed virtual clock; no guest NTP daemon is allowed to dial out.
systemctl disable --now chrony.service unattended-upgrades.service \
  ModemManager.service multipathd.service udisks2.service >/dev/null 2>&1 || true
systemctl mask chrony.service unattended-upgrades.service \
  ModemManager.service multipathd.service udisks2.service >/dev/null 2>&1 || true
systemctl disable --now systemd-networkd-wait-online.service >/dev/null 2>&1 || true
systemctl mask systemd-networkd-wait-online.service >/dev/null 2>&1 || true

# Runtime DNS is unnecessary on every role: all permitted service peers are
# literal IPs pinned by the trusted Mac during an explicit activation step.
systemctl disable --now systemd-resolved.service systemd-resolved.socket \
  systemd-resolved-varlink.socket systemd-resolved-monitor.socket >/dev/null 2>&1 || true
systemctl mask systemd-resolved.service systemd-resolved.socket \
  systemd-resolved-varlink.socket systemd-resolved-monitor.socket >/dev/null 2>&1 || true
if [[ -L /etc/resolv.conf ]]; then
  cp --dereference /etc/resolv.conf /etc/resolv.conf.secure-sandbox-backup 2>/dev/null || true
  unlink /etc/resolv.conf
fi
install -m 644 /dev/null /etc/resolv.conf

echo "configured:$role"
