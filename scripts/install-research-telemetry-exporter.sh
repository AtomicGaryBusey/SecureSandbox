#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi
[[ "$(id -u agent)" == 1001 ]] || {
  echo "The audited agent identity must have the pinned UID 1001." >&2
  exit 2
}

exporter_source="${1:-/tmp/telemetry_exporter.py}"
unit_source="${2:-/tmp/telemetry-exporter.service}"
client_cert="${3:-/tmp/research-telemetry.crt}"
ca_cert="${4:-/tmp/ca.crt}"
audit_rules="${5:-/tmp/50-secure-sandbox.rules}"
firewall_renderer="${6:-/tmp/render_research_firewall.py}"

for source in "$exporter_source" "$unit_source" "$client_cert" "$ca_cert" "$audit_rules" "$firewall_renderer"; do
  [[ -f "$source" ]] || { echo "Missing required file: $source" >&2; exit 2; }
done

if ! getent group telemetry-exporter >/dev/null; then
  groupadd --system telemetry-exporter
fi
if ! id telemetry-exporter >/dev/null 2>&1; then
  useradd --system --gid telemetry-exporter --home-dir /nonexistent \
    --shell /usr/sbin/nologin telemetry-exporter
fi

identity_dir=/etc/secure-sandbox/telemetry
[[ -d "$identity_dir" && ! -L "$identity_dir" \
  && -f "$identity_dir/client.key" && ! -L "$identity_dir/client.key" \
  && "$(stat -c %h "$identity_dir/client.key")" == 1 ]] || {
  echo "Telemetry client private key is missing." >&2
  exit 2
}
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g telemetry-exporter -m 750 "$identity_dir"
install -o root -g root -m 755 "$exporter_source" \
  /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 755 "$firewall_renderer" \
  /usr/local/libexec/secure-sandbox/render_research_firewall.py
install -o root -g root -m 644 "$unit_source" \
  /etc/systemd/system/telemetry-exporter.service
install -o root -g root -m 600 "$audit_rules" \
  /etc/audit/rules.d/50-secure-sandbox.rules
install -o root -g telemetry-exporter -m 640 "$client_cert" \
  "$identity_dir/client.crt"
install -o root -g telemetry-exporter -m 640 "$ca_cert" \
  "$identity_dir/ca.crt"
chown root:telemetry-exporter "$identity_dir/client.key"
chmod 640 "$identity_dir/client.key"
rm -f /tmp/research-telemetry.csr

python3 -m py_compile /usr/local/libexec/secure-sandbox/telemetry_exporter.py
/usr/local/libexec/secure-sandbox/render_research_firewall.py --output /run/research-nftables.new
nft -c -f /run/research-nftables.new
install -o root -g root -m 600 /run/research-nftables.new /etc/nftables.conf
nft -f /etc/nftables.conf
rm -f /run/research-nftables.new
systemd-analyze security telemetry-exporter.service --offline=yes >/dev/null
augenrules --load >/dev/null
systemctl daemon-reload
systemctl enable --now telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service

echo "research-telemetry:active"
