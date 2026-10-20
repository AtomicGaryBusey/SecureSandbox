#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

shipper_source="${1:-/tmp/azure_shipper.py}"
unit_source="${2:-/tmp/azure-shipper.service}"
renderer_source="${3:-/tmp/render_gateway_firewall.py}"
for source in "$shipper_source" "$unit_source" "$renderer_source"; do
  [[ -f "$source" ]] || { echo "Missing required file: $source" >&2; exit 2; }
done
getent group telemetry >/dev/null || {
  echo "Install the telemetry receiver before the Azure shipper." >&2
  exit 2
}
if ! getent group azure-shipper >/dev/null; then
  groupadd --system azure-shipper
fi
if ! id azure-shipper >/dev/null 2>&1; then
  useradd --system --gid azure-shipper --groups telemetry --home-dir /nonexistent \
    --shell /usr/sbin/nologin azure-shipper
fi

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o azure-shipper -g azure-shipper -m 700 /var/lib/secure-sandbox/azure-shipper
install -o root -g root -m 755 "$shipper_source" \
  /usr/local/libexec/secure-sandbox/azure_shipper.py
install -o root -g root -m 755 "$renderer_source" \
  /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
install -o root -g root -m 644 "$unit_source" \
  /etc/systemd/system/azure-shipper.service
python3 -m py_compile \
  /usr/local/libexec/secure-sandbox/azure_shipper.py \
  /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
systemd-analyze security azure-shipper.service --offline=yes >/dev/null
systemctl daemon-reload
systemctl disable --now azure-shipper.service >/dev/null 2>&1 || true

echo "azure-shipper:installed-inactive"
