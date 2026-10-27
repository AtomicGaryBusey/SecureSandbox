#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

# This installer is also reused by the encrypted conversation-archive
# activation path to install the shared pinned-TLS client.  Preserve an
# already-configured metadata shipper across that update instead of silently
# disabling off-host evidence collection.
shipper_was_enabled=0
shipper_was_active=0
systemctl is-enabled --quiet azure-shipper.service 2>/dev/null && shipper_was_enabled=1
systemctl is-active --quiet azure-shipper.service 2>/dev/null && shipper_was_active=1

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

if [[ "$shipper_was_enabled" -eq 1 ]]; then
  systemctl enable azure-shipper.service >/dev/null
  if [[ "$shipper_was_active" -eq 1 ]]; then
    test -r /etc/secure-sandbox/azure-shipper.json
    test -r /etc/credstore.encrypted/azure-shipper.client_secret
    systemctl restart azure-shipper.service
    systemctl is-active --quiet azure-shipper.service
  fi
else
  systemctl disable --now azure-shipper.service >/dev/null 2>&1 || true
fi

if [[ "$shipper_was_active" -eq 1 ]]; then
  echo "azure-shipper:installed-active-state-restored"
else
  echo "azure-shipper:installed-inactive"
fi
