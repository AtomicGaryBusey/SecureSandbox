#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

receiver_source="${1:-/tmp/telemetry_receiver.py}"
local_source="${2:-/tmp/local_telemetry_exporter.py}"
receiver_unit="${3:-/tmp/telemetry-receiver.service}"
local_unit="${4:-/tmp/local-telemetry-exporter.service}"
config_template="${5:-/tmp/telemetry.json}"
client_cert="${6:-/tmp/research-telemetry.crt}"
shared_init="${7:-/tmp/__init__.py}"
bounded_http="${8:-/tmp/bounded_http.py}"

for source in "$receiver_source" "$local_source" "$receiver_unit" \
  "$local_unit" "$config_template" "$client_cert" "$shared_init" "$bounded_http"; do
  [[ -f "$source" ]] || { echo "Missing required file: $source" >&2; exit 2; }
done
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -o root -g root -m 644 "$shared_init" /usr/local/libexec/secure-sandbox/shared/__init__.py
install -o root -g root -m 755 "$bounded_http" /usr/local/libexec/secure-sandbox/shared/bounded_http.py
for source in ca.crt server.crt server.key; do
  [[ -f "/etc/secure-sandbox/pki/$source" ]] || {
    echo "Gateway broker PKI is missing: $source" >&2
    exit 2
  }
done

if ! getent group telemetry >/dev/null; then
  groupadd --system telemetry
fi
if ! id telemetry >/dev/null 2>&1; then
  useradd --system --gid telemetry --home-dir /nonexistent \
    --shell /usr/sbin/nologin telemetry
fi

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g telemetry -m 750 /etc/secure-sandbox/telemetry
install -d -o telemetry -g telemetry -m 770 /var/lib/secure-sandbox/telemetry
install -o root -g root -m 755 "$receiver_source" \
  /usr/local/libexec/secure-sandbox/telemetry_receiver.py
install -o root -g root -m 755 "$local_source" \
  /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py
install -o root -g root -m 644 "$receiver_unit" \
  /etc/systemd/system/telemetry-receiver.service
install -o root -g root -m 644 "$local_unit" \
  /etc/systemd/system/local-telemetry-exporter.service
install -o root -g telemetry -m 640 /etc/secure-sandbox/pki/ca.crt \
  /etc/secure-sandbox/telemetry/ca.crt
install -o root -g telemetry -m 640 /etc/secure-sandbox/pki/server.crt \
  /etc/secure-sandbox/telemetry/server.crt
install -o root -g telemetry -m 640 /etc/secure-sandbox/pki/server.key \
  /etc/secure-sandbox/telemetry/server.key

fingerprint="$(openssl x509 -in "$client_cert" -outform DER | sha256sum | awk '{print $1}')"
sed "s/CLIENT_CERT_SHA256/$fingerprint/" "$config_template" \
  > /etc/secure-sandbox/telemetry.json
chown root:telemetry /etc/secure-sandbox/telemetry.json
chmod 640 /etc/secure-sandbox/telemetry.json

python3 -m py_compile \
  /usr/local/libexec/secure-sandbox/telemetry_receiver.py \
  /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py
systemd-analyze security telemetry-receiver.service --offline=yes >/dev/null
systemd-analyze security local-telemetry-exporter.service --offline=yes >/dev/null
systemctl daemon-reload
systemctl enable --now telemetry-receiver.service local-telemetry-exporter.service
systemctl is-active --quiet telemetry-receiver.service
systemctl is-active --quiet local-telemetry-exporter.service

echo "gateway-telemetry:active"
