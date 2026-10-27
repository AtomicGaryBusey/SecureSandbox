#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi

broker_source="${1:-/tmp/model_broker.py}"
service_source="${2:-/tmp/model-broker.service}"
config_source="${3:-/tmp/broker.mock.json}"
client_cert="${4:-/tmp/research-client.crt}"
renderer_source="${5:-/tmp/render_gateway_firewall.py}"
shared_init="${6:-/tmp/__init__.py}"
bounded_http="${7:-/tmp/bounded_http.py}"

for source in "$broker_source" "$service_source" "$config_source" "$client_cert" "$renderer_source" "$shared_init" "$bounded_http"; do
  [[ -f "$source" ]] || { echo "Missing required file: $source" >&2; exit 2; }
done

if ! getent group model-broker >/dev/null; then
  groupadd --system model-broker
fi
if ! id model-broker >/dev/null 2>&1; then
  useradd --system --gid model-broker --home-dir /nonexistent \
    --shell /usr/sbin/nologin model-broker
fi

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -o root -g root -m 644 "$shared_init" /usr/local/libexec/secure-sandbox/shared/__init__.py
install -o root -g root -m 755 "$bounded_http" /usr/local/libexec/secure-sandbox/shared/bounded_http.py
install -d -o root -g model-broker -m 750 /etc/secure-sandbox/pki
install -o root -g root -m 755 "$broker_source" \
  /usr/local/libexec/secure-sandbox/model_broker.py
install -o root -g root -m 755 "$renderer_source" \
  /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
install -o root -g root -m 644 "$service_source" \
  /etc/systemd/system/model-broker.service

for required_pki in ca.key ca.crt server.key server.crt; do
  [[ -f "/etc/secure-sandbox/pki/$required_pki" ]] || {
    echo "Gateway PKI is not initialized: $required_pki" >&2
    exit 2
  }
done

fingerprint="$(openssl x509 -in "$client_cert" -outform DER | sha256sum | awk '{print $1}')"
sed "s/CLIENT_CERT_SHA256/$fingerprint/" "$config_source" \
  > /etc/secure-sandbox/broker.json

chown root:model-broker \
  /etc/secure-sandbox/pki/ca.crt \
  /etc/secure-sandbox/pki/server.crt \
  /etc/secure-sandbox/pki/server.key \
  /etc/secure-sandbox/broker.json
chmod 640 \
  /etc/secure-sandbox/pki/ca.crt \
  /etc/secure-sandbox/pki/server.crt \
  /etc/secure-sandbox/pki/server.key \
  /etc/secure-sandbox/broker.json
chmod 600 /etc/secure-sandbox/pki/ca.key
rm -f /etc/secure-sandbox/pki/server.csr /etc/secure-sandbox/pki/ca.srl

/usr/local/libexec/secure-sandbox/model_broker.py \
  --config /etc/secure-sandbox/broker.json --validate
systemd-analyze security model-broker.service --offline=yes >/dev/null
systemctl daemon-reload
systemctl enable --now model-broker.service
systemctl is-active --quiet model-broker.service

echo "model-broker:active"
