#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi

if ! getent group telemetry-exporter >/dev/null; then
  groupadd --system telemetry-exporter
fi
if ! id telemetry-exporter >/dev/null 2>&1; then
  useradd --system --gid telemetry-exporter --home-dir /nonexistent \
    --shell /usr/sbin/nologin telemetry-exporter
fi

identity_dir=/etc/secure-sandbox/telemetry
if [[ -e "$identity_dir/client.key" || -L "$identity_dir/client.key" ]]; then
  echo "Refusing to replace existing telemetry client key." >&2
  exit 2
fi

install -d -o root -g telemetry-exporter -m 750 "$identity_dir"
openssl genpkey -algorithm ED25519 -out "$identity_dir/client.key"
openssl req -new -key "$identity_dir/client.key" \
  -out /tmp/research-telemetry.csr \
  -subj '/CN=secure-sandbox-research-telemetry'
chown root:telemetry-exporter "$identity_dir/client.key"
chmod 640 "$identity_dir/client.key"
chmod 644 /tmp/research-telemetry.csr

echo "research-telemetry-identity:csr-ready"
