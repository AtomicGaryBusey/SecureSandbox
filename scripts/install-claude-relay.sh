#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi

relay_source="${1:-/tmp/claude_relay.py}"
service_source="${2:-/tmp/claude-relay.service}"
client_cert="${3:-/tmp/client.crt}"
ca_cert="${4:-/tmp/ca.crt}"
run_id_source="${5:-/tmp/manage_run_id.py}"

for source in "$relay_source" "$service_source" "$client_cert" "$ca_cert" "$run_id_source"; do
  [[ -f "$source" ]] || { echo "Missing required file: $source" >&2; exit 2; }
done

if ! getent group claude-relay >/dev/null; then
  groupadd --system claude-relay
fi
if ! id claude-relay >/dev/null 2>&1; then
  useradd --system --gid claude-relay --home-dir /nonexistent \
    --shell /usr/sbin/nologin claude-relay
fi

identity_dir=/etc/secure-sandbox/relay
source_identity_dir=/home/agent/.config/secure-sandbox
if [[ -f "$source_identity_dir/client.key" && ! -L "$source_identity_dir/client.key" \
    && "$(stat -c %h "$source_identity_dir/client.key")" == 1 ]]; then
  client_key="$source_identity_dir/client.key"
elif [[ -f "$identity_dir/client.key" && ! -L "$identity_dir/client.key" \
    && "$(stat -c %h "$identity_dir/client.key")" == 1 ]]; then
  client_key="$identity_dir/client.key"
else
  echo "Research client private key is missing." >&2
  exit 2
fi

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g claude-relay -m 750 "$identity_dir"
install -o root -g root -m 755 "$relay_source" \
  /usr/local/libexec/secure-sandbox/claude_relay.py
install -o root -g root -m 755 "$run_id_source" \
  /usr/local/libexec/secure-sandbox/manage_run_id.py
install -o root -g root -m 644 "$service_source" \
  /etc/systemd/system/claude-relay.service
if [[ "$client_key" != "$identity_dir/client.key" ]]; then
  install -o root -g claude-relay -m 640 "$client_key" "$identity_dir/client.key"
fi
install -o root -g claude-relay -m 640 "$client_cert" "$identity_dir/client.crt"
install -o root -g claude-relay -m 640 "$ca_cert" "$identity_dir/ca.crt"
rm -f "$source_identity_dir/client.key" "$source_identity_dir/client.csr"

python3 -m py_compile /usr/local/libexec/secure-sandbox/claude_relay.py
python3 -m py_compile /usr/local/libexec/secure-sandbox/manage_run_id.py
systemd-analyze security claude-relay.service --offline=yes >/dev/null
systemctl daemon-reload
systemctl enable --now claude-relay.service
systemctl is-active --quiet claude-relay.service

echo "claude-relay:active"
