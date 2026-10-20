#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
getent group conversation-shipper >/dev/null || groupadd --system conversation-shipper
id conversation-shipper >/dev/null 2>&1 || useradd --system --gid conversation-shipper --home-dir /nonexistent --shell /usr/sbin/nologin conversation-shipper
dir=/etc/secure-sandbox/conversation-transport
[[ ! -e "$dir/client.key" ]] || { echo "Refusing to replace key." >&2; exit 2; }
install -d -o root -g conversation-shipper -m 750 "$dir"
openssl genpkey -algorithm ED25519 -out "$dir/client.key"
openssl req -new -key "$dir/client.key" -out /tmp/research-conversation.csr -subj '/CN=secure-sandbox-research-conversation'
chown root:conversation-shipper "$dir/client.key"; chmod 640 "$dir/client.key"; chmod 644 /tmp/research-conversation.csr
echo conversation-transport:csr-ready
