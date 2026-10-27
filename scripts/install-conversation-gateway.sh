#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }
receiver="${1:-/tmp/conversation_receiver.py}"; shipper="${2:-/tmp/conversation_azure_shipper.py}"
receiver_unit="${3:-/tmp/conversation-receiver.service}"; shipper_unit="${4:-/tmp/conversation-azure-shipper.service}"
client_cert="${5:-/tmp/research-conversation.crt}"
shared_init="${6:-/tmp/__init__.py}"; bounded_http="${7:-/tmp/bounded_http.py}"
for source in "$receiver" "$shipper" "$receiver_unit" "$shipper_unit" "$shared_init" "$bounded_http"; do [[ -f "$source" ]] || exit 2; done
getent group conversation-archive >/dev/null || groupadd --system conversation-archive
getent group conversation-azure >/dev/null || groupadd --system conversation-azure
id conversation-receiver >/dev/null 2>&1 || useradd --system --gid conversation-archive --groups telemetry --home-dir /nonexistent --shell /usr/sbin/nologin conversation-receiver
id conversation-azure >/dev/null 2>&1 || useradd --system --gid conversation-azure --groups conversation-archive --home-dir /nonexistent --shell /usr/sbin/nologin conversation-azure
install -d -o conversation-receiver -g conversation-archive -m 2770 /var/lib/secure-sandbox/conversation-spool
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox/shared
install -o root -g root -m 644 "$shared_init" /usr/local/libexec/secure-sandbox/shared/__init__.py
install -o root -g root -m 755 "$bounded_http" /usr/local/libexec/secure-sandbox/shared/bounded_http.py
install -o root -g root -m 755 "$receiver" /usr/local/libexec/secure-sandbox/conversation_receiver.py
install -o root -g root -m 755 "$shipper" /usr/local/libexec/secure-sandbox/conversation_azure_shipper.py
install -o root -g root -m 644 "$receiver_unit" /etc/systemd/system/conversation-receiver.service
install -o root -g root -m 644 "$shipper_unit" /etc/systemd/system/conversation-azure-shipper.service
[[ -f "$client_cert" ]] || { echo "Missing $client_cert" >&2; exit 2; }
fingerprint="$(openssl x509 -in "$client_cert" -outform DER | sha256sum | awk '{print $1}')"
printf '{"server_certificate":"/etc/secure-sandbox/telemetry/server.crt","server_private_key":"/etc/secure-sandbox/telemetry/server.key","client_ca_certificate":"/etc/secure-sandbox/telemetry/ca.crt","allowed_client_sha256":["%s"]}\n' "$fingerprint" > /etc/secure-sandbox/conversation-receiver.json
chown root:conversation-archive /etc/secure-sandbox/conversation-receiver.json
chmod 640 /etc/secure-sandbox/conversation-receiver.json
python3 -m py_compile /usr/local/libexec/secure-sandbox/conversation_receiver.py /usr/local/libexec/secure-sandbox/conversation_azure_shipper.py
systemctl daemon-reload; systemctl enable --now conversation-receiver.service
echo conversation-gateway:receiver-active
