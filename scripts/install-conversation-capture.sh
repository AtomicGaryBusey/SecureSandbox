#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
capture="${1:-/tmp/conversation_capture.py}"
shipper="${2:-/tmp/conversation_shipper.py}"
capture_unit="${3:-/tmp/conversation-capture.service}"
shipper_unit="${4:-/tmp/conversation-shipper.service}"
recipient_file="${5:-/tmp/conversation-recipient.txt}"
cert="${6:-/tmp/research-conversation.crt}"
ca="${7:-/tmp/ca.crt}"
age_binary="${8:-/tmp/age}"
renderer="${9:-/tmp/render_research_firewall.py}"
failure_unit="${10:-/tmp/conversation-capture-failure.service}"
for source in "$capture" "$shipper" "$capture_unit" "$shipper_unit" "$recipient_file" "$cert" "$ca" "$age_binary" "$renderer" "$failure_unit"; do
  [[ -f "$source" ]] || { echo "Missing $source" >&2; exit 2; }
done
getent group conversation-shipper >/dev/null || groupadd --system conversation-shipper
id conversation-shipper >/dev/null 2>&1 || useradd --system --gid conversation-shipper --home-dir /nonexistent --shell /usr/sbin/nologin conversation-shipper
identity=/etc/secure-sandbox/conversation-transport
[[ -f "$identity/client.key" ]] || { echo "Conversation transport key is missing." >&2; exit 2; }
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g conversation-shipper -m 750 /var/lib/secure-sandbox/conversation-capture "$identity"
install -d -o root -g conversation-shipper -m 2770 /var/lib/secure-sandbox/conversation-outbox
install -d -o root -g conversation-shipper -m 2770 /var/lib/secure-sandbox/conversation-quarantine
install -o root -g root -m 755 "$capture" /usr/local/libexec/secure-sandbox/conversation_capture.py
install -o root -g root -m 755 "$shipper" /usr/local/libexec/secure-sandbox/conversation_shipper.py
install -o root -g root -m 755 "$renderer" /usr/local/libexec/secure-sandbox/render_research_firewall.py
install -o root -g root -m 755 "$age_binary" /usr/local/bin/age
install -o root -g root -m 644 "$capture_unit" /etc/systemd/system/conversation-capture.service
install -o root -g root -m 644 "$shipper_unit" /etc/systemd/system/conversation-shipper.service
install -o root -g root -m 644 "$failure_unit" /etc/systemd/system/conversation-capture-failure.service
install -o root -g root -m 644 "$recipient_file" /etc/secure-sandbox/conversation-recipient.txt
install -o root -g conversation-shipper -m 640 "$cert" "$identity/client.crt"
install -o root -g conversation-shipper -m 640 "$ca" "$identity/ca.crt"
chown root:conversation-shipper "$identity/client.key"; chmod 640 "$identity/client.key"
python3 -m py_compile /usr/local/libexec/secure-sandbox/conversation_capture.py /usr/local/libexec/secure-sandbox/conversation_shipper.py
/usr/local/libexec/secure-sandbox/render_research_firewall.py --output /run/research-nftables.new
nft -c -f /run/research-nftables.new
install -o root -g root -m 600 /run/research-nftables.new /etc/nftables.conf
nft -f /etc/nftables.conf
rm -f /run/research-nftables.new
systemctl daemon-reload
systemctl enable --now conversation-capture.service conversation-shipper.service
systemctl is-active --quiet conversation-capture.service conversation-shipper.service
echo conversation-capture:active
