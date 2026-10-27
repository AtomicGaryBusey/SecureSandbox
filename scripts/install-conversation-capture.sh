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
if [[ ! -f "$age_binary" && -x /usr/bin/age ]]; then age_binary=/usr/bin/age; fi
for source in "$capture" "$shipper" "$capture_unit" "$shipper_unit" "$recipient_file" "$cert" "$ca" "$age_binary" "$renderer" "$failure_unit"; do
  [[ -f "$source" ]] || { echo "Missing $source" >&2; exit 2; }
done
[[ "$age_binary" == /usr/bin/age ]]
[[ "$(stat -c '%u:%g:%a:%h' "$age_binary")" == "0:0:755:1" ]]
[[ "$(dpkg-query -W -f='${db:Status-Status}' age)" == installed ]]
[[ -z "$(dpkg -V age)" ]]
"$age_binary" --version >/dev/null
getent group conversation-shipper >/dev/null || groupadd --system conversation-shipper
id conversation-shipper >/dev/null 2>&1 || useradd --system --gid conversation-shipper --home-dir /nonexistent --shell /usr/sbin/nologin conversation-shipper
id agent >/dev/null 2>&1 || { echo "Agent account is missing." >&2; exit 2; }
install -d -o agent -g agent -m 700 /home/agent/.claude /home/agent/.claude/projects
test "$(stat -c %U:%G:%a /home/agent/.claude/projects)" = agent:agent:700
identity=/etc/secure-sandbox/conversation-transport
[[ -d "$identity" && ! -L "$identity" \
  && -f "$identity/client.key" && ! -L "$identity/client.key" \
  && "$(stat -c %h "$identity/client.key")" == 1 ]] \
  || { echo "Conversation transport key is missing or untrusted." >&2; exit 2; }
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g conversation-shipper -m 750 /var/lib/secure-sandbox/conversation-capture "$identity"
install -d -o root -g root -m 755 /var/lib/secure-sandbox/run-lifecycle
install -d -o root -g root -m 700 /var/lib/secure-sandbox/run-lifecycle/capture-receipts
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
rm -f /run/secure-sandbox/conversation-capture-fatal /run/secure-sandbox/conversation-capture-ready
systemctl enable --now conversation-capture.service conversation-shipper.service
for _ in $(seq 1 20); do
  [[ -f /run/secure-sandbox/conversation-capture-ready ]] && break
  sleep 0.25
done
systemctl is-active --quiet conversation-capture.service conversation-shipper.service
test -f /run/secure-sandbox/conversation-capture-ready
test ! -e /run/secure-sandbox/conversation-capture-fatal
systemctl reset-failed conversation-capture-failure.service >/dev/null 2>&1 || true
echo conversation-capture:active
