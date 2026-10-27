#!/bin/bash
set -euo pipefail
backup_id="${1:-}"
[[ "$backup_id" =~ ^conversation-capture-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "backup_id_invalid" >&2; exit 2; }
test ! -e /run/secure-sandbox/run-id
! pgrep -x claude >/dev/null
install -d -o root -g root -m 700 "/var/lib/secure-sandbox/policy-backups/$backup_id"
cp --no-dereference /usr/local/libexec/secure-sandbox/conversation_capture.py "/var/lib/secure-sandbox/policy-backups/$backup_id/conversation_capture.py"
cp --no-dereference /usr/local/libexec/secure-sandbox/telemetry_exporter.py "/var/lib/secure-sandbox/policy-backups/$backup_id/telemetry_exporter.py"
install -o root -g root -m 755 /tmp/conversation_capture.py /usr/local/libexec/secure-sandbox/conversation_capture.py
install -o root -g root -m 755 /tmp/telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py
python3 -m py_compile /usr/local/libexec/secure-sandbox/conversation_capture.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py
rm -f /run/secure-sandbox/conversation-capture-fatal /run/secure-sandbox/conversation-capture-ready
systemctl restart conversation-capture.service telemetry-exporter.service
for ignored in 1 2 3 4 5; do test -f /run/secure-sandbox/conversation-capture-ready && break; sleep 1; done
systemctl is-active --quiet conversation-capture.service telemetry-exporter.service
test -f /run/secure-sandbox/conversation-capture-ready
test ! -e /run/secure-sandbox/conversation-capture-fatal
/usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
echo "conversation-capture:fixed:$backup_id"
