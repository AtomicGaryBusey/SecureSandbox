#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
importer="${1:-/tmp/source_importer.py}"
wrapper="${2:-/tmp/source_import_wrapper.py}"
shipper=/tmp/conversation_shipper.py; shipper_unit=/tmp/conversation-shipper.service; telemetry=/tmp/telemetry_exporter.py
for source in "$importer" "$wrapper" "$shipper" "$shipper_unit" "$telemetry"; do [[ -f "$source" ]] || { echo "Missing $source" >&2; exit 2; }; done
getent group conversation-shipper >/dev/null || { echo "conversation-shipper group missing" >&2; exit 2; }
[[ -x /usr/local/bin/age && -f /etc/secure-sandbox/conversation-recipient.txt ]] || { echo "evidence prerequisites missing" >&2; exit 2; }
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g root -m 700 /var/lib/secure-sandbox/source-acquisition /var/lib/secure-sandbox/source-acquisition/staging
install -d -o agent -g agent -m 750 /home/agent/research-workspace
install -d -o root -g root -m 755 /home/agent/research-workspace/baselines /home/agent/research-workspace/repos /home/agent/research-workspace/source-manifests
install -o root -g root -m 755 "$importer" /usr/local/libexec/secure-sandbox/source_importer.py
install -o root -g root -m 755 "$wrapper" /usr/local/sbin/secure-sandbox-source-import
install -d -o root -g conversation-shipper -m 2770 /var/lib/secure-sandbox/conversation-quarantine
install -o root -g root -m 755 "$shipper" /usr/local/libexec/secure-sandbox/conversation_shipper.py
install -o root -g root -m 644 "$shipper_unit" /etc/systemd/system/conversation-shipper.service
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
python3 -m py_compile /usr/local/libexec/secure-sandbox/source_importer.py /usr/local/sbin/secure-sandbox-source-import \
  /usr/local/libexec/secure-sandbox/conversation_shipper.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py
rm -f -- /etc/sudoers.d/secure-sandbox-source-import
visudo -c >/dev/null
if [[ ! -f /home/agent/research-workspace/repos/INDEX.json ]]; then
  printf '%s\n' '{"schema":"secure-sandbox-source-registry-v1","sources":[]}' > /home/agent/research-workspace/repos/INDEX.json
  chown root:root /home/agent/research-workspace/repos/INDEX.json
  chmod 444 /home/agent/research-workspace/repos/INDEX.json
fi
systemctl daemon-reload
systemctl restart conversation-shipper.service telemetry-exporter.service
systemctl is-active --quiet conversation-shipper.service telemetry-exporter.service
if [[ -x /tmp/update-policy-hash.sh ]]; then /tmp/update-policy-hash.sh research >/dev/null; fi
echo source-acquisition:research-active
