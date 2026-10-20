#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/evidence-receipts-latest)}"
[[ "$backup_id" =~ ^evidence-receipts-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid backup ID" >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "Backup not found" >&2; exit 2; }
systemctl disable --now corpus-broker.service >/dev/null 2>&1 || true
restore() {
  local name="$1" destination="$2" mode="$3"
  if [[ -f "$backup/$name" ]]; then install -o root -g root -m "$mode" "$backup/$name" "$destination"
  elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"
  else echo "Incomplete backup: $name" >&2; exit 2; fi
}
restore evidence_receipts.py /usr/local/libexec/secure-sandbox/evidence_receipts.py 755
restore bounded_unix_server.py /usr/local/libexec/secure-sandbox/bounded_unix_server.py 755
restore corpus_broker.py /usr/local/libexec/secure-sandbox/corpus_broker.py 755
restore corpus-broker.service /etc/systemd/system/corpus-broker.service 644
restore corpus_intelligence_mcp.py /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py 755
restore execution_broker.py /usr/local/libexec/secure-sandbox/execution_broker.py 755
restore execution_mcp.py /usr/local/libexec/secure-sandbox/execution_mcp.py 755
restore execution-broker.service /etc/systemd/system/execution-broker.service 644
restore findings_broker.py /usr/local/libexec/secure-sandbox/findings_broker.py 755
restore findings_mcp.py /usr/local/libexec/secure-sandbox/findings_mcp.py 755
restore findings-broker.service /etc/systemd/system/findings-broker.service 644
restore telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py 755
restore secure-sandbox-persona.md /etc/claude-code/secure-sandbox-persona.md 444
restore rollback_evidence_receipts.sh /usr/local/libexec/secure-sandbox/rollback_evidence_receipts.sh 755
restore update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh 755
systemctl daemon-reload
systemctl restart execution-broker.service findings-broker.service telemetry-exporter.service
if [[ -f /etc/systemd/system/corpus-broker.service ]]; then systemctl enable --now corpus-broker.service; fi
/usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
echo "evidence-receipts:rolled-back:$backup_id"
