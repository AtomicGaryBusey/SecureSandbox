#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/findings-adjudication-latest)}"
[[ "$backup_id" =~ ^findings-adjudication-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid backup ID" >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" && ! -L "$backup" ]] || { echo "Backup not found" >&2; exit 2; }
systemctl disable --now findings-broker.service >/dev/null 2>&1 || true
restore() {
  local name="$1" destination="$2" mode="$3"
  if [[ -f "$backup/$name" ]]; then install -o root -g root -m "$mode" "$backup/$name" "$destination"
  elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"
  else echo "Incomplete backup: $name" >&2; exit 2; fi
}
restore findings_broker.py /usr/local/libexec/secure-sandbox/findings_broker.py 755
restore findings_mcp.py /usr/local/libexec/secure-sandbox/findings_mcp.py 755
restore finding_admin.py /usr/local/libexec/secure-sandbox/finding_admin.py 755
restore findings-broker.service /etc/systemd/system/findings-broker.service 644
restore managed-settings.json /etc/claude-code/managed-settings.json 644
restore managed-mcp.json /etc/claude-code/managed-mcp.json 644
restore secure-sandbox-persona.md /etc/claude-code/secure-sandbox-persona.md 444
restore telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py 755
restore rollback_findings_adjudication.sh /usr/local/libexec/secure-sandbox/rollback_findings_adjudication.sh 755
systemctl daemon-reload
if [[ -f /etc/systemd/system/findings-broker.service ]]; then systemctl enable --now findings-broker.service; fi
systemctl restart telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
echo "findings-adjudication:rolled-back:$backup_id"
