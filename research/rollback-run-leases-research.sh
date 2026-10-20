#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/run-leases-research-latest)}"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"; [[ -d "$backup" ]] || exit 2
systemctl disable --now run-lease-watchdog.service >/dev/null 2>&1 || true
for destination in /usr/local/libexec/secure-sandbox/run_lease_watchdog.py /usr/local/libexec/secure-sandbox/run_lease_process.py /etc/sudoers.d/secure-sandbox-run-lease /etc/systemd/system/run-lease-watchdog.service /usr/local/bin/research-claude /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh /usr/local/libexec/secure-sandbox/telemetry_exporter.py /etc/claude-code/secure-sandbox-persona.md; do
  name="$(basename "$destination")"; if [[ -f "$backup/$name" ]]; then cp --no-dereference "$backup/$name" "$destination"; elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"; fi
done
if [[ -f /etc/sudoers.d/secure-sandbox-run-lease ]]; then visudo -cf /etc/sudoers.d/secure-sandbox-run-lease >/dev/null; fi
rm -f /run/secure-sandbox/run-lease.json /run/secure-sandbox/run-process.json
systemctl daemon-reload
if [[ -f /etc/systemd/system/run-lease-watchdog.service ]]; then systemctl enable --now run-lease-watchdog.service; fi
systemctl restart telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
echo "run-leases-research:rolled-back:$backup_id"

