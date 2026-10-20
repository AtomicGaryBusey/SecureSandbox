#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
watchdog="${1:-/tmp/run_lease_watchdog.py}"
unit="${2:-/tmp/run-lease-watchdog.service}"
launcher="${3:-/tmp/research-claude.proposed}"
rollback="${4:-/tmp/rollback-run-leases-research.sh}"
telemetry="${5:-/tmp/telemetry_exporter.py}"
supervisor="${6:-/tmp/run_lease_process.py}"
persona="${7:-/tmp/glm-persona.md}"
sudoers="${8:-/tmp/run-lease-supervisor.sudoers}"
for source in "$watchdog" "$unit" "$launcher" "$rollback" "$telemetry" "$supervisor" "$persona" "$sudoers"; do [[ -f "$source" && ! -L "$source" ]] || exit 2; done
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m py_compile "$watchdog" "$telemetry" "$supervisor"; bash -n "$launcher" "$rollback"; visudo -cf "$sudoers" >/dev/null
backup_id="run-leases-research-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for current in /usr/local/libexec/secure-sandbox/run_lease_watchdog.py /usr/local/libexec/secure-sandbox/run_lease_process.py /etc/sudoers.d/secure-sandbox-run-lease /etc/systemd/system/run-lease-watchdog.service /usr/local/bin/research-claude /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh /usr/local/libexec/secure-sandbox/telemetry_exporter.py /etc/claude-code/secure-sandbox-persona.md; do
  name="$(basename "$current")"; if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR
install -o root -g root -m 755 "$watchdog" /usr/local/libexec/secure-sandbox/run_lease_watchdog.py
install -o root -g root -m 755 "$supervisor" /usr/local/libexec/secure-sandbox/run_lease_process.py
install -o root -g root -m 440 "$sudoers" /etc/sudoers.d/secure-sandbox-run-lease
install -o root -g root -m 644 "$unit" /etc/systemd/system/run-lease-watchdog.service
install -o root -g root -m 755 "$launcher" /usr/local/bin/research-claude
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 444 "$persona" /etc/claude-code/secure-sandbox-persona.md
systemd-analyze verify /etc/systemd/system/run-lease-watchdog.service >/dev/null
rm -f /run/secure-sandbox/run-lease.json /run/secure-sandbox/run-process.json
systemctl daemon-reload
systemctl enable run-lease-watchdog.service >/dev/null
systemctl restart run-lease-watchdog.service
systemctl is-active --quiet run-lease-watchdog.service
systemctl restart telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/run-leases-research-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/run-leases-research-latest
trap - ERR
echo "run-leases-research:installed:$backup_id"

