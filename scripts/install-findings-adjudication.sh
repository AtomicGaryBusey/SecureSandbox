#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
broker="${1:-/tmp/findings_broker.py}"; mcp="${2:-/tmp/findings_mcp.py}"
admin="${3:-/tmp/finding_admin.py}"; unit="${4:-/tmp/findings-broker.service}"
settings="${5:-/tmp/managed-settings.proposed.json}"; managed_mcp="${6:-/tmp/managed-mcp.json}"
persona="${7:-/tmp/glm-persona.md}"; telemetry="${8:-/tmp/telemetry_exporter.py}"
rollback="${9:-/tmp/rollback_findings_adjudication.sh}"
update_policy_hash="/tmp/update-policy-hash.sh"
for source in "$broker" "$mcp" "$admin" "$unit" "$settings" "$managed_mcp" "$persona" "$telemetry" "$rollback" "$update_policy_hash"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Invalid deployment source: $source" >&2; exit 2; }
done
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m py_compile "$broker" "$mcp" "$admin" "$telemetry"
python3 -m json.tool "$settings" >/dev/null; python3 -m json.tool "$managed_mcp" >/dev/null
bash -n "$rollback"

backup_id="findings-adjudication-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
destinations=(
  /usr/local/libexec/secure-sandbox/findings_broker.py
  /usr/local/libexec/secure-sandbox/findings_mcp.py
  /usr/local/libexec/secure-sandbox/finding_admin.py
  /etc/systemd/system/findings-broker.service
  /etc/claude-code/managed-settings.json
  /etc/claude-code/managed-mcp.json
  /etc/claude-code/secure-sandbox-persona.md
  /usr/local/libexec/secure-sandbox/telemetry_exporter.py
  /usr/local/libexec/secure-sandbox/rollback_findings_adjudication.sh
  /usr/local/libexec/secure-sandbox/update-policy-hash.sh
)
for current in "${destinations[@]}"; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR

getent group findings-broker >/dev/null || groupadd --system findings-broker
findings_group="$(getent group findings-broker)" || { echo "Required service group missing: findings-broker" >&2; exit 2; }
IFS=: read -r findings_group_name _ findings_gid findings_members <<< "$findings_group"
[[ "$findings_group_name" == findings-broker && "$findings_gid" -ne 0 \
  && ( -z "$findings_members" || "$findings_members" == findings-broker ) ]] \
  || { echo "Service group is untrusted: findings-broker" >&2; exit 2; }
getent passwd findings-broker >/dev/null || useradd --system --gid findings-broker --home /nonexistent --shell /usr/sbin/nologin findings-broker
findings_account="$(getent passwd findings-broker)" || { echo "Required service account missing: findings-broker" >&2; exit 2; }
IFS=: read -r findings_name _ findings_uid findings_primary_gid _ findings_home findings_shell <<< "$findings_account"
[[ "$findings_name" == findings-broker && "$findings_uid" -ne 0 && "$findings_home" == /nonexistent \
  && "$findings_shell" == /usr/sbin/nologin ]] \
  || { echo "Service account is untrusted: findings-broker" >&2; exit 2; }
usermod -a -G findings-broker findings-broker
findings_group="$(getent group findings-broker)" || { echo "Required service group missing: findings-broker" >&2; exit 2; }
IFS=: read -r findings_group_name _ findings_gid findings_members <<< "$findings_group"
[[ "$findings_group_name" == findings-broker && "$findings_gid" -ne 0 \
  && ( -z "$findings_members" || "$findings_members" == findings-broker ) \
  && ( "$findings_primary_gid" == "$findings_gid" || "$findings_members" == findings-broker ) ]] \
  || { echo "Service identity is untrusted: findings-broker" >&2; exit 2; }
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o findings-broker -g agent -m 700 /var/lib/secure-sandbox/findings
install -d -o findings-broker -g findings-broker -m 700 \
  /var/lib/secure-sandbox/findings/candidates /var/lib/secure-sandbox/findings/amendments
install -d -o root -g findings-broker -m 750 /var/lib/secure-sandbox/findings/adjudication
install -d -o root -g root -m 700 \
  /var/lib/secure-sandbox/findings/snapshots /var/lib/secure-sandbox/findings/archive
install -o root -g root -m 755 "$broker" /usr/local/libexec/secure-sandbox/findings_broker.py
install -o root -g root -m 755 "$mcp" /usr/local/libexec/secure-sandbox/findings_mcp.py
install -o root -g root -m 755 "$admin" /usr/local/libexec/secure-sandbox/finding_admin.py
install -o root -g root -m 644 "$unit" /etc/systemd/system/findings-broker.service
install -o root -g root -m 644 "$settings" /etc/claude-code/managed-settings.json
install -o root -g root -m 644 "$managed_mcp" /etc/claude-code/managed-mcp.json
install -o root -g root -m 444 "$persona" /etc/claude-code/secure-sandbox-persona.md
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback_findings_adjudication.sh
install -o root -g root -m 755 "$update_policy_hash" /usr/local/libexec/secure-sandbox/update-policy-hash.sh
systemd-analyze verify /etc/systemd/system/findings-broker.service >/dev/null
systemctl daemon-reload
systemctl enable findings-broker.service >/dev/null
systemctl restart findings-broker.service telemetry-exporter.service
for _ in $(seq 1 50); do [[ -S /run/secure-sandbox-findings/findings.sock ]] && break; sleep 0.1; done
systemctl is-active --quiet findings-broker.service telemetry-exporter.service
test "$(stat -c %U:%G:%a /var/lib/secure-sandbox/findings)" = findings-broker:agent:700
test "$(stat -c %U:%G:%a /run/secure-sandbox-findings/findings.sock)" = findings-broker:agent:660
sudo -u agent test -w /run/secure-sandbox-findings/findings.sock
! sudo -u agent test -r /var/lib/secure-sandbox/findings
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/findings-adjudication-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/findings-adjudication-latest
trap - ERR
echo "findings-adjudication:installed:$backup_id"
