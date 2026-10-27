#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
names=(evidence_receipts.py bounded_unix_server.py corpus_broker.py corpus-broker.service corpus_intelligence_mcp.py execution_broker.py execution_mcp.py execution-broker.service findings_broker.py findings_mcp.py findings-broker.service telemetry_exporter.py glm-persona.md rollback_evidence_receipts.sh update-policy-hash.sh)
for name in "${names[@]}"; do [[ -f "/tmp/$name" && ! -L "/tmp/$name" ]] || { echo "Invalid artifact: $name" >&2; exit 2; }; done
python3 -m py_compile /tmp/evidence_receipts.py /tmp/bounded_unix_server.py /tmp/corpus_broker.py /tmp/corpus_intelligence_mcp.py /tmp/execution_broker.py /tmp/execution_mcp.py /tmp/findings_broker.py /tmp/findings_mcp.py /tmp/telemetry_exporter.py
bash -n /tmp/rollback_evidence_receipts.sh /tmp/update-policy-hash.sh
backup_id="evidence-receipts-$(date -u +%Y%m%dT%H%M%SZ)-$$"; backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
touch "$backup/service-state-recorded"
for service in corpus-broker.service execution-broker.service findings-broker.service telemetry-exporter.service; do
  systemctl is-enabled --quiet "$service" 2>/dev/null && touch "$backup/$service.was-enabled" || true
  systemctl is-active --quiet "$service" 2>/dev/null && touch "$backup/$service.was-active" || true
done
destinations=(
 /usr/local/libexec/secure-sandbox/evidence_receipts.py /usr/local/libexec/secure-sandbox/bounded_unix_server.py /usr/local/libexec/secure-sandbox/corpus_broker.py
 /etc/systemd/system/corpus-broker.service /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py
 /usr/local/libexec/secure-sandbox/execution_broker.py /usr/local/libexec/secure-sandbox/execution_mcp.py /etc/systemd/system/execution-broker.service
 /usr/local/libexec/secure-sandbox/findings_broker.py /usr/local/libexec/secure-sandbox/findings_mcp.py
 /etc/systemd/system/findings-broker.service /usr/local/libexec/secure-sandbox/telemetry_exporter.py
 /etc/claude-code/secure-sandbox-persona.md /usr/local/libexec/secure-sandbox/rollback_evidence_receipts.sh
 /usr/local/libexec/secure-sandbox/update-policy-hash.sh)
for current in "${destinations[@]}"; do name="$(basename "$current")"; if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi; done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash /tmp/rollback_evidence_receipts.sh "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR
systemctl stop corpus-broker.service execution-broker.service findings-broker.service telemetry-exporter.service
getent group evidence-receipts >/dev/null || groupadd --system evidence-receipts
getent group findings-broker >/dev/null || groupadd --system findings-broker
findings_group="$(getent group findings-broker)" || { echo "Required service group missing: findings-broker" >&2; exit 2; }
IFS=: read -r findings_group_name _ findings_gid findings_members <<< "$findings_group"
[[ "$findings_group_name" == findings-broker && "$findings_gid" -ne 0 \
  && ( -z "$findings_members" || "$findings_members" == findings-broker ) ]] \
  || { echo "Service group is untrusted: findings-broker" >&2; exit 2; }
getent passwd corpus-broker >/dev/null || useradd --system --home /nonexistent --shell /usr/sbin/nologin --gid agent corpus-broker
getent passwd findings-broker >/dev/null || useradd --system --home /nonexistent --shell /usr/sbin/nologin --gid findings-broker findings-broker
for user in corpus-broker execution-broker findings-broker; do
  account="$(getent passwd "$user")" || { echo "Required service account missing: $user" >&2; exit 2; }
  IFS=: read -r name _ uid _ _ home shell <<< "$account"
  [[ "$name" == "$user" && "$uid" -ne 0 && "$home" == /nonexistent && "$shell" == /usr/sbin/nologin ]] \
    || { echo "Service account is untrusted: $user" >&2; exit 2; }
done
for user in corpus-broker execution-broker findings-broker; do usermod -a -G evidence-receipts "$user"; done
usermod -a -G findings-broker findings-broker
findings_group="$(getent group findings-broker)" || { echo "Required service group missing: findings-broker" >&2; exit 2; }
IFS=: read -r findings_group_name _ findings_gid findings_members <<< "$findings_group"
findings_account="$(getent passwd findings-broker)" || { echo "Required service account missing: findings-broker" >&2; exit 2; }
IFS=: read -r findings_name _ findings_uid findings_primary_gid _ findings_home findings_shell <<< "$findings_account"
[[ "$findings_group_name" == findings-broker && "$findings_gid" -ne 0 \
  && ( -z "$findings_members" || "$findings_members" == findings-broker ) \
  && "$findings_name" == findings-broker && "$findings_uid" -ne 0 \
  && "$findings_home" == /nonexistent && "$findings_shell" == /usr/sbin/nologin \
  && ( "$findings_primary_gid" == "$findings_gid" || "$findings_members" == findings-broker ) ]] \
  || { echo "Service identity is untrusted: findings-broker" >&2; exit 2; }
install -d -o root -g evidence-receipts -m 750 /var/lib/secure-sandbox/evidence-receipts
install -d -o corpus-broker -g evidence-receipts -m 2750 /var/lib/secure-sandbox/evidence-receipts/corpus
install -d -o execution-broker -g evidence-receipts -m 2750 /var/lib/secure-sandbox/evidence-receipts/execution
install -o root -g root -m 755 /tmp/evidence_receipts.py /usr/local/libexec/secure-sandbox/evidence_receipts.py
install -o root -g root -m 755 /tmp/bounded_unix_server.py /usr/local/libexec/secure-sandbox/bounded_unix_server.py
install -o root -g root -m 755 /tmp/corpus_broker.py /usr/local/libexec/secure-sandbox/corpus_broker.py
install -o root -g root -m 644 /tmp/corpus-broker.service /etc/systemd/system/corpus-broker.service
install -o root -g root -m 755 /tmp/corpus_intelligence_mcp.py /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py
install -o root -g root -m 755 /tmp/execution_broker.py /usr/local/libexec/secure-sandbox/execution_broker.py
install -o root -g root -m 755 /tmp/execution_mcp.py /usr/local/libexec/secure-sandbox/execution_mcp.py
install -o root -g root -m 644 /tmp/execution-broker.service /etc/systemd/system/execution-broker.service
install -o root -g root -m 755 /tmp/findings_broker.py /usr/local/libexec/secure-sandbox/findings_broker.py
install -o root -g root -m 755 /tmp/findings_mcp.py /usr/local/libexec/secure-sandbox/findings_mcp.py
install -o root -g root -m 644 /tmp/findings-broker.service /etc/systemd/system/findings-broker.service
install -o root -g root -m 755 /tmp/telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 444 /tmp/glm-persona.md /etc/claude-code/secure-sandbox-persona.md
install -o root -g root -m 755 /tmp/rollback_evidence_receipts.sh /usr/local/libexec/secure-sandbox/rollback_evidence_receipts.sh
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
PYTHONPATH=/usr/local/libexec/secure-sandbox python3 -c 'import json; import evidence_receipts; print(json.dumps(evidence_receipts.repair_receipt_modes(), separators=(",", ":"), sort_keys=True))'
systemd-analyze verify /etc/systemd/system/corpus-broker.service /etc/systemd/system/execution-broker.service /etc/systemd/system/findings-broker.service >/dev/null
systemctl daemon-reload; systemctl enable corpus-broker.service >/dev/null
systemctl restart corpus-broker.service execution-broker.service findings-broker.service telemetry-exporter.service
for _ in $(seq 1 50); do [[ -S /run/secure-sandbox-corpus/corpus.sock ]] && break; sleep 0.1; done
systemctl is-active --quiet corpus-broker.service execution-broker.service findings-broker.service telemetry-exporter.service
test "$(stat -c %U:%G:%a /run/secure-sandbox-corpus/corpus.sock)" = corpus-broker:agent:660
sudo -u agent test -w /run/secure-sandbox-corpus/corpus.sock
! sudo -u agent test -r /var/lib/secure-sandbox/evidence-receipts
/usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/evidence-receipts-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/evidence-receipts-latest
trap - ERR
echo "evidence-receipts:installed:$backup_id"
