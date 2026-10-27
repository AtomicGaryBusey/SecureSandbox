#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
watchdog="${1:-/tmp/run_lease_watchdog.py}"
unit="${2:-/tmp/run-lease-watchdog.service}"
launcher="${3:-/tmp/research-claude.proposed}"
rollback="${4:-/tmp/rollback-run-leases-research.sh}"
telemetry="${5:-/tmp/telemetry_exporter.py}"
supervisor="${6:-/tmp/run_lease_process.py}"
persona="${7:-/tmp/glm-persona.md}"
sudoers="${8:-/tmp/run-lease-supervisor.sudoers}"
ssh_entry="${9:-/tmp/research_agent_ssh_entry.py}"
sshd_policy="${10:-/tmp/sshd-agent-fixed-command.conf}"
run_id_manager="${11:-/tmp/manage_run_id.py}"
install_recovery="${12:-/tmp/run-leases-install-recovery.sh}"
install_recovery_unit="${13:-/tmp/run-leases-install-recovery.service}"
managed_settings="${14:-/tmp/managed-settings.proposed.json}"
auditor=/tmp/claude_tool_auditor.py; artifact=/tmp/artifact_collector.py; relay=/tmp/claude_relay.py
capture=/tmp/conversation_capture.py; dependency=/tmp/dependency_orchestrator.py
receipts=/tmp/evidence_receipts.py; findings=/tmp/findings_broker.py; memory=/tmp/memory_proposal.py
review_publisher=/tmp/review_bundle_publisher.py; source_importer=/tmp/source_importer.py
artifact_failure=/tmp/artifact-capture-failure.service
conversation_failure=/tmp/conversation-capture-failure.service
conversation_unit=/tmp/conversation-capture.service
shipper_unit=/tmp/conversation-shipper.service
for source in "$watchdog" "$unit" "$launcher" "$rollback" "$telemetry" "$supervisor" "$persona" "$sudoers" "$ssh_entry" "$sshd_policy" "$run_id_manager" "$install_recovery" "$install_recovery_unit" "$managed_settings" "$auditor" "$artifact" "$relay" "$capture" "$dependency" "$receipts" "$findings" "$memory" "$review_publisher" "$source_importer" "$artifact_failure" "$conversation_failure" "$conversation_unit" "$shipper_unit"; do [[ -f "$source" && ! -L "$source" ]] || exit 2; done
if [[ -e /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending ]]; then
  /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh
fi
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id ]] || { echo "active agent run or boundary verification" >&2; exit 1; }
[[ ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "unreconciled run lifecycle" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m py_compile "$watchdog" "$telemetry" "$supervisor" "$ssh_entry" "$run_id_manager" "$auditor" "$artifact" "$relay" "$capture" "$dependency" "$receipts" "$findings" "$memory" "$review_publisher" "$source_importer"; bash -n "$launcher" "$rollback" "$install_recovery"; visudo -cf "$sudoers" >/dev/null
python3 -m json.tool "$managed_settings" >/dev/null
python3 - "$managed_settings" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    settings = json.load(stream)
expected = {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:18080",
    "ANTHROPIC_AUTH_TOKEN": "sandbox-relay-nonsecret",
    "CLAUDE_CODE_USE_GATEWAY": "1",
}
environment = settings.get("env")
if not isinstance(environment, dict) or any(environment.get(key) != value for key, value in expected.items()):
    raise SystemExit("managed Claude gateway environment is missing or invalid")
denied_entries = settings.get("sandbox", {}).get("credentials", {}).get("envVars", [])
denied = {
    entry.get("name") for entry in denied_entries
    if isinstance(entry, dict) and entry.get("mode") == "deny"
} if isinstance(denied_entries, list) else set()
if not {"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"}.issubset(denied):
    raise SystemExit("managed Claude tool credential deny list is missing gateway variables")
PY
backup_id="${15:-run-leases-research-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
[[ "$backup_id" =~ ^run-leases-research-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid Research backup identity." >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ ! -e "$backup" && ! -L "$backup" ]] || { echo "Research backup identity already exists." >&2; exit 1; }
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
install -d -o root -g root -m 755 /var/lib/secure-sandbox/run-lifecycle
install -d -o root -g root -m 700 /var/lib/secure-sandbox/run-lifecycle/completed \
  /var/lib/secure-sandbox/run-lifecycle/capture-receipts
id agent >/dev/null 2>&1 || { echo "Agent account is missing." >&2; exit 2; }
install -d -o agent -g agent -m 700 /home/agent/.claude /home/agent/.claude/projects
test "$(stat -c %U:%G:%a /home/agent/.claude/projects)" = agent:agent:700
for current in /usr/local/libexec/secure-sandbox/run_lease_watchdog.py /usr/local/libexec/secure-sandbox/run_lease_process.py /usr/local/libexec/secure-sandbox/research_agent_ssh_entry.py /usr/local/libexec/secure-sandbox/manage_run_id.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py /usr/local/libexec/secure-sandbox/claude_tool_auditor.py /usr/local/libexec/secure-sandbox/artifact_collector.py /usr/local/libexec/secure-sandbox/claude_relay.py /usr/local/libexec/secure-sandbox/conversation_capture.py /usr/local/libexec/secure-sandbox/dependency_orchestrator.py /usr/local/libexec/secure-sandbox/evidence_receipts.py /usr/local/libexec/secure-sandbox/findings_broker.py /usr/local/libexec/secure-sandbox/memory_proposal.py /usr/local/libexec/secure-sandbox/review_bundle_publisher.py /usr/local/libexec/secure-sandbox/source_importer.py /etc/ssh/sshd_config.d/20-secure-sandbox-agent-command.conf /etc/sudoers.d/secure-sandbox-run-lease /etc/systemd/system/run-lease-watchdog.service /etc/systemd/system/artifact-capture-failure.service /etc/systemd/system/conversation-capture-failure.service /etc/systemd/system/conversation-capture.service /etc/systemd/system/conversation-shipper.service /usr/local/bin/research-claude /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh /etc/systemd/system/run-leases-install-recovery.service /etc/claude-code/secure-sandbox-persona.md /etc/claude-code/managed-settings.json; do
  name="$(basename "$current")"; if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR
install -o root -g root -m 755 "$install_recovery" /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh
install -o root -g root -m 644 "$install_recovery_unit" /etc/systemd/system/run-leases-install-recovery.service
systemctl daemon-reload
systemctl enable run-leases-install-recovery.service >/dev/null
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
chown root:root /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
chmod 600 /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
sync -d /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
install -o root -g root -m 755 "$watchdog" /usr/local/libexec/secure-sandbox/run_lease_watchdog.py
install -o root -g root -m 755 "$supervisor" /usr/local/libexec/secure-sandbox/run_lease_process.py
install -o root -g root -m 755 "$ssh_entry" /usr/local/libexec/secure-sandbox/research_agent_ssh_entry.py
install -o root -g root -m 755 "$run_id_manager" /usr/local/libexec/secure-sandbox/manage_run_id.py
install -o root -g root -m 755 "$auditor" /usr/local/libexec/secure-sandbox/claude_tool_auditor.py
install -o root -g root -m 755 "$artifact" /usr/local/libexec/secure-sandbox/artifact_collector.py
install -o root -g root -m 755 "$relay" /usr/local/libexec/secure-sandbox/claude_relay.py
install -o root -g root -m 755 "$capture" /usr/local/libexec/secure-sandbox/conversation_capture.py
install -o root -g root -m 755 "$dependency" /usr/local/libexec/secure-sandbox/dependency_orchestrator.py
install -o root -g root -m 755 "$receipts" /usr/local/libexec/secure-sandbox/evidence_receipts.py
install -o root -g root -m 755 "$findings" /usr/local/libexec/secure-sandbox/findings_broker.py
install -o root -g root -m 755 "$memory" /usr/local/libexec/secure-sandbox/memory_proposal.py
install -o root -g root -m 755 "$review_publisher" /usr/local/libexec/secure-sandbox/review_bundle_publisher.py
install -o root -g root -m 755 "$source_importer" /usr/local/libexec/secure-sandbox/source_importer.py
install -o root -g root -m 644 "$sshd_policy" /etc/ssh/sshd_config.d/20-secure-sandbox-agent-command.conf
install -o root -g root -m 440 "$sudoers" /etc/sudoers.d/secure-sandbox-run-lease
install -o root -g root -m 644 "$unit" /etc/systemd/system/run-lease-watchdog.service
install -o root -g root -m 644 "$artifact_failure" /etc/systemd/system/artifact-capture-failure.service
install -o root -g root -m 644 "$conversation_failure" /etc/systemd/system/conversation-capture-failure.service
install -o root -g root -m 644 "$conversation_unit" /etc/systemd/system/conversation-capture.service
install -d -o root -g conversation-shipper -m 2770 /var/lib/secure-sandbox/conversation-quarantine
install -o root -g root -m 644 "$shipper_unit" /etc/systemd/system/conversation-shipper.service
install -o root -g root -m 755 "$launcher" /usr/local/bin/research-claude
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 444 "$persona" /etc/claude-code/secure-sandbox-persona.md
install -o root -g root -m 644 "$managed_settings" /etc/claude-code/managed-settings.json
systemd-analyze verify /etc/systemd/system/run-lease-watchdog.service /etc/systemd/system/artifact-capture-failure.service /etc/systemd/system/conversation-capture-failure.service /etc/systemd/system/conversation-capture.service /etc/systemd/system/conversation-shipper.service /etc/systemd/system/run-leases-install-recovery.service >/dev/null
sshd -t
effective_agent_policy="$(sshd -T -C user=agent,host=localhost,addr=127.0.0.1)"
grep -qx 'forcecommand /usr/local/libexec/secure-sandbox/research_agent_ssh_entry.py' <<<"$effective_agent_policy"
grep -qx 'disableforwarding yes' <<<"$effective_agent_policy"
grep -qx 'permituserrc no' <<<"$effective_agent_policy"
grep -qx 'permituserenvironment no' <<<"$effective_agent_policy"
rm -f /run/secure-sandbox/run-lease.json /run/secure-sandbox/run-process.json
systemctl daemon-reload
systemctl enable run-lease-watchdog.service >/dev/null
systemctl restart run-lease-watchdog.service
systemctl is-active --quiet run-lease-watchdog.service
systemctl restart telemetry-exporter.service
systemctl is-active --quiet telemetry-exporter.service
systemctl restart claude-relay.service claude-tool-auditor.service conversation-capture.service artifact-collector.service corpus-broker.service execution-broker.service findings-broker.service memory-proposal.service
systemctl is-active --quiet claude-relay.service claude-tool-auditor.service conversation-capture.service artifact-collector.service corpus-broker.service execution-broker.service findings-broker.service memory-proposal.service
test -f /run/secure-sandbox/conversation-capture-ready
test ! -e /run/secure-sandbox/conversation-capture-fatal
test -f /run/secure-sandbox/artifact-capture-ready
test ! -e /run/secure-sandbox/artifact-capture-fatal
systemctl reset-failed conversation-capture-failure.service artifact-capture-failure.service >/dev/null 2>&1 || true
systemctl reload ssh.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/run-leases-research-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/run-leases-research-latest
trap - ERR
rm -f /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
sync -d /var/lib/secure-sandbox/policy-backups
echo "run-leases-research:installed:$backup_id"

