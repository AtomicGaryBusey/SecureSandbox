#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run or boundary verification" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/run-leases-research-latest)}"
[[ "$backup_id" =~ ^run-leases-research-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "Invalid rollback generation." >&2; exit 2; }
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"; [[ -d "$backup" ]] || exit 2
self_destination=/usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh
watchdog_was_active=false
if systemctl is-active --quiet run-lease-watchdog.service; then watchdog_was_active=true; fi
systemctl disable --now run-lease-watchdog.service >/dev/null 2>&1 || true
for destination in /usr/local/libexec/secure-sandbox/run_lease_watchdog.py /usr/local/libexec/secure-sandbox/run_lease_process.py /usr/local/libexec/secure-sandbox/research_agent_ssh_entry.py /usr/local/libexec/secure-sandbox/manage_run_id.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py /usr/local/libexec/secure-sandbox/claude_tool_auditor.py /usr/local/libexec/secure-sandbox/artifact_collector.py /usr/local/libexec/secure-sandbox/claude_relay.py /usr/local/libexec/secure-sandbox/conversation_capture.py /usr/local/libexec/secure-sandbox/dependency_orchestrator.py /usr/local/libexec/secure-sandbox/evidence_receipts.py /usr/local/libexec/secure-sandbox/findings_broker.py /usr/local/libexec/secure-sandbox/memory_proposal.py /usr/local/libexec/secure-sandbox/corpus_broker.py /usr/local/libexec/secure-sandbox/codegraph_query_service.py /usr/local/libexec/secure-sandbox/review_bundle_publisher.py /usr/local/libexec/secure-sandbox/source_importer.py /usr/local/libexec/secure-sandbox/shared/__init__.py /usr/local/libexec/secure-sandbox/shared/bounded_http.py /usr/local/libexec/secure-sandbox/bounded_unix_server.py /etc/ssh/sshd_config.d/20-secure-sandbox-agent-command.conf /etc/sudoers.d/secure-sandbox-run-lease /etc/systemd/system/run-lease-watchdog.service /etc/systemd/system/artifact-capture-failure.service /etc/systemd/system/conversation-capture-failure.service /etc/systemd/system/conversation-capture.service /etc/systemd/system/conversation-shipper.service /usr/local/bin/research-claude /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh /etc/systemd/system/run-leases-install-recovery.service /etc/claude-code/secure-sandbox-persona.md /etc/claude-code/managed-settings.json; do
  [[ "$destination" != "$self_destination" ]] || continue
  name="$(basename "$destination")"; if [[ -f "$backup/$name" ]]; then cp --no-dereference "$backup/$name" "$destination"; elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"; fi
done
if [[ -f /etc/sudoers.d/secure-sandbox-run-lease ]]; then visudo -cf /etc/sudoers.d/secure-sandbox-run-lease >/dev/null; fi
sshd -t
rm -f /run/secure-sandbox/run-lease.json /run/secure-sandbox/run-process.json
systemctl daemon-reload
if [[ -f /etc/systemd/system/run-leases-install-recovery.service ]]; then
  systemctl enable run-leases-install-recovery.service >/dev/null
else
  systemctl disable run-leases-install-recovery.service >/dev/null 2>&1 || true
fi
if [[ -f /etc/systemd/system/run-lease-watchdog.service ]]; then
  systemctl enable run-lease-watchdog.service >/dev/null
  if [[ "$watchdog_was_active" == true ]]; then systemctl start run-lease-watchdog.service; fi
fi
for service in telemetry-exporter.service claude-relay.service claude-tool-auditor.service conversation-capture.service artifact-collector.service corpus-broker.service execution-broker.service findings-broker.service memory-proposal.service codegraph-query.service; do
  if systemctl is-active --quiet "$service"; then systemctl restart "$service"; fi
done
if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
# Never truncate the script Bash is currently reading.  Publish its predecessor
# through a new inode so this invocation can finish on its already-open inode.
self_name="$(basename "$self_destination")"
if [[ -f "$backup/$self_name" ]]; then
  self_tmp="${self_destination}.rollback.$$"
  install -o root -g root -m 755 "$backup/$self_name" "$self_tmp"
  mv -f -- "$self_tmp" "$self_destination"
elif [[ -f "$backup/$self_name.absent" ]]; then
  rm -f -- "$self_destination"
fi
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
rm -f /var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending
sync -d /var/lib/secure-sandbox/policy-backups
echo "run-leases-research:rolled-back:$backup_id"

