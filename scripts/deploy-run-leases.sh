#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; ssh_config="$root_dir/config/ssh_config"
transaction="$root_dir/runs/run-leases-deploy.pending.json"
umask 077
mkdir -p "$root_dir/runs"
rollback_pending() {
  [[ -e "$transaction" || -L "$transaction" ]] || return 0
  [[ -f "$transaction" && ! -L "$transaction" ]] || { echo "invalid host deploy transaction" >&2; return 1; }
  gateway_backup="$(jq -er '.gateway_backup // empty' "$transaction" 2>/dev/null || true)"
  research_backup="$(jq -er '.research_backup // empty' "$transaction" 2>/dev/null || true)"
  [[ -z "$gateway_backup" || "$gateway_backup" =~ ^run-leases-gateway-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "invalid Gateway rollback identity" >&2; return 1; }
  [[ -z "$research_backup" || "$research_backup" =~ ^run-leases-research-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "invalid Research rollback identity" >&2; return 1; }
  if [[ -n "$research_backup" ]]; then
    op-agents read 'op://Agents/SecureSandbox-Research/password' \
      | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' sh -c 'if test -d /var/lib/secure-sandbox/policy-backups/$research_backup; then /usr/local/libexec/secure-sandbox/rollback-run-leases-research.sh $research_backup; fi'"
  fi
  if [[ -n "$gateway_backup" ]]; then
    op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
      | ssh -F "$ssh_config" sandbox-gateway "sudo -S -p '' sh -c 'if test -d /var/lib/secure-sandbox/policy-backups/$gateway_backup; then /usr/local/libexec/secure-sandbox/rollback-run-leases-gateway.sh $gateway_backup; fi'"
  fi
  rm -f "$transaction"
  /bin/sync
}
rollback_pending
printf '{"schema":"secure-sandbox-run-leases-deploy-transaction-v1"}\n' > "$transaction"
/bin/sync
trap 'rollback_pending' ERR
trap 'rollback_pending; exit 70' HUP INT TERM
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && test ! -e /run/secure-sandbox/evidence-run-id && ! pgrep -x claude >/dev/null'
scp -F "$ssh_config" "$root_dir/gateway/run_lease.py" "$root_dir/gateway/model_broker.py" "$root_dir/gateway/model-broker.service" "$root_dir/gateway/local_telemetry_exporter.py" "$root_dir/gateway/run-lease-profiles.json" "$root_dir/gateway/rollback-run-leases-gateway.sh" "$root_dir/gateway/run-leases-install-recovery.sh" "$root_dir/gateway/run-leases-install-recovery.service" "$root_dir/scripts/install-run-leases-gateway.sh" "$root_dir/scripts/update-policy-hash.sh" sandbox-gateway:/tmp/
scp -F "$ssh_config" \
  "$root_dir/research/run_lease_watchdog.py" "$root_dir/research/run_lease_process.py" \
  "$root_dir/research/research_agent_ssh_entry.py" "$root_dir/research/sshd-agent-fixed-command.conf" \
  "$root_dir/research/manage_run_id.py" "$root_dir/research/run-lease-supervisor.sudoers" \
  "$root_dir/research/run-lease-watchdog.service" "$root_dir/research/research-claude.proposed" \
  "$root_dir/research/glm-persona.md" "$root_dir/research/rollback-run-leases-research.sh" \
  "$root_dir/research/telemetry_exporter.py" "$root_dir/research/claude_tool_auditor.py" \
  "$root_dir/research/artifact_collector.py" "$root_dir/research/claude_relay.py" \
  "$root_dir/research/conversation_capture.py" "$root_dir/research/dependency_orchestrator.py" \
  "$root_dir/research/evidence_receipts.py" "$root_dir/research/findings_broker.py" \
  "$root_dir/research/memory_proposal.py" "$root_dir/research/review_bundle_publisher.py" \
  "$root_dir/research/source_importer.py" "$root_dir/research/artifact-capture-failure.service" \
  "$root_dir/research/conversation-capture-failure.service" "$root_dir/research/conversation-capture.service" \
  "$root_dir/research/conversation-shipper.service" \
  "$root_dir/research/run-leases-install-recovery.sh" "$root_dir/research/run-leases-install-recovery.service" \
  "$root_dir/scripts/install-run-leases-research.sh" "$root_dir/scripts/update-policy-hash.sh" \
  sandbox-research-admin:/tmp/
deployment_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
gateway_backup="run-leases-gateway-$deployment_stamp-$$"
research_backup="run-leases-research-$deployment_stamp-$$"
jq -nc --arg gateway "$gateway_backup" '{schema:"secure-sandbox-run-leases-deploy-transaction-v1",gateway_backup:$gateway}' > "$transaction.new"
mv "$transaction.new" "$transaction"
/bin/sync
gateway_result="$(op-agents read 'op://Agents/SecureSandbox-Gateway/password' | ssh -F "$ssh_config" sandbox-gateway "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh; SECURE_SANDBOX_BACKUP_ID=$gateway_backup bash /tmp/install-run-leases-gateway.sh'")"
[[ "${gateway_result##*:}" == "$gateway_backup" ]] || exit 1
jq -nc --arg gateway "$gateway_backup" --arg research "$research_backup" '{schema:"secure-sandbox-run-leases-deploy-transaction-v1",gateway_backup:$gateway,research_backup:$research}' > "$transaction.new"
mv "$transaction.new" "$transaction"
/bin/sync
research_result="$(op-agents read 'op://Agents/SecureSandbox-Research/password' | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh; SECURE_SANDBOX_BACKUP_ID=$research_backup bash /tmp/install-run-leases-research.sh'")"
[[ "${research_result##*:}" == "$research_backup" ]] || exit 1
rm -f "$transaction"
/bin/sync
trap - ERR HUP INT TERM
printf '%s\n%s\n' "$gateway_result" "$research_result"
