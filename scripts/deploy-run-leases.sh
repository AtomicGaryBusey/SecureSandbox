#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
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
    "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
      run rollback-run-leases-research "$research_backup"
  fi
  if [[ -n "$gateway_backup" ]]; then
    "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-gateway-control \
      run rollback-run-leases-gateway "$gateway_backup"
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
deployment_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
gateway_backup="run-leases-gateway-$deployment_stamp-$$"
research_backup="run-leases-research-$deployment_stamp-$$"
jq -nc --arg gateway "$gateway_backup" '{schema:"secure-sandbox-run-leases-deploy-transaction-v1",gateway_backup:$gateway}' > "$transaction.new"
mv "$transaction.new" "$transaction"
/bin/sync
gateway_result="$("/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-gateway-control deploy install-run-leases-gateway.sh \
  /tmp/run_lease.py /tmp/model_broker.py /tmp/local_telemetry_exporter.py /tmp/run-lease-profiles.json \
  /tmp/rollback-run-leases-gateway.sh /tmp/model-broker.service /tmp/run-leases-install-recovery.sh /tmp/run-leases-install-recovery.service "$gateway_backup" \
  --file "$root_dir/gateway/run_lease.py" --file "$root_dir/gateway/model_broker.py" --file "$root_dir/gateway/model-broker.service" \
  --file "$root_dir/gateway/local_telemetry_exporter.py" --file "$root_dir/gateway/run-lease-profiles.json" \
  --file "$root_dir/gateway/telemetry_receiver.py" --file "$root_dir/gateway/conversation_receiver.py" \
  --file "$root_dir/gateway/update_client_fingerprints.py" \
  --file "$root_dir/gateway/rollback-run-leases-gateway.sh" --file "$root_dir/gateway/run-leases-install-recovery.sh" \
  --file "$root_dir/gateway/run-leases-install-recovery.service" --file "$root_dir/scripts/install-run-leases-gateway.sh" \
  --file "$root_dir/shared/__init__.py:shared_init.py" --file "$root_dir/shared/bounded_http.py" \
  --file "$root_dir/scripts/update-policy-hash.sh")"
[[ "${gateway_result##*:}" == "$gateway_backup" ]] || exit 1
jq -nc --arg gateway "$gateway_backup" --arg research "$research_backup" '{schema:"secure-sandbox-run-leases-deploy-transaction-v1",gateway_backup:$gateway,research_backup:$research}' > "$transaction.new"
mv "$transaction.new" "$transaction"
/bin/sync
research_result="$("/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy install-run-leases-research.sh \
  /tmp/run_lease_watchdog.py /tmp/run-lease-watchdog.service /tmp/research-claude.proposed /tmp/rollback-run-leases-research.sh \
  /tmp/telemetry_exporter.py /tmp/run_lease_process.py /tmp/glm-persona.md /tmp/run-lease-supervisor.sudoers \
  /tmp/research_agent_ssh_entry.py /tmp/sshd-agent-fixed-command.conf /tmp/manage_run_id.py /tmp/run-leases-install-recovery.sh \
  /tmp/run-leases-install-recovery.service /tmp/managed-settings.proposed.json "$research_backup" \
  --file "$root_dir/research/run_lease_watchdog.py" --file "$root_dir/research/run_lease_process.py" \
  --file "$root_dir/research/research_agent_ssh_entry.py" --file "$root_dir/research/sshd-agent-fixed-command.conf" \
  --file "$root_dir/research/manage_run_id.py" --file "$root_dir/research/run-lease-supervisor.sudoers" \
  --file "$root_dir/research/run-lease-watchdog.service" --file "$root_dir/research/research-claude.proposed" \
  --file "$root_dir/research/glm-persona.md" --file "$root_dir/research/rollback-run-leases-research.sh" \
  --file "$root_dir/research/telemetry_exporter.py" --file "$root_dir/research/claude_tool_auditor.py" \
  --file "$root_dir/research/artifact_collector.py" --file "$root_dir/research/claude_relay.py" \
  --file "$root_dir/research/conversation_capture.py" --file "$root_dir/research/conversation_shipper.py" \
  --file "$root_dir/research/dependency_orchestrator.py" \
  --file "$root_dir/research/evidence_receipts.py" --file "$root_dir/research/findings_broker.py" \
  --file "$root_dir/research/memory_proposal.py" --file "$root_dir/research/corpus_broker.py" \
  --file "$root_dir/research/codegraph_query_service.py" --file "$root_dir/research/codegraph_indexer.py" \
  --file "$root_dir/research/review_bundle_publisher.py" \
  --file "$root_dir/research/source_importer.py" --file "$root_dir/research/artifact-capture-failure.service" \
  --file "$root_dir/research/conversation-capture-failure.service" --file "$root_dir/research/conversation-capture.service" \
  --file "$root_dir/research/conversation-shipper.service" --file "$root_dir/research/run-leases-install-recovery.sh" \
  --file "$root_dir/research/run-leases-install-recovery.service" --file "$root_dir/scripts/install-run-leases-research.sh" \
  --file "$root_dir/research/managed-settings.proposed.json" \
  --file "$root_dir/shared/__init__.py:shared_init.py" --file "$root_dir/shared/bounded_http.py" --file "$root_dir/research/bounded_unix_server.py" \
  --file "$root_dir/scripts/update-policy-hash.sh")"
[[ "${research_result##*:}" == "$research_backup" ]] || exit 1
rm -f "$transaction"
/bin/sync
trap - ERR HUP INT TERM
printf '%s\n%s\n' "$gateway_result" "$research_result"
