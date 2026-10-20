#!/bin/bash
set -euo pipefail

role="${1:-}"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root in a guest." >&2
  exit 1
fi
case "$role" in gateway|research|target) ;; *) echo "Usage: update-policy-hash.sh gateway|research|target" >&2; exit 2;; esac

common=(
  /etc/netplan/10-secure-sandbox.yaml
  /etc/nftables.conf
  /etc/ssh/sshd_config.d/10-secure-sandbox.conf
  /etc/sysctl.d/60-secure-sandbox.conf
)
case "$role" in
  gateway)
    files=("${common[@]}"
      /etc/secure-sandbox/broker.json
      /etc/secure-sandbox/telemetry.json
      /etc/secure-sandbox/conversation-receiver.json
      /etc/secure-sandbox/conversation-azure.json
      /etc/secure-sandbox/source-acquisition.json
      /etc/secure-sandbox/run-lease-profiles.json
      /etc/credstore.encrypted/model-broker.provider_token
      /etc/systemd/system/model-broker.service
      /etc/systemd/system/model-broker.service.d/production.conf
      /etc/systemd/system/telemetry-receiver.service
      /etc/systemd/system/local-telemetry-exporter.service
      /etc/systemd/system/azure-shipper.service
      /etc/systemd/system/conversation-receiver.service
      /etc/systemd/system/conversation-azure-shipper.service
      /usr/local/libexec/secure-sandbox/model_broker.py
      /usr/local/libexec/secure-sandbox/telemetry_receiver.py
      /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py
      /usr/local/libexec/secure-sandbox/azure_shipper.py
      /usr/local/libexec/secure-sandbox/conversation_receiver.py
      /usr/local/libexec/secure-sandbox/conversation_azure_shipper.py
      /usr/local/libexec/secure-sandbox/source_controller.py
      /usr/local/libexec/secure-sandbox/source_fetcher.py
      /usr/local/libexec/secure-sandbox/run_lease.py
      /usr/local/libexec/secure-sandbox/pki_lifecycle.py
      /usr/local/libexec/secure-sandbox/pki_generation.py
      /etc/systemd/system/pki-expiry-check.service
      /etc/systemd/system/pki-expiry-check.timer
      /etc/secure-sandbox/pki-generation.json
      /etc/secure-sandbox/pki/ca.crt
      /etc/secure-sandbox/pki/ca.key
      /etc/secure-sandbox/pki/server.crt
      /etc/secure-sandbox/pki/server.key
      /etc/secure-sandbox/telemetry/ca.crt
      /etc/secure-sandbox/telemetry/server.crt
      /etc/secure-sandbox/telemetry/server.key
      /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
      /usr/local/libexec/secure-sandbox/update_client_fingerprints.py)
    ;;
  research)
    files=("${common[@]}"
      /etc/systemd/system/claude-relay.service
      /etc/systemd/system/claude-tool-auditor.service
      /etc/systemd/system/telemetry-exporter.service
      /etc/systemd/system/conversation-capture.service
      /etc/systemd/system/conversation-capture-failure.service
      /etc/systemd/system/conversation-shipper.service
      /etc/systemd/system/artifact-collector.service
      /etc/systemd/system/artifact-capture-failure.service
      /etc/systemd/system/execution-broker.service
      /etc/systemd/system/corpus-broker.service
      /etc/systemd/system/run-lease-watchdog.service
      /etc/systemd/system/memory-proposal.service
      /etc/systemd/system/findings-broker.service
      /etc/systemd/system/review-bundle-mount.service
      /etc/secure-sandbox/execution-broker.json
      /etc/secure-sandbox/conversation-recipient.txt
      /etc/claude-code/managed-settings.json
      /etc/claude-code/managed-mcp.json
      /etc/claude-code/secure-sandbox-persona.md
      /etc/audit/rules.d/50-secure-sandbox.rules
      /usr/local/bin/claude
      /usr/local/bin/age
      /usr/local/bin/research-claude
      /usr/local/libexec/secure-sandbox/claude_relay.py
      /usr/local/libexec/secure-sandbox/claude_tool_auditor.py
      /usr/local/libexec/secure-sandbox/manage_run_id.py
      /usr/local/libexec/secure-sandbox/telemetry_exporter.py
      /usr/local/libexec/secure-sandbox/conversation_capture.py
      /usr/local/libexec/secure-sandbox/conversation_shipper.py
      /usr/local/libexec/secure-sandbox/artifact_collector.py
      /usr/local/libexec/secure-sandbox/session_registry.py
      /usr/local/libexec/secure-sandbox/render_research_firewall.py
      /usr/local/libexec/secure-sandbox/execution_broker.py
      /usr/local/libexec/secure-sandbox/execution_mcp.py
      /usr/local/libexec/secure-sandbox/evidence_receipts.py
      /usr/local/libexec/secure-sandbox/bounded_unix_server.py
      /usr/local/libexec/secure-sandbox/corpus_broker.py
      /usr/local/libexec/secure-sandbox/memory_proposal.py
      /usr/local/libexec/secure-sandbox/memory_proposal_mcp.py
      /usr/local/libexec/secure-sandbox/findings_broker.py
      /usr/local/libexec/secure-sandbox/findings_mcp.py
      /usr/local/libexec/secure-sandbox/finding_admin.py
      /usr/local/libexec/secure-sandbox/rollback_evidence_receipts.sh
      /usr/local/libexec/secure-sandbox/source_importer.py
      /usr/local/libexec/secure-sandbox/source_import_wrapper.py
      /usr/local/libexec/secure-sandbox/source_integrity.py
      /usr/local/libexec/secure-sandbox/source_integrity_mcp.py
      /usr/local/libexec/secure-sandbox/review_bundle.py
      /usr/local/libexec/secure-sandbox/review_bundle_publisher.py
      /usr/local/libexec/secure-sandbox/corpus_intelligence.py
      /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py
      /usr/local/libexec/secure-sandbox/codegraph_adapter.py
      /usr/local/libexec/secure-sandbox/codegraph_indexer.py
      /usr/local/libexec/secure-sandbox/codegraph_query_service.py
      /usr/local/libexec/secure-sandbox/codegraph_runner.cjs
      /usr/local/libexec/secure-sandbox/dependency_orchestrator.py
      /usr/local/libexec/secure-sandbox/run_lease_watchdog.py
      /usr/local/libexec/secure-sandbox/run_lease_process.py
      /etc/sudoers.d/secure-sandbox-run-lease
      /usr/local/libexec/secure-sandbox/pki_lifecycle.py
      /usr/local/libexec/secure-sandbox/pki_generation.py
      /usr/local/libexec/secure-sandbox/pki_guest_helpers.py
      /etc/systemd/system/pki-expiry-check.service
      /etc/systemd/system/pki-expiry-check.timer
      /etc/secure-sandbox/pki-generation.json
      /etc/secure-sandbox/relay/ca.crt
      /etc/secure-sandbox/relay/client.crt
      /etc/secure-sandbox/relay/client.key
      /etc/secure-sandbox/telemetry/ca.crt
      /etc/secure-sandbox/telemetry/client.crt
      /etc/secure-sandbox/telemetry/client.key
      /etc/secure-sandbox/conversation-transport/ca.crt
      /etc/secure-sandbox/conversation-transport/client.crt
      /etc/secure-sandbox/conversation-transport/client.key
      /etc/systemd/system/codegraph-query.service)
    ;;
  target) files=("${common[@]}"
      /home/labadmin/.config/secure-sandbox-execution.json
      /home/labadmin/.config/systemd/user/secure-sandbox-execution.service
      /home/labadmin/.local/libexec/secure-sandbox/execution_service.py) ;;
esac

install -d -o root -g root -m 755 /etc/secure-sandbox
{
  for file in "${files[@]}"; do
    if [[ -f "$file" ]]; then
      sha256sum "$file"
    else
      printf 'MISSING  %s\n' "$file"
    fi
  done
  for unit in chrony unattended-upgrades ModemManager multipathd udisks2 systemd-networkd-wait-online; do
    printf '%s %s\n' "$unit" "$(systemctl is-enabled "$unit.service" 2>/dev/null || true)"
  done
} | sha256sum | awk '{print $1}' > /etc/secure-sandbox/policy.sha256
chown root:root /etc/secure-sandbox/policy.sha256
chmod 644 /etc/secure-sandbox/policy.sha256
cat /etc/secure-sandbox/policy.sha256
