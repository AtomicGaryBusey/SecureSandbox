#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
scp -F "$ssh_config" \
  "$root_dir/research/memory_proposal.py" \
  "$root_dir/research/memory_proposal_mcp.py" \
  "$root_dir/research/memory-proposal.service" \
  "$root_dir/research/managed-settings.proposed.json" \
  "$root_dir/research/managed-mcp.json" \
  "$root_dir/research/research-claude.proposed" \
  "$root_dir/research/run_lease_process.py" \
  "$root_dir/research/run-lease-supervisor.sudoers" \
  "$root_dir/research/glm-persona.md" \
  "$root_dir/research/telemetry_exporter.py" \
  "$root_dir/research/rollback_agent_memory_governance.sh" \
  "$root_dir/scripts/install-agent-memory-governance.sh" \
  "$root_dir/scripts/update-policy-hash.sh" \
  sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh; bash /tmp/install-agent-memory-governance.sh'"
