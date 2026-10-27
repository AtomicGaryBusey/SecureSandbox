#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-agent-memory-governance.sh \
  --file "$root_dir/research/memory_proposal.py" --file "$root_dir/research/memory_proposal_mcp.py" \
  --file "$root_dir/research/memory-proposal.service" --file "$root_dir/research/managed-settings.proposed.json" \
  --file "$root_dir/research/managed-mcp.json" --file "$root_dir/research/research-claude.proposed" \
  --file "$root_dir/research/run_lease_process.py" --file "$root_dir/research/run-lease-supervisor.sudoers" \
  --file "$root_dir/research/glm-persona.md" --file "$root_dir/research/telemetry_exporter.py" \
  --file "$root_dir/research/rollback_agent_memory_governance.sh" \
  --file "$root_dir/scripts/install-agent-memory-governance.sh" --file "$root_dir/scripts/update-policy-hash.sh"
