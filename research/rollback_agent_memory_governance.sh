#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
backup_id="${1:-$(cat /var/lib/secure-sandbox/policy-backups/agent-memory-governance-latest)}"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
[[ -d "$backup" ]] || { echo "Unknown rollback generation." >&2; exit 2; }
systemctl disable --now memory-proposal.service >/dev/null 2>&1 || true
destinations=(
  /usr/local/libexec/secure-sandbox/memory_proposal.py
  /usr/local/libexec/secure-sandbox/memory_proposal_mcp.py
  /etc/systemd/system/memory-proposal.service
  /etc/claude-code/managed-settings.json
  /etc/claude-code/managed-mcp.json
  /usr/local/bin/research-claude
  /usr/local/libexec/secure-sandbox/run_lease_process.py
  /etc/sudoers.d/secure-sandbox-run-lease
  /etc/claude-code/secure-sandbox-persona.md
  /usr/local/libexec/secure-sandbox/telemetry_exporter.py
  /usr/local/libexec/secure-sandbox/rollback_agent_memory_governance.sh
)
for destination in "${destinations[@]}"; do
  name="$(basename "$destination")"
  if [[ -f "$backup/$name" ]]; then cp --no-dereference "$backup/$name" "$destination"
  elif [[ -f "$backup/$name.absent" ]]; then rm -f -- "$destination"
  fi
done
if [[ -f /etc/sudoers.d/secure-sandbox-run-lease ]]; then visudo -cf /etc/sudoers.d/secure-sandbox-run-lease >/dev/null; fi
memory_dir=/home/agent/.claude/projects/-home-agent-research-workspace/memory
if [[ -d "$backup/disabled-auto-memory" && ! -e "$memory_dir" ]]; then
  mv "$backup/disabled-auto-memory" "$memory_dir"
  chown -R agent:agent "$memory_dir"
fi
systemctl daemon-reload
if [[ -f /etc/systemd/system/memory-proposal.service ]]; then systemctl enable --now memory-proposal.service; fi
systemctl restart telemetry-exporter.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
echo "agent-memory-governance:rolled-back:$backup_id"
