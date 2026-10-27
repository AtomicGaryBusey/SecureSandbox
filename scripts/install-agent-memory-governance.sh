#!/bin/bash
set -euo pipefail
install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
broker="${1:-/tmp/memory_proposal.py}"
mcp="${2:-/tmp/memory_proposal_mcp.py}"
unit="${3:-/tmp/memory-proposal.service}"
settings="${4:-/tmp/managed-settings.proposed.json}"
managed_mcp="${5:-/tmp/managed-mcp.json}"
launcher="${6:-/tmp/research-claude.proposed}"
supervisor="${7:-/tmp/run_lease_process.py}"
persona="${8:-/tmp/glm-persona.md}"
telemetry="${9:-/tmp/telemetry_exporter.py}"
rollback="${10:-/tmp/rollback_agent_memory_governance.sh}"
sudoers="${11:-/tmp/run-lease-supervisor.sudoers}"
for source in "$broker" "$mcp" "$unit" "$settings" "$managed_mcp" "$launcher" "$supervisor" "$persona" "$telemetry" "$rollback" "$sudoers"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Invalid deployment source: $source" >&2; exit 2; }
done
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
python3 -m py_compile "$broker" "$mcp" "$supervisor" "$telemetry"
python3 -m json.tool "$settings" >/dev/null
python3 -m json.tool "$managed_mcp" >/dev/null
bash -n "$launcher" "$rollback"
visudo -cf "$sudoers" >/dev/null

backup_id="agent-memory-governance-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
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
for current in "${destinations[@]}"; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
chmod -R go-rwx "$backup"
rollback_on_error() { trap - ERR; bash "$rollback" "$backup_id" >/dev/null || true; }
trap rollback_on_error ERR

getent passwd memory-proposal >/dev/null || useradd --system --home /nonexistent --shell /usr/sbin/nologin memory-proposal
install -o root -g root -m 755 "$broker" /usr/local/libexec/secure-sandbox/memory_proposal.py
install -o root -g root -m 755 "$mcp" /usr/local/libexec/secure-sandbox/memory_proposal_mcp.py
install -o root -g root -m 644 "$unit" /etc/systemd/system/memory-proposal.service
install -o root -g root -m 644 "$settings" /etc/claude-code/managed-settings.json
install -o root -g root -m 644 "$managed_mcp" /etc/claude-code/managed-mcp.json
install -o root -g root -m 755 "$launcher" /usr/local/bin/research-claude
install -o root -g root -m 755 "$supervisor" /usr/local/libexec/secure-sandbox/run_lease_process.py
install -o root -g root -m 440 "$sudoers" /etc/sudoers.d/secure-sandbox-run-lease
install -o root -g root -m 444 "$persona" /etc/claude-code/secure-sandbox-persona.md
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 755 "$rollback" /usr/local/libexec/secure-sandbox/rollback_agent_memory_governance.sh

memory_dir=/home/agent/.claude/projects/-home-agent-research-workspace/memory
if [[ -d "$memory_dir" && ! -L "$memory_dir" ]]; then
  mv "$memory_dir" "$backup/disabled-auto-memory"
  chown -R root:root "$backup/disabled-auto-memory"
  chmod -R go-rwx "$backup/disabled-auto-memory"
fi

systemd-analyze verify /etc/systemd/system/memory-proposal.service >/dev/null
systemctl daemon-reload
systemctl enable memory-proposal.service >/dev/null
systemctl restart memory-proposal.service
systemctl restart telemetry-exporter.service
systemctl is-active --quiet memory-proposal.service telemetry-exporter.service
for _ in $(seq 1 50); do
  [[ -S /run/secure-sandbox-memory/memory-proposal.sock ]] && break
  sleep 0.1
done
test "$(stat -c %U:%G:%a /var/lib/secure-sandbox/memory-proposals)" = memory-proposal:agent:700
test "$(stat -c %U:%G:%a /run/secure-sandbox-memory/memory-proposal.sock)" = memory-proposal:agent:660
sudo -u agent test -w /run/secure-sandbox-memory/memory-proposal.sock
! sudo -u agent test -r /var/lib/secure-sandbox/memory-proposals
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/agent-memory-governance-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/agent-memory-governance-latest
trap - ERR
echo "agent-memory-governance:installed:$backup_id"
