#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; ssh_config="$root_dir/config/ssh_config"
[[ "$(ssh -F "$ssh_config" sandbox-research-admin 'test -e /run/secure-sandbox/run-id; echo $?')" == 1 ]] || { echo "Refusing deployment during an active run." >&2; exit 1; }

scp -F "$ssh_config" "$root_dir/target/execution_service.py" "$root_dir/target/build-python-runtime.sh" \
  "$root_dir/target/secure-sandbox-execution.service" "$root_dir/scripts/install-disposable-execution-target.sh" \
  "$root_dir/scripts/update-policy-hash.sh" \
  sandbox-target-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Execution-Broker/password' \
  | ssh -F "$ssh_config" sandbox-target-admin 'umask 077; cat > /tmp/execution-token'
op-agents read 'op://Agents/SecureSandbox-Target/password' \
  | ssh -F "$ssh_config" sandbox-target-admin "sudo -S -p '' bash /tmp/install-disposable-execution-target.sh"

scp -F "$ssh_config" "$root_dir/research/execution_broker.py" "$root_dir/research/execution_mcp.py" \
  "$root_dir/research/execution-broker.service" "$root_dir/research/managed-settings.proposed.json" \
  "$root_dir/research/managed-mcp.json" "$root_dir/research/render_research_firewall.py" \
  "$root_dir/research/telemetry_exporter.py" "$root_dir/scripts/install-disposable-execution-research.sh" \
  "$root_dir/scripts/update-policy-hash.sh" sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Execution-Broker/password' \
  | ssh -F "$ssh_config" sandbox-research-admin 'umask 077; cat > /tmp/execution-token'
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh; bash /tmp/install-disposable-execution-research.sh'"

op-agents read 'op://Agents/SecureSandbox-Target/password' \
  | ssh -F "$ssh_config" sandbox-target-admin "sudo -S -p '' /tmp/update-policy-hash.sh target >/dev/null"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null"
echo disposable-execution:deployed
