#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
scp -q -F "$ssh_config" \
  "$root_dir/research/findings_broker.py" \
  "$root_dir/research/findings_mcp.py" \
  "$root_dir/research/finding_admin.py" \
  "$root_dir/research/findings-broker.service" \
  "$root_dir/research/managed-settings.proposed.json" \
  "$root_dir/research/managed-mcp.json" \
  "$root_dir/research/glm-persona.md" \
  "$root_dir/research/telemetry_exporter.py" \
  "$root_dir/research/rollback_findings_adjudication.sh" \
  "$root_dir/scripts/install-findings-adjudication.sh" \
  "$root_dir/scripts/update-policy-hash.sh" \
  sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh; bash /tmp/install-findings-adjudication.sh'"
