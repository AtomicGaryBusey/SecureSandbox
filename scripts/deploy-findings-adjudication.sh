#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy install-findings-adjudication.sh \
  --file "$root_dir/research/findings_broker.py" --file "$root_dir/research/findings_mcp.py" \
  --file "$root_dir/research/finding_admin.py" --file "$root_dir/research/findings-broker.service" \
  --file "$root_dir/research/managed-settings.proposed.json" --file "$root_dir/research/managed-mcp.json" \
  --file "$root_dir/research/glm-persona.md" --file "$root_dir/research/telemetry_exporter.py" \
  --file "$root_dir/research/rollback_findings_adjudication.sh" \
  --file "$root_dir/scripts/install-findings-adjudication.sh" --file "$root_dir/scripts/update-policy-hash.sh"
