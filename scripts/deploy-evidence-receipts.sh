#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; ssh_config="$root_dir/config/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
scp -q -F "$ssh_config" \
 "$root_dir/research/evidence_receipts.py" "$root_dir/research/bounded_unix_server.py" "$root_dir/research/corpus_broker.py" "$root_dir/research/corpus-broker.service" \
 "$root_dir/research/corpus_intelligence_mcp.py" "$root_dir/research/execution_broker.py" "$root_dir/research/execution_mcp.py" "$root_dir/research/execution-broker.service" \
 "$root_dir/research/findings_broker.py" "$root_dir/research/findings_mcp.py" "$root_dir/research/findings-broker.service" \
 "$root_dir/research/telemetry_exporter.py" "$root_dir/research/glm-persona.md" "$root_dir/research/rollback_evidence_receipts.sh" \
 "$root_dir/scripts/install-evidence-receipts.sh" "$root_dir/scripts/update-policy-hash.sh" sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Research/password' | ssh -F "$ssh_config" sandbox-research-admin \
 "sudo -S -p '' bash /tmp/install-evidence-receipts.sh"
