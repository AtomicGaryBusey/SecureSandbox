#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy install-evidence-receipts.sh \
 --file "$root_dir/research/evidence_receipts.py" --file "$root_dir/research/bounded_unix_server.py" --file "$root_dir/research/corpus_broker.py" --file "$root_dir/research/corpus-broker.service" \
 --file "$root_dir/research/corpus_intelligence_mcp.py" --file "$root_dir/research/execution_broker.py" --file "$root_dir/research/execution_mcp.py" --file "$root_dir/research/execution-broker.service" \
 --file "$root_dir/research/findings_broker.py" --file "$root_dir/research/findings_mcp.py" --file "$root_dir/research/findings-broker.service" \
 --file "$root_dir/research/telemetry_exporter.py" --file "$root_dir/research/glm-persona.md" --file "$root_dir/research/rollback_evidence_receipts.sh" \
 --file "$root_dir/scripts/install-evidence-receipts.sh" --file "$root_dir/scripts/update-policy-hash.sh"
