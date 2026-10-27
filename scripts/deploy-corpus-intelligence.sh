#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"

exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-corpus-intelligence.sh \
  /tmp/managed-settings.proposed.json /tmp/managed-mcp.json /tmp/corpus_intelligence.py \
  /tmp/corpus_intelligence_mcp.py /tmp/telemetry_exporter.py /tmp/rollback_corpus_intelligence.sh \
  --file "$root_dir/research/managed-settings.proposed.json" --file "$root_dir/research/managed-mcp.json" \
  --file "$root_dir/research/corpus_intelligence.py" --file "$root_dir/research/corpus_intelligence_mcp.py" \
  --file "$root_dir/research/telemetry_exporter.py" --file "$root_dir/research/rollback_corpus_intelligence.sh" \
  --file "$root_dir/scripts/install-corpus-intelligence.sh"
