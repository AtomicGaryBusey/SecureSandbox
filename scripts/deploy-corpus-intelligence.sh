#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"

scp -F "$ssh_config" \
  "$root_dir/research/managed-settings.proposed.json" \
  "$root_dir/research/managed-mcp.json" \
  "$root_dir/research/corpus_intelligence.py" \
  "$root_dir/research/corpus_intelligence_mcp.py" \
  "$root_dir/research/telemetry_exporter.py" \
  "$root_dir/research/rollback_corpus_intelligence.sh" \
  "$root_dir/scripts/install-corpus-intelligence.sh" \
  sandbox-research-admin:/tmp/

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
    "sudo -S -p '' bash /tmp/install-corpus-intelligence.sh /tmp/managed-settings.proposed.json /tmp/managed-mcp.json /tmp/corpus_intelligence.py /tmp/corpus_intelligence_mcp.py /tmp/telemetry_exporter.py /tmp/rollback_corpus_intelligence.sh"
