#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
bundle="${CODEGRAPH_BUNDLE:-$HOME/CodeGraph/release/codegraph-linux-arm64.tar.gz}"
[[ -f "$bundle" ]] || { echo "Missing pinned CodeGraph bundle: $bundle" >&2; exit 1; }
scp -F "$ssh_config" "$bundle" \
  "$root_dir/research/codegraph_runner.cjs" \
  "$root_dir/research/codegraph_adapter.py" \
  "$root_dir/research/codegraph_query_service.py" \
  "$root_dir/research/codegraph_indexer.py" \
  "$root_dir/research/codegraph-query.service" \
  "$root_dir/research/corpus_intelligence.py" \
  "$root_dir/scripts/install-codegraph-adapter.sh" \
  sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
    "sudo -S -p '' bash /tmp/install-codegraph-adapter.sh"
