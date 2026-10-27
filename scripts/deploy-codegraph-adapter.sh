#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
bundle="${CODEGRAPH_BUNDLE:-$HOME/CodeGraph/release/codegraph-linux-arm64.tar.gz}"
[[ -f "$bundle" ]] || { echo "Missing pinned CodeGraph bundle: $bundle" >&2; exit 1; }
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-codegraph-adapter.sh --file "$bundle" \
  --file "$root_dir/research/codegraph_runner.cjs" --file "$root_dir/research/codegraph_adapter.py" \
  --file "$root_dir/research/codegraph_query_service.py" --file "$root_dir/research/codegraph_indexer.py" \
  --file "$root_dir/research/codegraph-query.service" --file "$root_dir/research/corpus_intelligence.py" \
  --file "$root_dir/research/bounded_unix_server.py" \
  --file "$root_dir/scripts/install-codegraph-adapter.sh"
