#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$#" -eq 6 ]] || {
  echo "usage: $0 source-id entrypoint-symbol entrypoint-file target-symbol target-file max-depth" >&2
  exit 2
}
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config

echo "DDD 1/5  Verify the agent lifecycle is idle"
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  --timeout-seconds 10 run lifecycle-idle >/dev/null

echo "DDD 2/5  Run focused CodeGraph, findings, MCP, and telemetry tests"
PYTHONPATH="$root_dir/research:$root_dir/scripts" python3 -m unittest \
  research.test_codegraph_reachability research.test_findings \
  research.test_corpus_intelligence research.test_telemetry_exporter

echo "DDD 3/5  Transactionally deploy CodeGraph and findings planes"
"$root_dir/scripts/deploy-codegraph-adapter.sh"
"$root_dir/scripts/deploy-findings-adjudication.sh"

echo "DDD 4/5  Run real reachability and verify its trusted findings pointer"
"$root_dir/scripts/verify-codegraph-findings-live.sh" "$@"

echo "DDD 5/5  Run the complete containment boundary"
"$root_dir/scripts/verify-boundaries.sh"

echo "codegraph-findings-ergonomics-ddd:deployed-and-boundary-verified"
