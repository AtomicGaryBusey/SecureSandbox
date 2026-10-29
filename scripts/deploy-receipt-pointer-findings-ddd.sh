#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config

echo "DDD 1/5  Verify the agent lifecycle is idle"
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  --timeout-seconds 10 run lifecycle-idle >/dev/null

echo "DDD 2/5  Run focused receipt, findings, MCP, and telemetry tests"
PYTHONPATH="$root_dir/research:$root_dir/scripts" python3 -m unittest \
  research.test_evidence_receipts research.test_findings research.test_execution_mcp \
  research.test_corpus_intelligence research.test_telemetry_exporter

echo "DDD 3/5  Transactionally deploy the reviewed evidence and findings plane"
"$root_dir/scripts/deploy-evidence-receipts.sh"

echo "DDD 4/5  Verify UUID resolution and diagnostics against live trusted receipts"
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy \
  install-receipt-pointer-findings-live-verifier.sh \
  --file "$root_dir/scripts/install-receipt-pointer-findings-live-verifier.sh" \
  --file "$root_dir/scripts/verify-receipt-pointer-findings-live.py"

echo "DDD 5/5  Run the complete containment boundary"
"$root_dir/scripts/verify-boundaries.sh"

echo receipt-pointer-findings-ddd:deployed-and-boundary-verified
