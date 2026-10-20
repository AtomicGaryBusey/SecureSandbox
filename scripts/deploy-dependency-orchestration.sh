#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"

scp -F "$ssh_config" \
  "$root_dir/research/dependency_orchestrator.py" \
  "$root_dir/research/telemetry_exporter.py" \
  "$root_dir/research/rollback_dependency_orchestration.sh" \
  "$root_dir/scripts/install-dependency-orchestration.sh" \
  sandbox-research-admin:/tmp/

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
    "sudo -S -p '' bash /tmp/install-dependency-orchestration.sh /tmp/dependency_orchestrator.py /tmp/telemetry_exporter.py /tmp/rollback_dependency_orchestration.sh"
