#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"

exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-dependency-orchestration.sh /tmp/dependency_orchestrator.py /tmp/telemetry_exporter.py /tmp/rollback_dependency_orchestration.sh \
  --file "$root_dir/research/dependency_orchestrator.py" --file "$root_dir/research/telemetry_exporter.py" \
  --file "$root_dir/research/rollback_dependency_orchestration.sh" --file "$root_dir/scripts/install-dependency-orchestration.sh"
