#!/bin/bash
set -euo pipefail

[[ "$#" -eq 6 ]] || { echo "usage: $0 source-id entrypoint-symbol entrypoint-file target-symbol target-file max-depth" >&2; exit 2; }
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
exec "$control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy \
  install-codegraph-findings-live-verifier.sh "$@" \
  --file "$root_dir/scripts/install-codegraph-findings-live-verifier.sh" \
  --file "$root_dir/scripts/verify-codegraph-findings-ergonomics-live.py"
