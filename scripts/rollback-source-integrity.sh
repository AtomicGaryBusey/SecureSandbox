#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
backup_id="${1:-}"
if [[ -z "$backup_id" ]]; then
  backup_id="$("/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
    sandbox-research-control run source-integrity-latest)"
fi
[[ "$backup_id" =~ ^source-integrity-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "invalid backup id" >&2; exit 1; }
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
  sandbox-research-control run rollback-source-integrity "$backup_id"
