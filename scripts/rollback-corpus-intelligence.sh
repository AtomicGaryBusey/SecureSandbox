#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
backup_id="${1:-}"
[[ "$backup_id" =~ ^corpus-intelligence-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] \
  || { echo "Usage: $0 corpus-intelligence-YYYYmmddTHHMMSSZ-PID" >&2; exit 2; }
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
  sandbox-research-control run rollback-corpus-intelligence "$backup_id"
