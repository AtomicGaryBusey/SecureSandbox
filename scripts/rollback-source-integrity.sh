#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
backup_id="${1:-}"
if [[ -z "$backup_id" ]]; then
  backup_id="$(op-agents read 'op://Agents/SecureSandbox-Research/password' \
    | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
      "sudo -S -p '' cat /var/lib/secure-sandbox/policy-backups/source-integrity-latest")"
fi
[[ "$backup_id" =~ ^source-integrity-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { echo "invalid backup id" >&2; exit 1; }
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/rollback_source_integrity.sh '$backup_id'"
