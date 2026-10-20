#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
backup_id="${1:-}"
[[ "$backup_id" =~ ^corpus-intelligence-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] \
  || { echo "Usage: $0 corpus-intelligence-YYYYmmddTHHMMSSZ-PID" >&2; exit 2; }
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/rollback_corpus_intelligence.sh '$backup_id'"
