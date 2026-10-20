#!/bin/bash
set -euo pipefail
[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
  || { echo "Usage: show-finding.sh FINDING_UUID" >&2; exit 2; }
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/finding_admin.py show '$1'"
