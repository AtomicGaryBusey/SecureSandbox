#!/bin/bash
set -euo pipefail
[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
  || { echo "Usage: show-finding.sh FINDING_UUID" >&2; exit 2; }
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
  sandbox-research-control run finding-show "$1"
