#!/bin/bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo "Usage: apply-finding-action.sh REQUEST.json" >&2; exit 2; }
request="$1"
[[ -f "$request" && ! -L "$request" ]] || { echo "Request must be a regular non-symlink file." >&2; exit 2; }
size="$(stat -f '%z' "$request")"
(( size > 0 && size <= 16384 )) || { echo "Request must be between 1 and 16384 bytes." >&2; exit 2; }
python3 -m json.tool "$request" >/dev/null
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
remote="/tmp/finding-action-$(uuidgen | tr '[:upper:]' '[:lower:]').json"
cleanup() { ssh -F "$ssh_config" sandbox-research-admin "rm -f -- '$remote'" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM
scp -q -F "$ssh_config" "$request" "sandbox-research-admin:$remote"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' /usr/local/libexec/secure-sandbox/finding_admin.py apply '$remote'"
