#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
backup_id="conversation-capture-$(date -u +%Y%m%dT%H%M%SZ)-$$"

python3 -m py_compile "$root_dir/research/conversation_capture.py"
python3 -m py_compile "$root_dir/research/telemetry_exporter.py"
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-conversation-capture-fix.sh "$backup_id" \
  --file "$root_dir/research/conversation_capture.py" --file "$root_dir/research/telemetry_exporter.py" \
  --file "$root_dir/scripts/install-conversation-capture-fix.sh"
