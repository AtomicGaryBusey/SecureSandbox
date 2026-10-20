#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' python3 -c 'import json,pathlib; p=pathlib.Path(\"/var/lib/secure-sandbox/memory-proposals\"); [print(json.dumps({k:d[k] for k in (\"proposal_id\",\"created_at\",\"category\",\"title\",\"content_sha256\",\"status\")},sort_keys=True)) for f in sorted(p.glob(\"*.json\")) for d in [json.loads(f.read_text())]]'"
