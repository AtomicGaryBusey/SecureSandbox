#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"

scp -F "$ssh_config" \
  "$root_dir/research/managed-settings.proposed.json" \
  "$root_dir/research/research-claude.proposed" \
  "$root_dir/research/managed-mcp.json" \
  "$root_dir/research/source_integrity.py" \
  "$root_dir/research/source_integrity_mcp.py" \
  "$root_dir/research/source_importer.py" \
  "$root_dir/research/source_import_wrapper.py" \
  "$root_dir/research/telemetry_exporter.py" \
  "$root_dir/research/rollback_source_integrity.sh" \
  "$root_dir/scripts/install-source-integrity.sh" \
  "$root_dir/scripts/update-policy-hash.sh" \
  sandbox-research-admin:/tmp/

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin \
    "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/update-policy-hash.sh /usr/local/libexec/secure-sandbox/update-policy-hash.sh; bash /tmp/install-source-integrity.sh /tmp/managed-settings.proposed.json /tmp/research-claude.proposed /tmp/managed-mcp.json /tmp/source_integrity.py /tmp/source_integrity_mcp.py /tmp/rollback_source_integrity.sh /tmp/source_importer.py /tmp/telemetry_exporter.py /tmp/source_import_wrapper.py'"
