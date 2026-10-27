#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"

exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy install-source-integrity.sh \
  /tmp/managed-settings.proposed.json /tmp/research-claude.proposed /tmp/managed-mcp.json \
  /tmp/source_integrity.py /tmp/source_integrity_mcp.py /tmp/rollback_source_integrity.sh \
  /tmp/source_importer.py /tmp/telemetry_exporter.py /tmp/source_import_wrapper.py \
  --file "$root_dir/research/managed-settings.proposed.json" --file "$root_dir/research/research-claude.proposed" \
  --file "$root_dir/research/managed-mcp.json" --file "$root_dir/research/source_integrity.py" \
  --file "$root_dir/research/source_integrity_mcp.py" --file "$root_dir/research/source_importer.py" \
  --file "$root_dir/research/source_import_wrapper.py" --file "$root_dir/research/telemetry_exporter.py" \
  --file "$root_dir/research/rollback_source_integrity.sh" --file "$root_dir/scripts/install-source-integrity.sh" \
  --file "$root_dir/scripts/update-policy-hash.sh"
