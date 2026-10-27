#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
ssh -F "$ssh_config" sandbox-research-admin 'test ! -e /run/secure-sandbox/run-id && ! pgrep -x claude >/dev/null'
exec "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control deploy install-review-bundle-verifier.sh \
 --file "$root_dir/research/managed-settings.proposed.json" --file "$root_dir/research/source_integrity_mcp.py" \
 --file "$root_dir/research/review_bundle.py" --file "$root_dir/research/review_bundle_publisher.py" \
 --file "$root_dir/research/review-bundle-mount.service" --file "$root_dir/research/telemetry_exporter.py" \
 --file "$root_dir/research/glm-persona.md" --file "$root_dir/research/rollback_review_bundle_verifier.sh" \
 --file "$root_dir/scripts/install-review-bundle-verifier.sh" --file "$root_dir/scripts/update-policy-hash.sh"
