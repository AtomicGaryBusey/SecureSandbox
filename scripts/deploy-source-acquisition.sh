#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"

python3 "$root_dir/scripts/resolve-source-endpoints.py" | \
  "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-gateway-control \
  deploy install-source-gateway.sh /tmp/source_controller.py /tmp/source_fetcher.py /tmp/source-acquisition.json /tmp/render_gateway_firewall.py \
  --stdin-file source-acquisition.json \
  --file "$root_dir/gateway/source_controller.py" --file "$root_dir/gateway/source_fetcher.py" \
  --file "$root_dir/gateway/render_gateway_firewall.py" --file "$root_dir/gateway/conversation_receiver.py" \
  --file "$root_dir/gateway/conversation_azure_shipper.py" --file "$root_dir/gateway/local_telemetry_exporter.py" \
  --file "$root_dir/scripts/install-source-gateway.sh" --file "$root_dir/scripts/update-policy-hash.sh"

"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-research-control \
  deploy install-source-research.sh /tmp/source_importer.py /tmp/source_import_wrapper.py \
  --file "$root_dir/research/source_importer.py" --file "$root_dir/research/source_import_wrapper.py" \
  --file "$root_dir/research/conversation_shipper.py" --file "$root_dir/research/conversation-shipper.service" \
  --file "$root_dir/research/telemetry_exporter.py" --file "$root_dir/scripts/install-source-research.sh" \
  --file "$root_dir/scripts/update-policy-hash.sh"

echo source-acquisition:deployed
