#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="$root_dir/config/ssh_config"

python3 "$root_dir/scripts/resolve-source-endpoints.py" \
  | ssh -F "$ssh_config" sandbox-gateway 'umask 077; tee /tmp/source-acquisition.json >/dev/null'

scp -F "$ssh_config" \
  "$root_dir/gateway/source_controller.py" \
  "$root_dir/gateway/source_fetcher.py" \
  "$root_dir/gateway/render_gateway_firewall.py" \
  "$root_dir/gateway/conversation_receiver.py" \
  "$root_dir/gateway/conversation_azure_shipper.py" \
  "$root_dir/gateway/local_telemetry_exporter.py" \
  "$root_dir/scripts/install-source-gateway.sh" \
  sandbox-gateway:/tmp/

op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
  | ssh -F "$ssh_config" sandbox-gateway \
    "sudo -S -p '' bash /tmp/install-source-gateway.sh /tmp/source_controller.py /tmp/source_fetcher.py /tmp/source-acquisition.json /tmp/render_gateway_firewall.py"

op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
  | ssh -F "$ssh_config" sandbox-gateway \
    "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/conversation_receiver.py /usr/local/libexec/secure-sandbox/conversation_receiver.py; install -o root -g root -m 755 /tmp/conversation_azure_shipper.py /usr/local/libexec/secure-sandbox/conversation_azure_shipper.py; install -o root -g root -m 755 /tmp/local_telemetry_exporter.py /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py; python3 -m py_compile /usr/local/libexec/secure-sandbox/conversation_receiver.py /usr/local/libexec/secure-sandbox/conversation_azure_shipper.py /usr/local/libexec/secure-sandbox/local_telemetry_exporter.py; systemctl restart conversation-receiver.service conversation-azure-shipper.service local-telemetry-exporter.service; systemctl is-active --quiet conversation-receiver.service conversation-azure-shipper.service local-telemetry-exporter.service'"

scp -F "$ssh_config" \
  "$root_dir/research/source_importer.py" \
  "$root_dir/research/source_import_wrapper.py" \
  "$root_dir/research/conversation_shipper.py" \
  "$root_dir/research/telemetry_exporter.py" \
  "$root_dir/scripts/install-source-research.sh" \
  sandbox-research-admin:/tmp/

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' bash /tmp/install-source-research.sh /tmp/source_importer.py /tmp/source_import_wrapper.py"

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
    "sudo -S -p '' sh -c 'install -o root -g root -m 755 /tmp/conversation_shipper.py /usr/local/libexec/secure-sandbox/conversation_shipper.py; install -o root -g root -m 755 /tmp/telemetry_exporter.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py; python3 -m py_compile /usr/local/libexec/secure-sandbox/conversation_shipper.py /usr/local/libexec/secure-sandbox/telemetry_exporter.py; systemctl restart conversation-shipper.service telemetry-exporter.service; systemctl is-active --quiet conversation-shipper.service telemetry-exporter.service'"

echo source-acquisition:deployed
