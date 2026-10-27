#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config
control_client=/usr/local/libexec/secure-sandbox-host/current/control_client
claude_binary="$root_dir/artifacts/claude-code/claude-2.1.300-linux-arm64"
bubblewrap="$root_dir/artifacts/ubuntu-26.04.1/packages/bubblewrap_0.11.1-1ubuntu0.3_arm64.deb"
socat="$root_dir/artifacts/ubuntu-26.04.1/packages/socat_1.8.1.1-1ubuntu0.1_arm64.deb"
recipient="$root_dir/config/conversation-age-recipient.txt"
control_public_key="$root_dir/runs/control_key.pub"

for path in "$control_client" "$ssh_config" "$claude_binary" "$bubblewrap" "$socat" "$recipient" \
  "$control_public_key" "$root_dir/scripts/install-privileged-control.sh" \
  "$root_dir/scripts/privileged_control.py" "$root_dir/scripts/privileged_control_entry.py" \
  "$root_dir/config/privileged-control.sudoers" "$root_dir/config/sshd-control.conf"; do
  [[ -f "$path" && ! -L "$path" ]] || { echo "foundation_artifact_invalid:$path" >&2; exit 2; }
done
"$control_client" client --ssh-config "$ssh_config" sandbox-research-control run lifecycle-idle >/dev/null

work="$(mktemp -d /tmp/secure-sandbox-foundation.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
umask 077

control() {
  local host="$1"
  shift
  "$control_client" client --ssh-config "$ssh_config" "$host" "$@"
}

install_control_plane() {
  local host="$1" role="$2" result
  result="$(control "$host" deploy install-privileged-control.sh "$role" /tmp/control_key.pub \
    --file "$root_dir/scripts/install-privileged-control.sh" \
    --file "$root_dir/scripts/privileged_control.py" \
    --file "$root_dir/scripts/privileged_control_entry.py" \
    --file "$root_dir/config/privileged-control.sudoers" \
    --file "$root_dir/config/sshd-control.conf" \
    --file "$control_public_key")"
  [[ "$result" == "privileged-control:installed:$role" ]] \
    || { echo "privileged_control_install_result_invalid:$role" >&2; return 1; }
}

# The seed establishes the first control plane. Restoration must still replace
# it with the exact source-bound revision before acceptance compares guest bytes
# with the current worktree.
install_control_plane sandbox-research-control research
control sandbox-research-control run lifecycle-idle >/dev/null
install_control_plane sandbox-gateway-control gateway
install_control_plane sandbox-target-control target

control sandbox-research-control deploy install-research-service-principals.sh \
  --file "$root_dir/scripts/install-research-service-principals.sh"

gzip -c -9 -- "$claude_binary" > "$work/claude-2.1.300-linux-arm64.gz"
[[ "$(stat -f %z "$work/claude-2.1.300-linux-arm64.gz")" -le 134217728 ]] \
  || { echo "compressed_claude_artifact_too_large" >&2; exit 2; }
control sandbox-research-control deploy install-claude-code.sh \
  /tmp/claude-2.1.300-linux-arm64.gz /tmp/bubblewrap.deb /tmp/socat.deb \
  --file "$root_dir/scripts/install-claude-code.sh" \
  --file "$work/claude-2.1.300-linux-arm64.gz" \
  --file "$bubblewrap:bubblewrap.deb" --file "$socat:socat.deb"

control sandbox-gateway-control deploy install-bootstrap-pki.sh gateway-init \
  --file "$root_dir/scripts/install-bootstrap-pki.sh" \
  --file "$root_dir/scripts/init-gateway-broker-pki.sh"
control sandbox-research-control deploy install-bootstrap-pki.sh research-create \
  --file "$root_dir/scripts/install-bootstrap-pki.sh" \
  --file "$root_dir/scripts/create-research-broker-identity.sh" \
  --file "$root_dir/scripts/create-research-telemetry-identity.sh" \
  --file "$root_dir/scripts/create-research-conversation-identity.sh"
scp -F "$ssh_config" \
  sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/broker.csr \
  sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/telemetry.csr \
  sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/conversation.csr "$work/"
control sandbox-gateway-control deploy install-bootstrap-pki.sh gateway-sign \
  --file "$root_dir/scripts/install-bootstrap-pki.sh" \
  --file "$root_dir/scripts/sign-research-broker-csr.sh" \
  --file "$root_dir/scripts/sign-research-telemetry-csr.sh" \
  --file "$root_dir/scripts/sign-research-conversation-csr.sh" \
  --file "$work/broker.csr" --file "$work/telemetry.csr" --file "$work/conversation.csr"

use_installed_identity=0
if control sandbox-research-control deploy install-bootstrap-pki.sh research-validate \
    --file "$root_dir/scripts/install-bootstrap-pki.sh" >/dev/null 2>&1; then
  scp -F "$ssh_config" \
    sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/installed-ca.crt \
    sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/installed-broker.crt \
    sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/installed-telemetry.crt \
    sandbox-research-admin:/var/lib/secure-sandbox/pki-exchange/bootstrap/installed-conversation.crt "$work/"
  scp -F "$ssh_config" sandbox-gateway:/var/lib/secure-sandbox/pki-exchange/bootstrap/ca.crt "$work/gateway-ca.crt"
  if cmp -s "$work/installed-ca.crt" "$work/gateway-ca.crt"; then
    cp "$work/installed-ca.crt" "$work/ca.crt"
    cp "$work/installed-broker.crt" "$work/broker.crt"
    cp "$work/installed-telemetry.crt" "$work/telemetry.crt"
    cp "$work/installed-conversation.crt" "$work/conversation.crt"
    use_installed_identity=1
  fi
fi
if [[ "$use_installed_identity" == 0 ]]; then
  scp -F "$ssh_config" \
    sandbox-gateway:/var/lib/secure-sandbox/pki-exchange/bootstrap/ca.crt \
    sandbox-gateway:/var/lib/secure-sandbox/pki-exchange/bootstrap/broker.crt \
    sandbox-gateway:/var/lib/secure-sandbox/pki-exchange/bootstrap/telemetry.crt \
    sandbox-gateway:/var/lib/secure-sandbox/pki-exchange/bootstrap/conversation.crt "$work/"
fi
openssl verify -CAfile "$work/ca.crt" "$work/broker.crt" "$work/telemetry.crt" "$work/conversation.crt" >/dev/null

control sandbox-gateway-control deploy install-model-broker.sh \
  --file "$root_dir/gateway/model_broker.py" --file "$root_dir/gateway/model-broker.service" \
  --file "$root_dir/gateway/broker.mock.json" --file "$work/broker.crt:research-client.crt" \
  --file "$root_dir/gateway/render_gateway_firewall.py" --file "$root_dir/shared/__init__.py:shared_init.py" \
  --file "$root_dir/shared/bounded_http.py" --file "$root_dir/scripts/install-model-broker.sh"
control sandbox-gateway-control deploy install-telemetry-receiver.sh \
  --file "$root_dir/gateway/telemetry_receiver.py" --file "$root_dir/gateway/local_telemetry_exporter.py" \
  --file "$root_dir/gateway/telemetry-receiver.service" --file "$root_dir/gateway/local-telemetry-exporter.service" \
  --file "$root_dir/gateway/telemetry.json" --file "$work/telemetry.crt:research-telemetry.crt" \
  --file "$root_dir/shared/__init__.py:shared_init.py" --file "$root_dir/shared/bounded_http.py" \
  --file "$root_dir/scripts/install-telemetry-receiver.sh"
control sandbox-gateway-control deploy install-conversation-gateway.sh \
  --file "$root_dir/gateway/conversation_receiver.py" --file "$root_dir/gateway/conversation_azure_shipper.py" \
  --file "$root_dir/gateway/conversation-receiver.service" --file "$root_dir/gateway/conversation-azure-shipper.service" \
  --file "$work/conversation.crt:research-conversation.crt" \
  --file "$root_dir/shared/__init__.py:shared_init.py" --file "$root_dir/shared/bounded_http.py" \
  --file "$root_dir/scripts/install-conversation-gateway.sh"

control sandbox-research-control deploy install-claude-relay.sh \
  --file "$root_dir/research/claude_relay.py" --file "$root_dir/research/claude-relay.service" \
  --file "$work/broker.crt:client.crt" --file "$work/ca.crt" \
  --file "$root_dir/research/manage_run_id.py" --file "$root_dir/shared/__init__.py:shared_init.py" \
  --file "$root_dir/shared/bounded_http.py" --file "$root_dir/scripts/install-claude-relay.sh"
control sandbox-research-control deploy install-research-telemetry-exporter.sh \
  --file "$root_dir/research/telemetry_exporter.py" --file "$root_dir/research/telemetry-exporter.service" \
  --file "$work/telemetry.crt:research-telemetry.crt" --file "$work/ca.crt" \
  --file "$root_dir/research/50-secure-sandbox.rules" --file "$root_dir/research/render_research_firewall.py" \
  --file "$root_dir/scripts/install-research-telemetry-exporter.sh"
control sandbox-research-control deploy install-conversation-capture.sh \
  /tmp/conversation_capture.py /tmp/conversation_shipper.py /tmp/conversation-capture.service \
  /tmp/conversation-shipper.service /tmp/conversation-recipient.txt /tmp/research-conversation.crt \
  /tmp/ca.crt /usr/bin/age /tmp/render_research_firewall.py /tmp/conversation-capture-failure.service \
  --file "$root_dir/research/conversation_capture.py" --file "$root_dir/research/conversation_shipper.py" \
  --file "$root_dir/research/conversation-capture.service" --file "$root_dir/research/conversation-shipper.service" \
  --file "$recipient:conversation-recipient.txt" --file "$work/conversation.crt:research-conversation.crt" \
  --file "$work/ca.crt" --file "$root_dir/research/render_research_firewall.py" \
  --file "$root_dir/research/conversation-capture-failure.service" --file "$root_dir/scripts/install-conversation-capture.sh"
control sandbox-research-control deploy install-artifact-collector.sh \
  --file "$root_dir/research/artifact_collector.py" --file "$root_dir/research/artifact-collector.service" \
  --file "$root_dir/research/artifact-capture-failure.service" --file "$root_dir/research/run_lease_watchdog.py" \
  --file "$root_dir/scripts/install-artifact-collector.sh"
control sandbox-research-control deploy install-claude-tool-auditor.sh \
  --file "$root_dir/research/claude_tool_auditor.py" --file "$root_dir/research/claude-tool-auditor.service" \
  --file "$root_dir/scripts/install-claude-tool-auditor.sh"

control sandbox-gateway-control deploy install-bootstrap-pki.sh cleanup \
  --file "$root_dir/scripts/install-bootstrap-pki.sh"
control sandbox-research-control deploy install-bootstrap-pki.sh cleanup \
  --file "$root_dir/scripts/install-bootstrap-pki.sh"
echo foundation:deployed
