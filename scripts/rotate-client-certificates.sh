#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="$root_dir/config/ssh_config"
rotation_dir="$(mktemp -d /tmp/secure-sandbox-cert-rotation.XXXXXX)"
trap 'rm -rf -- "$rotation_dir"' EXIT
umask 077

"$root_dir/scripts/sync-lab-time.sh" --check
active_run="$(ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 \
  sandbox-research-admin 'if test -f /run/secure-sandbox/run-id; then cat /run/secure-sandbox/run-id; fi')"
if [[ -n "$active_run" ]]; then
  echo "Refusing certificate rotation while Claude run $active_run is active." >&2
  exit 1
fi

# Build CSRs from the existing private keys. Private keys never leave Research.
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' sh -c '
      openssl req -new -key /etc/secure-sandbox/relay/client.key \
        -out /tmp/research-broker-renew.csr -subj /CN=secure-sandbox-research;
      openssl req -new -key /etc/secure-sandbox/telemetry/client.key \
        -out /tmp/research-telemetry-renew.csr -subj /CN=secure-sandbox-research-telemetry;
      openssl req -new -key /etc/secure-sandbox/conversation-transport/client.key \
        -out /tmp/research-conversation-renew.csr -subj /CN=secure-sandbox-research-conversation;
      chmod 644 /tmp/research-broker-renew.csr /tmp/research-telemetry-renew.csr /tmp/research-conversation-renew.csr'"
scp -F "$ssh_config" \
  sandbox-research-admin:/tmp/research-broker-renew.csr \
  sandbox-research-admin:/tmp/research-telemetry-renew.csr \
  sandbox-research-admin:/tmp/research-conversation-renew.csr \
  "$rotation_dir/"

scp -F "$ssh_config" \
  "$rotation_dir/research-broker-renew.csr" \
  "$rotation_dir/research-telemetry-renew.csr" \
  "$rotation_dir/research-conversation-renew.csr" \
  "$root_dir/scripts/sign-research-broker-csr.sh" \
  "$root_dir/scripts/sign-research-telemetry-csr.sh" \
  "$root_dir/scripts/sign-research-conversation-csr.sh" \
  "$root_dir/scripts/update-policy-hash.sh" \
  "$root_dir/gateway/update_client_fingerprints.py" \
  "$root_dir/gateway/conversation_receiver.py" \
  sandbox-gateway:/tmp/
op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
  | ssh -F "$ssh_config" sandbox-gateway "sudo -S -p '' sh -c '
      /tmp/sign-research-broker-csr.sh /tmp/research-broker-renew.csr /tmp/research-broker-renew.crt;
      /tmp/sign-research-telemetry-csr.sh /tmp/research-telemetry-renew.csr /tmp/research-telemetry-renew.crt;
      /tmp/sign-research-conversation-csr.sh /tmp/research-conversation-renew.csr /tmp/research-conversation-renew.crt;
      install -o root -g root -m 755 /tmp/update_client_fingerprints.py /usr/local/libexec/secure-sandbox/update_client_fingerprints.py;
      install -o root -g root -m 755 /tmp/conversation_receiver.py /usr/local/libexec/secure-sandbox/conversation_receiver.py;
      python3 -m py_compile /usr/local/libexec/secure-sandbox/conversation_receiver.py;
      /usr/local/libexec/secure-sandbox/update_client_fingerprints.py --retain-existing \
        --broker-cert /tmp/research-broker-renew.crt \
        --telemetry-cert /tmp/research-telemetry-renew.crt \
        --conversation-cert /tmp/research-conversation-renew.crt;
      systemctl restart model-broker telemetry-receiver conversation-receiver;
      cp /etc/secure-sandbox/pki/ca.crt /tmp/secure-sandbox-ca.crt;
      chmod 644 /tmp/secure-sandbox-ca.crt'"
scp -F "$ssh_config" \
  sandbox-gateway:/tmp/research-broker-renew.crt \
  sandbox-gateway:/tmp/research-telemetry-renew.crt \
  sandbox-gateway:/tmp/research-conversation-renew.crt \
  sandbox-gateway:/tmp/secure-sandbox-ca.crt \
  "$rotation_dir/"
scp -F "$ssh_config" \
  "$rotation_dir/research-broker-renew.crt" \
  "$rotation_dir/research-telemetry-renew.crt" \
  "$rotation_dir/research-conversation-renew.crt" \
  "$rotation_dir/secure-sandbox-ca.crt" \
  "$root_dir/research/conversation_shipper.py" \
  "$root_dir/research/conversation-shipper.service" \
  sandbox-research-admin:/tmp/

op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' sh -c '
      install -o root -g claude-relay -m 640 /tmp/research-broker-renew.crt /etc/secure-sandbox/relay/client.crt;
      install -o root -g claude-relay -m 640 /tmp/secure-sandbox-ca.crt /etc/secure-sandbox/relay/ca.crt;
      install -o root -g telemetry-exporter -m 640 /tmp/research-telemetry-renew.crt /etc/secure-sandbox/telemetry/client.crt;
      install -o root -g telemetry-exporter -m 640 /tmp/secure-sandbox-ca.crt /etc/secure-sandbox/telemetry/ca.crt;
      install -o root -g conversation-shipper -m 640 /tmp/research-conversation-renew.crt /etc/secure-sandbox/conversation-transport/client.crt;
      install -o root -g conversation-shipper -m 640 /tmp/secure-sandbox-ca.crt /etc/secure-sandbox/conversation-transport/ca.crt;
      install -d -o root -g conversation-shipper -m 2770 /var/lib/secure-sandbox/conversation-quarantine;
      install -o root -g root -m 755 /tmp/conversation_shipper.py /usr/local/libexec/secure-sandbox/conversation_shipper.py;
      install -o root -g root -m 644 /tmp/conversation-shipper.service /etc/systemd/system/conversation-shipper.service;
      systemctl daemon-reload;
      systemctl restart claude-relay telemetry-exporter conversation-shipper'"

# Prove the new broker identity works before removing the old fingerprints.
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
      "sudo -S -p '' -u agent curl -fsS --max-time 5 http://127.0.0.1:18080/healthz >/dev/null"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
      "sudo -S -p '' -u conversation-shipper /usr/local/libexec/secure-sandbox/conversation_shipper.py --health"
sleep 2
op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
  | ssh -F "$ssh_config" sandbox-gateway "sudo -S -p '' sh -c '
      /usr/local/libexec/secure-sandbox/update_client_fingerprints.py \
        --broker-cert /tmp/research-broker-renew.crt \
        --telemetry-cert /tmp/research-telemetry-renew.crt \
        --conversation-cert /tmp/research-conversation-renew.crt;
      /tmp/update-policy-hash.sh gateway >/dev/null;
      systemctl restart model-broker telemetry-receiver conversation-receiver;
      rm -f /tmp/research-broker-renew.csr /tmp/research-telemetry-renew.csr /tmp/research-conversation-renew.csr \
        /tmp/research-broker-renew.crt /tmp/research-telemetry-renew.crt /tmp/research-conversation-renew.crt \
        /tmp/secure-sandbox-ca.crt /tmp/conversation_receiver.py'"
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin "sudo -S -p '' rm -f \
      /tmp/research-broker-renew.csr /tmp/research-telemetry-renew.csr /tmp/research-conversation-renew.csr \
      /tmp/research-broker-renew.crt /tmp/research-telemetry-renew.crt /tmp/research-conversation-renew.crt \
      /tmp/secure-sandbox-ca.crt /tmp/conversation_shipper.py /tmp/conversation-shipper.service"

scp -F "$ssh_config" "$root_dir/scripts/update-policy-hash.sh" sandbox-research-admin:/tmp/
op-agents read 'op://Agents/SecureSandbox-Research/password' \
  | ssh -F "$ssh_config" sandbox-research-admin \
      "sudo -S -p '' /tmp/update-policy-hash.sh research >/dev/null"

"$root_dir/scripts/verify-boundaries.sh"
