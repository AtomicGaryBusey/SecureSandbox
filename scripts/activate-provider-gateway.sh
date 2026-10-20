#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi
if [[ "$#" -lt 1 ]]; then
  echo "Usage: activate-provider-gateway.sh GLOBAL_IPV4 [GLOBAL_IPV4 ...]" >&2
  exit 2
fi

activation_dir="$(mktemp -d /run/secure-sandbox-activate.XXXXXX)"
trap 'rm -rf -- "$activation_dir"' EXIT
umask 077

python3 - "$activation_dir/broker.json" "$@" <<'PY'
import ipaddress
import json
import sys
import uuid

output, *addresses = sys.argv[1:]
validated = []
for value in addresses:
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global:
        raise SystemExit("provider address is not global IPv4")
    if str(address) not in validated:
        validated.append(str(address))

with open("/etc/secure-sandbox/broker.json", encoding="utf-8") as handle:
    config = json.load(handle)
config.update({
    "mode": "production",
    "upstream_origin": "https://api.abliteration.ai",
    "allowed_upstream_hosts": ["api.abliteration.ai"],
    "upstream_ipv4": validated,
    "session_id": str(uuid.uuid4()),
})
with open(output, "w", encoding="utf-8") as handle:
    json.dump(config, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY

/usr/local/libexec/secure-sandbox/model_broker.py \
  --config "$activation_dir/broker.json" --validate

/usr/local/libexec/secure-sandbox/render_gateway_firewall.py \
  --broker-config "$activation_dir/broker.json" \
  --azure-config /etc/secure-sandbox/azure-shipper.json \
  --archive-config /etc/secure-sandbox/conversation-azure.json \
  --output "$activation_dir/nftables.conf"
nft -c -f "$activation_dir/nftables.conf"

install -d -o root -g root -m 700 /etc/credstore.encrypted
systemd-creds encrypt --with-key=host --name=provider_token \
  - /etc/credstore.encrypted/model-broker.provider_token
chmod 600 /etc/credstore.encrypted/model-broker.provider_token

install -d -o root -g root -m 755 /etc/systemd/system/model-broker.service.d
install -o root -g root -m 644 /tmp/model-broker-production.conf \
  /etc/systemd/system/model-broker.service.d/production.conf
install -o root -g model-broker -m 640 "$activation_dir/broker.json" \
  /etc/secure-sandbox/broker.json
install -o root -g root -m 600 "$activation_dir/nftables.conf" /etc/nftables.conf

systemctl daemon-reload
nft -f /etc/nftables.conf
systemctl restart model-broker.service
systemctl is-active --quiet model-broker.service
if [[ -x /tmp/update-policy-hash.sh ]]; then
  /tmp/update-policy-hash.sh gateway >/dev/null
fi
echo "model-broker:production-active"
