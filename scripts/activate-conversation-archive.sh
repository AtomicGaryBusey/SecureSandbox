#!/bin/bash
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }
config_source="${1:-/tmp/conversation-azure.json}"
if [[ -x /tmp/install-azure-shipper.sh ]]; then
  /tmp/install-azure-shipper.sh
fi
[[ -f "$config_source" ]] || exit 2
[[ -x /usr/local/libexec/secure-sandbox/azure_shipper.py ]] || {
  echo "Azure shipper support is not installed." >&2
  exit 2
}
activation_dir="$(mktemp -d /run/secure-sandbox-conversation.XXXXXX)"
trap 'rm -rf -- "$activation_dir"' EXIT
umask 077
install -m 600 "$config_source" "$activation_dir/config.json"
python3 - "$activation_dir/config.json" <<'PY'
import ipaddress,json,sys,uuid
with open(sys.argv[1],encoding='utf-8') as h: c=json.load(h)
uuid.UUID(c['tenant_id']); uuid.UUID(c['client_id'])
assert c['container']=='conversations'
assert c['storage_host'].endswith('.blob.core.windows.net')
for key in ('token_ipv4','storage_ipv4'):
    assert c[key] and all(ipaddress.ip_address(x).version==4 and ipaddress.ip_address(x).is_global for x in c[key])
PY
/usr/local/libexec/secure-sandbox/render_gateway_firewall.py \
  --broker-config /etc/secure-sandbox/broker.json \
  --azure-config /etc/secure-sandbox/azure-shipper.json \
  --archive-config "$activation_dir/config.json" \
  --output "$activation_dir/nftables.conf"
nft -c -f "$activation_dir/nftables.conf"
install -d -o root -g root -m 700 /etc/credstore.encrypted
systemd-creds encrypt --with-key=host --name=client_secret \
  - /etc/credstore.encrypted/conversation-azure.client_secret < /tmp/azure-client-secret
chmod 600 /etc/credstore.encrypted/conversation-azure.client_secret
install -o root -g conversation-azure -m 640 "$activation_dir/config.json" /etc/secure-sandbox/conversation-azure.json
install -o root -g root -m 600 "$activation_dir/nftables.conf" /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable conversation-azure-shipper.service
systemctl restart conversation-azure-shipper.service
systemctl is-active --quiet conversation-azure-shipper.service conversation-receiver.service
[[ -x /tmp/update-policy-hash.sh ]] && /tmp/update-policy-hash.sh gateway >/dev/null || true
echo conversation-archive:active
