#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Gateway." >&2
  exit 1
fi
config_source="${1:-/tmp/azure-shipper.json}"
[[ -f "$config_source" ]] || { echo "Missing Azure shipper config." >&2; exit 2; }
[[ -x /usr/local/libexec/secure-sandbox/azure_shipper.py ]] || {
  echo "Azure shipper is not installed." >&2
  exit 2
}

activation_dir="$(mktemp -d /run/secure-sandbox-azure.XXXXXX)"
trap 'rm -rf -- "$activation_dir"' EXIT
umask 077
install -m 600 "$config_source" "$activation_dir/azure-shipper.json"
/usr/local/libexec/secure-sandbox/azure_shipper.py \
  --config "$activation_dir/azure-shipper.json" --validate
/usr/local/libexec/secure-sandbox/render_gateway_firewall.py \
  --broker-config /etc/secure-sandbox/broker.json \
  --azure-config "$activation_dir/azure-shipper.json" \
  --archive-config /etc/secure-sandbox/conversation-azure.json \
  --output "$activation_dir/nftables.conf"
nft -c -f "$activation_dir/nftables.conf"

install -d -o root -g root -m 700 /etc/credstore.encrypted
systemd-creds encrypt --with-key=host --name=client_secret \
  - /etc/credstore.encrypted/azure-shipper.client_secret
chmod 600 /etc/credstore.encrypted/azure-shipper.client_secret
install -o root -g azure-shipper -m 640 "$activation_dir/azure-shipper.json" \
  /etc/secure-sandbox/azure-shipper.json
install -o root -g root -m 600 "$activation_dir/nftables.conf" /etc/nftables.conf

nft -f /etc/nftables.conf
systemctl enable --now azure-shipper.service
systemctl is-active --quiet azure-shipper.service
if [[ -x /tmp/update-policy-hash.sh ]]; then
  /tmp/update-policy-hash.sh gateway >/dev/null
fi
echo "azure-shipper:active"
