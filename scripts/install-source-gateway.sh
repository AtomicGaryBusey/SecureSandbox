#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Gateway." >&2; exit 1; }
controller="${1:-/tmp/source_controller.py}"
fetcher="${2:-/tmp/source_fetcher.py}"
config="${3:-/tmp/source-acquisition.json}"
renderer="${4:-/tmp/render_gateway_firewall.py}"
for source in "$controller" "$fetcher" "$config" "$renderer"; do
  [[ -f "$source" ]] || { echo "Missing $source" >&2; exit 2; }
done
getent group source-fetcher >/dev/null || groupadd --system source-fetcher
id source-fetcher >/dev/null 2>&1 || useradd --system --gid source-fetcher --home-dir /nonexistent --shell /usr/sbin/nologin source-fetcher
install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox
install -d -o root -g source-fetcher -m 750 /var/lib/secure-sandbox/source-acquisition
install -d -o root -g source-fetcher -m 2750 /var/lib/secure-sandbox/source-acquisition/plans
install -d -o source-fetcher -g source-fetcher -m 700 /var/lib/secure-sandbox/source-acquisition/spool
install -o root -g root -m 755 "$controller" /usr/local/libexec/secure-sandbox/source_controller.py
install -o root -g root -m 755 "$fetcher" /usr/local/libexec/secure-sandbox/source_fetcher.py
install -o root -g root -m 755 "$renderer" /usr/local/libexec/secure-sandbox/render_gateway_firewall.py
install -o root -g source-fetcher -m 640 "$config" /etc/secure-sandbox/source-acquisition.json
python3 -m py_compile /usr/local/libexec/secure-sandbox/source_controller.py /usr/local/libexec/secure-sandbox/source_fetcher.py
/usr/local/libexec/secure-sandbox/source_fetcher.py --config /etc/secure-sandbox/source-acquisition.json --help >/dev/null
/usr/local/libexec/secure-sandbox/render_gateway_firewall.py \
  --broker-config /etc/secure-sandbox/broker.json \
  --azure-config /etc/secure-sandbox/azure-shipper.json \
  --archive-config /etc/secure-sandbox/conversation-azure.json \
  --source-config /etc/secure-sandbox/source-acquisition.json \
  --output /run/source-nftables.new
nft -c -f /run/source-nftables.new
install -o root -g root -m 600 /run/source-nftables.new /etc/nftables.conf
nft -f /etc/nftables.conf
rm -f /run/source-nftables.new
if [[ -x /tmp/update-policy-hash.sh ]]; then /tmp/update-policy-hash.sh gateway >/dev/null; fi
echo source-acquisition:gateway-active
