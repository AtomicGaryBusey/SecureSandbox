#!/bin/zsh
set -euo pipefail

if (( $# != 5 )); then
  print -u2 "Usage: activate-azure.sh TENANT_ID CLIENT_ID INGESTION_ENDPOINT DCR_IMMUTABLE_ID STREAM_NAME"
  exit 2
fi
tenant_id="$1"
client_id="$2"
ingestion_endpoint="$3"
dcr_id="$4"
stream_name="$5"
root_dir="${0:A:h:h}"
ssh_config="$root_dir/config/ssh_config"
activation_dir="$(mktemp -d /tmp/secure-sandbox-azure-activate.XXXXXX)"
trap 'rm -rf -- "$activation_dir"' EXIT
umask 077

ingestion_host="$(python3 - "$ingestion_endpoint" <<'PY'
import sys
import urllib.parse
value = urllib.parse.urlsplit(sys.argv[1])
if value.scheme != "https" or not value.hostname or not value.hostname.endswith(".ingest.monitor.azure.com"):
    raise SystemExit("invalid Azure ingestion endpoint")
print(value.hostname)
PY
)"
# `dig +short A` may include CNAME targets before the terminal A records.
# Keep only literal IPv4 answers so the generated firewall allowlist remains
# data-only and the strict ipaddress validator below never sees DNS names.
token_ipv4=("${(@f)$(dig +short A login.microsoftonline.com | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | sort -u)}")
ingestion_ipv4=("${(@f)$(dig +short A "$ingestion_host" | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | sort -u)}")
(( ${#token_ipv4} > 0 && ${#ingestion_ipv4} > 0 )) || {
  print -u2 "Azure host resolution returned no IPv4 addresses."
  exit 1
}

python3 - "$activation_dir/azure-shipper.json" "$tenant_id" "$client_id" \
  "$ingestion_endpoint" "$dcr_id" "$stream_name" \
  "${(j:,:)token_ipv4}" "${(j:,:)ingestion_ipv4}" <<'PY'
import ipaddress
import json
import sys
output, tenant, client, endpoint, dcr, stream, token_csv, ingest_csv = sys.argv[1:]
def addresses(value):
    result = []
    for item in value.split(","):
        parsed = ipaddress.ip_address(item)
        if parsed.version != 4 or not parsed.is_global:
            raise SystemExit("Azure endpoint resolved to non-global IPv4")
        if str(parsed) not in result:
            result.append(str(parsed))
    return result
with open(output, "w", encoding="utf-8") as handle:
    json.dump({
        "tenant_id": tenant,
        "client_id": client,
        "ingestion_endpoint": endpoint,
        "dcr_immutable_id": dcr,
        "stream_name": stream,
        "token_ipv4": addresses(token_csv),
        "ingestion_ipv4": addresses(ingest_csv),
    }, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY

scp -F "$ssh_config" \
  "$root_dir/gateway/azure_shipper.py" \
  "$root_dir/gateway/azure-shipper.service" \
  "$root_dir/gateway/render_gateway_firewall.py" \
  "$root_dir/scripts/install-azure-shipper.sh" \
  "$root_dir/scripts/activate-azure-shipper.sh" \
  "$root_dir/scripts/update-policy-hash.sh" \
  "$activation_dir/azure-shipper.json" \
  sandbox-gateway:/tmp/
op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
  | ssh -F "$ssh_config" sandbox-gateway \
      "sudo -S -p '' /tmp/install-azure-shipper.sh"
(
  op-agents read 'op://Agents/SecureSandbox-Gateway/password'
  op-agents read 'op://Agents/SecureSandbox-Azure-Ingestion/credential'
) | ssh -F "$ssh_config" sandbox-gateway \
      "sudo -S -p '' /tmp/activate-azure-shipper.sh /tmp/azure-shipper.json"

print "Azure endpoint pins: ${(j: :)token_ipv4} ${(j: :)ingestion_ipv4}"
"$root_dir/scripts/verify-boundaries.sh"
