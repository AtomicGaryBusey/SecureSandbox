#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
credential_reference_file="$root_dir/config/provider-credential-reference.txt"
[[ -f "$credential_reference_file" && ! -L "$credential_reference_file" ]] || {
  echo "Copy config/provider-credential-reference.example.txt to the ignored live path and set the provider credential reference." >&2
  exit 2
}
provider_credential_reference="$(<"$credential_reference_file")"
[[ "$provider_credential_reference" =~ ^op://[^/]+/[^/]+/[^/]+$ ]] || {
  echo "Invalid provider credential reference." >&2
  exit 2
}

provider_ipv4=()
while IFS= read -r address; do
  [[ -n "$address" ]] && provider_ipv4+=("$address")
# `dig +short A` may emit CNAME targets before terminal A records. Keep only
# literal IPv4 values; the strict global-address validator below is retained.
done < <(dig +short A api.abliteration.ai \
  | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' \
  | sort -u)
if [[ "${#provider_ipv4[@]}" -eq 0 ]]; then
  echo "api.abliteration.ai returned no IPv4 addresses." >&2
  exit 1
fi
python3 - "${provider_ipv4[@]}" <<'PY'
import ipaddress
import sys
for value in sys.argv[1:]:
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global:
        raise SystemExit("refusing non-global provider address")
PY

op-agents read "$provider_credential_reference" | \
  "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" sandbox-gateway-control \
  deploy activate-provider-gateway.sh "${provider_ipv4[@]}" --stdin-file provider-token \
  --file "$root_dir/scripts/activate-provider-gateway.sh" --file "$root_dir/scripts/update-policy-hash.sh" \
  --file "$root_dir/gateway/model-broker-production.conf"

echo "Abliteration egress is pinned to: ${provider_ipv4[*]}"
"$root_dir/scripts/verify-boundaries.sh"
