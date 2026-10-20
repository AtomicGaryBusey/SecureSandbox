#!/bin/bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="$root_dir/config/external-containment.json"
[[ -f "$config" && ! -L "$config" ]] || {
  echo "Missing local Azure configuration: config/external-containment.json" >&2
  exit 2
}
subscription="$(jq -er '.subscription_id | select(test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' "$config")"
group="secure-sandbox-monitoring"
deployment="secure-sandbox-conversation-archive"
policy_id="$(az deployment group show --subscription "$subscription" --resource-group "$group" --name "$deployment" --query properties.outputs.immutabilityPolicyId.value -o tsv)"
etag="$(az rest --method get --url "https://management.azure.com${policy_id}?api-version=2023-05-01" --query etag -o tsv)"
az rest --method post --url "https://management.azure.com${policy_id}/lock?api-version=2023-05-01" --headers "If-Match=$etag" --only-show-errors >/dev/null
state="$(az rest --method get --url "https://management.azure.com${policy_id}?api-version=2023-05-01" --query properties.state -o tsv)"
[[ "$state" == Locked ]] || { echo "Immutability policy did not lock." >&2; exit 1; }
echo "conversation-retention:locked-30-days"
