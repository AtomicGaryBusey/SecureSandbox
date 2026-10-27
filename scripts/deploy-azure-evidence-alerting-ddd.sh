#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
config="$root_dir/config/external-containment.json"
outputs="$root_dir/runs/azure-deployment-outputs.json"
resource_group="secure-sandbox-monitoring"
location="$(az group show --name "$resource_group" --query location -o tsv)"
subscription_id="$(jq -er .subscription_id "$config")"
[[ "$(az account show --query id -o tsv)" == "$subscription_id" ]] || {
  print -u2 azure_subscription_mismatch
  exit 1
}

client_id="$(op-agents read 'op://Agents/SecureSandbox-Azure-Ingestion/username')"
principal_id="$(az ad sp show --id "$client_id" --query id -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"
alert_email="$(az monitor action-group show --resource-group "$resource_group" \
  --name secsandbox-security-alerts --query 'emailReceivers[0].emailAddress' -o tsv)"
[[ -n "$alert_email" ]] || { print -u2 azure_alert_recipient_missing; exit 1; }

temporary="$(mktemp -d "${TMPDIR:-/tmp}/secure-sandbox-azure-evidence.XXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT
umask 077

print "DDD 1/7  Build and validate the reviewed Azure evidence template"
az bicep build --file "$root_dir/azure/main.bicep" --stdout > "$temporary/main.arm.json"
jq -e '.resources|length>=8' "$temporary/main.arm.json" >/dev/null

print "DDD 2/7  Reject destructive Azure changes before deployment"
az deployment group what-if --resource-group "$resource_group" \
  --name secure-sandbox-evidence-ddd-what-if \
  --template-file "$root_dir/azure/main.bicep" \
  --parameters location="$location" ingestionPrincipalObjectId="$principal_id" \
    alertEmail="$alert_email" monthlyBudgetUsd=10 \
  --no-pretty-print --result-format FullResourcePayloads -o json > "$temporary/what-if.json"
jq -e '[.changes[]? | select(.changeType=="Delete" or .changeType=="Deploy" or .changeType=="Unsupported")] | length==0' \
  "$temporary/what-if.json" >/dev/null || { print -u2 destructive_azure_what_if; exit 1; }

print "DDD 3/7  Deploy the exact workspace, DCR, alert, lock, and budget resources"
deployment_name="secure-sandbox-evidence-ddd-$(date -u +%Y%m%dT%H%M%SZ)"
az deployment group create --resource-group "$resource_group" --name "$deployment_name" \
  --template-file "$root_dir/azure/main.bicep" \
  --parameters location="$location" ingestionPrincipalObjectId="$principal_id" \
    alertEmail="$alert_email" monthlyBudgetUsd=10 \
  --query properties.outputs -o json > "$temporary/outputs.json"
mkdir -p "$root_dir/runs"
install -m 600 "$temporary/outputs.json" "$outputs"

print "DDD 4/7  Verify the exact live Azure resource topology"
"$root_dir/scripts/verify-azure-evidence-plane.sh" "$config" "$outputs"
"$root_dir/scripts/verify-azure-alert-semantics.sh" "$config"

print "DDD 5/7  Activate the pinned least-privilege Gateway shipper"
endpoint="$(jq -er '.logsIngestionEndpoint.value' "$outputs")"
dcr_immutable_id="$(jq -er '.dcrImmutableId.value' "$outputs")"
stream_name="$(jq -er '.streamName.value' "$outputs")"
"$root_dir/scripts/activate-azure.sh" "$tenant_id" "$client_id" "$endpoint" "$dcr_immutable_id" "$stream_name"

print "DDD 6/7  Wait for fresh off-host heartbeat and denial evidence"
workspace_customer_id="$(jq -er .workspace_customer_id "$config")"
verified=0
for _ in {1..24}; do
  if "$root_dir/scripts/verify-azure-evidence.sh" "$subscription_id" "$workspace_customer_id"; then
    verified=1
    break
  fi
  sleep 15
done
[[ "$verified" -eq 1 ]] || { print -u2 azure_evidence_acceptance_timeout; exit 1; }

print "DDD 7/7  Verify the complete SecureSandbox boundary"
"$root_dir/scripts/verify-boundaries.sh"
print "azure-evidence-alerting-ddd:deployed-and-boundary-verified"
