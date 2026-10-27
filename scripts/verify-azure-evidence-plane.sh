#!/bin/bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
config="${1:-$root_dir/config/external-containment.json}"
outputs="${2:-$root_dir/runs/azure-deployment-outputs.json}"
resource_group="secure-sandbox-monitoring"
prefix="secsandbox"

for command in az jq op-agents; do
  command -v "$command" >/dev/null || { echo "missing_command:$command" >&2; exit 2; }
done
jq -e '
  .schema == "secure-sandbox-external-containment-config-v1"
  and (.subscription_id | type == "string" and length > 0)
  and (.workspace_customer_id | type == "string" and length > 0)
' "$config" >/dev/null
jq -e '
  ["workspaceResourceId","workspaceName","tableName","dcrResourceId","dcrImmutableId","logsIngestionEndpoint","streamName"]
  - keys | length == 0
' "$outputs" >/dev/null

output_value() {
  jq -er --arg name "$1" '.[$name] | if type == "object" then .value else . end' "$outputs"
}

subscription_id="$(jq -er .subscription_id "$config")"
[[ "$(az account show --query id -o tsv)" == "$subscription_id" ]] \
  || { echo "azure_subscription_mismatch" >&2; exit 1; }
workspace_id="$(output_value workspaceResourceId)"
dcr_id="$(output_value dcrResourceId)"
workspace_name="$(output_value workspaceName)"
dcr_immutable_id="$(output_value dcrImmutableId)"
logs_endpoint="$(output_value logsIngestionEndpoint)"
stream_name="$(output_value streamName)"

workspace="$(az rest --method get --url "https://management.azure.com${workspace_id}?api-version=2025-07-01")"
jq -e '
  .properties.provisioningState == "Succeeded"
  and .properties.retentionInDays == 30
  and .properties.workspaceCapping.dailyQuotaGb == 0.1
  and .properties.publicNetworkAccessForIngestion == "Enabled"
  and .properties.features.enableLogAccessUsingOnlyResourcePermissions == true
' <<<"$workspace" >/dev/null
echo "PASS  Azure workspace has exact retention, access, and 0.1 GB/day safety cap"

table="$(az rest --method get --url "https://management.azure.com${workspace_id}/tables/SecureSandbox_CL?api-version=2025-07-01")"
jq -e '
  .properties.provisioningState == "Succeeded"
  and .properties.plan == "Analytics"
  and .properties.retentionInDays == 30
  and (.properties.schema.columns | map(.name)) == [
    "TimeGenerated","RunId","VmId","AgentId","EventType","Severity","Decision",
    "Destination","DestinationPort","Status","RequestBytes","ResponseBytes",
    "RequestId","PolicyHash","Message"
  ]
' <<<"$table" >/dev/null
echo "PASS  Azure metadata-only table has the exact bounded schema"

dcr="$(az rest --method get --url "https://management.azure.com${dcr_id}?api-version=2024-03-11")"
jq -e --arg immutable "$dcr_immutable_id" --arg endpoint "$logs_endpoint" --arg stream "$stream_name" '
  .kind == "Direct"
  and .properties.provisioningState == "Succeeded"
  and .properties.immutableId == $immutable
  and .properties.endpoints.logsIngestion == $endpoint
  and (.properties.streamDeclarations | keys) == [$stream]
  and .properties.dataFlows[0].transformKql == "source"
  and .properties.dataFlows[0].outputStream == $stream
' <<<"$dcr" >/dev/null
echo "PASS  Direct-ingestion DCR matches the retained deployment outputs"

client_id="$(op-agents read 'op://Agents/SecureSandbox-Azure-Ingestion/username')"
principal_id="$(az ad sp show --id "$client_id" --query id -o tsv)"
role_count="$(az role assignment list --all -o json | jq --arg scope "$dcr_id" --arg principal "$principal_id" '[.[] | select((.scope|ascii_downcase)==($scope|ascii_downcase) and .principalId==$principal and .roleDefinitionName=="Monitoring Metrics Publisher")] | length')"
[[ "$role_count" == 1 ]] || { echo "azure_ingestion_role_invalid" >&2; exit 1; }
echo "PASS  Ingestion identity has one DCR-scoped Monitoring Metrics Publisher role"

locks="$(az lock list --resource-group "$resource_group" -o json)"
jq -e 'any(.[]; .name=="protect-security-evidence" and .level=="CanNotDelete")' <<<"$locks" >/dev/null
echo "PASS  Azure workspace deletion lock is present"

action_group="$(az monitor action-group show --resource-group "$resource_group" --name "${prefix}-security-alerts" -o json)"
jq -e '.enabled==true and (.emailReceivers|length)==1 and .emailReceivers[0].useCommonAlertSchema==true' <<<"$action_group" >/dev/null
echo "PASS  Azure action group has one Common Alert Schema email receiver"

verify_alert() {
  local name="$1" severity="$2"
  local rule
  rule="$(az rest --method get --url "https://management.azure.com/subscriptions/${subscription_id}/resourceGroups/${resource_group}/providers/Microsoft.Insights/scheduledQueryRules/${name}?api-version=2023-12-01")"
  jq -e --argjson severity "$severity" '
    .properties.enabled == true
    and .properties.severity == $severity
    and .properties.evaluationFrequency == "PT5M"
    and .properties.windowSize == "PT15M"
    and (.properties.actions.actionGroups|length)==1
  ' <<<"$rule" >/dev/null
}
verify_alert "${prefix}-posture" 1
verify_alert "${prefix}-availability" 3
verify_alert "${prefix}-ingestion-health" 2
echo "PASS  Containment, availability, and ingestion-health alerts are active"

budget="$(az rest --method get --url "https://management.azure.com/subscriptions/${subscription_id}/resourceGroups/${resource_group}/providers/Microsoft.Consumption/budgets/${prefix}-monthly-budget?api-version=2024-08-01")"
jq -e '
  .properties.category == "Cost"
  and .properties.amount == 10
  and .properties.timeGrain == "Monthly"
  and (.properties.notifications | length) == 2
  and all(.properties.notifications[]; .enabled == true and (.contactGroups|length)==1)
' <<<"$budget" >/dev/null
echo "PASS  Resource-group monthly budget has actual and forecast notifications"

[[ "$workspace_name" == "${prefix}-law-"* ]] || { echo "azure_workspace_name_invalid" >&2; exit 1; }
echo "AZURE EVIDENCE PLANE RESOURCE VERIFICATION PASSED"
