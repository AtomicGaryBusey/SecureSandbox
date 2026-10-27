@description('Azure region of the existing Log Analytics workspace.')
param location string

@description('Existing Log Analytics workspace name.')
param workspaceName string

@description('Existing action group name.')
param actionGroupName string

@description('Short lowercase prefix used by the SecureSandbox deployment.')
@minLength(3)
@maxLength(16)
param prefix string = 'secsandbox'

@description('Existing custom Log Analytics table name.')
param tableName string = 'SecureSandbox_CL'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' existing = {
  name: workspaceName
}

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' existing = {
  name: actionGroupName
}

resource postureAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${prefix}-posture'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: 'SecureSandbox containment violation or missing heartbeat'
    description: 'Sev1 detects explicit containment/evidence violations and missing Gateway/Research heartbeats; availability failures are classified separately.'
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [workspace.id]
    severity: 1
    criteria: {
      allOf: [
        {
          query: 'let Expected = datatable(VmId:string)["gateway", "research"]; let Observed = ${tableName} | extend ObservedAt=coalesce(ingestion_time(), TimeGenerated); let Missing = Expected | join kind=leftouter (Observed | where EventType == "heartbeat" | summarize LastHeartbeat=max(ObservedAt) by VmId) on VmId | where isnull(LastHeartbeat) or LastHeartbeat < ago(10m) | project Reason="missing_heartbeat", VmId; let Violations = Observed | where ObservedAt > ago(5m) | where RunId != "boundary-test" | where EventType in ("network_connect_unapproved", "firewall_forward_deny", "firewall_egress_deny", "unexpected_destination", "metadata_attempt", "policy_tamper", "sandbox_bypass_requested", "privilege_escalation_requested", "security_policy_change_requested", "network_tunnel_requested", "risky_tool_approval", "request_denied", "conversation_capture_failed", "conversation_forward_failed", "conversation_blob_upload_failed", "artifact_capture_failed", "artifact_forward_failed", "artifact_blob_upload_failed", "source_import_rejected", "source_manifest_forward_failed", "source_manifest_blob_upload_failed") or (Severity == "critical" and EventType !in ("upstream_failed", "corpus_query_rejected", "source_fetch_failed")) | where not(EventType == "firewall_egress_deny" and Destination == "ff02:0000:0000:0000:0000:0000:0000:0016" and DestinationPort == 0) | project Reason="containment_violation", VmId; union Missing, Violations'
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            minFailingPeriodsToAlert: 1
            numberOfEvaluationPeriods: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [actionGroup.id]
    }
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
  }
}

resource availabilityAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${prefix}-availability'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: 'SecureSandbox sustained model-provider availability failure'
    description: 'Sev3 requires at least three upstream failures in 15 minutes with no later successful model response.'
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [workspace.id]
    severity: 3
    criteria: {
      allOf: [
        {
          query: 'let Observed = ${tableName} | extend ObservedAt=coalesce(ingestion_time(), TimeGenerated); let Failures = Observed | where ObservedAt > ago(15m) and EventType == "upstream_failed" | summarize FailureCount=count(), LastFailure=max(ObservedAt) by VmId; let Recoveries = Observed | where ObservedAt > ago(15m) and EventType == "request_complete" | summarize LastSuccess=max(ObservedAt) by VmId; Failures | join kind=leftouter Recoveries on VmId | where FailureCount >= 3 and (isnull(LastSuccess) or LastSuccess < LastFailure) | project VmId, FailureCount, LastFailure, LastSuccess'
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            minFailingPeriodsToAlert: 1
            numberOfEvaluationPeriods: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [actionGroup.id]
    }
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
  }
}

resource ingestionHealthAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${prefix}-ingestion-health'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: 'SecureSandbox Azure ingestion stopped or throttled'
    description: 'Sev2 detects the workspace daily cap, an ingestion-rate limit, or another Azure ingestion error.'
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [workspace.id]
    severity: 2
    criteria: {
      allOf: [
        {
          query: '_LogOperation | where TimeGenerated > ago(15m) | where Category =~ "Ingestion" | where Level in~ ("Warning", "Error")'
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            minFailingPeriodsToAlert: 1
            numberOfEvaluationPeriods: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [actionGroup.id]
    }
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
  }
}

output postureAlertId string = postureAlert.id
output availabilityAlertId string = availabilityAlert.id
output ingestionHealthAlertId string = ingestionHealthAlert.id
