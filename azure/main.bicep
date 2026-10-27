@description('Azure region; keep the workspace and direct-ingestion DCR together.')
param location string = resourceGroup().location

@description('Short lowercase prefix used in globally unique resource names.')
@minLength(3)
@maxLength(16)
param prefix string = 'secsandbox'

@description('Object ID of an existing Entra service principal used only for ingestion. Leave empty to omit the role assignment.')
param ingestionPrincipalObjectId string = ''

@description('Email recipient for security alerts. Leave empty to deploy alerts without a notification action group.')
param alertEmail string = ''

@description('Monthly resource-group cost budget in USD. Set to zero to omit the budget.')
@minValue(0)
param monthlyBudgetUsd int = 10

@description('First day of the current UTC month used as the budget period start.')
param budgetStartDate string = utcNow('yyyy-MM-01')

@minValue(30)
@maxValue(730)
param retentionDays int = 30

var suffix = uniqueString(subscription().id, resourceGroup().id)
var workspaceName = '${prefix}-law-${suffix}'
var dcrName = '${prefix}-dcr-${suffix}'
var tableName = 'SecureSandbox_CL'
var streamName = 'Custom-${tableName}'
var tableColumns = [
  { name: 'TimeGenerated', type: 'dateTime' }
  { name: 'RunId', type: 'string' }
  { name: 'VmId', type: 'string' }
  { name: 'AgentId', type: 'string' }
  { name: 'EventType', type: 'string' }
  { name: 'Severity', type: 'string' }
  { name: 'Decision', type: 'string' }
  { name: 'Destination', type: 'string' }
  { name: 'DestinationPort', type: 'int' }
  { name: 'Status', type: 'int' }
  { name: 'RequestBytes', type: 'long' }
  { name: 'ResponseBytes', type: 'long' }
  { name: 'RequestId', type: 'string' }
  { name: 'PolicyHash', type: 'string' }
  { name: 'Message', type: 'string' }
]
// The DCR provider requires lowercase "datetime", while the Log Analytics
// table provider requires "dateTime" for the same logical timestamp type.
var streamColumns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'RunId', type: 'string' }
  { name: 'VmId', type: 'string' }
  { name: 'AgentId', type: 'string' }
  { name: 'EventType', type: 'string' }
  { name: 'Severity', type: 'string' }
  { name: 'Decision', type: 'string' }
  { name: 'Destination', type: 'string' }
  { name: 'DestinationPort', type: 'int' }
  { name: 'Status', type: 'int' }
  { name: 'RequestBytes', type: 'long' }
  { name: 'ResponseBytes', type: 'long' }
  { name: 'RequestId', type: 'string' }
  { name: 'PolicyHash', type: 'string' }
  { name: 'Message', type: 'string' }
]
var monitoringMetricsPublisherRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '3913510d-42f4-4e42-8a64-420c390055eb'
)

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: workspaceName
  location: location
  properties: {
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    retentionInDays: retentionDays
    sku: {
      name: 'PerGB2018'
    }
    workspaceCapping: {
      // Bicep numeric literals are integers; parse JSON to preserve Azure's
      // supported fractional 100 MiB/day safety cap.
      dailyQuotaGb: json('0.1')
    }
  }
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2025-07-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionDays
    totalRetentionInDays: retentionDays
    schema: {
      name: tableName
      description: 'Metadata-only SecureSandbox control, egress, and lifecycle events.'
      columns: tableColumns
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  // Azure validates the output table during DCR creation; the workspace ID
  // reference alone does not serialize creation behind the child table.
  dependsOn: [table]
  properties: {
    streamDeclarations: {
      '${streamName}': {
        columns: streamColumns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'secureSandboxWorkspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['secureSandboxWorkspace']
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
}

resource ingestRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(ingestionPrincipalObjectId)) {
  name: guid(dcr.id, ingestionPrincipalObjectId, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    principalId: ingestionPrincipalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: monitoringMetricsPublisherRoleId
  }
}

resource workspaceLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'protect-security-evidence'
  scope: workspace
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of SecureSandbox evidence. Owners can remove the lock deliberately.'
  }
}

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(alertEmail)) {
  name: '${prefix}-security-alerts'
  location: 'global'
  properties: {
    enabled: true
    groupShortName: 'SecSandbox'
    emailReceivers: [
      {
        name: 'owner'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
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
      actionGroups: empty(alertEmail) ? [] : [actionGroup.id]
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
      actionGroups: empty(alertEmail) ? [] : [actionGroup.id]
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
      actionGroups: empty(alertEmail) ? [] : [actionGroup.id]
    }
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
  }
}

resource monthlyBudget 'Microsoft.Consumption/budgets@2024-08-01' = if (!empty(alertEmail) && monthlyBudgetUsd > 0) {
  name: '${prefix}-monthly-budget'
  properties: {
    category: 'Cost'
    amount: monthlyBudgetUsd
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
    }
    notifications: {
      Actual_GreaterThanOrEqualTo_80_Percent: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
        contactGroups: [actionGroup.id]
      }
      Forecasted_GreaterThanOrEqualTo_100_Percent: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [alertEmail]
        contactGroups: [actionGroup.id]
      }
    }
  }
}

output workspaceResourceId string = workspace.id
output workspaceName string = workspace.name
output tableName string = tableName
output streamName string = streamName
output dcrResourceId string = dcr.id
output dcrImmutableId string = dcr.properties.immutableId
output logsIngestionEndpoint string = dcr.properties.endpoints.logsIngestion
output ingestionHealthAlertId string = ingestionHealthAlert.id
output monthlyBudgetName string = (!empty(alertEmail) && monthlyBudgetUsd > 0) ? monthlyBudget.name : ''
