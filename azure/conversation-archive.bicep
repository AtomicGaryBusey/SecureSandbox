@description('Azure region for the encrypted conversation and artifact evidence archive.')
param location string = resourceGroup().location

@description('Object ID of the dedicated add-only archive service principal.')
param archivePrincipalObjectId string

@description('Object ID of the human archive reader. Reader cannot modify or delete blobs.')
param archiveReaderObjectId string

@minValue(1)
@maxValue(365)
param immutabilityDays int = 30

var suffix = uniqueString(subscription().id, resourceGroup().id, 'conversation-archive')
var accountName = 'ssarchive${suffix}'
var containerName = 'conversations'
var roleDefinitionGuid = guid(subscription().id, 'SecureSandbox encrypted conversation blob creator')
var blobReaderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: accountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: account
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: false }
    isVersioningEnabled: false
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: { publicAccess: 'None' }
}

// Deploy unlocked for the end-to-end acceptance test. The activation script
// performs Azure's irreversible lock operation only after a byte-for-byte
// encrypt/upload/download/decrypt proof succeeds.
resource immutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: container
  name: 'default'
  properties: {
    allowProtectedAppendWrites: false
    allowProtectedAppendWritesAll: false
    immutabilityPeriodSinceCreationInDays: immutabilityDays
  }
}

resource uploadRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleDefinitionGuid
  properties: {
    roleName: 'SecureSandbox Encrypted Conversation Blob Creator'
    description: 'Can create new immutable conversation and artifact ciphertext blobs; cannot list, read, overwrite, or delete.'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action']
        notDataActions: []
      }
    ]
  }
}

resource uploadAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, archivePrincipalObjectId, uploadRole.id)
  scope: container
  properties: {
    principalId: archivePrincipalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: uploadRole.id
  }
}

resource readerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, archiveReaderObjectId, blobReaderRoleId)
  scope: container
  properties: {
    principalId: archiveReaderObjectId
    principalType: 'User'
    roleDefinitionId: blobReaderRoleId
  }
}

resource archiveLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'protect-conversation-archive'
  scope: account
  properties: {
    level: 'CanNotDelete'
    notes: 'Protects the encrypted conversation archive from accidental resource deletion.'
  }
}

output archiveStorageAccount string = account.name
output archiveContainer string = container.name
output immutabilityPolicyId string = immutability.id
output uploadRoleDefinitionId string = uploadRole.id
