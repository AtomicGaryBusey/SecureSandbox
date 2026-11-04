import Darwin
import Foundation
import SecureSandboxNativeSessionUIProtocol

struct CatalogClient: Sendable {
    let repositoryPath: String

    func load<T: Decodable>(_ catalog: String, as type: T.Type) throws -> T {
        guard ["overview", "sessions", "sources", "findings", "artifacts", "activity", "maintenance"].contains(catalog) else {
            throw CatalogError.invalidCatalog
        }
        return try execute(catalog: catalog, arguments: ["catalog", catalog], as: type)
    }

    func planSource(url: String, ref: String) throws -> SourcePlan {
        try execute(catalog: "source-plan", arguments: ["plan-source", url, ref], as: SourcePlan.self)
    }

    func planNpm(package: String, version: String) throws -> SourcePlan {
        try execute(catalog: "source-plan", arguments: ["plan-npm", package, version], as: SourcePlan.self)
    }

    func sourceStatus(planID: String) throws -> SourcePlanStatus {
        let value = try execute(catalog: "source-status", arguments: ["source-status", planID], as: SourcePlanStatus.self)
        guard value.schema == "secure-sandbox-source-plan-status-v1", value.planID == planID else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func applySource(planID: String) throws -> SourceImportResult {
        try execute(catalog: "source-import", arguments: ["apply-source", planID], as: SourceImportResult.self)
    }

    func labelSession(id: String, label: String) throws -> SessionLabelResult {
        try execute(catalog: "session-label", arguments: ["label-session", id, label], as: SessionLabelResult.self)
    }

    func unlabelSession(id: String) throws -> SessionLabelResult {
        try execute(catalog: "session-label", arguments: ["unlabel-session", id], as: SessionLabelResult.self)
    }

    func findingDetail(id: String) throws -> FindingDetail {
        try execute(catalog: "finding-detail", arguments: ["finding-detail", id], as: FindingDetail.self)
    }

    func applyFindingTransition(_ request: FindingTransitionRequest) throws -> FindingTransitionResult {
        let input = try JSONEncoder().encode(request)
        guard input.count <= 16384 else { throw CatalogError.oversized }
        let value = try execute(catalog: "finding-transition", arguments: ["finding-transition"],
                                input: input, as: FindingTransitionResult.self)
        guard value.status == "verified", value.findingID == request.findingID,
              value.state == request.toState else { throw CatalogError.invalidSchema }
        return value
    }

    func applyFindingRelation(_ request: FindingRelationRequest) throws -> FindingRelationResult {
        let input = try JSONEncoder().encode(request)
        guard input.count <= 16384 else { throw CatalogError.oversized }
        let value = try execute(catalog: "finding-relation", arguments: ["finding-relation"],
                                input: input, as: FindingRelationResult.self)
        guard value.status == "verified", value.findingID == request.findingID,
              value.targetFindingID == request.targetFindingID,
              value.relation == request.relation else { throw CatalogError.invalidSchema }
        return value
    }

    func findingReopenOptions(id: String) throws -> FindingReopenOptions {
        let value = try execute(catalog: "finding-reopen-options", arguments: ["finding-reopen-options", id],
                                as: FindingReopenOptions.self)
        guard value.findingID == id else { throw CatalogError.invalidSchema }
        return value
    }

    func reopenFinding(_ request: FindingReopenRequest) throws -> FindingTransitionResult {
        let input = try JSONEncoder().encode(request)
        guard input.count <= 16384 else { throw CatalogError.oversized }
        let value = try execute(catalog: "finding-reopen", arguments: ["finding-reopen"],
                                input: input, as: FindingTransitionResult.self)
        guard value.status == "verified", value.findingID == request.findingID,
              value.state == "needs_evidence" else { throw CatalogError.invalidSchema }
        return value
    }

    func disposeFinding(_ request: FindingDispositionRequest) throws -> FindingDispositionResult {
        let input = try JSONEncoder().encode(request)
        guard input.count <= 16384 else { throw CatalogError.oversized }
        let value = try execute(catalog: "finding-disposition", arguments: ["finding-disposition"],
                                input: input, as: FindingDispositionResult.self)
        guard value.status == "verified", value.findingID == request.findingID,
              value.state == request.expectedState else { throw CatalogError.invalidSchema }
        return value
    }

    func artifactDetail(id: String) throws -> ArtifactDetail {
        try execute(catalog: "artifact-detail", arguments: ["artifact-detail", id], as: ArtifactDetail.self)
    }

    func verifyBoundaries() throws -> BoundaryVerificationResult {
        try execute(catalog: "boundary-verification", arguments: ["verify-boundaries"], as: BoundaryVerificationResult.self)
    }

    func lifecycle(_ operation: String) throws -> LifecycleResult {
        guard ["start", "stop"].contains(operation) else { throw CatalogError.invalidCatalog }
        return try execute(catalog: "lifecycle", arguments: ["lifecycle", operation], as: LifecycleResult.self)
    }

    func lifecycleProgress() throws -> LifecycleProgress {
        try execute(catalog: "lifecycle-progress", arguments: ["lifecycle-progress"], as: LifecycleProgress.self)
    }

    func panic() throws -> PanicResult {
        try execute(catalog: "panic", arguments: ["panic"], as: PanicResult.self)
    }

    func reloadControlIdentities() throws -> IdentityReloadResult {
        try execute(catalog: "key-load", arguments: ["reload-control-identities"], as: IdentityReloadResult.self)
    }

    func dependencyPlan(sourceID: String) throws -> DependencyPlan {
        try execute(catalog: "dependency-plan", arguments: ["dependency-plan", sourceID], as: DependencyPlan.self)
    }

    func dependencyStatus(planID: String) throws -> DependencyStatus {
        try execute(catalog: "dependency-status", arguments: ["dependency-status", planID], as: DependencyStatus.self)
    }

    func dependencyApply(planID: String, expectedDigest: String) throws -> DependencyBundle {
        try execute(catalog: "dependency-apply", arguments: ["dependency-apply", planID, expectedDigest], as: DependencyBundle.self)
    }

    func dependencyBundles() throws -> [DependencyBundleRecord] {
        try execute(catalog: "dependency-bundles", arguments: ["dependency-bundles"], as: [DependencyBundleRecord].self)
    }

    func indexSource(kind: String, sourceID: String) throws -> SourceIndexResult {
        guard ["corpus", "codegraph"].contains(kind) else { throw CatalogError.invalidCatalog }
        return try execute(catalog: "source-index", arguments: ["index-source", kind, sourceID], as: SourceIndexResult.self)
    }

    func indexSourceStatus(kind: String, sourceID: String) throws -> SourceIndexResult {
        guard ["corpus", "codegraph"].contains(kind) else { throw CatalogError.invalidCatalog }
        return try execute(catalog: "source-index-status",
                           arguments: ["index-source-status", kind, sourceID],
                           as: SourceIndexResult.self)
    }

    func backupPreflight(destination: String) throws -> BackupPreflight {
        try execute(catalog: "backup-preflight", arguments: ["backup-preflight", destination], as: BackupPreflight.self)
    }

    func planBackup(destination: String) throws -> BackupPlan {
        try execute(catalog: "backup-plan", arguments: ["backup-plan", destination], as: BackupPlan.self)
    }

    func backupPlanDetail(planID: String) throws -> BackupPlan {
        try execute(catalog: "backup-plan-detail", arguments: ["backup-plan-detail", planID], as: BackupPlan.self)
    }

    func submitBackup(planID: String) throws -> BackupSubmission {
        try execute(catalog: "backup-submit", arguments: ["backup-submit", planID], as: BackupSubmission.self)
    }

    func backupStatus(planID: String) throws -> BackupOperationStatus {
        try execute(catalog: "backup-status", arguments: ["backup-status", planID], as: BackupOperationStatus.self)
    }

    func backupInventory(destination: String) throws -> BackupInventory {
        try execute(catalog: "backup-inventory", arguments: ["backup-inventory", destination], as: BackupInventory.self)
    }

    func restorePreview(destination: String, generationID: String) throws -> RestorePreview {
        try execute(catalog: "restore-preview", arguments: ["restore-preview", destination, generationID], as: RestorePreview.self)
    }

    func planRestore(source: String, generationID: String) throws -> RestorePlan {
        try execute(catalog: "restore-plan", arguments: ["restore-plan", source, generationID], as: RestorePlan.self)
    }

    func restorePlanDetail(restoreID: String) throws -> RestorePlan {
        try execute(catalog: "restore-plan-detail", arguments: ["restore-plan-detail", restoreID], as: RestorePlan.self)
    }

    func submitRestore(restoreID: String) throws -> RestoreSubmission {
        try execute(catalog: "restore-submit", arguments: ["restore-submit", restoreID], as: RestoreSubmission.self)
    }

    func restoreStatus(restoreID: String) throws -> RestoreOperationStatus {
        try execute(catalog: "restore-status", arguments: ["restore-status", restoreID], as: RestoreOperationStatus.self)
    }

    func recoverRestore(restoreID: String) throws -> RestoreSubmission {
        try execute(catalog: "restore-recover", arguments: ["restore-recover", restoreID], as: RestoreSubmission.self)
    }

    func restoreRetirementPreview(restoreID: String) throws -> RestoreRetirement {
        try execute(catalog: "restore-retirement-preview",
                    arguments: ["restore-retirement-preview", restoreID], as: RestoreRetirement.self)
    }

    func retireRestoreGeneration(restoreID: String) throws -> RestoreSubmission {
        try execute(catalog: "restore-retirement-submit",
                    arguments: ["restore-retirement-submit", restoreID], as: RestoreSubmission.self)
    }

    func restoreRetirementStatus(restoreID: String) throws -> RestoreRetirement {
        try execute(catalog: "restore-retirement-status",
                    arguments: ["restore-retirement-status", restoreID], as: RestoreRetirement.self)
    }

    func memoryProposals() throws -> [MemoryProposal] {
        try execute(catalog: "memory-proposals", arguments: ["memory-proposals"], as: [MemoryProposal].self)
    }

    func transcriptDetail(runID: String) throws -> TranscriptDetail {
        try execute(catalog: "transcript-detail", arguments: ["transcript-detail", runID], as: TranscriptDetail.self)
    }

    func exportTranscript(runID: String, destination: URL) throws -> TranscriptExport {
        let value = try execute(catalog: "transcript-export",
                                arguments: ["transcript-export", runID, destination.path], as: TranscriptExport.self)
        guard value.status == "verified", value.runID == runID, value.recordCount > 0,
              value.byteCount > 0, value.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func toolResults(runID: String) throws -> ToolResultCatalog {
        try execute(catalog: "tool-results", arguments: ["tool-results", runID], as: ToolResultCatalog.self)
    }

    func toolResultDetail(runID: String, toolUseID: String, expectedSHA256: String) throws -> ToolResultDetail {
        try execute(catalog: "tool-result-detail", arguments: ["tool-result-detail", runID, toolUseID, expectedSHA256], as: ToolResultDetail.self)
    }

    func sessionRuns(sessionID: String) throws -> SessionRuns {
        try execute(catalog: "session-runs", arguments: ["session-runs", sessionID], as: SessionRuns.self)
    }

    func leaseStatus(runID: String) throws -> LeaseStatus {
        try execute(catalog: "lease-status", arguments: ["lease-status", runID], as: LeaseStatus.self)
    }

    func renewLease(runID: String, seconds: Int) throws -> LeaseStatus {
        guard [300, 900].contains(seconds) else { throw CatalogError.invalidCatalog }
        return try execute(catalog: "lease-renew", arguments: ["lease-renew", runID, String(seconds)], as: LeaseStatus.self)
    }

    func leaseReconcilePlan(runID: String) throws -> LeaseReconcilePlan {
        let value = try execute(catalog: "lease-reconcile-plan", arguments: ["lease-reconcile-plan", runID],
                                as: LeaseReconcilePlan.self)
        guard value.schema == "secure-sandbox-lease-reconcile-plan-v1", value.runID == runID else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func reconcileLease(runID: String, expectedDigest: String) throws -> LeaseCompleted {
        let value = try execute(catalog: "lease-reconcile", arguments: ["lease-reconcile", runID, expectedDigest],
                                as: LeaseCompleted.self)
        guard value.runID == runID, value.phase == "committed",
              value.gatewaySummarySHA256 == expectedDigest else { throw CatalogError.invalidSchema }
        return value
    }

    func completedLease(runID: String) throws -> LeaseCompleted {
        let value = try execute(catalog: "lease-completed", arguments: ["lease-completed", runID],
                                as: LeaseCompleted.self)
        guard value.runID == runID, value.phase == "committed" else { throw CatalogError.invalidSchema }
        return value
    }

    func applyTimeSync() throws -> TimeSyncResult {
        try execute(catalog: "time-sync", arguments: ["apply-time-sync"], as: TimeSyncResult.self)
    }

    func safetyAudit() throws -> SafetyAuditResult {
        try execute(catalog: "safety-audit", arguments: ["safety-audit"], as: SafetyAuditResult.self)
    }

    func snapshotPolicy() throws -> SnapshotPolicyResult {
        try execute(catalog: "snapshot-policy", arguments: ["snapshot-policy"], as: SnapshotPolicyResult.self)
    }

    func snapshotPreview() throws -> SnapshotPreview {
        try execute(catalog: "snapshot-preview", arguments: ["snapshot-preview"], as: SnapshotPreview.self)
    }

    func applySnapshotRetention() throws -> SnapshotApplyResult {
        try execute(catalog: "snapshot-apply", arguments: ["snapshot-apply"], as: SnapshotApplyResult.self)
    }

    func modelProfiles() throws -> ModelProfileCatalogStatus {
        let value = try execute(catalog: "model-profiles", arguments: ["model-profiles"],
                                as: ModelProfileCatalogStatus.self)
        guard value.schema == "secure-sandbox-model-profile-catalog-status-v1",
              value.status == "verified", ["example", "staged"].contains(value.source),
              value.catalog.schema == "secure-sandbox-model-profile-catalog-v1",
              !value.catalog.profiles.isEmpty, value.catalog.profiles.count <= 16 else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func saveModelProfiles(_ catalog: ModelProfileCatalog) throws -> ModelProfileCatalogStatus {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let input = try encoder.encode(catalog)
        guard input.count <= 64 * 1024 else { throw CatalogError.oversized }
        let value = try execute(catalog: "model-profiles-save", arguments: ["model-profiles-save"],
                                input: input, as: ModelProfileCatalogStatus.self)
        guard value.schema == "secure-sandbox-model-profile-catalog-status-v1",
              value.status == "verified", value.source == "staged" else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func nativeVendorStacks() throws -> NativeVendorStackCatalogStatus {
        let value = try execute(catalog: "native-vendor-stacks",
                                arguments: ["native-vendor-stacks"],
                                as: NativeVendorStackCatalogStatus.self)
        let readinessStates = Set(value.stacks.map(\.readiness.status))
        guard value.schema == "secure-sandbox-native-vendor-stack-catalog-status-v1",
              value.status == "verified", ["example", "staged"].contains(value.source),
              value.catalog.schema == "secure-sandbox-native-vendor-stack-catalog-v1",
              !value.catalog.stacks.isEmpty, value.catalog.stacks.count <= 8,
              value.stacks.count == value.catalog.stacks.count,
              value.stacks.map(\.stack) == value.catalog.stacks,
              readinessStates.isSubset(of: [
                  "configuration-required", "login-required", "content-ready",
              ]),
              value.stacks.allSatisfy({ item in
                  item.revisionSHA256.count == 64
                      && item.readiness.schema == "secure-sandbox-native-vendor-stack-readiness-v1"
                      && item.readiness.stackID == item.stack.stackID
                      && item.readiness.stackSHA256 == item.revisionSHA256
                      && item.stack.mode == "native-vendor-harness-model-stack"
              }) else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func saveNativeVendorStacks(
        _ catalog: NativeVendorStackCatalog
    ) throws -> NativeVendorStackCatalogStatus {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let input = try encoder.encode(catalog)
        guard input.count <= 64 * 1024 else { throw CatalogError.oversized }
        let value = try execute(catalog: "native-vendor-stacks-save",
                                arguments: ["native-vendor-stacks-save"],
                                input: input, as: NativeVendorStackCatalogStatus.self)
        guard value.schema == "secure-sandbox-native-vendor-stack-catalog-status-v1",
              value.status == "verified", value.source == "staged" else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func nativeStackActionPlan(
        action: String,
        stackID: String,
        inspection: NativeStackInspection,
        observedAccountSubjectSHA256: String? = nil,
        observedWorkspaceSHA256: String? = nil
    ) throws -> NativeStackActionPlan {
        let actions = Set([
            "signin-begin", "binding-commit", "status-verify", "entitlement-verify",
            "activate", "rollback", "logout", "credential-destroy", "recover",
        ])
        guard actions.contains(action), inspection.status.stackID == stackID else {
            throw CatalogError.invalidCatalog
        }
        var arguments = ["native-stack-action-plan", action, stackID]
        if let observedAccountSubjectSHA256 {
            arguments += ["--observed-account-subject-sha256", observedAccountSubjectSHA256]
        }
        if let observedWorkspaceSHA256 {
            arguments += ["--observed-workspace-sha256", observedWorkspaceSHA256]
        }
        let value = try execute(
            catalog: "native-stack-action-plan", arguments: arguments,
            input: inspection.canonicalStatus, as: NativeStackActionPlan.self
        )
        guard value.schema == "secure-sandbox-native-stack-action-plan-v1",
              value.action == action, value.identity.stackID == stackID,
              value.identity.stackSHA256 == inspection.status.stackSHA256,
              value.currentStatusSHA256 == inspection.status.statusSHA256,
              value.actionID.range(
                of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
                options: .regularExpression
              ) != nil,
              value.planSHA256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
              value.createdAt < value.expiresAt,
              value.expiresAt <= value.createdAt + 300,
              value.expiresAt > Int(Date().timeIntervalSince1970),
              (value.observedAccountSubjectSHA256 == nil)
                == (value.observedWorkspaceSHA256 == nil),
              action == "binding-commit"
                ? (value.observedAccountSubjectSHA256 == observedAccountSubjectSHA256
                    && value.observedWorkspaceSHA256 == observedWorkspaceSHA256
                    && observedAccountSubjectSHA256 != nil)
                : (value.observedAccountSubjectSHA256 == nil
                    && value.observedWorkspaceSHA256 == nil)
        else { throw CatalogError.invalidSchema }
        return value
    }

    func authorizeNativeStackAction(
        _ plan: NativeStackActionPlan
    ) throws -> NativeStackActionReceipt {
        guard !(plan.action == "signin-begin"
                && plan.identity.vendorID == "anthropic") else {
            throw CatalogError.invalidCatalog
        }
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-stack-action-receipt",
            arguments: [
                "native-stack-action-authorize", plan.actionID, plan.planSHA256,
                "Control Center", session,
            ],
            as: NativeStackActionReceipt.self
        )
        guard value.schema == "secure-sandbox-native-stack-action-receipt-v1",
              value.actionID == plan.actionID, value.action == plan.action,
              value.planSHA256 == plan.planSHA256,
              value.result == "verified",
              value.statusSHA256.range(
                of: #"^[0-9a-f]{64}$"#, options: .regularExpression
              ) != nil,
              value.evidenceSHA256.range(
                of: #"^[0-9a-f]{64}$"#, options: .regularExpression
              ) != nil,
              value.receiptSHA256.range(
                of: #"^[0-9a-f]{64}$"#, options: .regularExpression
              ) != nil
        else { throw CatalogError.invalidSchema }
        return value
    }

    func authorizeNativeClaudeLogin(
        _ plan: NativeStackActionPlan
    ) throws -> NativeTerminalHandle {
        guard plan.action == "signin-begin", plan.identity.vendorID == "anthropic" else {
            throw CatalogError.invalidCatalog
        }
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-stack-action-receipt",
            arguments: [
                "native-stack-action-authorize", plan.actionID, plan.planSHA256,
                "Control Center", session,
            ],
            as: NativeTerminalHandle.self
        )
        try value.validate(expectedKinds: ["claude-login"])
        guard value.operationID == plan.actionID else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func authorizeNativeClaudeSessionStart(
        _ plan: NativeSessionPlan
    ) throws -> NativeTerminalHandle {
        guard plan.action == .start, plan.authority.vendorID == "anthropic" else {
            throw CatalogError.invalidCatalog
        }
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-session-authorize-result",
            arguments: [
                "native-session-authorize", plan.actionID, plan.planSHA256,
                "Control Center", session,
            ],
            input: plan.canonicalData,
            as: NativeTerminalHandle.self
        )
        try value.validate(expectedKinds: ["claude-session"])
        guard value.operationID == plan.actionID, value.sessionID == plan.sessionID else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func authorizeNativeCodexSessionStart(
        _ plan: NativeSessionPlan
    ) throws -> NativeCodexUIHandle {
        guard plan.action == .start, plan.authority.vendorID == "openai" else {
            throw CatalogError.invalidCatalog
        }
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-session-authorize-result",
            arguments: [
                "native-session-authorize", plan.actionID, plan.planSHA256,
                "Control Center", session,
            ],
            input: plan.canonicalData,
            as: NativeCodexUIHandle.self
        )
        try value.validate(plan: plan)
        return value
    }

    func authorizeNativeSessionStop(
        _ plan: NativeSessionPlan
    ) throws -> NativeSessionStopReply {
        guard plan.action == .stop,
              ["anthropic", "openai"].contains(plan.authority.vendorID) else {
            throw CatalogError.invalidCatalog
        }
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-session-authorize-result",
            arguments: [
                "native-session-authorize", plan.actionID, plan.planSHA256,
                "Control Center", session,
            ],
            input: plan.canonicalData,
            as: NativeSessionStopReply.self
        )
        let harness = plan.authority.vendorID == "anthropic" ? "claude" : "codex"
        guard value.schema == "secure-sandbox-native-\(harness)-session-stop-reply-v1",
              value.operationID == plan.actionID,
              value.sessionID == plan.sessionID,
              value.state == "absent",
              NativeStackControlClient.isSHA256(value.finalSummarySHA256),
              NativeStackControlClient.isSHA256(value.evidenceSHA256) else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func nativeStackCatalogPromotionPlan(
        publicStatus: NativeStackPublicCatalogStatus,
        expectedStagedCatalogSHA256: String
    ) throws -> NativeStackCatalogPromotionPlan {
        let value = try execute(
            catalog: "native-stack-catalog-promotion-plan",
            arguments: [
                "native-stack-catalog-promotion-plan", publicStatus.catalogSHA256,
                publicStatus.hostReleaseID,
            ],
            as: NativeStackCatalogPromotionPlan.self
        )
        guard value.schema == "secure-sandbox-native-stack-catalog-promotion-plan-v1",
              value.previousCatalogSHA256 == publicStatus.catalogSHA256,
              value.hostReleaseID == publicStatus.hostReleaseID,
              value.sourceSHA256 == expectedStagedCatalogSHA256,
              value.catalogSHA256 == expectedStagedCatalogSHA256,
              value.promotionID.range(
                of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
                options: .regularExpression
              ) != nil,
              value.planSHA256.range(
                of: #"^[0-9a-f]{64}$"#, options: .regularExpression
              ) != nil,
              value.createdAt < value.expiresAt,
              value.expiresAt <= value.createdAt + 300,
              value.expiresAt > Int(Date().timeIntervalSince1970)
        else { throw CatalogError.invalidSchema }
        return value
    }

    func authorizeNativeStackCatalogPromotion(
        _ plan: NativeStackCatalogPromotionPlan
    ) throws -> NativeStackCatalogPromotionReceipt {
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-stack-catalog-promotion-receipt",
            arguments: [
                "native-stack-catalog-promotion-authorize", plan.promotionID,
                plan.planSHA256, "Control Center", session,
            ],
            as: NativeStackCatalogPromotionReceipt.self
        )
        guard value.schema == "secure-sandbox-native-stack-catalog-promotion-receipt-v1",
              value.promotionID == plan.promotionID,
              value.planSHA256 == plan.planSHA256,
              value.sourceSHA256 == plan.sourceSHA256,
              value.previousCatalogSHA256 == plan.previousCatalogSHA256,
              value.catalogSHA256 == plan.catalogSHA256,
              value.hostReleaseID == plan.hostReleaseID,
              value.status == "authorized-for-publication",
              value.receiptSHA256.range(
                of: #"^[0-9a-f]{64}$"#, options: .regularExpression
              ) != nil
        else { throw CatalogError.invalidSchema }
        return value
    }

    func nativeProgramAttestationPlan(
        stackID: String,
        catalogSHA256: String,
        inspection: NativeStackInspection
    ) throws -> NativeProgramAttestationPlan {
        guard NativeStackControlClient.isIdentifier(stackID),
              NativeStackControlClient.isSHA256(catalogSHA256),
              inspection.status.stackID == stackID
        else { throw CatalogError.invalidCatalog }
        let value = try execute(
            catalog: "native-program-attestation-plan",
            arguments: [
                "native-program-attestation-plan", stackID, catalogSHA256,
            ],
            input: inspection.canonicalStatus,
            as: NativeProgramAttestationPlan.self
        )
        try value.validateDigest()
        let now = Int(Date().timeIntervalSince1970)
        guard value.schema == "secure-sandbox-native-program-attestation-plan-v1",
              value.attestationID.range(
                of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
                options: .regularExpression
              ) != nil,
              value.stackID == stackID,
              value.stackSHA256 == inspection.status.stackSHA256,
              value.catalogSHA256 == catalogSHA256,
              value.statusSHA256 == inspection.status.statusSHA256,
              NativeStackControlClient.isSHA256(value.harnessGenerationID),
              value.harnessGenerationID == inspection.status.harness.generationID,
              NativeStackControlClient.isSHA256(value.accountSubjectSHA256),
              value.accountSubjectSHA256
                == inspection.status.accountBinding.accountSubjectSHA256,
              NativeStackControlClient.isSHA256(value.workspaceSHA256),
              value.workspaceSHA256
                == inspection.status.accountBinding.workspaceSHA256,
              NativeStackControlClient.isIdentifier(value.programID),
              NativeStackControlClient.isIdentifier(value.programTier),
              NativeStackControlClient.isIdentifier(value.programRequirementsVersion),
              value.assurance == "operator-external",
              value.createdAt <= now, now < value.expiresAt,
              value.expiresAt <= value.createdAt + 180,
              NativeStackControlClient.isSHA256(value.planSHA256)
        else { throw CatalogError.invalidSchema }
        return value
    }

    func authorizeNativeProgramAttestation(
        _ plan: NativeProgramAttestationPlan
    ) throws -> NativeProgramAttestationResult {
        let session = UUID().uuidString.lowercased()
        let value = try execute(
            catalog: "native-program-attestation-result",
            arguments: [
                "native-program-attestation-authorize", plan.attestationID,
                plan.planSHA256, "Control Center", session,
            ],
            as: NativeProgramAttestationResult.self
        )
        guard value.schema == "secure-sandbox-native-stack-provider-result-v1",
              value.actionID == plan.attestationID,
              value.action == "program-attest",
              value.planSHA256 == plan.planSHA256,
              NativeStackControlClient.isSHA256(value.authorizationSHA256),
              value.status == "verified",
              NativeStackControlClient.isSHA256(value.evidenceSHA256)
        else { throw CatalogError.invalidSchema }
        return value
    }

    func modelProfileActivationPlan(profileID: String, mode: String) throws -> ModelProfileActivationPlan {
        let value = try execute(catalog: "model-profile-activation-plan",
                                arguments: ["model-profile-activation-plan", profileID, mode],
                                as: ModelProfileActivationPlan.self)
        guard value.schema == "secure-sandbox-model-profile-activation-plan-v1",
              value.activationID.count == 36, value.planSHA256.count == 64,
              value.currentGenerationSHA256.count == 64,
              value.broker.profileID == profileID, value.broker.mode == mode else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func activateModelProfile(_ plan: ModelProfileActivationPlan) throws -> ModelProfileActivationSubmit {
        let session = "model-profile-\(UUID().uuidString.lowercased())"
        let value = try execute(catalog: "model-profile-activate",
                                arguments: ["model-profile-activate", plan.activationID,
                                            plan.planSHA256, "Control Center", session],
                                as: ModelProfileActivationSubmit.self)
        guard value.schema == "secure-sandbox-model-profile-activation-submit-v1",
              value.status == "submitted", value.activationID == plan.activationID,
              value.planSHA256 == plan.planSHA256 else { throw CatalogError.invalidSchema }
        return value
    }

    func harnessStatus() throws -> HarnessControlCenterStatus {
        let value = try execute(catalog: "harness-status", arguments: ["harness-status"],
                                as: HarnessControlCenterStatus.self)
        guard value.schema == "secure-sandbox-harness-control-center-status-v1",
              value.lifecycle.schema == "secure-sandbox-harness-lifecycle-status-v1",
              value.lifecycle.authority == "none",
              !value.lifecycle.automaticDownload, !value.lifecycle.automaticInstall,
              value.protectedActions.requiresTouchID,
              !value.protectedActions.passwordFallback else { throw CatalogError.invalidSchema }
        return value
    }

    func harnessReleases() throws -> HarnessReleaseCatalog {
        let value = try execute(catalog: "harness-releases", arguments: ["harness-releases"],
                                as: HarnessReleaseCatalog.self)
        guard value.schema == "secure-sandbox-harness-release-catalog-v1",
              value.authority == "signed-metadata-only", !value.releases.isEmpty,
              value.releases.count <= 64 else { throw CatalogError.invalidSchema }
        return value
    }

    func harnessAcceptanceStatus() throws -> HarnessAcceptanceAvailability {
        let value = try execute(catalog: "harness-acceptance-status",
                                arguments: ["harness-acceptance-status"],
                                as: HarnessAcceptanceAvailability.self)
        guard value.schema == "secure-sandbox-harness-lifecycle-acceptance-availability-v2",
              value.suiteID == "secure-sandbox-disposable-mac-harness-lifecycle-v4",
              value.suiteSHA256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
              value.caseCount == 91, value.observationCount == 198,
              value.authority == "none",
              ["available", "not-enrolled", "rejected"].contains(value.availability) else {
            throw CatalogError.invalidSchema
        }
        if value.availability != "available" {
            guard value.status == nil, value.nextStep == nil, value.reason != nil else {
                throw CatalogError.invalidSchema
            }
            return value
        }
        guard value.reason == nil, let status = value.status, let next = value.nextStep,
              status.schema == "secure-sandbox-harness-lifecycle-acceptance-status-v1",
              !status.campaignID.isEmpty,
              status.suiteSHA256 == value.suiteSHA256,
              status.caseCount == value.caseCount,
              status.observationCount == value.observationCount,
              status.authority == "none",
              (0...value.caseCount).contains(status.completedCaseCount),
              status.completedCases.count == status.completedCaseCount,
              Set(status.completedCases).count == status.completedCases.count,
              status.missing.count == value.caseCount - status.completedCaseCount,
              status.missing.allSatisfy({ !$0.caseID.isEmpty && !$0.evidenceKinds.isEmpty }),
              status.readyForAssembly == status.missing.isEmpty,
              status.nextCase == status.missing.first?.caseID,
              next.schema == "secure-sandbox-harness-lifecycle-acceptance-next-v1",
              next.campaignID == status.campaignID,
              next.suiteSHA256 == value.suiteSHA256,
              next.authority == "none" else {
            throw CatalogError.invalidSchema
        }
        if status.readyForAssembly {
            guard next.status == "complete", next.casePlan == nil,
                  next.missingEvidence.isEmpty else { throw CatalogError.invalidSchema }
        } else {
            guard next.status == "pending", let casePlan = next.casePlan,
                  casePlan.caseID == status.nextCase,
                  casePlan.procedure.schema
                    == "secure-sandbox-harness-lifecycle-acceptance-procedure-v1",
                  casePlan.procedure.caseID == casePlan.caseID,
                  casePlan.procedure.action == casePlan.caseID,
                  casePlan.procedure.procedureSHA256.range(
                    of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
                  !next.missingEvidence.isEmpty else { throw CatalogError.invalidSchema }
        }
        return value
    }

    func checkHarnessMetadata() throws -> HarnessLifecycleReceipt {
        let value = try execute(catalog: "harness-receipt", arguments: ["harness-check"],
                                as: HarnessLifecycleReceipt.self)
        guard value.schema == "secure-sandbox-harness-lifecycle-receipt-v1",
              value.action == "check", value.status == "metadata_verified" else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func acquireHarness(generationID: String) throws -> HarnessLifecycleReceipt {
        guard generationID.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
            throw CatalogError.invalidCatalog
        }
        let value = try execute(catalog: "harness-receipt",
                                arguments: ["harness-acquire", generationID],
                                as: HarnessLifecycleReceipt.self)
        guard value.schema == "secure-sandbox-harness-lifecycle-receipt-v1",
              value.action == "acquire", value.generationID == generationID else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func verifyHarness(generationID: String) throws -> HarnessLifecycleReceipt {
        guard generationID.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
            throw CatalogError.invalidCatalog
        }
        let value = try execute(catalog: "harness-receipt",
                                arguments: ["harness-verify", generationID],
                                as: HarnessLifecycleReceipt.self)
        guard value.schema == "secure-sandbox-harness-lifecycle-receipt-v1",
              value.action == "verify", value.generationID == generationID,
              value.note == "not_admitted_not_executable" else { throw CatalogError.invalidSchema }
        return value
    }

    func runHarnessQualificationSelfTest() throws -> HarnessQualificationReport {
        let value = try execute(catalog: "harness-qualification",
                                arguments: ["harness-qualification-self-test"],
                                as: HarnessQualificationReport.self)
        guard value.schema == "secure-sandbox-harness-qualification-report-v1",
              value.status == "fixture_qualified", value.authority == "none",
              value.note == "fixture_qualified_not_admitted",
              !value.caseResults.isEmpty,
              value.caseResults.allSatisfy({ $0.status == "passed" }) else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func planHarnessGeneration(operation: String, generationID: String?, reason: String?) throws -> HarnessGenerationPlan {
        var arguments = ["harness-generation-plan", operation]
        if let generationID { arguments.append(generationID) }
        if let reason { arguments.append(reason) }
        let value = try execute(catalog: "harness-generation-plan", arguments: arguments,
                                as: HarnessGenerationPlan.self)
        guard value.schema == "secure-sandbox-harness-control-center-plan-v1",
              value.operation == operation, value.planSHA256.count == 64,
              value.expiresAt > Int(Date().timeIntervalSince1970) else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func authorizeHarnessGeneration(_ plan: HarnessGenerationPlan) throws -> HarnessGenerationResult {
        let session = "harness-lifecycle-\(UUID().uuidString.lowercased())"
        let value = try execute(
            catalog: "harness-generation-authorize",
            arguments: ["harness-generation-authorize", plan.operation, plan.identifier,
                        plan.planSHA256, "Control Center", session],
            as: HarnessGenerationResult.self
        )
        guard value.schema == "secure-sandbox-harness-control-center-result-v1",
              value.operation == plan.operation, value.boundary == "verified" else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    private func execute<T: Decodable>(catalog: String, arguments: [String],
                                      input: Data? = nil, as type: T.Type) throws -> T {
        guard repositoryPath == ControlCenterPaths.repository else {
            throw CatalogError.untrustedRepository
        }
        let script = URL(fileURLWithPath: repositoryPath)
            .appending(path: "scripts/control-center-api.py")
        guard ControlCenterPaths.hasLocalBridge() else {
            throw CatalogError.missingBridge
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [script.path] + arguments
        process.currentDirectoryURL = URL(fileURLWithPath: repositoryPath)
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let inputPipe = input == nil ? nil : Pipe()
        if let inputPipe { process.standardInput = inputPipe }
        try NativeDescriptorInheritanceGate.run(process)
        let longAction = ["lifecycle", "snapshot-apply", "restore-preview", "restore-plan",
                          "apply-source", "transcript-export",
                          "verify-boundaries", "safety-audit", "index-source", "dependency-apply",
                          "backup-preflight", "backup-plan", "backup-inventory",
                          "harness-check", "harness-acquire", "harness-verify",
                          "harness-qualification-self-test", "harness-generation-plan",
                          "harness-generation-authorize", "native-stack-action-plan",
                          "native-stack-action-authorize",
                          "native-program-attestation-plan",
                          "native-program-attestation-authorize",
                          "native-session-authorize",
                          "native-stack-catalog-promotion-plan",
                          "native-stack-catalog-promotion-authorize"].contains(arguments.first ?? "")
        let deadline = DispatchWorkItem { [weak process] in
            if process?.isRunning == true { process?.terminate() }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + (longAction ? 1_500 : 400),
                                                        execute: deadline)
        defer {
            deadline.cancel()
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
        }
        if let input, let inputPipe {
            try inputPipe.fileHandleForWriting.write(contentsOf: input)
            try inputPipe.fileHandleForWriting.close()
        }
        var data = Data()
        while let chunk = try output.fileHandleForReading.read(upToCount: 64 * 1024), !chunk.isEmpty {
            data.append(chunk)
            if data.count > 8 * 1024 * 1024 { throw CatalogError.oversized }
        }
        process.waitUntilExit()
        if process.terminationReason == .uncaughtSignal, process.terminationStatus == SIGTERM {
            throw CatalogError.timeout
        }
        if process.terminationStatus != 0 {
            if let failure = try? JSONDecoder().decode(Failure.self, from: data) {
                throw CatalogError.bridge(failure.error)
            }
            throw CatalogError.bridge("The host catalog could not be loaded.")
        }
        let envelope = try JSONDecoder().decode(Envelope<T>.self, from: data)
        guard envelope.schema == "secure-sandbox-control-center-v1", envelope.catalog == catalog else {
            throw CatalogError.invalidSchema
        }
        return envelope.data
    }

    private struct Failure: Decodable { let error: String }
}

enum CatalogError: LocalizedError {
    case invalidCatalog, missingBridge, untrustedRepository, oversized, invalidSchema, timeout, bridge(String)

    var errorDescription: String? {
        switch self {
        case .invalidCatalog: "Unknown catalog."
        case .missingBridge: "The reviewed SecureSandbox installation is unavailable."
        case .untrustedRepository: "The app refused an unrecognized SecureSandbox installation path."
        case .oversized: "The catalog exceeded its size limit."
        case .timeout: "The host operation exceeded its deadline. Inspect its state before another attempt."
        case .invalidSchema: "The host returned an unsupported catalog version."
        case .bridge(let detail): detail
        }
    }
}
