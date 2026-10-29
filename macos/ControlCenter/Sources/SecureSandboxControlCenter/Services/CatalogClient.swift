import Foundation

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

    func indexSource(kind: String, sourceID: String) throws -> SourceIndexResult {
        guard ["corpus", "codegraph"].contains(kind) else { throw CatalogError.invalidCatalog }
        return try execute(catalog: "source-index", arguments: ["index-source", kind, sourceID], as: SourceIndexResult.self)
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

    func memoryProposals() throws -> [MemoryProposal] {
        try execute(catalog: "memory-proposals", arguments: ["memory-proposals"], as: [MemoryProposal].self)
    }

    func transcriptDetail(runID: String) throws -> TranscriptDetail {
        try execute(catalog: "transcript-detail", arguments: ["transcript-detail", runID], as: TranscriptDetail.self)
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

    private func execute<T: Decodable>(catalog: String, arguments: [String],
                                      input: Data? = nil, as type: T.Type) throws -> T {
        let script = URL(fileURLWithPath: repositoryPath)
            .appending(path: "scripts/control-center-api.py")
        guard FileManager.default.isReadableFile(atPath: script.path) else {
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
        try process.run()
        if let input, let inputPipe {
            try inputPipe.fileHandleForWriting.write(contentsOf: input)
            try inputPipe.fileHandleForWriting.close()
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard data.count <= 8 * 1024 * 1024 else { throw CatalogError.oversized }
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
    case invalidCatalog, missingBridge, oversized, invalidSchema, bridge(String)

    var errorDescription: String? {
        switch self {
        case .invalidCatalog: "Unknown catalog."
        case .missingBridge: "The SecureSandbox repository was not found. Set its location in Settings."
        case .oversized: "The catalog exceeded its size limit."
        case .invalidSchema: "The host returned an unsupported catalog version."
        case .bridge(let detail): detail
        }
    }
}
