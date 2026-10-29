import SwiftUI
import UniformTypeIdentifiers

struct RecoveryView: View {
    let store: CatalogStore
    private let repositoryPath = ControlCenterPaths.repository
    @State private var choosingDestination = false
    @State private var preflight: BackupPreflight?
    @State private var preflightError: String?
    @State private var checking = false
    @State private var snapshotDetail: SnapshotPolicyResult?
    @State private var snapshotError: String?
    @State private var checkingSnapshots = false
    @State private var snapshotPreview: SnapshotPreview?
    @State private var snapshotPreviewError: String?
    @State private var checkingSnapshotPreview = false
    @State private var confirmingSnapshotApply = false
    @State private var applyingSnapshots = false
    @State private var snapshotApplyResult: SnapshotApplyResult?
    @AppStorage("backupPlanID") private var backupPlanID = ""
    @State private var backupPlan: BackupPlan?
    @State private var backupStatus: BackupOperationStatus?
    @State private var backupError: String?
    @State private var planningBackup = false
    @State private var submittingBackup = false
    @State private var confirmBackup = false
    @State private var monitorVersion = 0
    @State private var choosingBackupSource = false
    @State private var backupInventory: BackupInventory?
    @State private var restorePreview: RestorePreview?
    @State private var restoreError: String?
    @State private var readingBackups = false
    @State private var verifyingBackup = false
    @AppStorage("restoreOperationID") private var restoreOperationID = ""
    @State private var restorePlan: RestorePlan?
    @State private var restoreStatus: RestoreOperationStatus?
    @State private var planningRestore = false
    @State private var submittingRestore = false
    @State private var confirmRestore = false
    @State private var confirmRecovery = false
    @State private var recoveringRestore = false
    @State private var restoreMonitorVersion = 0

    private var backupMonitorKey: String { "\(backupPlanID):\(monitorVersion)" }
    private var restoreMonitorKey: String { "\(restoreOperationID):\(restoreMonitorVersion)" }

    var body: some View {
        ScrollView {
        VStack(alignment: .leading, spacing: 20) {
            Text("Recovery").font(.largeTitle.bold())
            GroupBox("Snapshot retention") {
                HStack {
                    Text("Policy check")
                    Spacer()
                    if let status = store.maintenance?.snapshotPolicy {
                        Label(status.capitalized, systemImage: status == "verified" ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(status == "verified" ? .green : .orange)
                    } else {
                        Text("Unavailable").foregroundStyle(.secondary)
                    }
                }
                .padding(8)
                VStack(alignment: .leading, spacing: 8) {
                    if checkingSnapshots { ProgressView("Reading retained snapshot policy…") }
                    if let snapshotDetail {
                        Label(snapshotDetail.detail,
                              systemImage: snapshotDetail.verified ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(snapshotDetail.verified ? .green : .orange)
                    }
                    if let snapshotError {
                        Label(snapshotError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Button("Check Snapshot Inventory") { Task { await checkSnapshots() } }
                        .disabled(checkingSnapshots)
                    Button("Check Consolidation Readiness") { Task { await checkSnapshotPreview() } }
                        .disabled(checkingSnapshotPreview)
                    if checkingSnapshotPreview { ProgressView("Checking snapshot deletion plan…") }
                    if let snapshotPreview {
                        ForEach(snapshotPreview.rows) { row in
                            LabeledContent(row.vm.capitalized,
                                           value: "\(row.count) snapshots · retain \(row.retain) · remove \(row.remove)")
                        }
                        LabeledContent("Host free space", value: ByteCountFormatter.string(fromByteCount: snapshotPreview.freeBytes, countStyle: .file))
                        LabeledContent("Required free space", value: ByteCountFormatter.string(fromByteCount: snapshotPreview.minimumBytes, countStyle: .file))
                        LabeledContent("Stack stopped", value: snapshotPreview.stackStopped ? "Verified" : "Required")
                        LabeledContent("Parallels GUI closed", value: snapshotPreview.guiClosed ? "Verified" : "Required")
                        Label(snapshotPreview.ready ? "Consolidation preflight passed" : "Consolidation is not ready",
                              systemImage: snapshotPreview.ready ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(snapshotPreview.ready ? .green : .orange)
                        if snapshotPreview.ready {
                            Button("Consolidate Snapshots…", role: .destructive) { confirmingSnapshotApply = true }
                                .disabled(applyingSnapshots)
                        }
                    }
                    if applyingSnapshots { ProgressView("Deleting unretained snapshots and checking all three VMs…") }
                    if let snapshotApplyResult {
                        Label(snapshotApplyResult.status == "verified" ? "Retained snapshots verified" : "Consolidation incomplete; inspect each VM",
                              systemImage: snapshotApplyResult.status == "verified" ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(snapshotApplyResult.status == "verified" ? .green : .orange)
                    }
                    if let snapshotPreviewError {
                        Label(snapshotPreviewError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
                .padding(8)
            }
            GroupBox("Coordinated VM backup") {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Choose a mounted, encrypted APFS destination. Preflight checks all three VM bundles, available space, and stopped VM state.")
                        .foregroundStyle(.secondary)
                    Button("Choose Destination…") { choosingDestination = true }
                    if checking { ProgressView("Checking backup destination…") }
                    if let preflight {
                        LabeledContent("Destination", value: preflight.destination)
                            .textSelection(.enabled)
                        LabeledContent("Backup data", value: ByteCountFormatter.string(fromByteCount: preflight.logicalBytes, countStyle: .file))
                        LabeledContent("Host configuration", value: ByteCountFormatter.string(fromByteCount: preflight.hostConfigBytes, countStyle: .file))
                        LabeledContent("Free space", value: ByteCountFormatter.string(fromByteCount: preflight.freeBytes, countStyle: .file))
                        LabeledContent("Required reserve", value: ByteCountFormatter.string(fromByteCount: preflight.reserveBytes, countStyle: .file))
                        LabeledContent("Encrypted APFS", value: preflight.encrypted ? "Verified" : "Required")
                        LabeledContent("Stack stopped", value: preflight.stackStopped ? "Verified" : "Required")
                        Label(preflight.ready ? "Destination preflight passed" : "Destination preflight needs attention",
                              systemImage: preflight.ready ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(preflight.ready ? .green : .orange)
                    }
                    if let preflightError {
                        Label(preflightError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Button("Prepare Backup") { Task { await prepareBackup() } }
                        .disabled(preflight?.ready != true || planningBackup || submittingBackup
                                  || (!backupPlanID.isEmpty && (backupStatus == nil
                                      || backupStatus?.state == "planned" || backupStatus?.state == "running")))
                    if planningBackup { ProgressView("Preparing one-time backup plan…") }
                    if let backupPlan {
                        Divider()
                        Text("One-time backup plan").font(.headline)
                        LabeledContent("Destination", value: backupPlan.destination)
                            .textSelection(.enabled)
                        LabeledContent("Volume UUID", value: backupPlan.volumeUUID)
                            .textSelection(.enabled)
                        LabeledContent("Backup data", value: ByteCountFormatter.string(fromByteCount: backupPlan.logicalBytes, countStyle: .file))
                        LabeledContent("Expires", value: Date(timeIntervalSince1970: TimeInterval(backupPlan.expiresUnix)).formatted())
                        Button("Start Backup…") { confirmBackup = true }
                            .disabled(submittingBackup || backupStatus?.state != "planned"
                                      || backupPlan.expiresUnix <= Int64(Date().timeIntervalSince1970))
                    }
                    if !backupPlanID.isEmpty {
                        Button("Refresh Backup Operation") { monitorVersion += 1 }
                            .disabled(submittingBackup)
                        if backupStatus?.state == "planned" {
                            Button("Forget Unsubmitted Backup Plan") {
                                backupPlanID = ""
                                backupPlan = nil
                                backupStatus = nil
                                backupError = nil
                            }
                            .disabled(submittingBackup)
                        }
                    }
                    if submittingBackup { ProgressView("Submitting backup…") }
                    if let backupStatus {
                        Divider()
                        Label(backupStatus.state.capitalized + " · " + backupStatus.phase,
                              systemImage: backupStatus.state == "verified" ? "checkmark.shield.fill" :
                                backupStatus.state == "failed" || backupStatus.state == "incomplete" ? "exclamationmark.triangle.fill" : "externaldrive")
                            .foregroundStyle(backupStatus.state == "verified" ? .green :
                                backupStatus.state == "failed" || backupStatus.state == "incomplete" ? .orange : .primary)
                        if let count = backupStatus.fileCount, let bytes = backupStatus.logicalBytes {
                            Text("Verified \(count) files · \(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file))")
                        }
                        if let error = backupStatus.error { Text(error).foregroundStyle(.orange) }
                        Text("Operation ID: \(backupStatus.planID)").font(.caption).textSelection(.enabled)
                    }
                    if let backupError {
                        Label(backupError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Text("A backup copies the stopped VM stack and selected non-secret host configuration, then verifies the published generation. Keep the operation ID until its final state is read back.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(8)
            }
            GroupBox("Restore preview") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Browse a backup volume and verify a generation before planning a restore.")
                        .foregroundStyle(.secondary)
                    Button("Browse Backup Volume…") { choosingBackupSource = true }
                    if readingBackups { ProgressView("Reading backup generations…") }
                    if let backupInventory {
                        LabeledContent("Source volume", value: backupInventory.destination)
                            .textSelection(.enabled)
                        LabeledContent("Encrypted APFS", value: backupInventory.encrypted ? "Verified" : "Required")
                        if backupInventory.entries.isEmpty { Text("No backup generations found").foregroundStyle(.secondary) }
                        ForEach(backupInventory.entries) { entry in
                            HStack {
                                Image(systemName: entry.state == "incomplete" ? "exclamationmark.triangle" : "externaldrive")
                                Text(entry.name).textSelection(.enabled)
                                Spacer()
                                if entry.state == "incomplete" {
                                    Text("Incomplete").foregroundStyle(.orange)
                                } else {
                                    Button("Verify & Preview") {
                                        Task { await previewRestore(entry.generationID) }
                                    }
                                    .disabled(verifyingBackup || !backupInventory.encrypted)
                                }
                            }
                        }
                    }
                    if verifyingBackup { ProgressView("Verifying backup contents…") }
                    if let restorePreview {
                        Divider()
                        Label(restorePreview.ready ? "Verified for restore planning" : "Restore preflight needs attention",
                              systemImage: restorePreview.ready ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(restorePreview.ready ? .green : .orange)
                        LabeledContent("Generation", value: restorePreview.generationID).textSelection(.enabled)
                        LabeledContent("Verified files", value: String(restorePreview.fileCount))
                        LabeledContent("Backup data", value: ByteCountFormatter.string(fromByteCount: restorePreview.logicalBytes, countStyle: .file))
                        LabeledContent("Host free space", value: ByteCountFormatter.string(fromByteCount: restorePreview.hostFreeBytes, countStyle: .file))
                        LabeledContent("Required reserve", value: ByteCountFormatter.string(fromByteCount: restorePreview.reserveBytes, countStyle: .file))
                        LabeledContent("Stack stopped", value: restorePreview.stackStopped ? "Verified" : "Required")
                        LabeledContent("Host configuration", value: restorePreview.hostConfigMatches ? "Matches archive" : "Differs from archive")
                        if !restorePreview.differingHostConfig.isEmpty {
                            Text("Different files: \(restorePreview.differingHostConfig.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                        }
                        Button("Prepare Restore") { Task { await prepareRestore() } }
                            .disabled(!restorePreview.ready || planningRestore || submittingRestore
                                      || (!restoreOperationID.isEmpty && (restoreStatus == nil
                                          || restoreStatus?.state == "planned" || restoreStatus?.state == "running")))
                    }
                    if planningRestore { ProgressView("Preparing one-time restore plan…") }
                    if let restorePlan {
                        Divider()
                        Text("One-time restore plan").font(.headline)
                        LabeledContent("Backup volume", value: restorePlan.source).textSelection(.enabled)
                        LabeledContent("Generation", value: restorePlan.generationID).textSelection(.enabled)
                        LabeledContent("Verified files", value: String(restorePlan.fileCount))
                        LabeledContent("Backup data", value: ByteCountFormatter.string(fromByteCount: restorePlan.logicalBytes, countStyle: .file))
                        LabeledContent("Expires", value: Date(timeIntervalSince1970: TimeInterval(restorePlan.expiresUnix)).formatted())
                        Button("Restore VM Stack…") { confirmRestore = true }
                            .disabled(submittingRestore || restoreStatus?.state != "planned"
                                      || restorePlan.expiresUnix <= Int64(Date().timeIntervalSince1970))
                    }
                    if !restoreOperationID.isEmpty {
                        Button("Refresh Restore Operation") { restoreMonitorVersion += 1 }
                            .disabled(submittingRestore || recoveringRestore)
                        if restoreStatus?.state == "planned" {
                            Button("Forget Unsubmitted Restore Plan") {
                                restoreOperationID = ""
                                restorePlan = nil
                                restoreStatus = nil
                                restoreError = nil
                            }
                            .disabled(submittingRestore)
                        }
                    }
                    if submittingRestore { ProgressView("Submitting restore…") }
                    if let restoreStatus {
                        Divider()
                        Label(restoreStatus.state.capitalized + " · " + restoreStatus.phase,
                              systemImage: restoreStatus.state == "verified" ? "checkmark.shield.fill" :
                                restoreStatus.state == "rolled_back" ? "arrow.uturn.backward.circle.fill" :
                                "exclamationmark.triangle.fill")
                            .foregroundStyle(restoreStatus.state == "verified" ? .green : .orange)
                        if let error = restoreStatus.error { Text(error).foregroundStyle(.orange) }
                        Text("Restore ID: \(restoreStatus.restoreID)").font(.caption).textSelection(.enabled)
                        if restoreStatus.recoverable {
                            Button("Recover Previous VM Stack…") { confirmRecovery = true }
                                .disabled(recoveringRestore)
                        }
                    }
                    if recoveringRestore { ProgressView("Submitting rollback recovery…") }
                    if let restoreError {
                        Label(restoreError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Text("The previous VM bundles are kept in quarantine after an accepted restore. Host configuration must match the archive; restore does not overwrite it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(8)
            }
        }
        .padding(28)
        }
        .navigationTitle("Recovery")
        .task { await checkSnapshots() }
        .task(id: backupMonitorKey) { await monitorBackup() }
        .task(id: restoreMonitorKey) { await monitorRestore() }
        .confirmationDialog("Start coordinated VM backup?", isPresented: $confirmBackup) {
            Button("Start Backup") { Task { await submitBackup() } }
        } message: {
            Text("The three stopped VM bundles will be copied to the selected encrypted volume. This plan can be submitted once.")
        }
        .confirmationDialog("Restore the selected VM generation?", isPresented: $confirmRestore) {
            Button("Restore VM Stack") { Task { await submitRestore() } }
        } message: {
            Text("The current stopped VM bundles will be quarantined. The archived bundles will be registered, started, and checked. Failed acceptance triggers rollback. This plan can be submitted once.")
        }
        .confirmationDialog("Recover the previous VM stack?", isPresented: $confirmRecovery) {
            Button("Recover Previous VMs") { Task { await recoverPreviousVMs() } }
        } message: {
            Text("The incomplete restore will be stopped and the quarantined prior bundles registered again. The operation will be read back by its restore ID.")
        }
        .confirmationDialog("Delete unretained VM snapshots?", isPresented: $confirmingSnapshotApply) {
            Button("Consolidate All Three VMs", role: .destructive) { Task { await applySnapshots() } }
        } message: {
            Text("The stopped stack, free space, Parallels GUI, and all three milestone inventories are checked again before deletion. Deleted snapshots cannot be recovered from this action.")
        }
        .fileImporter(isPresented: $choosingDestination, allowedContentTypes: [.folder]) { result in
            switch result {
            case .success(let url): Task { await checkDestination(url.path) }
            case .failure(let error): preflightError = error.localizedDescription
            }
        }
        .fileImporter(isPresented: $choosingBackupSource, allowedContentTypes: [.folder]) { result in
            switch result {
            case .success(let url): Task { await loadBackupInventory(url.path) }
            case .failure(let error): restoreError = error.localizedDescription
            }
        }
    }

    private func checkDestination(_ destination: String) async {
        checking = true
        preflight = nil
        preflightError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            preflight = try await Task.detached {
                try client.backupPreflight(destination: destination)
            }.value
        } catch {
            preflightError = error.localizedDescription
        }
        checking = false
    }

    private func prepareBackup() async {
        guard let destination = preflight?.destination, preflight?.ready == true else { return }
        planningBackup = true
        backupError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let plan = try await Task.detached { try client.planBackup(destination: destination) }.value
            backupPlan = plan
            backupStatus = nil
            backupPlanID = plan.planID
        } catch {
            backupError = error.localizedDescription
        }
        planningBackup = false
    }

    private func submitBackup() async {
        guard let plan = backupPlan, plan.planID == backupPlanID else { return }
        submittingBackup = true
        backupError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            _ = try await Task.detached { try client.submitBackup(planID: plan.planID) }.value
            backupPlan = nil
            backupStatus = try await Task.detached { try client.backupStatus(planID: plan.planID) }.value
            monitorVersion += 1
        } catch {
            backupPlan = nil
            backupStatus = nil
            backupError = "Backup submission outcome is unclear: \(error.localizedDescription). Refresh operation \(plan.planID) before taking another action."
            monitorVersion += 1
        }
        submittingBackup = false
    }

    private func monitorBackup() async {
        guard !backupPlanID.isEmpty else { return }
        let client = CatalogClient(repositoryPath: repositoryPath)
        while !Task.isCancelled {
            do {
                let planID = backupPlanID
                let current = try await Task.detached { try client.backupStatus(planID: planID) }.value
                guard planID == backupPlanID else { return }
                backupStatus = current
                backupError = nil
                if current.state == "planned" && backupPlan == nil {
                    backupPlan = try await Task.detached { try client.backupPlanDetail(planID: planID) }.value
                }
                if current.state != "running" { return }
            } catch {
                backupError = error.localizedDescription
                return
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func loadBackupInventory(_ destination: String) async {
        readingBackups = true
        backupInventory = nil
        restorePreview = nil
        restoreError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            backupInventory = try await Task.detached {
                try client.backupInventory(destination: destination)
            }.value
        } catch {
            restoreError = error.localizedDescription
        }
        readingBackups = false
    }

    private func previewRestore(_ generationID: String) async {
        guard let destination = backupInventory?.destination else { return }
        verifyingBackup = true
        restorePreview = nil
        restoreError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            restorePreview = try await Task.detached {
                try client.restorePreview(destination: destination, generationID: generationID)
            }.value
        } catch {
            restoreError = error.localizedDescription
        }
        verifyingBackup = false
    }

    private func prepareRestore() async {
        guard let preview = restorePreview, preview.ready else { return }
        planningRestore = true
        restoreError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let plan = try await Task.detached {
                try client.planRestore(source: preview.destination, generationID: preview.generationID)
            }.value
            restorePlan = plan
            restoreStatus = nil
            restoreOperationID = plan.restoreID
        } catch {
            restoreError = error.localizedDescription
        }
        planningRestore = false
    }

    private func submitRestore() async {
        guard let plan = restorePlan, plan.restoreID == restoreOperationID else { return }
        submittingRestore = true
        restoreError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            _ = try await Task.detached { try client.submitRestore(restoreID: plan.restoreID) }.value
            restorePlan = nil
            restoreStatus = try await Task.detached { try client.restoreStatus(restoreID: plan.restoreID) }.value
            restoreMonitorVersion += 1
        } catch {
            restorePlan = nil
            restoreStatus = nil
            restoreError = "Restore submission outcome is unclear: \(error.localizedDescription). Refresh operation \(plan.restoreID) before taking another action."
            restoreMonitorVersion += 1
        }
        submittingRestore = false
    }

    private func monitorRestore() async {
        guard !restoreOperationID.isEmpty else { return }
        let client = CatalogClient(repositoryPath: repositoryPath)
        while !Task.isCancelled {
            do {
                let restoreID = restoreOperationID
                let current = try await Task.detached { try client.restoreStatus(restoreID: restoreID) }.value
                guard restoreID == restoreOperationID else { return }
                restoreStatus = current
                restoreError = nil
                if current.state == "planned" && restorePlan == nil {
                    restorePlan = try await Task.detached { try client.restorePlanDetail(restoreID: restoreID) }.value
                }
                if current.state != "running" { return }
            } catch {
                restoreError = error.localizedDescription
                return
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func recoverPreviousVMs() async {
        guard let status = restoreStatus, status.recoverable,
              status.restoreID == restoreOperationID else { return }
        recoveringRestore = true
        restoreError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            _ = try await Task.detached { try client.recoverRestore(restoreID: status.restoreID) }.value
            restoreStatus = try await Task.detached { try client.restoreStatus(restoreID: status.restoreID) }.value
            restoreMonitorVersion += 1
        } catch {
            restoreStatus = nil
            restoreError = "Rollback recovery outcome is unclear: \(error.localizedDescription). Refresh restore \(status.restoreID) before another action."
            restoreMonitorVersion += 1
        }
        recoveringRestore = false
    }

    private func checkSnapshots() async {
        checkingSnapshots = true
        snapshotDetail = nil
        snapshotError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            snapshotDetail = try await Task.detached { try client.snapshotPolicy() }.value
        } catch {
            snapshotError = error.localizedDescription
        }
        checkingSnapshots = false
    }

    private func checkSnapshotPreview() async {
        checkingSnapshotPreview = true
        snapshotPreview = nil
        snapshotPreviewError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            snapshotPreview = try await Task.detached { try client.snapshotPreview() }.value
        } catch {
            snapshotPreviewError = error.localizedDescription
        }
        checkingSnapshotPreview = false
    }

    private func applySnapshots() async {
        guard snapshotPreview?.ready == true else { return }
        applyingSnapshots = true
        snapshotApplyResult = nil
        snapshotPreviewError = nil
        snapshotPreview = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            snapshotApplyResult = try await Task.detached { try client.applySnapshotRetention() }.value
            snapshotPreview = try await Task.detached { try client.snapshotPreview() }.value
        } catch {
            snapshotPreviewError = "Consolidation outcome is unclear: \(error.localizedDescription). Inspect snapshot inventory before any retry."
        }
        applyingSnapshots = false
    }
}
