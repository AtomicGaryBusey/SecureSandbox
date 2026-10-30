import SwiftUI
import UniformTypeIdentifiers

struct RecoveryView: View {
    let store: CatalogStore
    @Bindable var workflow: RecoveryWorkflowState
    private let repositoryPath = ControlCenterPaths.repository
    @State private var choosingDestination = false
    @State private var confirmingSnapshotApply = false
    @AppStorage("backupPlanID") private var backupPlanID = ""
    @State private var confirmBackup = false
    @State private var choosingBackupSource = false
    @AppStorage("restoreOperationID") private var restoreOperationID = ""
    @State private var confirmRestore = false
    @State private var confirmRecovery = false
    @State private var confirmRetirement = false

    private var preflight: BackupPreflight? { get { workflow.preflight } nonmutating set { workflow.preflight = newValue } }
    private var preflightError: String? { get { workflow.preflightError } nonmutating set { workflow.preflightError = newValue } }
    private var checking: Bool { get { workflow.checking } nonmutating set { workflow.checking = newValue } }
    private var snapshotDetail: SnapshotPolicyResult? { get { workflow.snapshotDetail } nonmutating set { workflow.snapshotDetail = newValue } }
    private var snapshotError: String? { get { workflow.snapshotError } nonmutating set { workflow.snapshotError = newValue } }
    private var checkingSnapshots: Bool { get { workflow.checkingSnapshots } nonmutating set { workflow.checkingSnapshots = newValue } }
    private var snapshotPreview: SnapshotPreview? { get { workflow.snapshotPreview } nonmutating set { workflow.snapshotPreview = newValue } }
    private var snapshotPreviewError: String? { get { workflow.snapshotPreviewError } nonmutating set { workflow.snapshotPreviewError = newValue } }
    private var checkingSnapshotPreview: Bool { get { workflow.checkingSnapshotPreview } nonmutating set { workflow.checkingSnapshotPreview = newValue } }
    private var applyingSnapshots: Bool { get { workflow.applyingSnapshots } nonmutating set { workflow.applyingSnapshots = newValue } }
    private var snapshotApplyResult: SnapshotApplyResult? { get { workflow.snapshotApplyResult } nonmutating set { workflow.snapshotApplyResult = newValue } }
    private var backupPlan: BackupPlan? { get { workflow.backupPlan } nonmutating set { workflow.backupPlan = newValue } }
    private var backupStatus: BackupOperationStatus? { get { workflow.backupStatus } nonmutating set { workflow.backupStatus = newValue } }
    private var backupError: String? { get { workflow.backupError } nonmutating set { workflow.backupError = newValue } }
    private var planningBackup: Bool { get { workflow.planningBackup } nonmutating set { workflow.planningBackup = newValue } }
    private var submittingBackup: Bool { get { workflow.submittingBackup } nonmutating set { workflow.submittingBackup = newValue } }
    private var monitorVersion: Int { get { workflow.monitorVersion } nonmutating set { workflow.monitorVersion = newValue } }
    private var backupInventory: BackupInventory? { get { workflow.backupInventory } nonmutating set { workflow.backupInventory = newValue } }
    private var restorePreview: RestorePreview? { get { workflow.restorePreview } nonmutating set { workflow.restorePreview = newValue } }
    private var restoreError: String? { get { workflow.restoreError } nonmutating set { workflow.restoreError = newValue } }
    private var readingBackups: Bool { get { workflow.readingBackups } nonmutating set { workflow.readingBackups = newValue } }
    private var verifyingBackup: Bool { get { workflow.verifyingBackup } nonmutating set { workflow.verifyingBackup = newValue } }
    private var restorePlan: RestorePlan? { get { workflow.restorePlan } nonmutating set { workflow.restorePlan = newValue } }
    private var restoreStatus: RestoreOperationStatus? { get { workflow.restoreStatus } nonmutating set { workflow.restoreStatus = newValue } }
    private var planningRestore: Bool { get { workflow.planningRestore } nonmutating set { workflow.planningRestore = newValue } }
    private var submittingRestore: Bool { get { workflow.submittingRestore } nonmutating set { workflow.submittingRestore = newValue } }
    private var recoveringRestore: Bool { get { workflow.recoveringRestore } nonmutating set { workflow.recoveringRestore = newValue } }
    private var restoreMonitorVersion: Int { get { workflow.restoreMonitorVersion } nonmutating set { workflow.restoreMonitorVersion = newValue } }
    private var retirement: RestoreRetirement? { get { workflow.retirement } nonmutating set { workflow.retirement = newValue } }
    private var checkingRetirement: Bool { get { workflow.checkingRetirement } nonmutating set { workflow.checkingRetirement = newValue } }
    private var submittingRetirement: Bool { get { workflow.submittingRetirement } nonmutating set { workflow.submittingRetirement = newValue } }
    private var retirementError: String? { get { workflow.retirementError } nonmutating set { workflow.retirementError = newValue } }

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
                        Label((backupStatus.state == "verified" ? "Verified at completion" : backupStatus.state.capitalized)
                              + " · " + backupStatus.phase,
                              systemImage: backupStatus.state == "verified" ? "checkmark.shield.fill" :
                                backupStatus.state == "failed" || backupStatus.state == "incomplete" ? "exclamationmark.triangle.fill" : "externaldrive")
                            .foregroundStyle(backupStatus.state == "verified" ? .green :
                                backupStatus.state == "failed" || backupStatus.state == "incomplete" ? .orange : .primary)
                        if let count = backupStatus.fileCount, let bytes = backupStatus.logicalBytes {
                            Text("Verified \(count) files · \(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file))")
                        }
                        if backupStatus.state == "verified" {
                            Text("Use Verify & Preview below to check the current backup contents before restore.")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Use This Verified Backup") {
                                Task { await loadVerifiedBackup(planID: backupStatus.planID) }
                            }
                            .disabled(readingBackups || verifyingBackup)
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
                        if ["verified", "rolled_back"].contains(restoreStatus.state) {
                            Button("Inspect Retained Generation") {
                                Task { await inspectRetirement() }
                            }
                            .disabled(checkingRetirement || submittingRetirement)
                        }
                    }
                    if recoveringRestore { ProgressView("Submitting rollback recovery…") }
                    if checkingRetirement { ProgressView("Verifying retained generation…") }
                    if let retirement {
                        Divider()
                        Label(retirement.state == "retired" ? "Retained generation retired" :
                              retirement.ready ? "Retained generation verified" : retirement.state.capitalized,
                              systemImage: retirement.state == "retired" ? "checkmark.shield.fill" :
                                retirement.ready ? "externaldrive.badge.checkmark" : "exclamationmark.triangle.fill")
                            .foregroundStyle(retirement.state == "retired" ? .green :
                                retirement.ready ? .primary : .orange)
                        LabeledContent("Retained item",
                                       value: retirement.kind == "failed_candidate" ?
                                        "Failed restore candidate" : "Previous VM generation")
                        if retirement.state != "retired" {
                            LabeledContent("Entries", value: String(retirement.entryCount))
                            LabeledContent("Reclaimable space", value: ByteCountFormatter.string(
                                fromByteCount: retirement.reclaimableBytes, countStyle: .file))
                        }
                        if let error = retirement.error {
                            Text(error).foregroundStyle(.orange)
                        }
                        if retirement.ready {
                            Button(retirement.state == "available" ?
                                   "Retire Retained Generation…" : "Retry Retirement…",
                                   role: .destructive) {
                                confirmRetirement = true
                            }
                            .disabled(submittingRetirement)
                        }
                    }
                    if submittingRetirement { ProgressView("Retiring retained generation…") }
                    if let retirementError {
                        Label(retirementError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
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
        .confirmationDialog("Permanently retire the retained generation?",
                            isPresented: $confirmRetirement) {
            Button("Retire Retained Generation", role: .destructive) {
                Task { await submitRetirement() }
            }
        } message: {
            Text("Only the independently verified retained generation will be deleted. The registered stopped VM stack remains untouched. This cannot be undone; preserve any external diagnostic copy first.")
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

    private func loadVerifiedBackup(planID: String) async {
        readingBackups = true
        backupInventory = nil
        restorePreview = nil
        restoreError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let plan = try await Task.detached {
                try client.backupPlanDetail(planID: planID)
            }.value
            backupInventory = try await Task.detached {
                try client.backupInventory(destination: plan.destination)
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

    private func inspectRetirement() async {
        guard !restoreOperationID.isEmpty else { return }
        let restoreID = restoreOperationID
        checkingRetirement = true
        retirement = nil
        retirementError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            retirement = try await Task.detached {
                try client.restoreRetirementPreview(restoreID: restoreID)
            }.value
        } catch {
            retirementError = error.localizedDescription
        }
        checkingRetirement = false
    }

    private func submitRetirement() async {
        guard let preview = retirement, preview.ready,
              preview.restoreID == restoreOperationID else { return }
        submittingRetirement = true
        retirementError = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            _ = try await Task.detached {
                try client.retireRestoreGeneration(restoreID: preview.restoreID)
            }.value
            while !Task.isCancelled {
                let current = try await Task.detached {
                    try client.restoreRetirementStatus(restoreID: preview.restoreID)
                }.value
                retirement = current
                if current.state != "running" { break }
                try await Task.sleep(for: .seconds(2))
            }
        } catch {
            retirementError = "Retirement outcome is unclear: \(error.localizedDescription). Inspect the retained generation before retrying."
        }
        submittingRetirement = false
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
