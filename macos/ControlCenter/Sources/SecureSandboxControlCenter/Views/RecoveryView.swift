import SwiftUI
import UniformTypeIdentifiers

struct RecoveryView: View {
    let store: CatalogStore
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var choosingDestination = false
    @State private var preflight: BackupPreflight?
    @State private var preflightError: String?
    @State private var checking = false
    @State private var snapshotDetail: SnapshotPolicyResult?
    @State private var snapshotError: String?
    @State private var checkingSnapshots = false
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

    private var backupMonitorKey: String { "\(backupPlanID):\(monitorVersion)" }

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
                        .disabled(preflight?.ready != true || planningBackup || submittingBackup)
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
                            .disabled(submittingBackup || backupStatus?.state == "running" || backupStatus?.state == "verified")
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
                    Text("A backup copies the stopped VM stack and selected non-secret host configuration, then verifies the published generation. Restore and rollback are still being built.")
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
                    }
                    if let restoreError {
                        Label(restoreError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Text("Restore transaction and rollback are not yet available.")
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
        .confirmationDialog("Start coordinated VM backup?", isPresented: $confirmBackup) {
            Button("Start Backup") { Task { await submitBackup() } }
        } message: {
            Text("The three stopped VM bundles will be copied to the selected encrypted volume. This plan can be submitted once.")
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
            backupError = error.localizedDescription
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
}
