import SwiftUI

enum SourcePlanKind: String, Identifiable {
    case github, npm
    var id: String { rawValue }
}

struct SourcePlanSheet: View {
    let store: CatalogStore
    let kind: SourcePlanKind
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow
    private let repositoryPath = ControlCenterPaths.repository
    @State private var url = ""
    @State private var ref: String
    @State private var plan: SourcePlan?
    @State private var planStatus: SourcePlanStatus?
    @State private var imported: SourceImportResult?
    @State private var existingSource: SourceRecord?
    @State private var isImporting = false
    @State private var error: String?
    @State private var isPlanning = false
    @State private var restoringPlan = false
    @AppStorage("githubSourcePlanID") private var githubPlanID = ""
    @AppStorage("npmSourcePlanID") private var npmPlanID = ""
    @AppStorage("githubSourceImportAttempted") private var githubImportAttempted = false
    @AppStorage("npmSourceImportAttempted") private var npmImportAttempted = false

    private var retainedPlanID: String { kind == .github ? githubPlanID : npmPlanID }
    private var importAttempted: Bool { kind == .github ? githubImportAttempted : npmImportAttempted }
    private var canForgetUnsubmittedPlan: Bool {
        !retainedPlanID.isEmpty && !importAttempted
            && (planStatus == nil || planStatus?.state == "planned")
    }
    private var canClearFinishedPlan: Bool {
        guard !retainedPlanID.isEmpty, let state = planStatus?.state else { return false }
        return ["failed", "expired", "completed"].contains(state)
    }
    private var planExpired: Bool {
        guard let plan, let expiry = ISO8601DateFormatter().date(from: plan.expiresAt) else { return true }
        return expiry <= Date()
    }

    init(store: CatalogStore, kind: SourcePlanKind) {
        self.store = store
        self.kind = kind
        _ref = State(initialValue: kind == .github ? "main" : "")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(kind == .github ? "Import a repository" : "Import an npm package").font(.title2.bold())
            Text(kind == .github
                 ? "Paste a public GitHub repository URL. The gateway resolves the ref to an immutable commit before import."
                 : "Enter a public package and exact version. The gateway verifies the registry metadata and package archive before import.")
                .foregroundStyle(.secondary)
            Form {
                TextField(kind == .github ? "Repository URL" : "Package name", text: $url,
                          prompt: Text(kind == .github ? "https://github.com/owner/repository" : "@scope/package"))
                TextField(kind == .github ? "Ref" : "Exact version", text: $ref,
                          prompt: Text(kind == .github ? "main" : "1.2.3"))
            }
            .formStyle(.grouped)
            if isPlanning { ProgressView("Resolving source…") }
            if restoringPlan { ProgressView("Reading prior source plan…") }
            if isImporting { ProgressView("Importing and verifying source…") }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
            if let plan {
                GroupBox("Resolved source") {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent(kind == .github ? "Repository" : "Registry source", value: plan.repository)
                        LabeledContent(kind == .github ? "Requested ref" : "Exact version", value: plan.requestedRef)
                        LabeledContent(kind == .github ? "Immutable commit" : "Package SHA-1 shasum", value: plan.resolvedCommit)
                            .textSelection(.enabled)
                        if kind == .npm {
                            Text("The gateway also checks npm's SHA-512 integrity value during acquisition.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        LabeledContent("Plan expires", value: plan.expiresAt)
                        LabeledContent("Plan ID", value: plan.planID)
                            .textSelection(.enabled)
                    }
                    .padding(8)
                }
                if let planStatus {
                    LabeledContent("Plan state", value: planStatus.state.capitalized)
                    if planStatus.state == "planned" && planExpired {
                        Text("This plan has expired. Check its status, then create a new plan.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    if planStatus.state == "planned" && importAttempted {
                        Text("An import was attempted. The app will not submit this plan again after an unclear outcome.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    if let sourceID = planStatus.sourceID {
                        LabeledContent("Imported source", value: sourceID)
                            .textSelection(.enabled)
                    }
                }
                if imported != nil {
                    Label("The source is published with archived evidence.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    if let imported {
                        Button("Analyze Source…") {
                            openWindow(id: "terminal", value: "source:\(imported.sourceID)")
                        }
                    }
                }
                if let existingSource, imported == nil {
                    Label("This exact source is already imported. Use its existing Sources entry.",
                          systemImage: "checkmark.seal")
                        .foregroundStyle(.orange)
                    Button("Analyze Existing Source…") {
                        openWindow(id: "terminal", value: "source:\(existingSource.id)")
                    }
                }
            }
            if !retainedPlanID.isEmpty && plan == nil && !restoringPlan {
                Button("Retry Prior Plan Readback") { Task { await restoreRetainedPlan() } }
            }
            if !retainedPlanID.isEmpty && planStatus == nil {
                Text(importAttempted
                     ? "An import was attempted. Keep this plan until its outcome can be read back."
                     : "Status is unavailable. You can discard this unsubmitted plan locally; the Gateway plan will expire on its own.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Close") { dismiss() }
                if let plan {
                    Button("Check Status") { Task { await checkStatus(planID: plan.planID) } }
                        .disabled(isPlanning || isImporting || restoringPlan)
                    Button("Import") { Task { await importSource(planID: plan.planID) } }
                        .disabled(planStatus?.state != "planned" || importAttempted || isPlanning || isImporting
                                  || restoringPlan || planExpired || existingSource != nil)
                }
                if canForgetUnsubmittedPlan || canClearFinishedPlan {
                    Button(canForgetUnsubmittedPlan ? "Forget Unsubmitted Plan" : "Clear Finished Plan") {
                        forgetPlan()
                    }
                    .disabled(isPlanning || isImporting || restoringPlan)
                }
                Button("Resolve") { Task { await resolve() } }
                    .disabled(url.isEmpty || ref.isEmpty || !retainedPlanID.isEmpty
                              || isPlanning || isImporting || restoringPlan)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 580)
        .task { await restoreRetainedPlan() }
    }

    private func retainPlanID(_ id: String) {
        if kind == .github { githubPlanID = id } else { npmPlanID = id }
    }

    private func retainImportAttempted(_ attempted: Bool) {
        if kind == .github { githubImportAttempted = attempted } else { npmImportAttempted = attempted }
    }

    private func forgetPlan() {
        guard canForgetUnsubmittedPlan || canClearFinishedPlan else { return }
        retainPlanID("")
        plan = nil
        planStatus = nil
        imported = nil
        existingSource = nil
        retainImportAttempted(false)
        error = nil
    }

    private func restoreRetainedPlan() async {
        let id = retainedPlanID
        guard !id.isEmpty, plan == nil, !restoringPlan else { return }
        restoringPlan = true
        await checkStatus(planID: id)
        restoringPlan = false
    }

    private func resolve() async {
        guard retainedPlanID.isEmpty else { return }
        isPlanning = true
        error = nil
        plan = nil
        planStatus = nil
        imported = nil
        existingSource = nil
        retainImportAttempted(false)
        let client = CatalogClient(repositoryPath: repositoryPath)
        let requestedURL = url
        let requestedRef = ref
        let selectedKind = kind
        do {
            plan = try await Task.detached {
                if selectedKind == .github {
                    return try client.planSource(url: requestedURL, ref: requestedRef)
                }
                return try client.planNpm(package: requestedURL, version: requestedRef)
            }.value
            if let plan {
                retainPlanID(plan.planID)
                await checkStatus(planID: plan.planID)
            }
        } catch {
            self.error = error.localizedDescription
        }
        isPlanning = false
    }

    private func checkStatus(planID: String, clearError: Bool = true) async {
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            let fresh = try await Task.detached {
                try client.sourceStatus(planID: planID)
            }.value
            guard (kind == .npm) == fresh.repository.hasPrefix("npm/") else {
                throw CatalogError.invalidSchema
            }
            planStatus = fresh
            plan = SourcePlan(planID: fresh.planID, repository: fresh.repository,
                              requestedRef: fresh.requestedRef,
                              resolvedCommit: fresh.resolvedCommit, expiresAt: fresh.expiresAt)
            retainImportAttempted(importAttempted || fresh.state != "planned")
            imported = nil
            let sources = try await Task.detached {
                try client.load("sources", as: [SourceRecord].self)
            }.value
            store.sources = sources
            store.errors.removeValue(forKey: "sources")
            existingSource = sources.first(where: {
                $0.repository == fresh.repository && $0.commit == fresh.resolvedCommit
                    && $0.id != fresh.sourceID
            })
            if fresh.state == "completed", let sourceID = fresh.sourceID {
                guard sources.contains(where: {
                    $0.id == sourceID && $0.repository == fresh.repository
                }) else {
                    throw CatalogError.bridge("Gateway completed the import, but Research has not confirmed the source in its catalog. Refresh status before analysis.")
                }
                imported = SourceImportResult(planID: fresh.planID, sourceID: sourceID,
                                              repository: fresh.repository)
            }
            if clearError || fresh.state == "completed" { error = nil }
        } catch {
            if clearError || self.error == nil { self.error = error.localizedDescription }
        }
    }

    private func importSource(planID: String) async {
        guard !importAttempted, retainedPlanID == planID,
              planStatus?.state == "planned", !planExpired else { return }
        retainImportAttempted(true)
        isImporting = true
        error = nil
        let client = CatalogClient(repositoryPath: repositoryPath)
        do {
            _ = try await Task.detached {
                try client.applySource(planID: planID)
            }.value
        } catch {
            self.error = error.localizedDescription
        }
        await checkStatus(planID: planID, clearError: false)
        isImporting = false
    }
}
