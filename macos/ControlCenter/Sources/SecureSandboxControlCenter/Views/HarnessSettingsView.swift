import SwiftUI

private enum HarnessConfirmation: Identifiable {
    case acquire(HarnessRelease)
    case verify(HarnessQuarantineGeneration)
    case qualification

    var id: String {
        switch self {
        case .acquire(let release): "acquire-\(release.generationID)"
        case .verify(let generation): "verify-\(generation.generationID)"
        case .qualification: "qualification"
        }
    }
}

struct HarnessSettingsView: View {
    let store: HarnessStore
    @AppStorage("automaticHarnessMetadataChecks") private var automaticChecks = false
    @State private var confirmation: HarnessConfirmation?
    @State private var reviewedRelease: HarnessRelease?
    @State private var reviewedPlan: HarnessGenerationPlan?

    var body: some View {
        Form {
            Section("Release metadata") {
                Toggle("Automatically check signed harness metadata", isOn: $automaticChecks)
                    .onChange(of: automaticChecks) { _, enabled in
                        if enabled { Task { await store.requestNotificationPermission() } }
                    }
                Text("Automatic checks fetch bounded signed metadata only. They may notify you, but never download, qualify, stage, activate, or install a harness.")
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Check for Releases") { Task { await store.checkMetadata() } }
                    Button("Refresh Status") { Task { await store.load() } }
                }
                .disabled(isBusy)
                if let floor = store.status?.lifecycle.floor {
                    LabeledContent("Verified sequence", value: String(floor.sequence))
                    digestRow("Envelope", floor.envelopeSHA256)
                    digestRow("Policy", floor.policySHA256)
                } else if store.status?.lifecycle.policyConfigured == false {
                    Label("No harness release policy is configured. Checks and downloads fail closed.", systemImage: "lock.fill")
                        .foregroundStyle(.secondary)
                }
            }

            if let catalog = store.releases {
                Section("Signed candidates — metadata authority only") {
                    ForEach(catalog.releases) { release in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("\(release.harnessID) \(release.version)").font(.headline)
                                Spacer()
                                Text("Sequence \(release.releaseSequence)").foregroundStyle(.secondary)
                            }
                            Text("\(release.vendorID) · \(release.platform) · \(release.artifact.size.formatted()) bytes")
                                .foregroundStyle(.secondary)
                            HStack {
                                Button("Review Evidence and Compatibility…") { reviewedRelease = release }
                                Button("Download to Quarantine…") { confirmation = .acquire(release) }
                                    .disabled(isBusy || isQuarantined(release.generationID))
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }

            Section("Inert quarantine") {
                if let generations = store.status?.lifecycle.generations, !generations.isEmpty {
                    ForEach(generations) { generation in
                        VStack(alignment: .leading, spacing: 5) {
                            digestRow("Generation", generation.generationID)
                            LabeledContent("Files", value: generation.artifactPresent && generation.manifestPresent ? "Artifact and manifest present" : "Incomplete — rejected")
                            Button("Verify Bytes and Evidence…") { confirmation = .verify(generation) }
                                .disabled(isBusy || !generation.artifactPresent || !generation.manifestPresent)
                        }
                        .padding(.vertical, 4)
                    }
                } else {
                    Text("No candidate bytes are quarantined.").foregroundStyle(.secondary)
                }
                Text("Quarantine is inert Host storage. A verified candidate is still not admitted, installed, executable, or selectable by a session.")
                    .foregroundStyle(.secondary)
            }

            Section("Containment qualification") {
                Button("Run Synthetic Containment Self-Test…") { confirmation = .qualification }
                    .disabled(isBusy)
                if let report = store.qualification {
                    LabeledContent("Result", value: "\(report.caseResults.count) synthetic cases passed")
                    digestRow("Report", report.reportSHA256)
                    Label("Fixture qualified; authority remains none.", systemImage: "checkmark.shield")
                        .foregroundStyle(.secondary)
                }
                Text("This executes only SecureSandbox’s tracked malicious fixture. It cannot qualify vendor bytes and cannot create admission evidence.")
                    .foregroundStyle(.secondary)
            }

            Section("Disposable-Mac lifecycle acceptance — read-only") {
                if let acceptance = store.acceptance {
                    LabeledContent("Suite", value: acceptance.suiteID)
                    LabeledContent("Required coverage",
                                   value: "\(acceptance.caseCount) cases · \(acceptance.observationCount) observations")
                    digestRow("Suite digest", acceptance.suiteSHA256)
                    if acceptance.availability == "available", let status = acceptance.status {
                        LabeledContent("Campaign", value: status.campaignID).textSelection(.enabled)
                        LabeledContent("Completed cases",
                                       value: "\(status.completedCaseCount) of \(status.caseCount)")
                        if let next = status.nextCase {
                            LabeledContent("Next case", value: next).textSelection(.enabled)
                        }
                        if status.readyForAssembly {
                            Label("All required observations are present and structurally verified; final assembly remains a separate CLI operation.",
                                  systemImage: "checkmark.shield")
                                .foregroundStyle(.secondary)
                        } else {
                            Label("Campaign is incomplete. Missing evidence remains fail-closed.",
                                  systemImage: "lock.fill")
                                .foregroundStyle(.secondary)
                        }
                    } else if acceptance.availability == "rejected" {
                        Label("Campaign status was rejected: \(acceptance.reason ?? "unknown reason")",
                              systemImage: "exclamationmark.shield.fill")
                            .foregroundStyle(.red).textSelection(.enabled)
                    } else {
                        Label("No disposable-Mac campaign is enrolled on this Mac.", systemImage: "lock.fill")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("Campaign status has not been loaded.").foregroundStyle(.secondary)
                }
                Button("Refresh Acceptance Status") { Task { await store.refreshAcceptanceStatus() } }
                    .disabled(isBusy)
                Text("Control Center can only verify and display campaign progress. It cannot enroll a Mac, run a case, create or edit evidence, assemble a verdict, or grant harness admission authority.")
                    .foregroundStyle(.secondary)
            }

            protectedSection
            operationSection

            Section("Non-negotiable policy") {
                Label(store.automaticOperationInvariant, systemImage: "hand.raised.fill")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .task { if store.status == nil { await store.load() } }
        .alert(item: $confirmation) { item in confirmationAlert(item) }
        .sheet(item: $reviewedRelease) { release in releaseReview(release) }
        .sheet(item: $reviewedPlan) { plan in planReview(plan) }
    }

    private var protectedSection: some View {
        Section("Protected Research generations") {
            if let protected = store.status?.protected, protected.availability == "available",
               let value = protected.status {
                LabeledContent("Boundary", value: value.status.capitalized)
                LabeledContent("Admission", value: value.admission.capitalized)
                LabeledContent("Active generation", value: value.activeGenerationID.map(shortDigest) ?? "None")
                LabeledContent("Retained generations", value: String(value.generations.count))
                if value.recoveryPending {
                    Label("Recovery is pending; admission remains fenced.", systemImage: "exclamationmark.shield.fill")
                        .foregroundStyle(.red)
                }
            } else if store.status?.protected.availability == "rejected" {
                Label("Protected generation status could not be verified. Treat Research admission state as unknown.", systemImage: "exclamationmark.shield.fill")
                    .foregroundStyle(.red)
            } else {
                Label("Protected generation inspection is not deployed on Research.", systemImage: "lock.fill")
                    .foregroundStyle(.secondary)
            }
            HStack {
                Button("Activate with Touch ID…") {
                    if let generation = store.status?.lifecycle.generations.first {
                        preparePlan("activate", generation.generationID)
                    }
                }.disabled(isBusy || store.status?.protectedActions.activate != true)
                Button("Roll Back with Touch ID…") {
                    preparePlan("rollback", store.status?.protected.status?.predecessorGenerationID)
                }.disabled(isBusy || store.status?.protectedActions.rollback != true)
                Button("Recover with Touch ID…") { preparePlan("recover", nil) }
                    .disabled(isBusy || store.status?.protectedActions.recover != true)
            }
            if let generations = store.status?.protected.status?.generations {
                ForEach(generations.filter { generation in
                    generation.status == "retained"
                    && generation.generationID != store.status?.protected.status?.activeGenerationID
                    && generation.generationID != store.status?.protected.status?.predecessorGenerationID
                }) { generation in
                    HStack {
                        Text(shortDigest(generation.generationID)).font(.system(.body, design: .monospaced))
                        Spacer()
                        Button("Retire…") { preparePlan("retire", generation.generationID) }
                            .disabled(isBusy || store.status?.protectedActions.retire != true)
                        Button("Revoke…", role: .destructive) { preparePlan("revoke", generation.generationID) }
                            .disabled(isBusy || store.status?.protectedActions.revoke != true)
                    }
                }
            }
            Text("Each mutation creates a short-lived exact plan for review, then requires Touch ID with no password fallback. Planning and execution independently reread Host sessions and Research runtime state; any drift rejects the operation.")
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var operationSection: some View {
        Section("Latest operation") {
            switch store.state {
            case .idle: LabeledContent("Status", value: "Ready")
            case .loading: ProgressView("Loading independently verified status…")
            case .running(let message): ProgressView(message)
            case .completed(let message): Label(message, systemImage: "checkmark.shield.fill")
            case .rejected(let reason):
                Label(reason, systemImage: "exclamationmark.shield.fill")
                    .foregroundStyle(.red).textSelection(.enabled)
            }
            if let receipt = store.lastReceipt {
                LabeledContent("Receipt", value: receipt.receiptID).textSelection(.enabled)
                LabeledContent("Action", value: receipt.action)
            }
        }
    }

    private var isBusy: Bool {
        if case .loading = store.state { return true }
        if case .running = store.state { return true }
        return false
    }

    private func isQuarantined(_ generationID: String) -> Bool {
        store.status?.lifecycle.generations.contains(where: { $0.generationID == generationID }) == true
    }

    private func confirmationAlert(_ item: HarnessConfirmation) -> Alert {
        switch item {
        case .acquire(let release):
            Alert(title: Text("Download exact candidate?"),
                  message: Text("Download \(release.harnessID) \(release.version) (\(shortDigest(release.generationID))) into inert quarantine? This does not install or admit it."),
                  primaryButton: .default(Text("Download to Quarantine")) {
                      Task { await store.acquire(generationID: release.generationID) }
                  }, secondaryButton: .cancel())
        case .verify(let generation):
            Alert(title: Text("Reverify quarantined candidate?"),
                  message: Text("Rehash the exact artifact and all required evidence for \(shortDigest(generation.generationID))? This grants no execution authority."),
                  primaryButton: .default(Text("Verify")) {
                      Task { await store.verify(generationID: generation.generationID) }
                  }, secondaryButton: .cancel())
        case .qualification:
            Alert(title: Text("Run synthetic containment self-test?"),
                  message: Text("This runs SecureSandbox’s built-in malicious fixture. Its result is diagnostic only and can never qualify or admit vendor bytes."),
                  primaryButton: .default(Text("Run Self-Test")) {
                      Task { await store.runQualificationSelfTest() }
                  }, secondaryButton: .cancel())
        }
    }

    private func releaseReview(_ release: HarnessRelease) -> some View {
        NavigationStack {
            Form {
                Section("Identity") {
                    LabeledContent("Harness", value: release.harnessID)
                    LabeledContent("Vendor", value: release.vendorID)
                    LabeledContent("Version", value: release.version)
                    LabeledContent("Platform", value: release.platform)
                    digestRow("Generation", release.generationID)
                    digestRow("Artifact", release.artifact.sha256)
                }
                Section("Compatibility") {
                    LabeledContent("Adapter", value: release.adapterID)
                    digestRow("Adapter digest", release.compatibility.adapterSHA256)
                    LabeledContent("Controller schema", value: release.compatibility.controllerSchema)
                }
                Section("Required evidence") {
                    ForEach(release.evidence) { evidence in
                        VStack(alignment: .leading) {
                            Label(evidence.kind, systemImage: evidence.required ? "checkmark.seal.fill" : "doc")
                            Text(evidence.sha256).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
                Section {
                    Text("These are authenticated release claims, not SecureSandbox admission or operator authorization.")
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Harness Candidate Review")
            .toolbar { Button("Done") { reviewedRelease = nil } }
        }
        .frame(width: 680, height: 620)
    }

    private func preparePlan(_ operation: String, _ generationID: String?) {
        let reason = operation == "retire" ? "Operator-requested retirement from Control Center"
            : operation == "revoke" ? "Operator-requested security revocation from Control Center" : nil
        Task {
            if let plan = await store.prepareGenerationPlan(operation: operation,
                                                            generationID: generationID, reason: reason) {
                reviewedPlan = plan
            }
        }
    }

    private func planReview(_ plan: HarnessGenerationPlan) -> some View {
        NavigationStack {
            Form {
                Section("Exact protected operation") {
                    LabeledContent("Action", value: plan.operation.capitalized)
                    LabeledContent("Generation", value: plan.generationID.map(grouped) ?? "Deterministic recovery")
                    LabeledContent("Plan / journal", value: grouped(plan.planSHA256))
                    LabeledContent("Expires", value: Date(timeIntervalSince1970: TimeInterval(plan.expiresAt)).formatted())
                    if let active = plan.activeRunCount { LabeledContent("Active Research runs", value: String(active)) }
                    if let resumable = plan.resumableSessionCount { LabeledContent("Resumable Host sessions", value: String(resumable)) }
                }
                Section {
                    Label("Touch ID is mandatory. Password fallback is forbidden. Any state or digest change rejects the plan.", systemImage: "touchid")
                    Button("Authorize Exact Plan with Touch ID…", role: plan.operation == "revoke" ? .destructive : nil) {
                        reviewedPlan = nil
                        Task { await store.authorizeGenerationPlan(plan) }
                    }
                    Button("Cancel", role: .cancel) { reviewedPlan = nil }
                }
            }
            .formStyle(.grouped).navigationTitle("Harness Lifecycle Review")
        }.frame(width: 680, height: 480)
    }

    @ViewBuilder
    private func digestRow(_ label: String, _ digest: String) -> some View {
        LabeledContent(label, value: grouped(digest)).textSelection(.enabled)
    }

    private func shortDigest(_ digest: String) -> String { String(digest.prefix(12)) + "…" }

    private func grouped(_ digest: String) -> String {
        stride(from: 0, to: digest.count, by: 8).map { offset in
            let start = digest.index(digest.startIndex, offsetBy: offset)
            let end = digest.index(start, offsetBy: min(8, digest.count - offset))
            return String(digest[start..<end])
        }.joined(separator: " ")
    }
}
