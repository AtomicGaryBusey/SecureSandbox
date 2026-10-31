import SwiftUI

struct ModelProfilesSettingsView: View {
    @State private var catalog: ModelProfileCatalog?
    @State private var catalogSHA256 = ""
    @State private var source = ""
    @State private var selectedID: String?
    @State private var loading = false
    @State private var saving = false
    @State private var planning = false
    @State private var activationPlan: ModelProfileActivationPlan?
    @State private var activationMode = "production"
    @State private var error: String?
    @State private var notice: String?

    private let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                VStack(spacing: 8) {
                    if let catalog {
                        List(catalog.profiles, selection: $selectedID) { profile in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(profile.displayName).fontWeight(.medium)
                                Text("\(profile.vendorName) · \(profile.adapterTitle)")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            .tag(profile.profileID)
                        }
                        .listStyle(.sidebar)
                    } else if loading {
                        ProgressView("Loading profiles…")
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        ContentUnavailableView("Profiles unavailable", systemImage: "cpu")
                    }
                    HStack {
                        Menu {
                            ForEach(ModelAdapter.allCases) { adapter in
                                Button(adapter.title) { add(adapter) }
                            }
                        } label: { Image(systemName: "plus") }
                        .menuStyle(.borderlessButton)
                        Button { deleteSelected() } label: { Image(systemName: "minus") }
                            .disabled(selectedID == nil || (catalog?.profiles.count ?? 0) <= 1)
                        Spacer()
                    }
                    .padding(.horizontal, 8)
                }
                .frame(minWidth: 220, idealWidth: 240, maxWidth: 280)

                if let binding = selectedProfileBinding {
                    ScrollView { ModelProfileEditor(profile: binding) }
                        .frame(minWidth: 500)
                } else {
                    ContentUnavailableView("Select a model profile", systemImage: "cpu")
                        .frame(minWidth: 500)
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 6) {
                if let error { Text(error).foregroundStyle(.red) }
                if let notice { Text(notice).foregroundStyle(.secondary) }
                HStack {
                    if !catalogSHA256.isEmpty {
                        Text("Catalog \(catalogSHA256.groupedDigest)")
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Spacer()
                    Button("Reload") { Task { await load() } }.disabled(loading || saving)
                    Picker("Activation", selection: $activationMode) {
                        Text("Production").tag("production")
                        Text("Safe Mock").tag("mock")
                    }
                    .pickerStyle(.segmented).frame(width: 190)
                    Button("Review Activation…") { Task { await planActivation() } }
                        .disabled(selectedID == nil || source != "staged" || loading || saving || planning)
                    Button("Save Staged Settings") { Task { await save() } }
                        .disabled(catalog == nil || loading || saving)
                        .keyboardShortcut("s", modifiers: .command)
                }
            }
            .padding(10)
        }
        .task { if catalog == nil { await load() } }
        .sheet(item: $activationPlan) { plan in
            ModelProfileActivationReview(plan: plan) { Task { await activate(plan) } }
        }
    }

    private var selectedProfileBinding: Binding<ModelProfile>? {
        guard let selectedID,
              let index = catalog?.profiles.firstIndex(where: { $0.profileID == selectedID }) else {
            return nil
        }
        return Binding(
            get: { catalog!.profiles[index] },
            set: { catalog!.profiles[index] = $0 }
        )
    }

    @MainActor private func load() async {
        loading = true; error = nil; notice = nil
        do {
            let value = try await Task.detached { try client.modelProfiles() }.value
            catalog = value.catalog
            catalogSHA256 = value.catalogSHA256
            source = value.source
            selectedID = value.catalog.profiles.first?.profileID
            notice = value.source == "example"
                ? "Showing the inert example. Save to create the private staged settings file."
                : "Loaded staged settings. Saving does not activate a model."
        } catch { self.error = error.localizedDescription }
        loading = false
    }

    @MainActor private func save() async {
        guard var value = catalog else { return }
        saving = true; error = nil; notice = nil
        value.profiles.sort { $0.profileID < $1.profileID }
        do {
            let result = try await Task.detached { try client.saveModelProfiles(value) }.value
            catalog = result.catalog
            catalogSHA256 = result.catalogSHA256
            source = result.source
            selectedID = result.catalog.profiles.contains(where: { $0.profileID == selectedID })
                ? selectedID : result.catalog.profiles.first?.profileID
            notice = "Staged settings saved with mode 0600. Live model authority is unchanged."
        } catch { self.error = error.localizedDescription }
        saving = false
    }

    @MainActor private func planActivation() async {
        guard let selectedID else { return }
        planning = true; error = nil; notice = nil
        let requestedMode = activationMode
        do {
            activationPlan = try await Task.detached {
                try client.modelProfileActivationPlan(profileID: selectedID, mode: requestedMode)
            }.value
        } catch { self.error = error.localizedDescription }
        planning = false
    }

    @MainActor private func activate(_ plan: ModelProfileActivationPlan) async {
        activationPlan = nil; error = nil; notice = "Waiting for exact Touch ID authorization…"
        do {
            _ = try await Task.detached { try client.activateModelProfile(plan) }.value
            notice = "Activation completed through the protected Host coordinator. Reload to verify active state."
        } catch { self.error = error.localizedDescription; notice = nil }
    }

    private func add(_ adapter: ModelAdapter) {
        guard var value = catalog, value.profiles.count < 16 else { return }
        var suffix = value.profiles.count + 1
        while value.profiles.contains(where: { $0.profileID == "new-profile-\(suffix)" }) { suffix += 1 }
        let profile = ModelProfile.template(adapter: adapter, id: "new-profile-\(suffix)")
        value.profiles.append(profile)
        catalog = value
        selectedID = profile.profileID
        notice = "New profile is local draft state until staged settings are saved."
    }

    private func deleteSelected() {
        guard let selectedID, var value = catalog, value.profiles.count > 1 else { return }
        value.profiles.removeAll { $0.profileID == selectedID }
        catalog = value
        self.selectedID = value.profiles.first?.profileID
        notice = "Profile removed from the draft. Save to update staged settings."
    }
}

private struct ModelProfileActivationReview: View {
    let plan: ModelProfileActivationPlan
    let approve: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var submitted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Review Exact Model Activation").font(.title2.weight(.semibold))
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                row("Profile", "\(plan.displayName) (\(plan.broker.profileID))")
                row("Vendor / model", "\(plan.broker.vendorID) / \(plan.broker.allowedModels.first ?? "—")")
                row("Current Gateway", "\(plan.current.gateway.profileID) / \(plan.current.gateway.model) [\(plan.current.gateway.mode)]")
                row("Current Research", currentResearchSummary)
                row("Current generation", plan.currentGenerationSHA256)
                row("Adapter", plan.broker.adapter)
                row("Mode", plan.broker.mode)
                row("Origin", plan.broker.upstreamOrigin)
                row("Pinned IPv4", plan.broker.upstreamIPv4.isEmpty ? "None (safe mock)" : plan.broker.upstreamIPv4.joined(separator: ", "))
                row("OAuth IPv4", plan.broker.oauthIPv4.isEmpty ? "Not used" : plan.broker.oauthIPv4.joined(separator: ", "))
                row("Credential", "\(plan.broker.credentialScheme) · \(plan.credentialReference)")
                row("Settings", settingsSummary)
                row("Broker limits", limitsSummary)
                row("Pricing", pricingSummary)
                row("Lease bounds", leaseSummary)
                row("Profile revision", plan.broker.profileSHA256)
                row("Plan digest", plan.planSHA256)
            }
            .font(.callout)
            Text("Touch ID authorizes only this digest. Saving settings alone never changes live authority, and an active session cannot switch profiles.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.disabled(submitted)
                Button("Authorize with Touch ID") {
                    submitted = true
                    approve()
                }
                .keyboardShortcut(.defaultAction).disabled(submitted)
            }
        }
        .padding(22).frame(minWidth: 720)
    }

    @ViewBuilder private func row(_ label: String, _ value: String) -> some View {
        GridRow { Text(label).foregroundStyle(.secondary); Text(value).monospaced().textSelection(.enabled) }
    }

    private var settingsSummary: String {
        let settings = plan.broker.settings
        var values = ["max_output=\(settings.maximumOutputTokens)"]
        if let value = settings.temperatureMilli { values.append("temperature_milli=\(value)") }
        if let value = settings.anthropicVersion { values.append("anthropic_version=\(value)") }
        if let value = settings.reasoningEffort { values.append("reasoning_effort=\(value)") }
        if let value = settings.cyberAccess { values.append("cyber_access=\(value)") }
        return values.joined(separator: ", ")
    }

    private var currentResearchSummary: String {
        let research = plan.current.research
        if research.state == "legacy_unbound" {
            return "Legacy session binding unavailable — exact activation will migrate"
        }
        return "\(research.profileID ?? "—") / \(research.model ?? "—") [\(research.mode ?? "—")]"
    }

    private var limitsSummary: String {
        let broker = plan.broker
        return "request=\(broker.maxRequestBytes)B, response=\(broker.maxResponseBytes)B, tokens=\(broker.maxTokens), rate=\(broker.rateLimitRequests)/\(broker.rateLimitWindowSeconds)s, timeouts=\(broker.clientTimeoutSeconds)/\(broker.upstreamTimeoutSeconds)s"
    }

    private var pricingSummary: String {
        let lease = plan.leaseProfiles
        return "input=\(lease.inputMicrousdPerMillionTokens), output=\(lease.outputMicrousdPerMillionTokens) micro-USD/M tokens"
    }

    private var leaseSummary: String {
        plan.leaseProfiles.profiles.keys.sorted().compactMap { name in
            guard let value = plan.leaseProfiles.profiles[name] else { return nil }
            return "\(name): \(value.durationSeconds)s/\(value.maximumTotalSeconds)s, req=\(value.maxRequests), in=\(value.maxInputTokens), out=\(value.maxOutputTokens), cost=\(value.maxCostMicrousd)"
        }.joined(separator: " · ")
    }
}

private struct ModelProfileEditor: View {
    @Binding var profile: ModelProfile

    var body: some View {
        Form {
            Section("Identity") {
                TextField("Profile ID", text: $profile.profileID)
                TextField("Display name", text: $profile.displayName)
                TextField("Vendor ID", text: $profile.vendorID)
                TextField("Vendor name", text: $profile.vendorName)
                TextField("Model ID", text: $profile.modelID)
                TextField("Model name", text: $profile.modelName)
            }
            Section("Provider adapter") {
                Picker("Adapter", selection: $profile.adapter) {
                    ForEach(ModelAdapter.allCases) { adapter in
                        Text(adapter.title).tag(adapter.rawValue)
                    }
                }
                .onChange(of: profile.adapter) { _, newValue in
                    profile.applyAdapter(ModelAdapter(rawValue: newValue) ?? .anthropic)
                }
                TextField("HTTPS origin", text: $profile.upstreamOrigin)
                Picker("Credential scheme", selection: $profile.credential.scheme) {
                    ForEach(profile.allowedCredentialSchemes, id: \.self) { Text($0).tag($0) }
                }
                TextField("1Password reference", text: $profile.credential.reference)
                Text("Only an op://Agents/item/field reference is stored. Never enter a secret value.")
                    .font(.caption).foregroundStyle(.secondary)
                if profile.adapter == ModelAdapter.google.rawValue {
                    TextField("Google Cloud project", text: optional($profile.deployment.projectID))
                    TextField("Location", text: optional($profile.deployment.location))
                }
            }
            Section("Inference settings") {
                integerField("Maximum output tokens", $profile.settings.maximumOutputTokens)
                integerField("Temperature (thousandths, blank = provider default)",
                             optionalInt($profile.settings.temperatureMilli))
                if profile.adapter == ModelAdapter.anthropic.rawValue {
                    TextField("Anthropic version", text: optional($profile.settings.anthropicVersion))
                } else {
                    Picker("Reasoning effort", selection: optional($profile.settings.reasoningEffort)) {
                        ForEach(["minimal", "low", "medium", "high"], id: \.self) { Text($0).tag($0) }
                    }
                }
                if profile.adapter == ModelAdapter.openAI.rawValue {
                    Picker("Cyber access", selection: optional($profile.settings.cyberAccess)) {
                        ForEach(["standard", "daybreak_blue", "daybreak_red"], id: \.self) { Text($0).tag($0) }
                    }
                }
            }
            Section("Broker limits") {
                integerField("Request bytes", $profile.limits.maxRequestBytes)
                integerField("Response bytes", $profile.limits.maxResponseBytes)
                integerField("Output tokens", $profile.limits.maxOutputTokens)
                integerField("Requests per window", $profile.limits.rateLimitRequests)
                integerField("Rate window seconds", $profile.limits.rateLimitWindowSeconds)
                integerField("Client timeout seconds", $profile.limits.clientTimeoutSeconds)
                integerField("Upstream timeout seconds", $profile.limits.upstreamTimeoutSeconds)
            }
            Section("Pricing") {
                integerField("Input micro-USD / million tokens", $profile.pricing.inputMicrousdPerMillionTokens)
                integerField("Output micro-USD / million tokens", $profile.pricing.outputMicrousdPerMillionTokens)
            }
            ForEach(["short", "standard", "extended"], id: \.self) { name in
                if let binding = leaseBinding(name) {
                    DisclosureGroup("\(name.capitalized) lease") {
                        integerField("Initial duration seconds", binding.durationSeconds)
                        integerField("Maximum duration seconds", binding.maximumTotalSeconds)
                        integerField("Maximum requests", binding.maxRequests)
                        integerField("Maximum input tokens", binding.maxInputTokens)
                        integerField("Maximum output tokens", binding.maxOutputTokens)
                        integerField("Maximum cost micro-USD", binding.maxCostMicrousd)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func integerField(_ title: String, _ value: Binding<Int>) -> some View {
        TextField(title, value: value, format: .number).monospacedDigit()
    }

    private func optional(_ value: Binding<String?>) -> Binding<String> {
        Binding(get: { value.wrappedValue ?? "" }, set: { value.wrappedValue = $0.isEmpty ? nil : $0 })
    }

    private func optionalInt(_ value: Binding<Int?>) -> Binding<Int> {
        Binding(get: { value.wrappedValue ?? 0 }, set: { value.wrappedValue = $0 })
    }

    private func leaseBinding(_ name: String) -> ModelLeaseBinding? {
        guard profile.leaseProfiles[name] != nil else { return nil }
        let root = Binding<ModelLeaseLimits>(
            get: { profile.leaseProfiles[name]! },
            set: { profile.leaseProfiles[name] = $0 }
        )
        return ModelLeaseBinding(root: root)
    }
}

private struct ModelLeaseBinding {
    let root: Binding<ModelLeaseLimits>
    var durationSeconds: Binding<Int> { root.durationSeconds }
    var maximumTotalSeconds: Binding<Int> { root.maximumTotalSeconds }
    var maxRequests: Binding<Int> { root.maxRequests }
    var maxInputTokens: Binding<Int> { root.maxInputTokens }
    var maxOutputTokens: Binding<Int> { root.maxOutputTokens }
    var maxCostMicrousd: Binding<Int> { root.maxCostMicrousd }
}

private enum ModelAdapter: String, CaseIterable, Identifiable {
    case anthropic = "anthropic-messages-v1"
    case openAI = "openai-responses-v1"
    case google = "google-openai-chat-v1"
    var id: String { rawValue }
    var title: String {
        switch self {
        case .anthropic: "Anthropic Messages"
        case .openAI: "OpenAI Responses"
        case .google: "Google OpenAI Chat"
        }
    }
}

private extension ModelProfile {
    var adapterTitle: String { ModelAdapter(rawValue: adapter)?.title ?? adapter }
    var allowedCredentialSchemes: [String] {
        switch ModelAdapter(rawValue: adapter) {
        case .anthropic: ["bearer", "anthropic-api-key"]
        case .openAI: ["bearer"]
        case .google: ["google-service-account-json"]
        case nil: []
        }
    }

    mutating func applyAdapter(_ adapter: ModelAdapter) {
        self.adapter = adapter.rawValue
        switch adapter {
        case .anthropic:
            deployment = ModelDeployment()
            credential.scheme = "bearer"
            settings.anthropicVersion = "2023-06-01"
            settings.cyberAccess = nil; settings.reasoningEffort = nil
        case .openAI:
            deployment = ModelDeployment()
            credential.scheme = "bearer"
            settings.anthropicVersion = nil
            settings.cyberAccess = "standard"; settings.reasoningEffort = "medium"
        case .google:
            deployment = ModelDeployment(location: "global", projectID: "project-id")
            credential.scheme = "google-service-account-json"
            settings.anthropicVersion = nil; settings.cyberAccess = nil
            settings.reasoningEffort = "medium"
            upstreamOrigin = "https://aiplatform.googleapis.com"
        }
    }

    static func template(adapter: ModelAdapter, id: String) -> ModelProfile {
        let lease = ModelLeaseLimits(durationSeconds: 3600, maximumTotalSeconds: 7200,
                                     maxRequests: 128, maxInputTokens: 1_000_000,
                                     maxOutputTokens: 250_000, maxCostMicrousd: 6_250_000)
        var value = ModelProfile(
            adapter: adapter.rawValue,
            credential: ModelCredential(reference: "op://Agents/Item/field", scheme: "bearer"),
            deployment: ModelDeployment(), displayName: "New Model Profile",
            leaseProfiles: ["short": lease, "standard": lease, "extended": lease],
            limits: ModelBrokerLimits(clientTimeoutSeconds: 15, maxOutputTokens: 32768,
                                      maxRequestBytes: 16_777_216, maxResponseBytes: 67_108_864,
                                      rateLimitRequests: 60, rateLimitWindowSeconds: 60,
                                      upstreamTimeoutSeconds: 120),
            modelID: "model-id", modelName: "Model", pricing: ModelPricing(
                inputMicrousdPerMillionTokens: 1, outputMicrousdPerMillionTokens: 1),
            profileID: id, settings: ModelInferenceSettings(
                maximumOutputTokens: 32768, temperatureMilli: nil),
            upstreamOrigin: "https://api.example.com", vendorID: "vendor", vendorName: "Vendor"
        )
        value.applyAdapter(adapter)
        return value
    }
}

private extension String {
    var groupedDigest: String {
        stride(from: 0, to: count, by: 8).map { offset in
            let start = index(startIndex, offsetBy: offset)
            let end = index(start, offsetBy: min(8, count - offset))
            return String(self[start..<end])
        }.joined(separator: " ")
    }
}
