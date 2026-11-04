import SwiftUI

struct ModelStackSettingsView: View {
    @AppStorage("modelSettingsSurface") private var selectedSurface = "brokered"

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Model execution mode").font(.headline)
                    Text("This selects the settings surface only. Saving never changes live authority.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Mode", selection: $selectedSurface) {
                    Text("Brokered Provider Profile").tag("brokered")
                    Text("Native Vendor Harness + Model Stack").tag("native")
                }
                .pickerStyle(.segmented)
                .frame(width: 430)
            }
            .padding(.horizontal, 10)

            Divider()

            if selectedSurface == "native" {
                NativeVendorStacksSettingsView()
            } else {
                ModelProfilesSettingsView()
            }
        }
    }
}

private struct NativeVendorStacksSettingsView: View {
    @State private var status: NativeVendorStackCatalogStatus?
    @State private var catalog: NativeVendorStackCatalog?
    @State private var persistedCatalog: NativeVendorStackCatalog?
    @State private var selectedID: String?
    @State private var loading = false
    @State private var saving = false
    @State private var error: String?
    @State private var notice: String?
    @State private var confirmingReload = false

    private let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                VStack(spacing: 8) {
                    if let catalog {
                        List(catalog.stacks, selection: $selectedID) { stack in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(stack.displayName).fontWeight(.medium)
                                Text("\(stack.vendorID) · \(stack.harness.harnessID)")
                                    .font(.caption).foregroundStyle(.secondary)
                                Text(readinessTitle(for: stack.stackID))
                                    .font(.caption2)
                                    .foregroundStyle(readinessColor(for: stack.stackID))
                            }
                            .tag(stack.stackID)
                        }
                        .listStyle(.sidebar)
                    } else if loading {
                        ProgressView("Loading native stacks…")
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        ContentUnavailableView("Native stacks unavailable", systemImage: "lock.shield")
                    }
                }
                .frame(minWidth: 230, idealWidth: 250, maxWidth: 290)

                if let binding = selectedStackBinding {
                    ScrollView {
                        NativeVendorStackEditor(
                            stack: binding,
                            readiness: readiness(for: binding.wrappedValue.stackID)
                        )
                    }
                    .frame(minWidth: 500)
                } else {
                    ContentUnavailableView("Select a native stack", systemImage: "lock.shield")
                        .frame(minWidth: 500)
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                if let error { Text(error).foregroundStyle(.red) }
                if let notice { Text(notice).foregroundStyle(.secondary) }
                HStack {
                    if let status {
                        Text("Catalog \(status.catalogSHA256.groupedDigest)")
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Spacer()
                    Button("Reload") { requestReload() }.disabled(loading || saving)
                    Button("Save Staged Settings") { Task { await save() } }
                        .disabled(catalog == nil || loading || saving)
                        .keyboardShortcut("s", modifiers: .command)
                }
            }
            .padding(10)
        }
        .task { if catalog == nil { await load() } }
        .alert("Discard Unsaved Native Stack Changes?", isPresented: $confirmingReload) {
            Button("Discard and Reload", role: .destructive) { Task { await load() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Reloading replaces every unsaved native-stack edit with the last staged settings.")
        }
    }

    private var selectedStackBinding: Binding<NativeVendorStack>? {
        guard let selectedID,
              let index = catalog?.stacks.firstIndex(where: { $0.stackID == selectedID }) else {
            return nil
        }
        return Binding(
            get: { catalog!.stacks[index] },
            set: { catalog!.stacks[index] = $0 }
        )
    }

    private var hasUnsavedChanges: Bool { catalog != persistedCatalog }

    private func readiness(for stackID: String) -> NativeVendorStackReadiness? {
        guard !hasUnsavedChanges else { return nil }
        return status?.stacks.first(where: { $0.stack.stackID == stackID })?.readiness
    }

    private func readinessTitle(for stackID: String) -> String {
        guard let readiness = readiness(for: stackID) else { return "Draft changed · validation pending" }
        switch readiness.status {
        case "configuration-required": return "Configuration required"
        case "login-required": return "Vendor sign-in required"
        case "content-ready": return "Content complete · not activated"
        default: return "Unrecognized state"
        }
    }

    private func readinessColor(for stackID: String) -> Color {
        readiness(for: stackID)?.status == "content-ready" ? .secondary : .orange
    }

    @MainActor private func load() async {
        loading = true; error = nil; notice = nil
        do {
            let value = try await Task.detached { try client.nativeVendorStacks() }.value
            status = value
            catalog = value.catalog
            persistedCatalog = value.catalog
            selectedID = value.catalog.stacks.first?.stackID
            notice = value.source == "example"
                ? "Showing inert templates. Exact harness admission and vendor sign-in are still required."
                : "Loaded private staged settings. No native stack is activated by this screen."
        } catch { self.error = error.localizedDescription }
        loading = false
    }

    @MainActor private func save() async {
        guard var value = catalog else { return }
        saving = true; error = nil; notice = nil
        value.stacks.sort { $0.stackID < $1.stackID }
        do {
            let result = try await Task.detached { try client.saveNativeVendorStacks(value) }.value
            status = result
            catalog = result.catalog
            persistedCatalog = result.catalog
            selectedID = result.catalog.stacks.contains(where: { $0.stackID == selectedID })
                ? selectedID : result.catalog.stacks.first?.stackID
            notice = "Staged settings saved with mode 0600. Login, egress, and live authority are unchanged."
        } catch { self.error = error.localizedDescription }
        saving = false
    }

    private func requestReload() {
        if hasUnsavedChanges {
            confirmingReload = true
        } else {
            Task { await load() }
        }
    }
}

private struct NativeVendorStackEditor: View {
    @Binding var stack: NativeVendorStack
    let readiness: NativeVendorStackReadiness?

    var body: some View {
        Form {
            Section("Stack identity") {
                TextField("Display name", text: $stack.displayName)
                LabeledContent("Stack ID", value: stack.stackID)
                LabeledContent("Vendor", value: stack.vendorID)
                LabeledContent("Mode", value: stack.mode)
                LabeledContent("Network policy", value: stack.networkPolicyID)
            }

            Section("Official harness and authentication") {
                LabeledContent("Harness", value: stack.harness.harnessID)
                LabeledContent("Adapter", value: stack.harness.adapterID)
                LabeledContent("Admitted generation", value: digest(stack.harness.generationID))
                LabeledContent("Authentication", value: stack.authentication.mode)
                LabeledContent("Credential custody", value: stack.authentication.credentialCustody)
                Text("Harness, authentication, custody, and network policy form a closed reviewed pairing and cannot be recombined here.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Provider authority") {
                LabeledContent("Program", value: stack.accountBinding.programID)
                LabeledContent("Tier", value: stack.accountBinding.programTier)
                LabeledContent("Requirements", value: stack.accountBinding.programRequirementsVersion)
                LabeledContent("Account binding", value: digest(stack.accountBinding.accountSubjectSHA256))
                LabeledContent("Workspace binding", value: digest(stack.accountBinding.workspaceSHA256))
                Button(signInTitle) {}
                    .disabled(true)
                    .help("Native sign-in remains unavailable until the exact harness, credential compartment, and protected ceremony are installed.")
                Text("Touch ID will authorize the future SecureSandbox ceremony; the vendor's own OAuth flow will establish provider identity.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Model") {
                if stack.vendorID == "openai" {
                    Picker("Model", selection: $stack.model.modelID) {
                        Text("GPT-6 Sol").tag("gpt-6-sol")
                        Text("GPT-6 Luna").tag("gpt-6-luna")
                    }
                    .onChange(of: stack.model.modelID) { _, modelID in
                        stack.model.modelName = modelID == "gpt-6-luna" ? "GPT-6 Luna" : "GPT-6 Sol"
                    }
                    Picker("Reasoning effort", selection: optional($stack.model.settings.reasoningEffort, fallback: "high")) {
                        ForEach(["low", "medium", "high", "xhigh"], id: \.self) { Text($0).tag($0) }
                    }
                    LabeledContent("Cyber access", value: stack.model.settings.cyberAccess ?? "daybreak_blue")
                } else {
                    LabeledContent("Model", value: "\(stack.model.modelName) (\(stack.model.modelID))")
                    Picker("Effort", selection: optional($stack.model.settings.effort, fallback: "high")) {
                        ForEach(["low", "medium", "high"], id: \.self) { Text($0).tag($0) }
                    }
                }
                Text("A running session is permanently bound to this exact model and cannot call another installed model or harness.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Readiness") {
                LabeledContent("Content state", value: readiness?.status ?? "Draft changed · save to validate")
                if let readiness, !readiness.missing.isEmpty {
                    LabeledContent("Missing", value: readiness.missing.joined(separator: ", "))
                }
                Text("Content-ready is not authenticated, entitled, admitted, connected, or activated. Those are separate protected states.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .textSelection(.enabled)
    }

    private var signInTitle: String {
        stack.vendorID == "anthropic" ? "Open Claude Code Sign-In…" : "Continue with ChatGPT…"
    }

    private func digest(_ value: String?) -> String {
        value?.groupedDigest ?? "Not bound"
    }

    private func optional(_ binding: Binding<String?>, fallback: String) -> Binding<String> {
        Binding(
            get: { binding.wrappedValue ?? fallback },
            set: { binding.wrappedValue = $0 }
        )
    }
}
