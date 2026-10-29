import SwiftUI

struct SettingsView: View {
    @AppStorage("appearancePreference") private var appearancePreference = AppAppearance.system.rawValue
    @AppStorage("exportProvenance") private var exportProvenance = false

    var body: some View {
        Form {
            Section("Appearance") {
                Picker("Appearance", selection: $appearancePreference) {
                    ForEach(AppAppearance.allCases) { choice in
                        Text(choice.title).tag(choice.rawValue)
                    }
                }
                .pickerStyle(.segmented)
            }
            Section("Evidence exports") {
                Toggle("Include provenance sidecars", isOn: $exportProvenance)
                Text("This choice is shared by export sheets. A provenance file records the verified archive identity and digest beside an export.")
                    .foregroundStyle(.secondary)
            }
            Section("Locations and diagnostics") {
                LabeledContent("SecureSandbox installation", value: ControlCenterPaths.repository)
                    .textSelection(.enabled)
                LabeledContent("Encrypted evidence archive", value: "Azure Blob Storage · conversations")
                LabeledContent("Host control bridge", value: ControlCenterPaths.repository + "/scripts/control-center-api.py")
                    .textSelection(.enabled)
                Text("The host configures archive access. Use Activity for metadata-only telemetry and Maintenance for boundary diagnostics.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .frame(width: 640, height: 520)
        .preferredColorScheme(AppAppearance.colorScheme(for: appearancePreference))
    }
}
