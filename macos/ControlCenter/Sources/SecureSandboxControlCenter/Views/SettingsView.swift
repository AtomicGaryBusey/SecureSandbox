import SwiftUI

struct SettingsView: View {
    var body: some View {
        Form {
            LabeledContent("SecureSandbox installation", value: ControlCenterPaths.repository)
                .textSelection(.enabled)
            Text("The app uses this installation for its reviewed host controls.")
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .padding()
        .frame(width: 540)
    }
}
