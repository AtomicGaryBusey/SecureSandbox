import SwiftUI

struct SettingsView: View {
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"

    var body: some View {
        Form {
            TextField("SecureSandbox repository", text: $repositoryPath)
                .help("Location of the reviewed host CLI and Control Center bridge")
        }
        .formStyle(.grouped)
        .padding()
        .frame(width: 540)
    }
}
