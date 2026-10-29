import SwiftUI

struct SessionLabelSheet: View {
    let store: CatalogStore
    let session: SessionRecord
    @Environment(\.dismiss) private var dismiss
    @State private var label = ""
    @State private var error: String?
    @State private var saving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Label session").font(.title2.bold())
            Text("Labels stay on this Mac. They do not change the guest session or its resume authority.")
                .foregroundStyle(.secondary)
            TextField("Label", text: $label)
                .onAppear { label = session.label == "-" ? "" : session.label }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { Task { await save() } }
                    .disabled(label.isEmpty || saving)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    private func save() async {
        saving = true
        error = nil
        do {
            try await store.setLabel(id: session.id, label: label)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
        saving = false
    }
}
