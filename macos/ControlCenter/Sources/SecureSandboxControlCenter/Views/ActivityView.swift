import SwiftUI

struct ActivityView: View {
    let store: CatalogStore
    let search: String

    private var filtered: [ActivityRecord] {
        store.activity.filter {
            search.isEmpty || $0.eventType.localizedCaseInsensitiveContains(search)
                || ($0.message?.localizedCaseInsensitiveContains(search) ?? false)
        }
        .sorted { $0.timeGenerated > $1.timeGenerated }
    }

    var body: some View {
        Group {
            if let error = store.errors["activity"] {
                ContentUnavailableView("Activity unavailable", systemImage: "wifi.slash", description: Text(error))
            } else {
                List(filtered) { event in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(event.eventType.replacingOccurrences(of: "_", with: " ").capitalized)
                                .font(.headline)
                            Spacer()
                            Text(event.severity.capitalized).foregroundStyle(event.severity == "error" ? .red : .secondary)
                        }
                        Text("\(event.timeGenerated) · \(event.vmID ?? "host")")
                            .font(.caption).foregroundStyle(.secondary)
                        if let message = event.message, !message.isEmpty {
                            Text(message).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
                .overlay {
                    if filtered.isEmpty { ContentUnavailableView.search(text: search) }
                }
            }
        }
        .navigationTitle("Activity")
    }
}
