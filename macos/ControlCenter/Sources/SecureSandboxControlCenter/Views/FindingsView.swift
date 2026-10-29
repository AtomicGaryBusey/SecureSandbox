import SwiftUI

struct FindingsView: View {
    let store: CatalogStore
    let search: String

    private var filtered: [FindingRecord] {
        store.findings.filter { search.isEmpty || $0.id.localizedCaseInsensitiveContains(search) || $0.state.localizedCaseInsensitiveContains(search) }
            .sorted { $0.submittedAt > $1.submittedAt }
    }

    var body: some View {
        Group {
            if let error = store.errors["findings"] {
                ContentUnavailableView("Findings unavailable", systemImage: "wifi.slash", description: Text(error))
            } else {
                List(filtered) { finding in
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(finding.proposedSeverity.capitalized) · \(finding.state.capitalized)")
                            .font(.headline)
                        Text("\(finding.submittedAt) · \(finding.id.prefix(8))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
                .overlay {
                    if filtered.isEmpty { ContentUnavailableView.search(text: search) }
                }
            }
        }
        .navigationTitle("Findings")
    }
}
