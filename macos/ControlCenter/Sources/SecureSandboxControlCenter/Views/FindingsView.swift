import SwiftUI

struct FindingsView: View {
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?
    @State private var showingDetail = false

    private var filtered: [FindingRecord] {
        store.findings.filter { search.isEmpty || $0.id.localizedCaseInsensitiveContains(search) || $0.state.localizedCaseInsensitiveContains(search) }
            .sorted { $0.submittedAt > $1.submittedAt }
    }

    var body: some View {
        Group {
            if let error = store.errors["findings"] {
                ContentUnavailableView("Findings unavailable", systemImage: "wifi.slash", description: Text(error))
            } else {
                List(filtered, selection: $selectedID) { finding in
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(finding.proposedSeverity.capitalized) · \(finding.state.capitalized)")
                            .font(.headline)
                        Text("\(OperatorDate.display(finding.submittedAt)) · \(finding.id.prefix(8))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .tag(finding.id)
                }
                .overlay {
                    if filtered.isEmpty { ContentUnavailableView.search(text: search) }
                }
            }
        }
        .navigationTitle("Findings")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingDetail = true
                } label: {
                    Label("Open Finding", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(selectedID == nil)
            }
        }
        .sheet(isPresented: $showingDetail) {
            if let selectedID {
                FindingDetailSheet(findingID: selectedID,
                                   disposition: store.findings.first { $0.findingID == selectedID }?.disposition ?? "unknown",
                                   otherFindings: store.findings.filter { $0.findingID != selectedID }) {
                    Task { await store.refresh() }
                }
            }
        }
    }
}
