import SwiftUI

struct FindingsView: View {
    let store: CatalogStore
    let search: String
    @State private var selectedID: String?
    @State private var showingDetail = false

    private var filtered: [FindingRecord] {
        store.findings.filter {
            search.isEmpty || $0.id.localizedCaseInsensitiveContains(search)
                || $0.state.localizedCaseInsensitiveContains(search)
                || $0.proposedSeverity.localizedCaseInsensitiveContains(search)
                || $0.disposition.localizedCaseInsensitiveContains(search)
                || (store.findingDisplayNames[$0.id] ?? "").localizedCaseInsensitiveContains(search)
        }
            .sorted {
                $0.submittedAt == $1.submittedAt ? $0.id < $1.id : $0.submittedAt > $1.submittedAt
            }
    }
    private var selectedFinding: FindingRecord? {
        filtered.first { $0.id == selectedID }
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
                        Text(store.findingDisplayNames[finding.id] ?? OperatorDate.display(finding.submittedAt))
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
        .onChange(of: search) { _, _ in
            if selectedFinding == nil { selectedID = nil }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    if selectedFinding != nil { showingDetail = true }
                } label: {
                    Label("Open Finding", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(selectedFinding == nil)
            }
        }
        .sheet(isPresented: $showingDetail) {
            if let selectedFinding {
                FindingDetailSheet(findingID: selectedFinding.id,
                                   disposition: selectedFinding.disposition,
                                   otherFindings: store.findings.filter { $0.findingID != selectedFinding.id }) {
                    Task { await store.refresh() }
                }
            }
        }
    }
}
