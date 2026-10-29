import AppKit
import SwiftTerm
import SwiftUI

struct TerminalWindowView: View {
    let sessionID: String
    private let repositoryPath = ControlCenterPaths.repository
    @State private var exitMessage: String?
    @State private var hasStarted = false
    @State private var sourceName: String?
    @State private var sessionName: String?
    @State private var leaseProfile: RunLeaseProfile = .standard

    private var sourceID: String? {
        guard sessionID.hasPrefix("source:") else { return nil }
        let id = String(sessionID.dropFirst("source:".count))
        return isCanonicalV4(id) ? id : nil
    }

    private var valid: Bool {
        sessionID == "new" || sourceID != nil || isCanonicalV4(sessionID)
    }

    private func isCanonicalV4(_ value: String) -> Bool {
        guard UUID(uuidString: value)?.uuidString.lowercased() == value else { return false }
        let bytes = Array(value.utf8)
        return bytes[14] == 0x34 && [0x38, 0x39, 0x61, 0x62].contains(bytes[19])
    }

    var body: some View {
        Group {
            if !valid {
                ContentUnavailableView("Invalid session", systemImage: "exclamationmark.triangle")
            } else if !ControlCenterPaths.hasLocalBridge() {
                ContentUnavailableView("SecureSandbox installation unavailable",
                                       systemImage: "exclamationmark.shield")
            } else if hasStarted {
                TerminalSurface(repositoryPath: repositoryPath,
                                executable: "/usr/local/bin/secure-sandbox-claude",
                                arguments: ["--lease-profile", leaseProfile.rawValue]
                                    + (sourceID.map { ["--source", $0] }
                                       ?? (sessionID == "new" ? [] : ["--resume", sessionID])),
                                exitLabel: "Session") { message in
                    exitMessage = message
                }
            } else {
                VStack(spacing: 16) {
                    Image(systemName: "terminal").font(.largeTitle).foregroundStyle(.secondary)
                    Text(sourceID != nil ? "Analyze \(sourceName ?? "selected source")"
                         : sessionID == "new" ? "Start a new analysis"
                         : "Resume \(sessionName ?? "this session")")
                        .font(.title2.bold())
                    if let sourceID {
                        Text("Registered source \(sourceID)").font(.caption.monospaced())
                            .foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Text("The approved launcher checks lab readiness and requests operator authorization when required.")
                        .foregroundStyle(.secondary)
                    Picker("Run lease", selection: $leaseProfile) {
                        ForEach(RunLeaseProfile.allCases) { profile in
                            Text(profile.title).tag(profile)
                        }
                    }
                    .frame(maxWidth: 300)
                    Text("The Gateway issues the selected run lease and enforces its limits.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button(sessionID == "new" || sourceID != nil ? "Start Analysis" : "Resume Session") {
                        hasStarted = true
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(sourceID != nil ? "Source Analysis"
                         : sessionID == "new" ? "New Analysis" : sessionName ?? "Resume Session")
        .task {
            let client = CatalogClient(repositoryPath: repositoryPath)
            if let sourceID {
                if let sources = try? await Task.detached(operation: {
                    try client.load("sources", as: [SourceRecord].self)
                }).value {
                    sourceName = sources.first(where: { $0.id == sourceID })?.repository
                }
            } else if sessionID != "new", valid {
                if let sessions = try? await Task.detached(operation: {
                    try client.load("sessions", as: [SessionRecord].self)
                }).value {
                    sessionName = SessionRecord.displayNames(in: sessions)[sessionID]
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let exitMessage {
                Text(exitMessage)
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(.regularMaterial)
            }
        }
    }
}

private enum RunLeaseProfile: String, CaseIterable, Identifiable {
    case short, standard, extended

    var id: String { rawValue }
    var title: String {
        switch self {
        case .short: "Short · 1 hour"
        case .standard: "Standard · 4 hours"
        case .extended: "Extended · 8 hours"
        }
    }
}

struct BreakGlassTerminalView: View {
    let destination: String
    @State private var hasStarted = false
    @State private var exitMessage: String?

    private var valid: Bool { destination == "admin" || destination == "target" }
    private var label: String { destination == "admin" ? "Research administrator" : "Target administrator" }

    var body: some View {
        Group {
            if !valid {
                ContentUnavailableView("Invalid destination", systemImage: "exclamationmark.triangle")
            } else if hasStarted {
                TerminalSurface(repositoryPath: NSHomeDirectory(),
                                executable: "/usr/bin/ssh",
                                arguments: ["-F", "/usr/local/libexec/secure-sandbox-host/current/ssh_config",
                                            destination == "admin" ? "sandbox-research-admin" : "sandbox-target-admin"],
                                exitLabel: label) { exitMessage = $0 }
            } else {
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.shield").font(.largeTitle).foregroundStyle(.orange)
                    Text("Open \(label) shell").font(.title2.bold())
                    Text(destination == "admin"
                         ? "This opens the direct Research administrator shell. Commands here bypass the analysis session workflow."
                         : "This opens the direct Target administrator shell. Commands here bypass the analysis session workflow.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Button("Open Direct Shell") { hasStarted = true }
                        .buttonStyle(.borderedProminent)
                }
                .padding(32)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(valid ? label : "Break Glass")
        .safeAreaInset(edge: .bottom) {
            if let exitMessage {
                Text(exitMessage).font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8).background(.regularMaterial)
            }
        }
    }
}

struct TerminalSurface: NSViewRepresentable {
    let repositoryPath: String
    let executable: String
    let arguments: [String]
    let exitLabel: String
    let onExit: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(exitLabel: exitLabel, onExit: onExit) }

    func makeNSView(context: Context) -> LocalProcessTerminalView {
        let view = LocalProcessTerminalView(frame: .zero)
        // Agent output is untrusted: deny OSC 52 clipboard access and link activation.
        view.terminalDelegate = context.coordinator
        view.processDelegate = context.coordinator
        view.linkReporting = .none
        view.startProcess(executable: executable, args: arguments, currentDirectory: repositoryPath)
        return view
    }

    func updateNSView(_ nsView: LocalProcessTerminalView, context: Context) {}

    static func dismantleNSView(_ nsView: LocalProcessTerminalView, coordinator: Coordinator) {
        nsView.terminate()
    }

    @MainActor final class Coordinator: NSObject, LocalProcessTerminalViewDelegate, TerminalViewDelegate {
        let exitLabel: String
        let onExit: (String) -> Void

        init(exitLabel: String, onExit: @escaping (String) -> Void) {
            self.exitLabel = exitLabel
            self.onExit = onExit
        }

        func sizeChanged(source: LocalProcessTerminalView, newCols: Int, newRows: Int) {}
        func setTerminalTitle(source: LocalProcessTerminalView, title: String) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func processTerminated(source: TerminalView, exitCode: Int32?) {
            onExit(exitCode.map { "\(exitLabel) process exited with status \($0)." } ?? "\(exitLabel) process ended.")
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            (source as? LocalProcessTerminalView)?.sizeChanged(source: source, newCols: newCols, newRows: newRows)
        }
        func setTerminalTitle(source: TerminalView, title: String) {}
        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            (source as? LocalProcessTerminalView)?.send(source: source, data: data)
        }
        func scrolled(source: TerminalView, position: Double) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {}
        func clipboardCopy(source: TerminalView, content: Data) {}
        func clipboardRead(source: TerminalView) -> Data? { nil }
        func programStatusChanged(source: TerminalView, records: [TerminalProgramStatus]) {}
        func kittyClipboardCapabilities(source: TerminalView) -> KittyClipboardCapabilities { [] }
        func kittyClipboardAvailableMimeTypes(source: TerminalView, location: KittyClipboardLocation) -> [String]? { [] }
        func kittyClipboardRead(source: TerminalView, location: KittyClipboardLocation, mimeType: String) -> KittyClipboardReadResult? { nil }
        func kittyClipboardWrite(source: TerminalView, location: KittyClipboardLocation, content: KittyClipboardWriteContent) -> KittyClipboardWriteResult { .unsupported }
        func kittyClipboardRequestPermission(source: TerminalView, request: KittyClipboardPermissionRequest) -> KittyClipboardPermissionResult { .deny }
    }
}
