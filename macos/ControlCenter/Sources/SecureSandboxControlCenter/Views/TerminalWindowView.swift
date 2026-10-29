import AppKit
import SwiftTerm
import SwiftUI

struct TerminalWindowView: View {
    let sessionID: String
    @AppStorage("repositoryPath") private var repositoryPath = NSHomeDirectory() + "/SecureSandbox"
    @State private var exitMessage: String?
    @State private var hasStarted = false

    private var valid: Bool {
        sessionID == "new" || UUID(uuidString: sessionID)?.uuidString.lowercased() == sessionID
    }

    var body: some View {
        Group {
            if !valid {
                ContentUnavailableView("Invalid session", systemImage: "exclamationmark.triangle")
            } else if hasStarted {
                TerminalSurface(repositoryPath: repositoryPath, sessionID: sessionID) { message in
                    exitMessage = message
                }
            } else {
                VStack(spacing: 16) {
                    Image(systemName: "terminal").font(.largeTitle).foregroundStyle(.secondary)
                    Text(sessionID == "new" ? "Start a new analysis" : "Resume this session")
                        .font(.title2.bold())
                    Text("The approved launcher checks lab readiness and requests operator authorization when required.")
                        .foregroundStyle(.secondary)
                    Button(sessionID == "new" ? "Start Analysis" : "Resume Session") {
                        hasStarted = true
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(sessionID == "new" ? "New Analysis" : "Session \(sessionID.prefix(8))")
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

private struct TerminalSurface: NSViewRepresentable {
    let repositoryPath: String
    let sessionID: String
    let onExit: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onExit: onExit) }

    func makeNSView(context: Context) -> LocalProcessTerminalView {
        let view = LocalProcessTerminalView(frame: .zero)
        // Agent output is untrusted: deny OSC 52 clipboard access and link activation.
        view.terminalDelegate = context.coordinator
        view.processDelegate = context.coordinator
        view.linkReporting = .none
        let args = sessionID == "new" ? [] : ["--resume", sessionID]
        view.startProcess(executable: "/usr/local/bin/secure-sandbox-claude",
                          args: args, currentDirectory: repositoryPath)
        return view
    }

    func updateNSView(_ nsView: LocalProcessTerminalView, context: Context) {}

    static func dismantleNSView(_ nsView: LocalProcessTerminalView, coordinator: Coordinator) {
        nsView.terminate()
    }

    @MainActor final class Coordinator: NSObject, LocalProcessTerminalViewDelegate, TerminalViewDelegate {
        let onExit: (String) -> Void

        init(onExit: @escaping (String) -> Void) { self.onExit = onExit }

        func sizeChanged(source: LocalProcessTerminalView, newCols: Int, newRows: Int) {}
        func setTerminalTitle(source: LocalProcessTerminalView, title: String) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func processTerminated(source: TerminalView, exitCode: Int32?) {
            onExit(exitCode.map { "Session process exited with status \($0)." } ?? "Session process ended.")
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
