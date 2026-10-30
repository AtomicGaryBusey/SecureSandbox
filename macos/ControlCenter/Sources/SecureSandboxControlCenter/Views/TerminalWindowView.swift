import AppKit
import Darwin
import SwiftTerm
import SwiftUI

private enum TerminalShutdownPolicy {
    // The controller uses this interval to close the Research lifecycle and
    // finalize its Gateway lease before the app force-kills a wedged child.
    static let controllerGraceSeconds: TimeInterval = 30
    // SwiftTerm independently escalates when its view is released.  Keep that
    // later than the app-owned deadline so deinitialization cannot preempt the
    // controller's durable teardown.
    static let swiftTermGraceSeconds: TimeInterval = 35
}

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
        let view = WindowAwareTerminalView(frame: .zero)
        // Agent output is untrusted: deny OSC 52 clipboard access and link activation.
        view.terminalDelegate = context.coordinator
        view.processDelegate = context.coordinator
        view.onWindowChange = { [weak coordinator = context.coordinator, weak view] window in
            guard let view else { return }
            coordinator?.bind(view, to: window)
        }
        context.coordinator.bind(view, to: view.window)
        view.linkReporting = .none
        view.process.killEscalationDelay = TerminalShutdownPolicy.swiftTermGraceSeconds
        view.startProcess(executable: executable, args: arguments, currentDirectory: repositoryPath)
        return view
    }

    func updateNSView(_ nsView: LocalProcessTerminalView, context: Context) {}

    static func dismantleNSView(_ nsView: LocalProcessTerminalView, coordinator: Coordinator) {
        coordinator.terminateForWindowClose()
    }

    @MainActor final class Coordinator: NSObject, LocalProcessTerminalViewDelegate, TerminalViewDelegate {
        private static var closingCoordinators: [pid_t: Coordinator] = [:]

        let exitLabel: String
        let onExit: (String) -> Void
        // Keep the PTY owner alive after SwiftUI removes the closed window.
        // Releasing it early closes the PTY and sends SIGHUP while the
        // controller is still processing its explicit SIGTERM cleanup.
        private var terminalView: LocalProcessTerminalView?
        private weak var observedWindow: NSWindow?
        private var closeObserver: NSObjectProtocol?
        private var closingPID: pid_t = 0

        init(exitLabel: String, onExit: @escaping (String) -> Void) {
            self.exitLabel = exitLabel
            self.onExit = onExit
        }

        isolated deinit {
            if let closeObserver { NotificationCenter.default.removeObserver(closeObserver) }
            NSObject.cancelPreviousPerformRequests(withTarget: self)
        }

        func bind(_ view: LocalProcessTerminalView, to window: NSWindow?) {
            terminalView = view
            guard observedWindow !== window else { return }
            if let closeObserver { NotificationCenter.default.removeObserver(closeObserver) }
            closeObserver = nil
            observedWindow = window
            guard let window else { return }
            closeObserver = NotificationCenter.default.addObserver(
                forName: NSWindow.willCloseNotification, object: window, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.terminateForWindowClose() }
            }
        }

        func terminateForWindowClose() {
            // NSWindow.willClose and SwiftUI dismantling both reach this
            // method.  Guard before signaling so a second callback cannot
            // interrupt the controller while its first SIGTERM is driving
            // durable lease cleanup.
            guard let terminalView, closingPID == 0 else { return }
            let pid = terminalView.process.shellPid
            guard pid > 0 else {
                terminalView.terminate()
                return
            }
            closingPID = pid
            Self.closingCoordinators[pid] = self
            terminalView.terminate()
            // The reviewed controller handles SIGTERM by hanging up its exact
            // SSH child and durably finalizing both lease authorities. Allow
            // that bounded cleanup to finish before force escalation.
            perform(#selector(forceTerminateIfNeeded(_:)),
                    with: NSNumber(value: pid),
                    afterDelay: TerminalShutdownPolicy.controllerGraceSeconds)
        }

        @objc private func forceTerminateIfNeeded(_ value: NSNumber) {
            let pid = pid_t(value.int32Value)
            guard closingPID == pid, terminalView?.process.shellPid == pid else { return }
            if Darwin.kill(-pid, SIGKILL) != 0 { _ = Darwin.kill(pid, SIGKILL) }
        }

        func sizeChanged(source: LocalProcessTerminalView, newCols: Int, newRows: Int) {}
        func setTerminalTitle(source: LocalProcessTerminalView, title: String) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func processTerminated(source: TerminalView, exitCode: Int32?) {
            let pid = closingPID
            closingPID = 0
            NSObject.cancelPreviousPerformRequests(withTarget: self)
            onExit(exitCode.map { "\(exitLabel) process exited with status \($0)." } ?? "\(exitLabel) process ended.")
            terminalView = nil
            if pid > 0 { Self.closingCoordinators.removeValue(forKey: pid) }
        }
        func processFailedToStart(source: TerminalView, error: LocalProcessError) {
            onExit("\(exitLabel) process could not start: \(error).")
            terminalView = nil
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

private final class WindowAwareTerminalView: LocalProcessTerminalView {
    var onWindowChange: ((NSWindow?) -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        onWindowChange?(window)
    }
}
