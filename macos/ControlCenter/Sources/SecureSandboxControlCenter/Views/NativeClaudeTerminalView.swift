import AppKit
import SecureSandboxNativeSessionUIProtocol
import SwiftTerm
import SwiftUI

struct NativeClaudeTerminalView: View {
    let handle: NativeTerminalHandle
    let title: String
    let sessionPlan: NativeSessionPlan?
    @Environment(\.dismiss) private var dismiss
    @State private var state = "Connecting directly to the protected broker…"
    @State private var pendingStopPlan: NativeSessionPlan?
    @State private var stopping = false
    @State private var stopError: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Label(title, systemImage: "lock.terminal")
                    .font(.headline)
                Spacer()
                Text(state)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if sessionPlan != nil {
                    Button("Review Stop…") {
                        Task { await prepareStop() }
                    }
                    .disabled(stopping)
                }
                Button("Close") { dismiss() }
            }
            .padding(10)
            Divider()
            NativeClaudeTerminalSurface(handle: handle) { message in
                state = message
            }
            .frame(minWidth: 760, minHeight: 500)
            Divider()
            Text("Direct signed-app broker channel · exact one-use claim · no helper process, transcript, logging, clipboard access, or links. Closing this surface closes the channel and triggers protected teardown.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
            if let stopError {
                Text(stopError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 10)
                    .padding(.bottom, 8)
            }
        }
        .interactiveDismissDisabled(false)
        .sheet(item: $pendingStopPlan) { plan in
            NativeSessionPlanSheet(
                plan: plan,
                sourceName: nil,
                onCancel: { pendingStopPlan = nil },
                onAuthorize: { Task { await authorizeStop(plan) } }
            )
        }
    }

    @MainActor private func prepareStop() async {
        guard !stopping, let sessionPlan else { return }
        stopping = true
        stopError = nil
        do {
            let request = try NativeSessionPlanRequest(
                action: .stop,
                sessionID: sessionPlan.sessionID,
                stackID: sessionPlan.stackID,
                stackSHA256: sessionPlan.stackSHA256,
                catalogSHA256: sessionPlan.catalogSHA256,
                sourceID: sessionPlan.sourceID,
                resumeSessionID: nil,
                leaseProfileID: nil
            )
            pendingStopPlan = try await Task.detached {
                try NativeSessionPlanBrokerClient().plan(request)
            }.value
        } catch { stopError = error.localizedDescription }
        stopping = false
    }

    @MainActor private func authorizeStop(_ plan: NativeSessionPlan) async {
        guard !stopping else { return }
        pendingStopPlan = nil
        stopping = true
        stopError = nil
        do {
            let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)
            _ = try await Task.detached {
                try client.authorizeNativeSessionStop(plan)
            }.value
            state = "Protected stop verified; process and egress are absent."
            dismiss()
        } catch { stopError = error.localizedDescription }
        stopping = false
    }
}

private struct NativeClaudeTerminalSurface: NSViewRepresentable {
    let handle: NativeTerminalHandle
    let onState: @MainActor (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(handle: handle, onState: onState)
    }

    func makeNSView(context: Context) -> NativeClaudeSecureTerminalView {
        let view = NativeClaudeSecureTerminalView(frame: .zero)
        view.terminalDelegate = context.coordinator
        view.linkReporting = .none
        context.coordinator.start(view)
        return view
    }

    func updateNSView(
        _ nsView: NativeClaudeSecureTerminalView, context: Context
    ) {}

    static func dismantleNSView(
        _ nsView: NativeClaudeSecureTerminalView, coordinator: Coordinator
    ) {
        coordinator.stop()
    }

    final class NativeClaudeSecureTerminalView: TerminalView {
        @objc override func paste(_ sender: Any) {}
        @objc override func copy(_ sender: Any) {}

        override func validateUserInterfaceItem(
            _ item: NSValidatedUserInterfaceItem
        ) -> Bool {
            switch item.action {
            case #selector(paste(_:)), #selector(copy(_:)),
                 #selector(performFindPanelAction(_:)),
                 #selector(performTextFinderAction(_:)):
                false
            default:
                super.validateUserInterfaceItem(item)
            }
        }

        @objc override func performFindPanelAction(_ sender: Any?) {}
        override func performTextFinderAction(_ sender: Any?) {}
    }

    @MainActor final class Coordinator: NSObject, TerminalViewDelegate {
        private let handle: NativeTerminalHandle
        private let onState: @MainActor (String) -> Void
        private weak var terminal: TerminalView?
        private var connection: NativeBrokerDuplexConnection?
        private var task: Task<Void, Never>?
        private var stopped = false

        init(
            handle: NativeTerminalHandle,
            onState: @escaping @MainActor (String) -> Void
        ) {
            self.handle = handle
            self.onState = onState
        }

        isolated deinit {
            task?.cancel()
            connection?.close()
        }

        func start(_ view: TerminalView) {
            terminal = view
            let sender = view.feedSender
            task = Task { [weak self, handle] in
                guard let self else { return }
                do {
                    let claim = try handle.claimData(expectedKind: handle.kind)
                    let connection = try await Task.detached {
                        try NativeBrokerDuplexConnection(claim: claim)
                    }.value
                    guard !Task.isCancelled, !stopped else {
                        connection.close()
                        return
                    }
                    self.connection = connection
                    var gate = try NativeStreamHeaderGate(expectedASCII: "SSTERM1\n")
                    while !Task.isCancelled, !stopped {
                        let chunk = try await Task.detached {
                            try connection.read()
                        }.value
                        guard let chunk else {
                            try gate.requireOpenAtEOF()
                            onState("Protected channel ended; teardown requested.")
                            return
                        }
                        let payload = try gate.receive(chunk)
                        if gate.isOpen {
                            onState("Protected channel active")
                        }
                        if !payload.isEmpty {
                            sender.feed(byteArray: Array(payload)[...])
                        }
                    }
                } catch is CancellationError {
                    return
                } catch {
                    guard !stopped else { return }
                    connection?.close()
                    onState(error.localizedDescription)
                }
            }
        }

        func stop() {
            guard !stopped else { return }
            stopped = true
            connection?.close()
            task?.cancel()
            task = nil
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {}
        func setTerminalTitle(source: TerminalView, title: String) {}
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            guard let connection, !stopped else { return }
            connection.enqueueWrite(Data(data)) { [weak self] error in
                Task { @MainActor in
                    guard let self, !self.stopped else { return }
                    self.connection?.close()
                    self.onState(error.localizedDescription)
                }
            }
        }
        func scrolled(source: TerminalView, position: Double) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
        func requestOpenLink(
            source: TerminalView, link: String, params: [String: String]
        ) {}
        func bell(source: TerminalView) {}
        func clipboardCopy(source: TerminalView, content: Data) {}
        func clipboardRead(source: TerminalView) -> Data? { nil }
        func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
        func programStatusChanged(
            source: TerminalView, records: [TerminalProgramStatus]
        ) {}
        func kittyClipboardCapabilities(
            source: TerminalView
        ) -> KittyClipboardCapabilities { [] }
        func kittyClipboardAvailableMimeTypes(
            source: TerminalView, location: KittyClipboardLocation
        ) -> [String]? { [] }
        func kittyClipboardRead(
            source: TerminalView, location: KittyClipboardLocation,
            mimeType: String
        ) -> KittyClipboardReadResult? { nil }
        func kittyClipboardWrite(
            source: TerminalView, location: KittyClipboardLocation,
            content: KittyClipboardWriteContent
        ) -> KittyClipboardWriteResult { .unsupported }
        func kittyClipboardRequestPermission(
            source: TerminalView, request: KittyClipboardPermissionRequest
        ) -> KittyClipboardPermissionResult { .deny }
    }
}
