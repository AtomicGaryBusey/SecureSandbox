import SecureSandboxNativeSessionUIProtocol
import SwiftUI

private struct NativeCodexRenderedMessage: Identifiable, Equatable {
    let id = UUID()
    let channel: String
    var text: String
}

private actor NativeCodexSessionChannel {
    private let connection: NativeBrokerDuplexConnection
    private var codec: NativeCodexUIProtocol

    init(
        connection: NativeBrokerDuplexConnection,
        plan: NativeSessionPlan,
        handle: NativeCodexUIHandle,
        reasoningEffort: String
    ) throws {
        self.connection = connection
        codec = try NativeCodexUIProtocol(
            runtimeAuthoritySHA256: plan.runtimeAuthoritySHA256,
            sessionLeaseSHA256: handle.sessionLeaseSHA256,
            expectedSessionIDSHA256: plan.expectedSessionIDSHA256,
            expectedModelID: plan.authority.modelID,
            expectedReasoningEffort: reasoningEffort,
            expectedHarnessGenerationID: plan.authority.harnessGenerationID,
            expectedHarnessExecutableSHA256:
                plan.authority.harnessExecutableSHA256,
            expectedSessionExpiresAt: handle.sessionExpiresAt
        )
    }

    func decode(_ line: Data) throws -> NativeCodexUIEvent {
        try codec.decodeEvent(line)
    }

    func requireClosedAtEOF() throws {
        try codec.requireClosedAtEOF()
    }

    func turn(_ text: String) throws {
        try connection.write(codec.turn(text))
    }

    func interrupt() throws {
        try connection.write(codec.interrupt())
    }

    func requestClose() throws {
        try connection.write(codec.close())
    }

    nonisolated func forceClose() { connection.close() }
}

struct NativeCodexSessionView: View {
    private static let maximumRenderedBytes = 8 * 1_024 * 1_024
    private static let maximumRenderedMessageBytes = 1_024 * 1_024
    private static let maximumRenderedMessages = 1_024

    let handle: NativeCodexUIHandle
    let plan: NativeSessionPlan
    let reasoningEffort: String
    @Environment(\.dismiss) private var dismiss
    @State private var channel: NativeCodexSessionChannel?
    @State private var messages: [NativeCodexRenderedMessage] = []
    @State private var renderedBytes = 0
    @State private var startNewRenderedMessage = true
    @State private var earlierOutputOmitted = false
    @State private var prompt = ""
    @State private var status = "Claiming the typed protected channel…"
    @State private var ready = false
    @State private var turnRunning = false
    @State private var closing = false
    @State private var error: String?
    @State private var pendingStopPlan: NativeSessionPlan?
    @State private var stopping = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Label("Codex Typed Session", systemImage: "text.bubble.fill")
                    .font(.headline)
                Text("\(plan.authority.modelID) · \(reasoningEffort) · Daybreak Blue")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(status).font(.caption).foregroundStyle(.secondary)
                Button("Review Stop…") { Task { await prepareStop() } }
                    .disabled(!ready || stopping || closing)
                Button("Request Close") { Task { await requestClose() } }
                    .disabled(!ready || closing)
            }
            .padding(10)
            Divider()

            if messages.isEmpty {
                ContentUnavailableView(
                    ready ? "Ready for a typed turn" : "Establishing typed channel",
                    systemImage: ready ? "checkmark.shield" : "ellipsis.shield",
                    description: Text(
                        "This surface admits only schema-pinned sanitized events. Raw app-server JSON and terminal bytes are never rendered."
                    )
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(messages) { message in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(message.channel == "assistant" ? "Codex" : "Tool")
                                    .font(.caption.bold())
                                    .foregroundStyle(.secondary)
                                Text(message.text)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .padding(10)
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                        }
                    }
                    .padding(12)
                }
            }

            Divider()
            VStack(alignment: .leading, spacing: 8) {
                if earlierOutputOmitted {
                    Label(
                        "Earlier sanitized output was removed from this in-memory view to keep its memory use bounded.",
                        systemImage: "text.badge.minus"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                TextEditor(text: $prompt)
                    .font(.body.monospaced())
                    .frame(minHeight: 70, maxHeight: 140)
                    .overlay {
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(.quaternary)
                    }
                    .disabled(!ready || turnRunning || closing)
                HStack {
                    Text("Typed turn only · exact model and cyber-access setting are requalified before usable output.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if turnRunning {
                        Button("Interrupt") { Task { await interrupt() } }
                    }
                    Button("Send Typed Turn") { Task { await sendTurn() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(!canSend)
                }
                if let error {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }
            .padding(10)
        }
        .frame(minWidth: 800, minHeight: 600)
        .interactiveDismissDisabled(false)
        .task { await run() }
        .onDisappear {
            channel?.forceClose()
        }
        .sheet(item: $pendingStopPlan) { stopPlan in
            NativeSessionPlanSheet(
                plan: stopPlan,
                sourceName: nil,
                onCancel: { pendingStopPlan = nil },
                onAuthorize: { Task { await authorizeStop(stopPlan) } }
            )
        }
    }

    private var canSend: Bool {
        ready && !turnRunning && !closing
            && !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    @MainActor private func run() async {
        do {
            try handle.validate(plan: plan)
            let claim = try handle.claimData(plan: plan)
            let connection = try await Task.detached {
                try NativeBrokerDuplexConnection(claim: claim)
            }.value
            let channel = try NativeCodexSessionChannel(
                connection: connection, plan: plan, handle: handle,
                reasoningEffort: reasoningEffort
            )
            self.channel = channel
            var framer = try NativeCanonicalLineFramer(
                maximumBytes: NativeCodexUIProtocol.maximumEventBytes
            )
            while !Task.isCancelled {
                let chunk = try await Task.detached {
                    try connection.read(maximumBytes: 16 * 1_024)
                }.value
                guard let chunk else {
                    try framer.requireEmptyAtEOF()
                    try await channel.requireClosedAtEOF()
                    return
                }
                for line in try framer.receive(chunk) {
                    let event = try await channel.decode(line)
                    apply(event)
                }
            }
        } catch is CancellationError {
            channel?.forceClose()
        } catch {
            channel?.forceClose()
            self.error = error.localizedDescription
            status = "Typed channel rejected"
        }
    }

    @MainActor private func apply(_ event: NativeCodexUIEvent) {
        switch event {
        case .ready:
            ready = true
            startNewRenderedMessage = true
            status = "Runtime-qualified typed channel active"
        case .textDelta(let channel, let text):
            guard !text.isEmpty else { return }
            appendRenderedText(channel: channel, text: text)
        case .turnStarted:
            turnRunning = true
            startNewRenderedMessage = true
            status = "Typed turn running"
        case .turnCompleted:
            turnRunning = false
            startNewRenderedMessage = true
            status = "Qualified typed turn complete"
        case .turnInterrupted:
            turnRunning = false
            startNewRenderedMessage = true
            status = "Typed turn interrupted"
        case .activity:
            status = "Codex is working within the exact session authority…"
        case .closed:
            ready = false
            turnRunning = false
            closing = true
            status = "Typed channel closed; teardown verified by the broker"
            channel?.forceClose()
            dismiss()
        }
    }

    @MainActor private func appendRenderedText(channel: String, text: String) {
        let addedBytes = text.lengthOfBytes(using: .utf8)
        var appendToLast = !startNewRenderedMessage
            && messages.last?.channel == channel
            && (messages.last?.text.lengthOfBytes(using: .utf8) ?? 0)
                + addedBytes <= Self.maximumRenderedMessageBytes

        while !messages.isEmpty,
              renderedBytes + addedBytes > Self.maximumRenderedBytes
                || (!appendToLast
                    && messages.count >= Self.maximumRenderedMessages) {
            let removed = messages.removeFirst()
            renderedBytes -= removed.text.lengthOfBytes(using: .utf8)
            earlierOutputOmitted = true
            if messages.isEmpty { appendToLast = false }
        }

        if appendToLast, !messages.isEmpty {
            messages[messages.count - 1].text += text
        } else {
            messages.append(.init(channel: channel, text: text))
        }
        renderedBytes += addedBytes
        startNewRenderedMessage = false
    }

    @MainActor private func sendTurn() async {
        guard canSend, let channel else { return }
        let value = prompt
        prompt = ""
        error = nil
        do { try await channel.turn(value) }
        catch {
            self.error = error.localizedDescription
            channel.forceClose()
        }
    }

    @MainActor private func interrupt() async {
        guard let channel, turnRunning, !closing else { return }
        error = nil
        do { try await channel.interrupt() }
        catch {
            self.error = error.localizedDescription
            channel.forceClose()
        }
    }

    @MainActor private func requestClose() async {
        guard let channel, ready, !closing else { return }
        closing = true
        status = "Waiting for sanitized final tail and closed event…"
        error = nil
        do { try await channel.requestClose() }
        catch {
            self.error = error.localizedDescription
            channel.forceClose()
        }
    }

    @MainActor private func prepareStop() async {
        guard !stopping else { return }
        stopping = true
        error = nil
        do {
            let request = try NativeSessionPlanRequest(
                action: .stop,
                sessionID: plan.sessionID,
                stackID: plan.stackID,
                stackSHA256: plan.stackSHA256,
                catalogSHA256: plan.catalogSHA256,
                sourceID: plan.sourceID,
                resumeSessionID: nil,
                leaseProfileID: nil
            )
            pendingStopPlan = try await Task.detached {
                try NativeSessionPlanBrokerClient().plan(request)
            }.value
        } catch { self.error = error.localizedDescription }
        stopping = false
    }

    @MainActor private func authorizeStop(_ stopPlan: NativeSessionPlan) async {
        guard !stopping else { return }
        pendingStopPlan = nil
        stopping = true
        error = nil
        do {
            let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)
            _ = try await Task.detached {
                try client.authorizeNativeSessionStop(stopPlan)
            }.value
            status = "Protected stop verified; process, projection, and egress are absent."
            channel?.forceClose()
            dismiss()
        } catch { self.error = error.localizedDescription }
        stopping = false
    }
}
