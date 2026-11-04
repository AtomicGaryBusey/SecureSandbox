import Foundation

public enum NativeCodexUIEvent: Equatable, Sendable {
    case ready(NativeCodexReady)
    case textDelta(channel: String, text: String)
    case turnStarted
    case turnCompleted(completionSHA256: String)
    case turnInterrupted
    case activity(code: String)
    case closed(reason: String)
}

public struct NativeCodexReady: Equatable, Sendable {
    public let sessionIDSHA256: String
    public let harnessGenerationID: String
    public let harnessExecutableSHA256: String
    public let modelID: String
    public let reasoningEffort: String
    public let qualificationAttestationSHA256: String
    public let sessionExpiresAt: Int
}

public struct NativeCodexUIProtocol: Sendable {
    public static let commandSchema = "secure-sandbox-native-codex-command-v1"
    public static let eventSchema = "secure-sandbox-native-codex-event-v1"
    public static let cyberAccessProgram = "daybreakBlue"
    public static let maximumCommandBytes = 65_536 + 4_096
    public static let maximumEventBytes = 48 * 1_024

    public let runtimeAuthoritySHA256: String
    public let sessionLeaseSHA256: String
    public let expectedSessionIDSHA256: String
    public let expectedModelID: String
    public let expectedReasoningEffort: String
    public let expectedHarnessGenerationID: String
    public let expectedHarnessExecutableSHA256: String
    public let expectedSessionExpiresAt: Int
    private var commandSequence = 1
    private var eventSequence = 1
    private var ready = false
    private var closeRequested = false
    private var closed = false

    public init(
        runtimeAuthoritySHA256: String,
        sessionLeaseSHA256: String,
        expectedSessionIDSHA256: String,
        expectedModelID: String,
        expectedReasoningEffort: String,
        expectedHarnessGenerationID: String,
        expectedHarnessExecutableSHA256: String,
        expectedSessionExpiresAt: Int
    ) throws {
        guard [runtimeAuthoritySHA256, sessionLeaseSHA256, expectedSessionIDSHA256,
               expectedHarnessGenerationID, expectedHarnessExecutableSHA256]
            .allSatisfy({ CanonicalNativeJSON.isSHA256($0) }),
              expectedModelID.range(
                of: #"^[a-z0-9][a-z0-9._-]{0,63}$"#,
                options: .regularExpression
              ) != nil,
              ["low", "medium", "high", "xhigh"].contains(expectedReasoningEffort),
              expectedSessionExpiresAt > 0 else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_identity_invalid")
        }
        self.runtimeAuthoritySHA256 = runtimeAuthoritySHA256
        self.sessionLeaseSHA256 = sessionLeaseSHA256
        self.expectedSessionIDSHA256 = expectedSessionIDSHA256
        self.expectedModelID = expectedModelID
        self.expectedReasoningEffort = expectedReasoningEffort
        self.expectedHarnessGenerationID = expectedHarnessGenerationID
        self.expectedHarnessExecutableSHA256 = expectedHarnessExecutableSHA256
        self.expectedSessionExpiresAt = expectedSessionExpiresAt
    }

    public mutating func turn(_ text: String) throws -> Data {
        try command(operation: "turn", payload: ["text": try safeText(
            text, maximum: 65_536, allowEmpty: false
        )])
    }

    public mutating func interrupt() throws -> Data {
        try command(operation: "interrupt", payload: [:])
    }

    public mutating func close() throws -> Data {
        let data = try command(operation: "close", payload: [:])
        closeRequested = true
        return data
    }

    public mutating func decodeEvent(_ data: Data) throws -> NativeCodexUIEvent {
        guard !closed else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_event_after_close")
        }
        let value = try CanonicalNativeJSON.parseLine(data, maximumBytes: Self.maximumEventBytes)
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "sequence", "runtime_authority_sha256",
            "session_lease_sha256", "event", "payload", "event_sha256",
        ], "native_codex_ui_event_fields_invalid")
        guard value["schema"] as? String == Self.eventSchema,
              CanonicalNativeJSON.exactInteger(value["sequence"]) == eventSequence,
              value["runtime_authority_sha256"] as? String == runtimeAuthoritySHA256,
              value["session_lease_sha256"] as? String == sessionLeaseSHA256,
              let event = value["event"] as? String,
              let payload = value["payload"] as? [String: Any],
              let supplied = value["event_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(supplied) else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_event_identity_invalid")
        }
        var body = value
        body.removeValue(forKey: "event_sha256")
        guard supplied == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_event_digest_mismatch")
        }
        let decoded = try decodePayload(event: event, payload: payload)
        eventSequence += 1
        return decoded
    }

    public func requireClosedAtEOF() throws {
        guard closed else {
            throw NativeSessionProtocolError.rejected(
                "native_codex_ui_closed_event_missing"
            )
        }
    }

    private mutating func command(operation: String, payload: [String: Any]) throws -> Data {
        guard ready, !closeRequested, !closed else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_command_not_ready")
        }
        let body: [String: Any] = [
            "schema": Self.commandSchema,
            "sequence": commandSequence,
            "runtime_authority_sha256": runtimeAuthoritySHA256,
            "operation": operation,
            "payload": payload,
        ]
        let data = try CanonicalNativeJSON.encodeLine(
            body.merging(["command_sha256": try CanonicalNativeJSON.digest(body)]) {
                current, _ in current
            }
        )
        guard data.count <= Self.maximumCommandBytes else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_command_oversized")
        }
        commandSequence += 1
        return data
    }

    private mutating func decodePayload(
        event: String, payload: [String: Any]
    ) throws -> NativeCodexUIEvent {
        if !ready {
            guard event == "ready", eventSequence == 1 else {
                throw NativeSessionProtocolError.rejected("native_codex_ui_ready_missing")
            }
            try CanonicalNativeJSON.requireKeys(payload, [
                "session_id_sha256", "harness_generation_id",
                "harness_executable_sha256", "model_id", "reasoning_effort",
                "cyber_access_program", "qualification_attestation_sha256",
                "session_lease_sha256", "session_expires_at",
            ], "native_codex_ui_ready_fields_invalid")
            guard payload["session_id_sha256"] as? String == expectedSessionIDSHA256,
                  payload["harness_generation_id"] as? String == expectedHarnessGenerationID,
                  payload["harness_executable_sha256"] as? String
                    == expectedHarnessExecutableSHA256,
                  payload["model_id"] as? String == expectedModelID,
                  payload["reasoning_effort"] as? String == expectedReasoningEffort,
                  payload["cyber_access_program"] as? String == Self.cyberAccessProgram,
                  let qualification = payload["qualification_attestation_sha256"] as? String,
                  CanonicalNativeJSON.isSHA256(qualification),
                  payload["session_lease_sha256"] as? String == sessionLeaseSHA256,
                  CanonicalNativeJSON.exactInteger(payload["session_expires_at"])
                    == expectedSessionExpiresAt else {
                throw NativeSessionProtocolError.rejected("native_codex_ui_ready_mismatch")
            }
            ready = true
            return .ready(.init(
                sessionIDSHA256: expectedSessionIDSHA256,
                harnessGenerationID: expectedHarnessGenerationID,
                harnessExecutableSHA256: expectedHarnessExecutableSHA256,
                modelID: expectedModelID,
                reasoningEffort: expectedReasoningEffort,
                qualificationAttestationSHA256: qualification,
                sessionExpiresAt: expectedSessionExpiresAt
            ))
        }
        switch event {
        case "text_delta":
            try CanonicalNativeJSON.requireKeys(
                payload, ["channel", "text"], "native_codex_ui_text_fields_invalid"
            )
            guard let channel = payload["channel"] as? String,
                  ["assistant", "tool"].contains(channel),
                  let text = payload["text"] as? String else {
                throw NativeSessionProtocolError.rejected("native_codex_ui_text_invalid")
            }
            return .textDelta(
                channel: channel,
                text: try safeText(text, maximum: 32 * 1_024, allowEmpty: true)
            )
        case "turn_started":
            try requireEmpty(payload); return .turnStarted
        case "turn_completed":
            try CanonicalNativeJSON.requireKeys(
                payload, ["qualified", "completion_sha256"],
                "native_codex_ui_completion_fields_invalid"
            )
            guard payload["qualified"] as? Bool == true,
                  let digest = payload["completion_sha256"] as? String,
                  CanonicalNativeJSON.isSHA256(digest) else {
                throw NativeSessionProtocolError.rejected("native_codex_ui_completion_invalid")
            }
            return .turnCompleted(completionSHA256: digest)
        case "turn_interrupted":
            try requireEmpty(payload); return .turnInterrupted
        case "activity":
            try CanonicalNativeJSON.requireKeys(
                payload, ["code"], "native_codex_ui_activity_fields_invalid"
            )
            guard let code = payload["code"] as? String,
                  code.range(of: #"^[a-z][a-zA-Z0-9_]{0,95}$"#,
                             options: .regularExpression) != nil else {
                throw NativeSessionProtocolError.rejected("native_codex_ui_activity_invalid")
            }
            return .activity(code: code)
        case "closed":
            try CanonicalNativeJSON.requireKeys(
                payload, ["reason"], "native_codex_ui_closed_fields_invalid"
            )
            guard closeRequested,
                  let reason = payload["reason"] as? String,
                  ["operator_close"].contains(reason) else {
                throw NativeSessionProtocolError.rejected("native_codex_ui_closed_invalid")
            }
            closed = true
            return .closed(reason: reason)
        case "ready":
            throw NativeSessionProtocolError.rejected("native_codex_ui_ready_replayed")
        default:
            throw NativeSessionProtocolError.rejected("native_codex_ui_event_unknown")
        }
    }

    private func requireEmpty(_ value: [String: Any]) throws {
        guard value.isEmpty else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_payload_not_empty")
        }
    }

    private func safeText(
        _ value: String, maximum: Int, allowEmpty: Bool
    ) throws -> String {
        let encoded = Data(value.utf8)
        let forbiddenMarkers = [
            "access_token", "openai_api_key", "openai_access_token",
            "openai_refresh_token", "chatgpt_access_token",
            "chatgpt_refresh_token", "authorization: bearer",
        ]
        guard encoded.count <= maximum, allowEmpty || !encoded.isEmpty,
              value.unicodeScalars.allSatisfy({ scalar in
                  (![.control, .format].contains(
                      scalar.properties.generalCategory
                  )) || scalar.value == 0x0a || scalar.value == 0x09
              }),
              !forbiddenMarkers.contains(where: { value.lowercased().contains($0) }) else {
            throw NativeSessionProtocolError.rejected("native_codex_ui_text_invalid")
        }
        return value
    }
}
