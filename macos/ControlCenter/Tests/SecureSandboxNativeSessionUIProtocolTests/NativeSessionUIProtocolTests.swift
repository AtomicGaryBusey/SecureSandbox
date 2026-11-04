import Darwin
import Foundation
import Testing
@testable import SecureSandboxNativeSessionUIProtocol

private let authority = String(repeating: "a", count: 64)
private let lease = String(repeating: "b", count: 64)
private let generation = String(repeating: "c", count: 64)
private let executable = String(repeating: "d", count: 64)
private let sessionDigest = String(repeating: "e", count: 64)

private func nullable(_ value: String?) -> Any {
    if let value { return value }
    return NSNull()
}

private func event(
    sequence: Int, name: String, payload: [String: Any], extra: [String: Any] = [:]
) throws -> Data {
    var body: [String: Any] = [
        "schema": NativeCodexUIProtocol.eventSchema,
        "sequence": sequence,
        "runtime_authority_sha256": authority,
        "session_lease_sha256": lease,
        "event": name,
        "payload": payload,
    ]
    body.merge(extra) { _, new in new }
    body["event_sha256"] = try CanonicalNativeJSON.digest(body)
    return try CanonicalNativeJSON.encodeLine(body)
}

private func protocolState() throws -> NativeCodexUIProtocol {
    try NativeCodexUIProtocol(
        runtimeAuthoritySHA256: authority,
        sessionLeaseSHA256: lease,
        expectedSessionIDSHA256: sessionDigest,
        expectedModelID: "gpt-6.1-sol",
        expectedReasoningEffort: "high",
        expectedHarnessGenerationID: generation,
        expectedHarnessExecutableSHA256: executable,
        expectedSessionExpiresAt: 4_000
    )
}

private func readyPayload() -> [String: Any] {
    [
        "session_id_sha256": sessionDigest,
        "harness_generation_id": generation,
        "harness_executable_sha256": executable,
        "model_id": "gpt-6.1-sol",
        "reasoning_effort": "high",
        "cyber_access_program": "daybreakBlue",
        "qualification_attestation_sha256": String(repeating: "f", count: 64),
        "session_lease_sha256": lease,
        "session_expires_at": 4_000,
    ]
}

private func digested(
    schema: String, body: [String: Any], digestKey: String
) throws -> [String: Any] {
    var value = body
    value["schema"] = schema
    value[digestKey] = try CanonicalNativeJSON.digest(body)
    return value
}

private func sessionReply(
    request: NativeSessionPlanRequest, extraPlan: [String: Any] = [:]
) throws -> Data {
    let nativeBody: [String: Any] = [
        "mode": "native-vendor-harness-model-stack",
        "stack_id": request.stackID,
        "stack_sha256": request.stackSHA256,
        "vendor_id": "openai",
        "harness_id": "codex-cli",
        "harness_generation_id": generation,
        "harness_adapter_id": "codex-native-oauth-v1",
        "authentication_mode": "openai-chatgpt-subscription-oauth",
        "credential_custody": "secure-enclave-host",
        "account_subject_sha256": String(repeating: "1", count: 64),
        "workspace_sha256": String(repeating: "2", count: 64),
        "program_id": "daybreak",
        "program_requirements_version": "2026-10-31",
        "program_tier": "daybreak-blue",
        "model_id": "gpt-6.1-sol",
        "model_settings_sha256": String(repeating: "3", count: 64),
        "network_policy_id": "openai-codex-native-oauth-v1",
    ]
    let native = try digested(
        schema: "secure-sandbox-native-stack-runtime-binding-v1",
        body: nativeBody, digestKey: "binding_sha256"
    )
    let modelBody: [String: Any] = [
        "authority": native,
        "mode": "native-vendor-harness-model-stack",
    ]
    let model = try digested(
        schema: "secure-sandbox-model-stack-runtime-binding-v1",
        body: modelBody, digestKey: "binding_sha256"
    )
    let contextBody: [String: Any] = [
        "session_id": request.sessionID,
        "source_id": NSNull(),
        "source_manifest_sha256": NSNull(),
        "persona_sha256": String(repeating: "4", count: 64),
        "tool_catalog_sha256": String(repeating: "5", count: 64),
        "extension_set_sha256": String(repeating: "6", count: 64),
    ]
    let context = try digested(
        schema: "secure-sandbox-session-context-binding-v1",
        body: contextBody, digestKey: "binding_sha256"
    )
    let harnessBody: [String: Any] = [
        "harness_id": "codex-cli",
        "harness_generation_id": generation,
        "harness_manifest_sha256": String(repeating: "7", count: 64),
        "harness_executable_sha256": executable,
        "harness_inventory_sha256": String(repeating: "8", count: 64),
        "harness_adapter_id": "codex-native-oauth-v1",
        "harness_adapter_sha256": String(repeating: "9", count: 64),
    ]
    let harness = try digested(
        schema: "secure-sandbox-harness-runtime-binding-v1",
        body: harnessBody, digestKey: "binding_sha256"
    )
    let runtimeBody: [String: Any] = [
        "model_stack_binding": model,
        "session_context_binding": context,
        "harness_binding": harness,
    ]
    let runtime = try digested(
        schema: "secure-sandbox-runtime-authority-v1",
        body: runtimeBody, digestKey: "binding_sha256"
    )
    var planBody: [String: Any] = [
        "action": request.action.rawValue,
        "action_id": request.actionID,
        "session_id": request.sessionID,
        "stack_id": request.stackID,
        "stack_sha256": request.stackSHA256,
        "catalog_sha256": request.catalogSHA256,
        "status_sha256": String(repeating: "0", count: 64),
        "runtime_authority": runtime,
        "runtime_authority_sha256": runtime["binding_sha256"]!,
        "source_id": NSNull(),
        "source_manifest_sha256": NSNull(),
        "resume_session_id": NSNull(),
        "lease_profile_id": nullable(request.leaseProfileID),
        "created_at": 1_000,
        "expires_at": 1_180,
    ]
    planBody.merge(extraPlan) { _, new in new }
    let plan = try digested(
        schema: NativeSessionPlanProtocol.planSchema,
        body: planBody, digestKey: "plan_sha256"
    )
    let replyBody: [String: Any] = [
        "action_id": request.actionID,
        "request_sha256": request.requestSHA256,
        "plan": plan,
    ]
    var reply = replyBody
    reply["schema"] = NativeSessionPlanProtocol.replySchema
    reply["reply_sha256"] = try CanonicalNativeJSON.digest(replyBody)
    return try CanonicalNativeJSON.encodeLine(reply)
}

@Suite(.serialized) struct NativeSessionUIProtocolTests {
    @Test func sessionPlanPinsRequestReplyAndEveryRuntimeAuthorityLayer() throws {
        let request = try NativeSessionPlanRequest(
            action: .start,
            actionID: "11111111-1111-4111-8111-111111111111",
            sessionID: "22222222-2222-4222-8222-222222222222",
            stackID: "openai-codex-daybreak",
            stackSHA256: String(repeating: "a", count: 64),
            catalogSHA256: String(repeating: "b", count: 64),
            sourceID: nil, resumeSessionID: nil,
            leaseProfileID: "interactive"
        )
        let plan = try NativeSessionPlanProtocol.decodeReply(
            sessionReply(request: request), request: request, now: 1_100
        )
        #expect(plan.authority.vendorID == "openai")
        #expect(plan.authority.modelID == "gpt-6.1-sol")
        #expect(plan.authority.harnessExecutableSHA256 == executable)
        #expect(plan.expectedSessionIDSHA256
            == "b454f82c5857ebabf342b7258e5cf7def78b7cd975814119462973de9a38df10")

        let changed = try NativeSessionPlanRequest(
            action: .start,
            actionID: "33333333-3333-4333-8333-333333333333",
            sessionID: request.sessionID,
            stackID: request.stackID,
            stackSHA256: request.stackSHA256,
            catalogSHA256: request.catalogSHA256,
            sourceID: nil, resumeSessionID: nil,
            leaseProfileID: "interactive"
        )
        #expect(throws: (any Error).self) {
            try NativeSessionPlanProtocol.decodeReply(
                sessionReply(request: request), request: changed, now: 1_100
            )
        }
        #expect(throws: (any Error).self) {
            try NativeSessionPlanProtocol.decodeReply(
                sessionReply(
                    request: request,
                    extraPlan: ["raw_provider_identifier": "forbidden"]
                ),
                request: request, now: 1_100
            )
        }
    }

    @Test func codexUIHandleIsDistinctExactOneShotTypedClaim() throws {
        let request = try NativeSessionPlanRequest(
            action: .start,
            actionID: "11111111-1111-4111-8111-111111111111",
            sessionID: "22222222-2222-4222-8222-222222222222",
            stackID: "openai-codex-daybreak",
            stackSHA256: String(repeating: "a", count: 64),
            catalogSHA256: String(repeating: "b", count: 64),
            sourceID: nil, resumeSessionID: nil,
            leaseProfileID: "interactive"
        )
        let plan = try NativeSessionPlanProtocol.decodeReply(
            sessionReply(request: request), request: request, now: 1_100
        )
        let body: [String: Any] = [
            "expires_at": 1_160,
            "handle_id": "33333333-3333-4333-8333-333333333333",
            "handle_sha256": String(repeating: "4", count: 64),
            "kind": "codex-typed-ui",
            "operation_id": plan.actionID,
            "runtime_authority_sha256": plan.runtimeAuthoritySHA256,
            "session_expires_at": 4_000,
            "session_id": plan.sessionID,
            "session_lease_sha256": String(repeating: "5", count: 64),
        ]
        var publicHandle = body
        publicHandle["schema"] = NativeCodexUIHandle.publicSchema
        publicHandle["reply_sha256"] = try CanonicalNativeJSON.digest(body)
        let handle = try NativeCodexUIHandle.decode(
            CanonicalNativeJSON.encodeLine(publicHandle), plan: plan, now: 1_100
        )
        let claim = try CanonicalNativeJSON.parseLine(
            handle.claimData(plan: plan, now: 1_100), maximumBytes: 32 * 1_024
        )
        #expect(Set(claim.keys)
            == ["schema", "handle_id", "handle_sha256", "request_sha256"])
        #expect(claim["schema"] as? String == NativeCodexUIHandle.claimSchema)

        publicHandle["terminal_kind"] = "forbidden"
        #expect(throws: (any Error).self) {
            try NativeCodexUIHandle.decode(
                CanonicalNativeJSON.encodeLine(publicHandle), plan: plan, now: 1_100
            )
        }
    }

    @Test func streamHeaderIsExactSplitSafeAndNeverReachesPayload() throws {
        var gate = try NativeStreamHeaderGate(expectedASCII: "SSTERM1\n")
        #expect(try gate.receive(Data("SST".utf8)).isEmpty)
        #expect(try gate.receive(Data("ERM1\nhello".utf8)) == Data("hello".utf8))
        #expect(gate.isOpen)
        #expect(try gate.receive(Data(" world".utf8)) == Data(" world".utf8))

        var hostile = try NativeStreamHeaderGate(expectedASCII: "SSTERM1\n")
        #expect(throws: (any Error).self) {
            try hostile.receive(Data("SSTERM2\n".utf8))
        }
        var truncated = try NativeStreamHeaderGate(expectedASCII: "SSTERM1\n")
        _ = try truncated.receive(Data("SST".utf8))
        #expect(throws: (any Error).self) { try truncated.requireOpenAtEOF() }

        var typedFramer = try NativeCanonicalLineFramer(
            maximumBytes: NativeCodexUIProtocol.maximumEventBytes
        )
        let typedLines = try typedFramer.receive(Data("SSSTRM1\n".utf8))
        var typedProtocol = try protocolState()
        #expect(throws: (any Error).self) {
            try typedProtocol.decodeEvent(try #require(typedLines.first))
        }
    }

    @Test func brokerPeerIdentityUsesKernelCredentialsAndRejectsNonRoot() throws {
        var descriptors: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
        defer {
            for descriptor in descriptors where descriptor >= 0 {
                Darwin.close(descriptor)
            }
        }
        try NativeBrokerPeerIdentity.validate(
            descriptors[0], expectedUID: geteuid(), expectedGID: getegid()
        )
        if geteuid() != 0 || getegid() != 0 {
            #expect(throws: (any Error).self) {
                try NativeBrokerPeerIdentity.requireRoot(descriptors[0])
            }
        }
    }

    @Test func borrowedDescriptorSurvivesOriginalNumberReuse() throws {
        var sockets: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
        let original = sockets[0]
        let peer = sockets[1]
        let borrowed = try NativeDescriptorBorrow.duplicateCloseOnExec(original)
        sockets[0] = -1
        defer {
            Darwin.close(borrowed)
            for descriptor in sockets where descriptor >= 0 {
                Darwin.close(descriptor)
            }
        }

        Darwin.close(original)
        var replacements: [Int32] = []
        defer { replacements.forEach { Darwin.close($0) } }
        while replacements.count < 256 {
            let replacement = Darwin.open("/dev/null", O_RDWR | O_CLOEXEC)
            #expect(replacement >= 0)
            replacements.append(replacement)
            if replacement == original { break }
            #expect(replacement < original)
        }
        #expect(replacements.last == original)

        let sent = Data("typed-command".utf8)
        let written = sent.withUnsafeBytes {
            Darwin.write(borrowed, $0.baseAddress!, sent.count)
        }
        #expect(written == sent.count)
        var received = [UInt8](repeating: 0, count: sent.count)
        #expect(Darwin.read(peer, &received, received.count) == sent.count)
        #expect(Data(received) == sent)
    }

    @Test func lineFramerRejectsNULOversizeAndTruncatedEOF() throws {
        var framer = try NativeCanonicalLineFramer(maximumBytes: 32)
        #expect(try framer.receive(Data("{\"a\":".utf8)).isEmpty)
        let lines = try framer.receive(Data("1}\n{\"b\":2}\n".utf8))
        #expect(lines == [Data("{\"a\":1}\n".utf8), Data("{\"b\":2}\n".utf8)])
        try framer.requireEmptyAtEOF()

        var nul = try NativeCanonicalLineFramer(maximumBytes: 32)
        #expect(throws: (any Error).self) { try nul.receive(Data([0])) }
        var oversized = try NativeCanonicalLineFramer(maximumBytes: 4)
        #expect(throws: (any Error).self) { try oversized.receive(Data("12345".utf8)) }
        var truncated = try NativeCanonicalLineFramer(maximumBytes: 32)
        _ = try truncated.receive(Data("{}".utf8))
        #expect(throws: (any Error).self) { try truncated.requireEmptyAtEOF() }
    }

    @Test func canonicalJSONMatchesPythonEscapesAndRejectsNonCanonicalInput() throws {
        let data = try CanonicalNativeJSON.encodeLine([
            "emoji": "😀", "line": "a\nb", "value": 2, "yes": true,
        ])
        #expect(String(decoding: data, as: UTF8.self)
            == #"{"emoji":"\ud83d\ude00","line":"a\nb","value":2,"yes":true}"# + "\n")
        #expect(try CanonicalNativeJSON.parseLine(data, maximumBytes: 1_024)["value"] as? Int == 2)
        #expect(throws: (any Error).self) {
            try CanonicalNativeJSON.parseLine(
                Data(#"{"yes": true}"#.utf8) + Data([0x0a]), maximumBytes: 1_024
            )
        }
    }

    @Test func terminalHandleRequiresExactKindDigestFreshnessAndFields() throws {
        let now = 1_000
        let body: [String: Any] = [
            "expires_at": now + 60,
            "handle_id": "11111111-1111-4111-8111-111111111111",
            "handle_sha256": String(repeating: "1", count: 64),
            "kind": "claude-login",
            "operation_id": "22222222-2222-4222-8222-222222222222",
            "session_id": "33333333-3333-4333-8333-333333333333",
        ]
        let data = try CanonicalNativeJSON.encodeLine(body.merging([
            "schema": NativeTerminalHandle.publicSchema,
            "reply_sha256": try CanonicalNativeJSON.digest(body),
        ]) { _, new in new })
        let handle = try NativeTerminalHandle.decode(data, now: now)
        let claim = try CanonicalNativeJSON.parseLine(
            handle.claimData(expectedKind: "claude-login"), maximumBytes: 32 * 1_024
        )
        #expect(claim["kind"] as? String == "claude-login")
        #expect(throws: (any Error).self) {
            try handle.claimData(expectedKind: "claude-session")
        }
        var extra = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        extra["token"] = "forbidden"
        #expect(throws: (any Error).self) {
            try NativeTerminalHandle.decode(
                CanonicalNativeJSON.encodeLine(extra), now: now
            )
        }
        #expect(throws: (any Error).self) {
            try NativeTerminalHandle.decode(data, now: now + 60)
        }
    }

    @Test func codexChannelRejectsCommandsBeforeReadyAndPinsEveryIdentity() throws {
        var value = try protocolState()
        #expect(throws: (any Error).self) { try value.turn("hello") }
        let decoded = try value.decodeEvent(try event(
            sequence: 1, name: "ready", payload: readyPayload()
        ))
        guard case .ready(let ready) = decoded else { Issue.record("expected ready"); return }
        #expect(ready.modelID == "gpt-6.1-sol")
        let command = try CanonicalNativeJSON.parseLine(
            value.turn("hello 😀"), maximumBytes: NativeCodexUIProtocol.maximumCommandBytes
        )
        #expect(command["operation"] as? String == "turn")
        #expect(command["sequence"] as? Int == 1)
        #expect(command["runtime_authority_sha256"] as? String == authority)
        #expect(throws: (any Error).self) {
            try value.turn("Authorization: Bearer secret")
        }
        #expect(throws: (any Error).self) {
            try value.turn("misleading \u{202E}text")
        }
    }

    @Test func codexEventsRejectExtraFieldsWrongSequenceReplayAndUnknownKinds() throws {
        var value = try protocolState()
        #expect(throws: (any Error).self) {
            try value.decodeEvent(try event(sequence: 1, name: "turn_started", payload: [:]))
        }
        _ = try value.decodeEvent(try event(
            sequence: 1, name: "ready", payload: readyPayload()
        ))
        #expect(throws: (any Error).self) {
            try value.decodeEvent(try event(
                sequence: 2, name: "ready", payload: readyPayload()
            ))
        }

        var extraReady = readyPayload()
        extraReady["raw_json"] = "forbidden"
        var other = try protocolState()
        #expect(throws: (any Error).self) {
            try other.decodeEvent(try event(sequence: 1, name: "ready", payload: extraReady))
        }

        var third = try protocolState()
        _ = try third.decodeEvent(try event(
            sequence: 1, name: "ready", payload: readyPayload()
        ))
        #expect(throws: (any Error).self) {
            try third.decodeEvent(try event(sequence: 3, name: "turn_started", payload: [:]))
        }
        #expect(throws: (any Error).self) {
            try third.decodeEvent(try event(sequence: 2, name: "raw_json", payload: [:]))
        }
    }

    @Test func codexTypedEventsAdmitOnlySafeTextAndQualifiedCompletion() throws {
        var value = try protocolState()
        _ = try value.decodeEvent(try event(
            sequence: 1, name: "ready", payload: readyPayload()
        ))
        #expect(try value.decodeEvent(try event(
            sequence: 2, name: "text_delta",
            payload: ["channel": "assistant", "text": "safe output"]
        )) == .textDelta(channel: "assistant", text: "safe output"))
        #expect(try value.decodeEvent(try event(
            sequence: 3, name: "turn_completed",
            payload: ["qualified": true, "completion_sha256": String(repeating: "9", count: 64)]
        )) == .turnCompleted(completionSHA256: String(repeating: "9", count: 64)))
        #expect(throws: (any Error).self) {
            try value.decodeEvent(try event(
                sequence: 4, name: "text_delta",
                payload: ["channel": "assistant", "text": "access_token leaked"]
            ))
        }
    }

    @Test func codexReadyPinsSessionAndCloseAcceptsSafeTailUntilServerClosed() throws {
        var wrong = try protocolState()
        var wrongReady = readyPayload()
        wrongReady["session_id_sha256"] = String(repeating: "0", count: 64)
        #expect(throws: (any Error).self) {
            try wrong.decodeEvent(try event(sequence: 1, name: "ready", payload: wrongReady))
        }

        var value = try protocolState()
        _ = try value.decodeEvent(try event(
            sequence: 1, name: "ready", payload: readyPayload()
        ))
        #expect(throws: (any Error).self) { try value.requireClosedAtEOF() }
        #expect(throws: (any Error).self) {
            try value.decodeEvent(try event(
                sequence: 2, name: "closed", payload: ["reason": "operator_close"]
            ))
        }
        _ = try value.close()
        #expect(throws: (any Error).self) { try value.interrupt() }
        #expect(try value.decodeEvent(try event(
            sequence: 2, name: "text_delta",
            payload: ["channel": "assistant", "text": "final safe tail"]
        )) == .textDelta(channel: "assistant", text: "final safe tail"))
        #expect(try value.decodeEvent(try event(
            sequence: 3, name: "closed", payload: ["reason": "operator_close"]
        )) == .closed(reason: "operator_close"))
        try value.requireClosedAtEOF()
        #expect(throws: (any Error).self) {
            try value.decodeEvent(try event(
                sequence: 4, name: "text_delta",
                payload: ["channel": "assistant", "text": "too late"]
            ))
        }
    }
}
