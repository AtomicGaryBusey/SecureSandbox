import AppKit
#if canImport(AuthorizationCore)
import AuthorizationCore
#endif
import Darwin
import Foundation
import LocalAuthentication
import Security

private let passwordFallbackExit: Int32 = 10
private let cancelledExit: Int32 = 20
private let rejectedExit: Int32 = 21
private let responseLimit = 16 * 1024 * 1024

private final class EvaluationState: @unchecked Sendable {
    private let lock = NSLock()
    private var value: (Bool, Int) = (false, -1)

    func store(success: Bool, error: Error?) {
        lock.lock()
        value = (success, (error as NSError?)?.code ?? -1)
        lock.unlock()
    }

    func load() -> (Bool, Int) {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func fail(_ message: String, code: Int32 = rejectedExit) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

private func argument(_ name: String) -> String {
    guard let index = CommandLine.arguments.firstIndex(of: name),
          index + 1 < CommandLine.arguments.count else {
        fail("missing_argument:\(name)")
    }
    return CommandLine.arguments[index + 1]
}

private func readRequest(path: String) throws -> Data {
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw CocoaError(.fileReadNoSuchFile) }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_nlink == 1,
          info.st_uid == getuid(),
          (info.st_mode & 0o777) == 0o600,
          info.st_size <= AuthorizationRequest.maximumBytes else {
        throw AuthorizationDocumentError.invalidField("request_file")
    }
    var result = Data(count: Int(info.st_size))
    var offset = 0
    while offset < result.count {
        let count = result.withUnsafeMutableBytes { buffer in
            Darwin.read(descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
        }
        guard count > 0 else { throw CocoaError(.fileReadUnknown) }
        offset += count
    }
    var trailing: UInt8 = 0
    guard Darwin.read(descriptor, &trailing, 1) == 0 else {
        throw AuthorizationDocumentError.tooLarge
    }
    return result
}

private func writeResult(
    path: String, status: Int32, requestID: String, requestSHA256: String
) throws {
    let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    let value: [String: Any] = [
        "request_id": requestID,
        "request_sha256": requestSHA256,
        "schema": "secure-sandbox-touchid-ui-result-v1",
        "status": Int(status),
    ]
    let encoded = try JSONSerialization.data(
        withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]
    ) + Data([0x0a])
    try writeAll(descriptor, encoded)
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
}

@MainActor
private func approvalAlert(for request: AuthorizationRequest, authority: String) -> NSAlert {
    let alert = NSAlert()
    alert.alertStyle = .critical
    alert.messageText = "SecureSandbox Authorization"
    alert.informativeText = "Approve only if this matches the agent conversation you intend to authorize."
    alert.addButton(withTitle: "Approve with Touch ID")
    if request.requiresBiometricApproval {
        alert.addButton(withTitle: "Cancel")
    } else {
        alert.addButton(withTitle: "Use Administrator Password")
        alert.addButton(withTitle: "Cancel")
    }
    alert.buttons.last?.keyEquivalent = "\u{1b}"

    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 620, height: 310))
    scroll.hasVerticalScroller = true
    scroll.borderType = .bezelBorder
    let text = NSTextView(frame: scroll.bounds)
    text.isEditable = false
    text.isSelectable = true
    text.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    text.string = request.displayText + "\n\nApproval authority:\n" + authority
    text.textContainerInset = NSSize(width: 8, height: 8)
    scroll.documentView = text
    alert.accessoryView = scroll
    return alert
}

@MainActor
private final class AuthorizationApplicationDelegate: NSObject, NSApplicationDelegate {
    private let request: AuthorizationRequest
    private let authority: String
    private(set) var response: NSApplication.ModalResponse?
    private var presentedAlert: NSAlert?

    init(request: AuthorizationRequest, authority: String) {
        self.request = request
        self.authority = authority
    }

    @objc private func expireAuthorization(_ timer: Timer) {
        guard response == nil, let alert = presentedAlert else { return }
        NSApplication.shared.stopModal(withCode: .abort)
        alert.window.orderOut(nil)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Present only after AppKit has completed the real application launch.
        // Directly calling finishLaunching() followed by runModal() can leave a
        // freshly rebooted Mac with a running-but-NotVisible process.
        DispatchQueue.main.async { [self] in
            let application = NSApplication.shared
            let alert = approvalAlert(for: request, authority: authority)
            let window = alert.window
            window.collectionBehavior.insert(.moveToActiveSpace)
            window.level = .modalPanel
            window.center()
            application.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            NSRunningApplication.current.activate(
                options: [.activateAllWindows, .activateIgnoringOtherApps]
            )
            application.arrangeInFront(nil)
            let remaining = max(
                0, TimeInterval(request.expiresAt) - Date().timeIntervalSince1970
            )
            presentedAlert = alert
            let expiryTimer = Timer(
                timeInterval: remaining, target: self,
                selector: #selector(expireAuthorization(_:)),
                userInfo: nil, repeats: false
            )
            RunLoop.main.add(expiryTimer, forMode: .modalPanel)
            response = alert.runModal()
            expiryTimer.invalidate()
            presentedAlert = nil
            alert.window.orderOut(nil)
            application.stop(nil)
            // Wake the outer application run loop so stop(_:) takes effect
            // immediately even when no further user event is queued.
            application.postEvent(
                NSEvent.otherEvent(
                    with: .applicationDefined, location: .zero,
                    modifierFlags: [], timestamp: 0, windowNumber: 0,
                    context: nil, subtype: 0, data1: 0, data2: 0
                )!,
                atStart: false
            )
        }
    }
}

@MainActor
private func approvalChoice(for request: AuthorizationRequest, authority: String) -> NSApplication.ModalResponse {
    let application = NSApplication.shared
    guard application.activationPolicy() == .regular
            || application.setActivationPolicy(.regular) else {
        fail("application_activation_policy_rejected")
    }
    let delegate = AuthorizationApplicationDelegate(request: request, authority: authority)
    application.delegate = delegate
    application.run()
    application.delegate = nil
    guard let response = delegate.response else {
        fail("authorization_window_not_presented")
    }
    return response
}

private func evaluateTouchID(_ request: AuthorizationRequest) -> Bool {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.localizedCancelTitle = "Cancel"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        fail("touch_id_unavailable:\(error?.code ?? -1)")
    }
    let reason = "Approve \(request.operation) for \(request.declaredAgent) [\(request.declaredSession)]"
    let semaphore = DispatchSemaphore(value: 0)
    let state = EvaluationState()
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
        success, error in
        state.store(success: success, error: error)
        semaphore.signal()
    }
    while semaphore.wait(timeout: .now() + 0.05) == .timedOut {
        RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.05))
    }
    let result = state.load()
    if !result.0 {
        FileHandle.standardError.write(Data("touch_id_rejected:\(result.1)\n".utf8))
    }
    return result.0
}

private func writeAll(_ descriptor: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let count = Darwin.write(descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            guard count > 0 else { throw POSIXError(.EIO) }
            offset += count
        }
    }
}

private func readExactly(_ descriptor: Int32, count: Int) throws -> Data {
    var result = Data(count: count)
    var offset = 0
    while offset < count {
        let amount = result.withUnsafeMutableBytes { raw in
            Darwin.read(descriptor, raw.baseAddress!.advanced(by: offset), count - offset)
        }
        guard amount > 0 else { throw POSIXError(.ECONNRESET) }
        offset += amount
    }
    return result
}

private final class BrokerSession {
    private let descriptor: Int32

    init(request: AuthorizationRequest, socketPath: String) throws {
        guard socketPath.utf8.count < MemoryLayout<sockaddr_un>.size - 2 else {
            throw POSIXError(.ENAMETOOLONG)
        }
        descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathCapacity = MemoryLayout.size(ofValue: address.sun_path)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: pathCapacity) { destination in
                _ = socketPath.withCString { source in
                    strlcpy(destination, source, pathCapacity)
                }
            }
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            close(descriptor)
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let begin: [String: Any] = [
            "phase": "begin",
            "request_id": request.requestID,
            "request_sha256": request.requestSHA256,
            "schema": "secure-sandbox-touchid-approval-v2",
        ]
        try sendJSON(begin)
    }

    deinit { close(descriptor) }

    func challenge() throws -> [String: Any] {
        let prefix = try readExactly(descriptor, count: 4)
        if String(data: prefix, encoding: .ascii) == "SSAR" {
            let header = prefix + (try readExactly(descriptor, count: 12))
            let fields = header.withUnsafeBytes { raw -> (UInt32, UInt32, UInt32) in
                func word(_ offset: Int) -> UInt32 {
                    UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
                }
                return (word(4), word(8), word(12))
            }
            guard fields.1 <= responseLimit, fields.2 <= responseLimit else {
                throw AuthorizationDocumentError.invalidField("broker_response")
            }
            FileHandle.standardOutput.write(try readExactly(descriptor, count: Int(fields.1)))
            FileHandle.standardError.write(try readExactly(descriptor, count: Int(fields.2)))
            throw AuthorizationDocumentError.invalidField(
                "broker_handshake_rejected_status_\(fields.0)"
            )
        }
        let value = try readJSONLine(limit: 65_536, initial: prefix)
        guard value["schema"] as? String == "secure-sandbox-touchid-challenge-v2" else {
            throw AuthorizationDocumentError.invalidField("broker_challenge")
        }
        return value
    }

    func finish(_ message: [String: Any]) throws -> Int32 {
        try sendJSON(message)
        shutdown(descriptor, SHUT_WR)
        let header = try readExactly(descriptor, count: 16)
        let fields = header.withUnsafeBytes { raw -> (String, UInt32, UInt32, UInt32) in
            let magic = String(data: Data(raw[0..<4]), encoding: .ascii) ?? ""
            func word(_ offset: Int) -> UInt32 {
                UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
            }
            return (magic, word(4), word(8), word(12))
        }
        guard fields.0 == "SSAR", fields.2 <= responseLimit, fields.3 <= responseLimit else {
            throw AuthorizationDocumentError.invalidField("broker_response")
        }
        FileHandle.standardOutput.write(try readExactly(descriptor, count: Int(fields.2)))
        FileHandle.standardError.write(try readExactly(descriptor, count: Int(fields.3)))
        return fields.1 <= UInt32(Int32.max) ? Int32(fields.1) : rejectedExit
    }

    private func sendJSON(_ value: [String: Any]) throws {
        let encoded = try JSONSerialization.data(
            withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]
        ) + Data([0x0a])
        try writeAll(descriptor, encoded)
    }

    private func readJSONLine(limit: Int, initial: Data = Data()) throws -> [String: Any] {
        var data = initial
        while !data.contains(0x0a) {
            var byte: UInt8 = 0
            guard Darwin.read(descriptor, &byte, 1) == 1 else { throw POSIXError(.ECONNRESET) }
            data.append(byte)
            guard data.count <= limit else { throw AuthorizationDocumentError.tooLarge }
        }
        guard data.last == 0x0a else { throw AuthorizationDocumentError.invalidJSON }
        let line = data.dropLast()
        guard let value = try JSONSerialization.jsonObject(with: line) as? [String: Any],
              try JSONSerialization.data(
                withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]
              ) == line else {
            throw AuthorizationDocumentError.notCanonical
        }
        return value
    }
}

private func challengeString(_ challenge: [String: Any], _ name: String) throws -> String {
    guard let value = challenge[name] as? String, !value.isEmpty,
          value.utf8.count <= 512,
          value.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value <= 126 }) else {
        throw AuthorizationDocumentError.invalidField(name)
    }
    return value
}

private func challengeInteger(_ challenge: [String: Any], _ name: String) throws -> Int {
    guard let value = challenge[name] as? Int, value >= 0 else {
        throw AuthorizationDocumentError.invalidField(name)
    }
    return value
}

private func challengeBoolean(_ challenge: [String: Any], _ name: String) throws -> Bool {
    guard let value = challenge[name] as? Bool else {
        throw AuthorizationDocumentError.invalidField(name)
    }
    return value
}

private func authoritySummary(_ challenge: [String: Any]) throws -> String {
    let mode = try challengeString(challenge, "mode")
    if mode == "legacy-touch-id" {
        return "Legacy software authority (migration has not activated v2)\nHost release: "
            + (try challengeString(challenge, "host_release_id"))
    }
    var lines = [
        "Mode: \(mode)",
        "Generation: \(try challengeString(challenge, "generation_id"))",
        "Epoch: \(try challengeInteger(challenge, "generation_epoch"))",
        "Algorithm: \(try challengeString(challenge, "algorithm"))",
        "Application tag: \(try challengeString(challenge, "application_tag"))",
        "Access group: \(try challengeString(challenge, "access_group"))",
        "Public key SHA-256: \((challenge["public_key_sha256"] as? String) ?? "pending creation")",
        "Host release: \(try challengeString(challenge, "host_release_id"))",
    ]
    if challenge["research_release_id"] != nil {
        lines.append("Research release: \(try challengeString(challenge, "research_release_id"))")
    }
    return lines.joined(separator: "\n")
}

private func freshSigningContext() -> LAContext {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.localizedCancelTitle = "Cancel"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

private func prepareSecureEnclaveKey(
    request: AuthorizationRequest,
    challenge: [String: Any]
) throws -> [String: Any] {
    let tag = try challengeString(challenge, "application_tag")
    let allowCreation = try challengeBoolean(challenge, "allow_creation")
    let expectedPublicKeySHA256 = allowCreation
        ? nil : try challengeString(challenge, "public_key_sha256")
    let reason = "Create the SecureSandbox execution-approval key"
    let context = freshSigningContext()
    let key: SecKey
    let identity: SecureEnclaveKeyIdentity
    do {
        (key, identity) = try SecureEnclaveKeyStore.lookup(
            applicationTag: tag, expectedPublicKeySHA256: expectedPublicKeySHA256,
            context: context, reason: reason
        )
    } catch SecureEnclaveKeyStoreError.lookup(let status) where status == errSecItemNotFound {
        guard allowCreation else {
            throw SecureEnclaveKeyStoreError.lookup(status)
        }
        try SecureEnclaveKeyStore.create(applicationTag: tag)
        (key, identity) = try SecureEnclaveKeyStore.lookup(
            applicationTag: tag, expectedPublicKeySHA256: nil,
            context: context, reason: reason
        )
    }
    let attestation: [String: Any] = [
        "schema": "secure-sandbox-execution-approval-preparation-v2",
        "authorization_request_id": request.requestID,
        "authorization_request_sha256": request.requestSHA256,
        "transaction_id": try challengeString(challenge, "transaction_id"),
        "generation_id": try challengeString(challenge, "generation_id"),
        "generation_epoch": try challengeInteger(challenge, "generation_epoch"),
        "operator_uid": try challengeInteger(challenge, "operator_uid"),
        "application_tag": tag,
        "access_group": try challengeString(challenge, "access_group"),
        "algorithm": try challengeString(challenge, "algorithm"),
        "host_release_id": try challengeString(challenge, "host_release_id"),
        "research_release_id": try challengeString(challenge, "research_release_id"),
        "public_key_spki_der_b64": ExecutionApprovalCrypto.canonicalBase64(identity.publicKeySPKIDER),
        "public_key_sha256": identity.publicKeySHA256,
        "prepared_at": Int(Date().timeIntervalSince1970),
    ]
    let signature = try SecureEnclaveKeyStore.sign(
        message: try ExecutionApprovalCrypto.canonicalJSON(attestation),
        key: key, context: context
    )
    return [
        "schema": "secure-sandbox-execution-approval-preparation-envelope-v2",
        "attestation": attestation,
        "signature_der_b64": ExecutionApprovalCrypto.canonicalBase64(signature),
    ]
}

private func signExecutionApproval(
    request: AuthorizationRequest,
    challenge: [String: Any]
) throws -> [String: Any] {
    guard let approval = try JSONSerialization.jsonObject(
        with: request.parametersCanonical
    ) as? [String: Any] else {
        throw AuthorizationDocumentError.invalidField("parameters")
    }
    let expectedDigest = try challengeString(challenge, "public_key_sha256")
    let context = freshSigningContext()
    let (key, identity) = try SecureEnclaveKeyStore.lookup(
        applicationTag: try challengeString(challenge, "application_tag"),
        expectedPublicKeySHA256: expectedDigest,
        context: context,
        reason: "Approve this exact SecureSandbox disposable execution"
    )
    guard identity.publicKeySHA256 == expectedDigest else {
        throw SecureEnclaveKeyStoreError.publicKeyMismatch
    }
    var approvalBytes = request.parametersCanonical
    approvalBytes.append(0x0a)
    let attestation: [String: Any] = [
        "schema": ExecutionApprovalCrypto.attestationSchema,
        "approval": approval,
        "approval_request_sha256": ExecutionApprovalCrypto.sha256Hex(approvalBytes),
        "authorization_request_id": request.requestID,
        "host_release_id": try challengeString(challenge, "host_release_id"),
        "approved_at": Int(Date().timeIntervalSince1970),
        "key_generation_id": try challengeString(challenge, "generation_id"),
        "key_generation_epoch": try challengeInteger(challenge, "generation_epoch"),
        "public_key_sha256": expectedDigest,
        "signature_algorithm": try challengeString(challenge, "algorithm"),
    ]
    let signature = try SecureEnclaveKeyStore.sign(
        message: try ExecutionApprovalCrypto.canonicalJSON(attestation),
        key: key, context: context
    )
    return [
        "schema": ExecutionApprovalCrypto.envelopeSchema,
        "attestation": attestation,
        "signature_der_b64": ExecutionApprovalCrypto.canonicalBase64(signature),
    ]
}

private func legacyAuthorization(_ request: AuthorizationRequest) -> [String: Any] {
    [
        "schema": "secure-sandbox-touchid-authorization-v2",
        "phase": "authorize",
        "request_id": request.requestID,
        "request_sha256": request.requestSHA256,
    ]
}

private func cancelledAuthorization(_ request: AuthorizationRequest) -> [String: Any] {
    [
        "schema": "secure-sandbox-touchid-decision-v2",
        "status": "cancelled",
        "request_id": request.requestID,
        "request_sha256": request.requestSHA256,
    ]
}

@MainActor
private func submit(_ request: AuthorizationRequest, socketPath: String) throws -> Int32 {
    let session = try BrokerSession(request: request, socketPath: socketPath)
    let challenge = try session.challenge()
    let mode = try challengeString(challenge, "mode")
    switch approvalChoice(for: request, authority: try authoritySummary(challenge)) {
    case .alertSecondButtonReturn where request.requiresBiometricApproval:
        return try session.finish(cancelledAuthorization(request))
    case .alertSecondButtonReturn:
        return passwordFallbackExit
    case .alertThirdButtonReturn:
        return try session.finish(cancelledAuthorization(request))
    case .alertFirstButtonReturn:
        if mode == "secure-enclave-prepare" {
            return try session.finish(prepareSecureEnclaveKey(request: request, challenge: challenge))
        }
        if mode == "secure-enclave-sign" {
            return try session.finish(signExecutionApproval(request: request, challenge: challenge))
        }
        guard mode == "legacy-touch-id" else {
            throw AuthorizationDocumentError.invalidField("challenge_mode")
        }
        guard evaluateTouchID(request) else { return rejectedExit }
        return try session.finish(legacyAuthorization(request))
    default:
        return try session.finish(cancelledAuthorization(request))
    }
}

var resultPath: String?
var resultRequestID = "unavailable"
var resultRequestSHA256 = String(repeating: "0", count: 64)
do {
    resultPath = argument("--result-path")
    let requestPath = argument("--request-path")
    let expectedDigest = argument("--request-sha256")
    let socketPath = argument("--socket-path")
    let request = try AuthorizationRequest.parse(try readRequest(path: requestPath), expectedSHA256: expectedDigest)
    resultRequestID = request.requestID
    resultRequestSHA256 = request.requestSHA256
    let status = try submit(request, socketPath: socketPath)
    try writeResult(
        path: resultPath!, status: status,
        requestID: resultRequestID, requestSHA256: resultRequestSHA256
    )
    exit(status)
} catch {
    if let path = resultPath {
        try? writeResult(
            path: path, status: rejectedExit,
            requestID: resultRequestID, requestSHA256: resultRequestSHA256
        )
    }
    fail("touchid_authorization_error:\(error)")
}
