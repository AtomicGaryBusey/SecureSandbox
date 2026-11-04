import Darwin
import Foundation
import SecureSandboxNativeAuthCore

protocol AuthorizationCallbackReceiving: Sendable {
    func begin() throws -> UInt16
    func waitForCallback(deadline: Date) async throws -> URL
    func cancel()
}

enum LoopbackHTTPRequestParser {
    static func callbackURL(from data: Data, expectedPort: UInt16) throws -> URL {
        guard (1...16_384).contains(data.count),
              let separator = data.range(of: Data("\r\n\r\n".utf8)),
              separator.upperBound == data.endIndex,
              let text = String(data: data[..<separator.lowerBound], encoding: .utf8),
              !text.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw NativeCredentialHelperError.callbackRejected
        }
        let lines = text.components(separatedBy: "\r\n")
        guard (2...65).contains(lines.count) else { throw NativeCredentialHelperError.callbackRejected }
        let requestParts = lines[0].split(separator: " ", omittingEmptySubsequences: false)
        guard requestParts.count == 3, requestParts[0] == "GET", requestParts[2] == "HTTP/1.1" else {
            throw NativeCredentialHelperError.callbackRejected
        }
        let target = String(requestParts[1])
        guard (1...8_192).contains(target.utf8.count),
              target.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              target.hasPrefix(OpenAISignInPolicy.callbackPath + "?"),
              !target.contains("#"), !target.contains("\\"), !target.contains("://") else {
            throw NativeCredentialHelperError.callbackRejected
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard !line.isEmpty, line.first != " ", line.first != "\t",
                  let colon = line.firstIndex(of: ":") else {
                throw NativeCredentialHelperError.callbackRejected
            }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...]
                .trimmingCharacters(in: .whitespaces)
            guard name.range(of: #"^[a-z0-9-]{1,64}$"#, options: .regularExpression) != nil,
                  headers[name] == nil,
                  value.utf8.count <= 1_024,
                  value.unicodeScalars.allSatisfy({
                      !CharacterSet.controlCharacters.contains($0) || $0 == "\t"
                  }) else {
                throw NativeCredentialHelperError.callbackRejected
            }
            headers[name] = value
        }
        guard headers["host"] == "127.0.0.1:\(expectedPort)",
              headers["transfer-encoding"] == nil,
              headers["content-length"].map({ $0 == "0" }) ?? true,
              let callback = URL(string: "http://127.0.0.1:\(expectedPort)\(target)") else {
            throw NativeCredentialHelperError.callbackRejected
        }
        return callback
    }
}

final class DarwinLoopbackAuthorizationReceiver: AuthorizationCallbackReceiving, @unchecked Sendable {
    private let lock = NSLock()
    private var listener: Int32 = -1
    private var activeListener: Int32 = -1
    private var port: UInt16 = 0

    func begin() throws -> UInt16 {
        lock.lock()
        defer { lock.unlock() }
        guard listener == -1, activeListener == -1, port == 0 else {
            throw NativeCredentialHelperError.loopbackUnavailable
        }
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NativeCredentialHelperError.loopbackUnavailable }
        var closeOnFailure = true
        defer { if closeOnFailure { Darwin.close(fd) } }
        var one: Int32 = 1
        guard Darwin.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
            throw NativeCredentialHelperError.loopbackUnavailable
        }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(0).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0, Darwin.listen(fd, 1) == 0 else {
            throw NativeCredentialHelperError.loopbackUnavailable
        }
        var bound = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &bound) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(fd, $0, &boundLength)
            }
        }
        let selected = UInt16(bigEndian: bound.sin_port)
        guard nameResult == 0, selected > 0,
              bound.sin_addr.s_addr == inet_addr("127.0.0.1") else {
            throw NativeCredentialHelperError.loopbackUnavailable
        }
        listener = fd
        port = selected
        closeOnFailure = false
        return selected
    }

    func waitForCallback(deadline: Date) async throws -> URL {
        let state: (Int32, UInt16) = try lock.withLock {
            guard listener >= 0, activeListener == -1, port > 0, deadline > Date() else {
                throw NativeCredentialHelperError.loopbackUnavailable
            }
            let state = (listener, port)
            activeListener = listener
            listener = -1
            port = 0
            return state
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async { [self] in
                    let result = Result { try acceptOne(fd: state.0, port: state.1, deadline: deadline) }
                    finish(fd: state.0)
                    continuation.resume(with: result)
                }
            }
        } onCancel: {
            self.cancel()
        }
    }

    func cancel() {
        let state = lock.withLock { () -> (Int32, Int32) in
            let idle = listener
            let active = activeListener
            listener = -1
            port = 0
            return (idle, active)
        }
        if state.0 >= 0 { Darwin.close(state.0) }
        if state.1 >= 0 { Darwin.shutdown(state.1, SHUT_RDWR) }
    }

    private func finish(fd: Int32) {
        lock.withLock {
            if activeListener == fd { activeListener = -1 }
        }
        Darwin.close(fd)
    }

    private func acceptOne(fd: Int32, port: UInt16, deadline: Date) throws -> URL {
        try wait(fd: fd, events: Int16(POLLIN), deadline: deadline)
        var peer = sockaddr_in()
        var peerLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let client = withUnsafeMutablePointer(to: &peer) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.accept(fd, $0, &peerLength)
            }
        }
        guard client >= 0, peer.sin_family == sa_family_t(AF_INET),
              peer.sin_addr.s_addr == inet_addr("127.0.0.1") else {
            if client >= 0 { Darwin.close(client) }
            throw NativeCredentialHelperError.callbackRejected
        }
        defer { Darwin.close(client) }
        var one: Int32 = 1
        guard Darwin.setsockopt(
            client, SOL_SOCKET, SO_NOSIGPIPE, &one,
            socklen_t(MemoryLayout.size(ofValue: one))
        ) == 0 else {
            throw NativeCredentialHelperError.callbackRejected
        }
        var request = Data()
        while request.range(of: Data("\r\n\r\n".utf8)) == nil {
            try wait(fd: client, events: Int16(POLLIN), deadline: deadline)
            var buffer = [UInt8](repeating: 0, count: 2_048)
            let count = Darwin.recv(client, &buffer, buffer.count, 0)
            guard count > 0, request.count + count <= 16_384 else {
                throw NativeCredentialHelperError.callbackRejected
            }
            request.append(contentsOf: buffer.prefix(count))
        }
        let callback = try LoopbackHTTPRequestParser.callbackURL(from: request, expectedPort: port)
        try writeResponse(client, status: "200 OK", body: "Authorization received. Return to SecureSandbox.")
        return callback
    }

    private func wait(fd: Int32, events: Int16, deadline: Date) throws {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else { throw NativeCredentialHelperError.callbackRejected }
        var descriptor = pollfd(fd: fd, events: events, revents: 0)
        let milliseconds = Int32(min(remaining * 1_000, Double(Int32.max)))
        let result = Darwin.poll(&descriptor, 1, milliseconds)
        guard result == 1, descriptor.revents & events != 0,
              descriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else {
            throw NativeCredentialHelperError.callbackRejected
        }
    }

    private func writeResponse(_ fd: Int32, status: String, body: String) throws {
        let bodyData = Data(body.utf8)
        let head = "HTTP/1.1 \(status)\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(bodyData.count)\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        let response = Data(head.utf8) + bodyData
        var written = 0
        while written < response.count {
            let count = response.withUnsafeBytes { bytes in
                Darwin.send(fd, bytes.baseAddress!.advanced(by: written), response.count - written, 0)
            }
            guard count > 0 else { throw NativeCredentialHelperError.callbackRejected }
            written += count
        }
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
