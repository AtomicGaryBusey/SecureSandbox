import Darwin
import Foundation
import SecureSandboxNativeSessionUIProtocol

enum NativeSessionBrokerError: LocalizedError {
    case rejected(String)

    var errorDescription: String? {
        switch self {
        case .rejected(let code):
            "Native session broker rejected the request (\(code))."
        }
    }
}

struct NativeSessionPlanBrokerClient: Sendable {
    func plan(_ request: NativeSessionPlanRequest) throws -> NativeSessionPlan {
        let descriptor = try NativeBrokerSocket.connect(receiveTimeoutSeconds: 190)
        defer { Darwin.close(descriptor) }
        try NativeBrokerSocket.writeAll(request.canonicalData, to: descriptor)
        guard shutdown(descriptor, SHUT_WR) == 0 else {
            throw NativeSessionBrokerError.rejected(
                "native_session_plan_socket_shutdown_failed"
            )
        }
        let reply = try NativeBrokerSocket.readAll(
            from: descriptor, maximumBytes: 1_048_576
        )
        return try NativeSessionPlanProtocol.decodeReply(reply, request: request)
    }
}

final class NativeBrokerDuplexConnection: @unchecked Sendable {
    private let stateLock = NSLock()
    private let writeQueue = DispatchQueue(
        label: "org.zebeth.securesandbox.native-broker-writer",
        qos: .userInitiated
    )
    private var descriptor: Int32
    private var finished = false

    init(claim: Data) throws {
        descriptor = try NativeBrokerSocket.connect(receiveTimeoutSeconds: nil)
        do {
            try NativeBrokerSocket.writeAll(claim, to: descriptor)
        } catch {
            Darwin.close(descriptor)
            descriptor = -1
            throw error
        }
    }

    deinit { finish() }

    func read(maximumBytes: Int = 32 * 1_024) throws -> Data? {
        let fd = try liveDescriptor()
        var bytes = [UInt8](repeating: 0, count: maximumBytes)
        while true {
            let count = Darwin.read(fd, &bytes, bytes.count)
            if count < 0 {
                if errno == EINTR { continue }
                if errno == ECONNRESET || errno == EBADF {
                    finish()
                    return nil
                }
                finish()
                throw NativeSessionBrokerError.rejected(
                    "native_stream_socket_read_failed"
                )
            }
            if count == 0 {
                finish()
                return nil
            }
            return Data(bytes.prefix(count))
        }
    }

    func write(_ data: Data) throws {
        guard !data.isEmpty else { return }
        try NativeBrokerSocket.writeAll(data, to: liveDescriptor())
    }

    func enqueueWrite(
        _ data: Data,
        onError: @escaping @Sendable (any Error) -> Void
    ) {
        guard !data.isEmpty else { return }
        writeQueue.async { [weak self] in
            guard let self else { return }
            do { try self.write(data) }
            catch { onError(error) }
        }
    }

    func close() {
        let fd = stateLock.withLock { () -> Int32 in
            guard !finished, descriptor >= 0 else { return -1 }
            return descriptor
        }
        if fd >= 0 { _ = shutdown(fd, SHUT_RDWR) }
    }

    func finish() {
        let fd = stateLock.withLock { () -> Int32 in
            guard !finished else { return -1 }
            finished = true
            let value = descriptor
            descriptor = -1
            return value
        }
        if fd >= 0 {
            _ = shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
    }

    private func liveDescriptor() throws -> Int32 {
        let fd = stateLock.withLock { finished ? -1 : descriptor }
        guard fd >= 0 else {
            throw NativeSessionBrokerError.rejected("native_stream_socket_closed")
        }
        return fd
    }
}

private enum NativeBrokerSocket {
    static let path = "/var/run/secure-sandbox-authorization.sock"

    static func connect(receiveTimeoutSeconds: Int?) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw NativeSessionBrokerError.rejected(
                "native_stream_socket_unavailable"
            )
        }
        do {
            var noSignal: Int32 = 1
            let size = socklen_t(MemoryLayout.size(ofValue: noSignal))
            _ = withUnsafePointer(to: &noSignal) {
                setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, size)
            }
            var sendTimeout = timeval(tv_sec: 10, tv_usec: 0)
            let sendTimeoutSize = socklen_t(MemoryLayout.size(ofValue: sendTimeout))
            _ = withUnsafePointer(to: &sendTimeout) {
                setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, $0,
                           sendTimeoutSize)
            }
            if let receiveTimeoutSeconds {
                var timeout = timeval(tv_sec: receiveTimeoutSeconds, tv_usec: 0)
                let timeoutSize = socklen_t(MemoryLayout.size(ofValue: timeout))
                _ = withUnsafePointer(to: &timeout) {
                    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, $0,
                               timeoutSize)
                }
            }

            var address = sockaddr_un()
            let pathBytes = Array(path.utf8CString)
            guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
                throw NativeSessionBrokerError.rejected(
                    "native_stream_socket_path_invalid"
                )
            }
            address.sun_family = sa_family_t(AF_UNIX)
            let addressLength = socklen_t(MemoryLayout<sockaddr_un>.size)
            address.sun_len = UInt8(addressLength)
            withUnsafeMutablePointer(to: &address.sun_path) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) {
                    destination in
                    for index in pathBytes.indices {
                        destination[index] = pathBytes[index]
                    }
                }
            }
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, addressLength)
                }
            }
            guard result == 0 else {
                throw NativeSessionBrokerError.rejected(
                    "native_stream_socket_connect_failed"
                )
            }
            try NativeBrokerPeerIdentity.requireRoot(descriptor)
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    static func writeAll(_ data: Data, to descriptor: Int32) throws {
        var offset = 0
        try data.withUnsafeBytes { bytes in
            while offset < data.count {
                let count = Darwin.write(
                    descriptor, bytes.baseAddress!.advanced(by: offset),
                    data.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw NativeSessionBrokerError.rejected(
                        "native_stream_socket_write_failed"
                    )
                }
                guard count > 0 else {
                    throw NativeSessionBrokerError.rejected(
                        "native_stream_socket_write_stalled"
                    )
                }
                offset += count
            }
        }
    }

    static func readAll(from descriptor: Int32, maximumBytes: Int) throws -> Data {
        var data = Data()
        while data.count <= maximumBytes {
            var bytes = [UInt8](
                repeating: 0, count: min(65_536, maximumBytes + 1 - data.count)
            )
            let count = Darwin.read(descriptor, &bytes, bytes.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw NativeSessionBrokerError.rejected(
                    "native_session_plan_socket_read_failed"
                )
            }
            if count == 0 { break }
            data.append(bytes, count: count)
        }
        guard (2...maximumBytes).contains(data.count) else {
            throw NativeSessionBrokerError.rejected(
                "native_session_plan_reply_size_invalid"
            )
        }
        return data
    }
}
