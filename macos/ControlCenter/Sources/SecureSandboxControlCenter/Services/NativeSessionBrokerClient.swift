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
        let reply = try NativeBrokerSocket.roundTrip(
            request.canonicalData,
            timeoutSeconds: 190,
            maximumReplyBytes: 1_048_576,
            shutdownError: "native_session_plan_socket_shutdown_failed",
            readError: "native_session_plan_socket_read_failed",
            sizeError: "native_session_plan_reply_size_invalid",
            timeoutError: "native_session_plan_deadline_exceeded"
        )
        return try NativeSessionPlanProtocol.decodeReply(reply, request: request)
    }
}

struct NativeProjectionRecoveryBrokerClient: Sendable {
    func identityPlan(
        _ request: NativeProjectionRecoveryPlanRequest
    ) throws -> NativeProjectionIdentityRecoveryPlan {
        let reply = try query(request)
        return try NativeProjectionRecoveryProtocol.decodeIdentityPlanReply(
            reply, request: request
        )
    }

    func reconciliationPlan(
        _ request: NativeProjectionRecoveryPlanRequest
    ) throws -> NativeProjectionReconciliationPlan {
        let reply = try query(request)
        return try NativeProjectionRecoveryProtocol
            .decodeReconciliationPlanReply(reply, request: request)
    }

    private func query(
        _ request: NativeProjectionRecoveryPlanRequest
    ) throws -> Data {
        try NativeBrokerSocket.roundTrip(
            request.canonicalData,
            timeoutSeconds: 190,
            maximumReplyBytes: 1_048_576,
            shutdownError: "native_projection_recovery_socket_shutdown_failed",
            readError: "native_projection_recovery_socket_read_failed",
            sizeError: "native_projection_recovery_reply_size_invalid",
            timeoutError: "native_projection_recovery_deadline_exceeded"
        )
    }
}

struct NativeDeploymentBrokerClient: Sendable {
    func plan(
        queryID: String = UUID().uuidString.lowercased()
    ) throws -> NativeDeploymentPlanQueryResult {
        let request = try NativeDeploymentQueryRequest(
            command: .plan, queryID: queryID
        )
        let reply = try query(request.canonicalData)
        let now = Int(Date().timeIntervalSince1970)
        return try NativeDeploymentProtocol.decodePlanReply(
            reply, request: request, now: now
        )
    }

    func status(
        queryID: String = UUID().uuidString.lowercased()
    ) throws -> NativeDeploymentStatusQueryResult {
        let request = try NativeDeploymentQueryRequest(
            command: .status, queryID: queryID
        )
        let reply = try query(request.canonicalData)
        return try NativeDeploymentProtocol.decodeStatusReply(
            reply, request: request
        )
    }

    func recoveryPlan(
        queryID: String = UUID().uuidString.lowercased()
    ) throws -> NativeDeploymentRecoveryPlanQueryResult {
        let request = try NativeDeploymentQueryRequest(
            command: .recoveryPlan, queryID: queryID
        )
        let reply = try query(request.canonicalData)
        return try NativeDeploymentProtocol.decodeRecoveryPlanReply(
            reply, request: request
        )
    }

    private func query(_ request: Data) throws -> Data {
        try NativeBrokerSocket.roundTrip(
            request,
            timeoutSeconds: 190,
            maximumReplyBytes: 4 * 1_024 * 1_024,
            shutdownError: "native_deployment_query_socket_shutdown_failed",
            readError: "native_deployment_query_socket_read_failed",
            sizeError: "native_deployment_query_reply_size_invalid",
            timeoutError: "native_deployment_query_deadline_exceeded"
        )
    }
}

struct NativeCatalogRecoveryBrokerClient: Sendable {
    func gate(
        queryID: String = UUID().uuidString.lowercased()
    ) throws -> NativeCatalogPromotionGateQueryResult {
        let request = try NativeCatalogPromotionGateRequest(queryID: queryID)
        let reply = try NativeBrokerSocket.roundTrip(
            request.canonicalData,
            timeoutSeconds: 190,
            maximumReplyBytes: 1_048_576,
            shutdownError: "native_catalog_gate_socket_shutdown_failed",
            readError: "native_catalog_gate_socket_read_failed",
            sizeError: "native_catalog_gate_reply_size_invalid",
            timeoutError: "native_catalog_gate_deadline_exceeded"
        )
        return try NativeCatalogRecoveryProtocol.decodeGateReply(
            reply, request: request
        )
    }

    func recover(
        expectedGateSHA256: String,
        recoveryID: String = UUID().uuidString.lowercased()
    ) throws -> NativeCatalogPromotionRecoveryResult {
        let request = try NativeCatalogPromotionRecoveryRequest(
            expectedGateSHA256: expectedGateSHA256,
            recoveryID: recoveryID
        )
        let reply = try NativeBrokerSocket.roundTrip(
            request.canonicalData,
            // The root recover-active operation owns 3,900 seconds. Preserve
            // a strict client margin for connect/send/final reply delivery.
            timeoutSeconds:
                NativeOperationDeadlinePolicy.directBrokerClientSeconds,
            maximumReplyBytes: 1_048_576,
            shutdownError: "native_catalog_recovery_socket_shutdown_failed",
            readError: "native_catalog_recovery_socket_read_failed",
            sizeError: "native_catalog_recovery_reply_size_invalid",
            timeoutError: "native_catalog_recovery_deadline_exceeded"
        )
        return try NativeCatalogRecoveryProtocol.decodeRecoveryReply(
            reply, request: request
        )
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
        let fd = try borrowedDescriptor()
        defer { Darwin.close(fd) }
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
        let fd = try borrowedDescriptor()
        defer { Darwin.close(fd) }
        try NativeBrokerSocket.writeAll(data, to: fd)
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
        stateLock.withLock {
            guard !finished, descriptor >= 0 else { return }
            _ = shutdown(descriptor, SHUT_RDWR)
        }
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

    private func borrowedDescriptor() throws -> Int32 {
        try stateLock.withLock {
            guard !finished, descriptor >= 0 else {
                throw NativeSessionBrokerError.rejected(
                    "native_stream_socket_closed"
                )
            }
            return try NativeDescriptorBorrow.duplicateCloseOnExec(descriptor)
        }
    }
}

private struct NativeBrokerDeadline {
    let uptimeNanoseconds: UInt64

    init(seconds: Int) throws {
        guard seconds > 0 else {
            throw NativeSessionBrokerError.rejected(
                "native_stream_deadline_invalid"
            )
        }
        let (duration, multipliedOverflow) = UInt64(seconds)
            .multipliedReportingOverflow(by: 1_000_000_000)
        let (deadline, addedOverflow) = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(duration)
        guard !multipliedOverflow, !addedOverflow else {
            throw NativeSessionBrokerError.rejected(
                "native_stream_deadline_invalid"
            )
        }
        uptimeNanoseconds = deadline
    }

    func remainingMilliseconds(timeoutError: String) throws -> Int32 {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < uptimeNanoseconds else {
            throw NativeSessionBrokerError.rejected(timeoutError)
        }
        let remaining = uptimeNanoseconds - now
        let milliseconds = (remaining + 999_999) / 1_000_000
        return Int32(min(milliseconds, UInt64(Int32.max)))
    }
}

private enum NativeBrokerSocket {
    static let path = "/var/run/secure-sandbox-authorization.sock"

    static func connect(
        receiveTimeoutSeconds: Int?,
        deadline: NativeBrokerDeadline? = nil,
        timeoutError: String = "native_stream_deadline_exceeded"
    ) throws -> Int32 {
        let descriptor: Int32
        do {
            descriptor = try NativeDescriptorInheritanceGate.makeUnixStreamSocket()
        } catch {
            throw NativeSessionBrokerError.rejected(
                "native_stream_socket_unavailable"
            )
        }
        do {
            var noSignal: Int32 = 1
            let size = socklen_t(MemoryLayout.size(ofValue: noSignal))
            let noSignalResult = withUnsafePointer(to: &noSignal) {
                setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, size)
            }
            guard noSignalResult == 0 else {
                throw NativeSessionBrokerError.rejected(
                    "native_stream_socket_nosigpipe_failed"
                )
            }
            var sendTimeout = timeval(tv_sec: 10, tv_usec: 0)
            let sendTimeoutSize = socklen_t(MemoryLayout.size(ofValue: sendTimeout))
            let sendTimeoutResult = withUnsafePointer(to: &sendTimeout) {
                setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, $0,
                           sendTimeoutSize)
            }
            guard sendTimeoutResult == 0 else {
                throw NativeSessionBrokerError.rejected(
                    "native_stream_socket_send_timeout_failed"
                )
            }
            if let receiveTimeoutSeconds {
                var timeout = timeval(tv_sec: receiveTimeoutSeconds, tv_usec: 0)
                let timeoutSize = socklen_t(MemoryLayout.size(ofValue: timeout))
                let receiveTimeoutResult = withUnsafePointer(to: &timeout) {
                    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, $0,
                               timeoutSize)
                }
                guard receiveTimeoutResult == 0 else {
                    throw NativeSessionBrokerError.rejected(
                        "native_stream_socket_receive_timeout_failed"
                    )
                }
            }
            if deadline != nil {
                let flags = fcntl(descriptor, F_GETFL)
                guard flags >= 0,
                      fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                    throw NativeSessionBrokerError.rejected(
                        "native_stream_socket_nonblocking_failed"
                    )
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
            let connectionResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, addressLength)
                }
            }
            if connectionResult != 0 {
                guard let deadline,
                      [EINPROGRESS, EAGAIN, EALREADY].contains(errno) else {
                    throw NativeSessionBrokerError.rejected(
                        "native_stream_socket_connect_failed"
                    )
                }
                try waitForReadiness(
                    descriptor,
                    events: Int16(POLLOUT),
                    deadline: deadline,
                    timeoutError: timeoutError,
                    ioError: "native_stream_socket_connect_failed"
                )
                var socketError: Int32 = 0
                var socketErrorSize = socklen_t(
                    MemoryLayout.size(ofValue: socketError)
                )
                let status = withUnsafeMutablePointer(to: &socketError) {
                    getsockopt(
                        descriptor, SOL_SOCKET, SO_ERROR, $0, &socketErrorSize
                    )
                }
                guard status == 0, socketError == 0 else {
                    throw NativeSessionBrokerError.rejected(
                        "native_stream_socket_connect_failed"
                    )
                }
            }
            try NativeBrokerPeerIdentity.requireRoot(descriptor)
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    static func writeAll(
        _ data: Data,
        to descriptor: Int32,
        deadline: NativeBrokerDeadline? = nil,
        timeoutError: String = "native_stream_deadline_exceeded",
        writeError: String = "native_stream_socket_write_failed"
    ) throws {
        var offset = 0
        try data.withUnsafeBytes { bytes in
            while offset < data.count {
                if let deadline {
                    try waitForReadiness(
                        descriptor,
                        events: Int16(POLLOUT),
                        deadline: deadline,
                        timeoutError: timeoutError,
                        ioError: writeError
                    )
                }
                let count = Darwin.write(
                    descriptor, bytes.baseAddress!.advanced(by: offset),
                    data.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    if deadline != nil && (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue
                    }
                    throw NativeSessionBrokerError.rejected(writeError)
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

    static func roundTrip(
        _ request: Data,
        timeoutSeconds: Int,
        maximumReplyBytes: Int,
        shutdownError: String,
        readError: String,
        sizeError: String,
        timeoutError: String
    ) throws -> Data {
        let deadline = try NativeBrokerDeadline(seconds: timeoutSeconds)
        let descriptor = try connect(
            receiveTimeoutSeconds: timeoutSeconds,
            deadline: deadline,
            timeoutError: timeoutError
        )
        defer { Darwin.close(descriptor) }
        try writeAll(
            request,
            to: descriptor,
            deadline: deadline,
            timeoutError: timeoutError,
            writeError: readError.replacingOccurrences(
                of: "_read_", with: "_write_"
            )
        )
        guard shutdown(descriptor, SHUT_WR) == 0 else {
            throw NativeSessionBrokerError.rejected(shutdownError)
        }
        let response = try readAll(
            from: descriptor,
            maximumBytes: maximumReplyBytes,
            deadline: deadline,
            readError: readError,
            sizeError: sizeError,
            timeoutError: timeoutError
        )
        if NativeBrokerRejectionFrame.hasMagic(response) {
            let rejection: String
            do {
                rejection = try NativeBrokerRejectionFrame.decodeRejectedError(
                    response
                )
            } catch {
                throw NativeSessionBrokerError.rejected(
                    "native_broker_rejection_frame_invalid"
                )
            }
            throw NativeSessionBrokerError.rejected(rejection)
        }
        return response
    }

    static func readAll(
        from descriptor: Int32,
        maximumBytes: Int,
        deadline: NativeBrokerDeadline? = nil,
        readError: String = "native_session_plan_socket_read_failed",
        sizeError: String = "native_session_plan_reply_size_invalid",
        timeoutError: String = "native_stream_deadline_exceeded"
    ) throws -> Data {
        var data = Data()
        while data.count <= maximumBytes {
            if let deadline {
                try waitForReadiness(
                    descriptor,
                    events: Int16(POLLIN),
                    deadline: deadline,
                    timeoutError: timeoutError,
                    ioError: readError
                )
            }
            var bytes = [UInt8](
                repeating: 0, count: min(65_536, maximumBytes + 1 - data.count)
            )
            let count = Darwin.read(descriptor, &bytes, bytes.count)
            if count < 0 {
                if errno == EINTR { continue }
                if deadline != nil && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue
                }
                throw NativeSessionBrokerError.rejected(readError)
            }
            if count == 0 { break }
            data.append(bytes, count: count)
        }
        guard (2...maximumBytes).contains(data.count) else {
            throw NativeSessionBrokerError.rejected(sizeError)
        }
        return data
    }

    private static func waitForReadiness(
        _ descriptor: Int32,
        events: Int16,
        deadline: NativeBrokerDeadline,
        timeoutError: String,
        ioError: String
    ) throws {
        while true {
            var item = pollfd(fd: descriptor, events: events, revents: 0)
            let timeout = try deadline.remainingMilliseconds(
                timeoutError: timeoutError
            )
            let result = Darwin.poll(&item, 1, timeout)
            if result < 0 {
                if errno == EINTR { continue }
                throw NativeSessionBrokerError.rejected(ioError)
            }
            guard result > 0 else {
                throw NativeSessionBrokerError.rejected(timeoutError)
            }
            let invalidEvents = Int16(POLLERR | POLLNVAL)
            guard item.revents & invalidEvents == 0 else {
                throw NativeSessionBrokerError.rejected(ioError)
            }
            if item.revents & events != 0 { return }
            if events == Int16(POLLIN), item.revents & Int16(POLLHUP) != 0 {
                return
            }
            if item.revents & Int16(POLLHUP) != 0 {
                throw NativeSessionBrokerError.rejected(ioError)
            }
        }
    }
}
