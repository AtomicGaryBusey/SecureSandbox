import Darwin
import Foundation

public struct NativeBoundedProcessResult: Sendable {
    public let output: Data
    public let terminationStatus: Int32
    public let terminationReason: Int
}

private final class NativeAnonymousProcessInput {
    private var stream: UnsafeMutablePointer<FILE>?
    let handle: FileHandle

    init(_ data: Data) throws {
        guard data.count <= 64 * 1_024 * 1_024 else {
            throw NativeSessionProtocolError.rejected(
                "native_process_input_oversized"
            )
        }
        let created: (UnsafeMutablePointer<FILE>, FileHandle) = try
            NativeDescriptorInheritanceGate.withProcessSpawnGate {
                guard let stream = Darwin.tmpfile() else {
                    throw NativeSessionProtocolError.rejected(
                        "native_process_input_create_failed"
                    )
                }
                let descriptor = fileno(stream)
                do {
                    guard descriptor >= 0,
                          fchmod(descriptor, mode_t(0o600)) == 0 else {
                        throw NativeSessionProtocolError.rejected(
                            "native_process_input_mode_failed"
                        )
                    }
                    let descriptorFlags = fcntl(descriptor, F_GETFD)
                    guard descriptorFlags >= 0,
                          fcntl(
                              descriptor, F_SETFD,
                              descriptorFlags | FD_CLOEXEC
                          ) == 0 else {
                        throw NativeSessionProtocolError.rejected(
                            "native_process_input_cloexec_failed"
                        )
                    }
                    var offset = 0
                    try data.withUnsafeBytes { bytes in
                        while offset < data.count {
                            let written = Darwin.write(
                                descriptor,
                                bytes.baseAddress!.advanced(by: offset),
                                data.count - offset
                            )
                            if written < 0 {
                                if errno == EINTR { continue }
                                throw NativeSessionProtocolError.rejected(
                                    "native_process_input_stage_failed"
                                )
                            }
                            guard written > 0 else {
                                throw NativeSessionProtocolError.rejected(
                                    "native_process_input_stage_stalled"
                                )
                            }
                            offset += written
                        }
                    }
                    guard lseek(descriptor, 0, SEEK_SET) == 0 else {
                        throw NativeSessionProtocolError.rejected(
                            "native_process_input_rewind_failed"
                        )
                    }
                    var observed = stat()
                    guard fstat(descriptor, &observed) == 0,
                          observed.st_uid == geteuid(),
                          observed.st_nlink == 0,
                          observed.st_size == data.count,
                          observed.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                          observed.st_mode & mode_t(0o777) == mode_t(0o600)
                    else {
                        throw NativeSessionProtocolError.rejected(
                            "native_process_input_identity_invalid"
                        )
                    }
                    return (
                        stream,
                        FileHandle(
                            fileDescriptor: descriptor, closeOnDealloc: false
                        )
                    )
                } catch {
                    fclose(stream)
                    throw error
                }
            }
        stream = created.0
        handle = created.1
    }

    func close() {
        guard let stream else { return }
        self.stream = nil
        fclose(stream)
    }

    deinit { close() }
}

private final class NativeBoundedProcessState: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var oversized = false
    private var readerFailed = false
    private var timedOut = false
    private var forceTerminationFailed = false
    private var outputCloseForced = false

    func append(_ chunk: Data, maximumBytes: Int) {
        lock.withLock {
            guard !oversized else { return }
            if chunk.count > maximumBytes - data.count {
                oversized = true
                data.removeAll(keepingCapacity: false)
                return
            }
            data.append(chunk)
        }
    }

    func markReaderFailed() { lock.withLock { readerFailed = true } }
    func markTimedOut() { lock.withLock { timedOut = true } }
    func markForceTerminationFailed() {
        lock.withLock { forceTerminationFailed = true }
    }
    func markOutputCloseForced() {
        lock.withLock { outputCloseForced = true }
    }

    func snapshot() -> (Data, Bool, Bool, Bool, Bool, Bool) {
        lock.withLock {
            (
                data, oversized, readerFailed, timedOut,
                forceTerminationFailed, outputCloseForced
            )
        }
    }
}

private final class NativeCloseOnceHandle: @unchecked Sendable {
    let handle: FileHandle
    private let lock = NSLock()
    private var closed = false

    init(_ handle: FileHandle) { self.handle = handle }

    func close() {
        let shouldClose = lock.withLock { () -> Bool in
            guard !closed else { return false }
            closed = true
            return true
        }
        if shouldClose { try? handle.close() }
    }
}

private final class NativeParentLivenessChannel: @unchecked Sendable {
    private let lock = NSLock()
    private let writerDone = DispatchSemaphore(value: 0)
    private var parentDescriptor: Int32
    private var childDescriptor: Int32
    private var writerStarted = false
    private var writerFinished = false
    private var writerFailed = false
    private var parentClosed = false
    private var finishStarted = false

    init() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
            throw NativeSessionProtocolError.rejected(
                "native_process_liveness_socket_unavailable"
            )
        }
        parentDescriptor = descriptors[0]
        childDescriptor = descriptors[1]
        do {
            try Self.requireCloseOnExec(parentDescriptor)
            try Self.requireCloseOnExec(childDescriptor)
            var noSignal: Int32 = 1
            let size = socklen_t(MemoryLayout.size(ofValue: noSignal))
            guard withUnsafePointer(to: &noSignal, {
                setsockopt(parentDescriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, size)
            }) == 0 else {
                throw NativeSessionProtocolError.rejected(
                    "native_process_liveness_socket_nosigpipe_failed"
                )
            }
        } catch {
            Darwin.close(parentDescriptor)
            Darwin.close(childDescriptor)
            parentDescriptor = -1
            childDescriptor = -1
            throw error
        }
    }

    deinit { finish() }

    func childHandle() throws -> FileHandle {
        let descriptor = lock.withLock { childDescriptor }
        guard descriptor >= 0 else {
            throw NativeSessionProtocolError.rejected(
                "native_process_liveness_socket_unavailable"
            )
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    }

    func closeChildInParent() {
        let descriptor = lock.withLock { () -> Int32 in
            let value = childDescriptor
            childDescriptor = -1
            return value
        }
        if descriptor >= 0 { Darwin.close(descriptor) }
    }

    func startWriting(_ data: Data) {
        let writerDescriptor = lock.withLock { () -> Int32 in
            guard !writerStarted, !parentClosed, parentDescriptor >= 0 else {
                return -1
            }
            writerStarted = true
            return fcntl(parentDescriptor, F_DUPFD_CLOEXEC, 3)
        }
        guard writerDescriptor >= 0 else {
            lock.withLock {
                writerFailed = true
                writerFinished = true
            }
            writerDone.signal()
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer { Darwin.close(writerDescriptor) }
            var failed = false
            data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < data.count {
                    let count = Darwin.send(
                        writerDescriptor,
                        bytes.baseAddress!.advanced(by: offset),
                        data.count - offset,
                        0
                    )
                    if count < 0 {
                        if errno == EINTR { continue }
                        failed = true
                        return
                    }
                    guard count > 0 else {
                        failed = true
                        return
                    }
                    offset += count
                }
            }
            if failed {
                lock.withLock { writerFailed = true }
                revoke()
            }
            lock.withLock { writerFinished = true }
            writerDone.signal()
        }
    }

    func revoke() {
        lock.withLock {
            if parentDescriptor >= 0 {
                _ = Darwin.shutdown(parentDescriptor, SHUT_WR)
            }
        }
    }

    func finish() {
        let shouldFinish = lock.withLock { () -> Bool in
            guard !finishStarted else { return false }
            finishStarted = true
            return true
        }
        guard shouldFinish else { return }
        revoke()
        let writerState = lock.withLock { (writerStarted, writerFinished) }
        if writerState.0, !writerState.1 {
            _ = writerDone.wait(timeout: .now() + 2)
        }
        let descriptors = lock.withLock { () -> (Int32, Int32) in
            guard !parentClosed else { return (-1, -1) }
            parentClosed = true
            let result = (parentDescriptor, childDescriptor)
            parentDescriptor = -1
            childDescriptor = -1
            return result
        }
        if descriptors.0 >= 0 {
            _ = Darwin.shutdown(descriptors.0, SHUT_RDWR)
            Darwin.close(descriptors.0)
        }
        if descriptors.1 >= 0 { Darwin.close(descriptors.1) }
    }

    func writerCompleted() -> Bool {
        lock.withLock { writerFinished }
    }

    func inputWriteFailed() -> Bool { lock.withLock { writerFailed } }

    private static func requireCloseOnExec(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0,
              fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0,
              fcntl(descriptor, F_GETFD) & FD_CLOEXEC == FD_CLOEXEC else {
            throw NativeSessionProtocolError.rejected(
                "native_process_liveness_socket_cloexec_failed"
            )
        }
    }
}

public enum NativeBoundedProcessRunner {
    /// Runs one local bridge with an absolute wall-clock bound. The direct
    /// child gets a short TERM grace, then SIGKILL. The read descriptor is
    /// closed independently so a descendant retaining stdout cannot keep the
    /// caller blocked after the bridge has terminated.
    public static func run(
        _ process: Process,
        input: Data?,
        deadlineSeconds: TimeInterval,
        terminationGraceSeconds: TimeInterval = 2,
        parentLiveness: Bool = false,
        maximumOutputBytes: Int
    ) throws -> NativeBoundedProcessResult {
        try run(
            process,
            input: input,
            deadlineSeconds: deadlineSeconds,
            terminationGraceSeconds: terminationGraceSeconds,
            parentLiveness: parentLiveness,
            maximumOutputBytes: maximumOutputBytes,
            beforeOutputCloseOnExec: { _, _ in }
        )
    }

    static func run(
        _ process: Process,
        input: Data?,
        deadlineSeconds: TimeInterval,
        terminationGraceSeconds: TimeInterval = 2,
        parentLiveness: Bool = false,
        maximumOutputBytes: Int,
        beforeOutputCloseOnExec: (Int32, Int32) throws -> Void
    ) throws -> NativeBoundedProcessResult {
        guard deadlineSeconds > 0,
              deadlineSeconds <= 24 * 60 * 60,
              terminationGraceSeconds >= 0,
              terminationGraceSeconds <= 10,
              maximumOutputBytes > 0,
              maximumOutputBytes <= 64 * 1_024 * 1_024 else {
            throw NativeSessionProtocolError.rejected(
                "native_process_limits_invalid"
            )
        }

        guard (input?.count ?? 0) <= 64 * 1_024 * 1_024 else {
            throw NativeSessionProtocolError.rejected(
                "native_process_input_oversized"
            )
        }
        let anonymousInput = parentLiveness
            ? nil : try input.map(NativeAnonymousProcessInput.init)
        defer { anonymousInput?.close() }
        let state = NativeBoundedProcessState()
        let terminated = DispatchSemaphore(value: 0)
        let readerDone = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        let spawned: (output: Pipe, liveness: NativeParentLivenessChannel?) = try
            NativeDescriptorInheritanceGate
            .withProcessSpawnGate {
                let candidate = Pipe()
                let liveness = try parentLiveness
                    ? NativeParentLivenessChannel() : nil
                let readDescriptor = candidate.fileHandleForReading.fileDescriptor
                let writeDescriptor = candidate.fileHandleForWriting.fileDescriptor
                do {
                    try beforeOutputCloseOnExec(
                        readDescriptor, writeDescriptor
                    )
                    try requireCloseOnExec(readDescriptor)
                    try requireCloseOnExec(writeDescriptor)
                    var environment = process.environment
                        ?? ProcessInfo.processInfo.environment
                    if let liveness {
                        environment["SECURE_SANDBOX_PARENT_LIVENESS_FD"] = "0"
                        environment["SECURE_SANDBOX_PARENT_INPUT_LENGTH"] = String(
                            input?.count ?? 0
                        )
                        process.standardInput = try liveness.childHandle()
                    } else {
                        environment.removeValue(
                            forKey: "SECURE_SANDBOX_PARENT_LIVENESS_FD"
                        )
                        environment.removeValue(
                            forKey: "SECURE_SANDBOX_PARENT_INPUT_LENGTH"
                        )
                        process.standardInput = anonymousInput?.handle
                            ?? FileHandle.nullDevice
                    }
                    process.environment = environment
                    process.standardOutput = candidate
                    try process.run()
                    liveness?.closeChildInParent()
                    liveness?.startWriting(input ?? Data())
                    return (candidate, liveness)
                } catch {
                    try? candidate.fileHandleForReading.close()
                    try? candidate.fileHandleForWriting.close()
                    liveness?.finish()
                    throw error
                }
            }
        let outputPipe = spawned.output
        let liveness = spawned.liveness
        defer { liveness?.finish() }
        let processIdentifier = process.processIdentifier
        let outputRead = NativeCloseOnceHandle(
            outputPipe.fileHandleForReading
        )

        DispatchQueue.global(qos: .utility).async {
            defer { readerDone.signal() }
            do {
                while let chunk = try outputRead.handle.read(
                    upToCount: 64 * 1_024
                ), !chunk.isEmpty {
                    state.append(chunk, maximumBytes: maximumOutputBytes)
                }
            } catch {
                if !state.snapshot().3 { state.markReaderFailed() }
            }
        }

        let timeoutWork = DispatchWorkItem {
            state.markTimedOut()
            liveness?.revoke()
            if process.isRunning { process.terminate() }
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + terminationGraceSeconds
            ) {
                if process.isRunning {
                    if Darwin.kill(processIdentifier, SIGKILL) != 0,
                       errno != ESRCH {
                        state.markForceTerminationFailed()
                    }
                }
                outputRead.close()
            }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + deadlineSeconds,
            execute: timeoutWork
        )

        let hardStop = DispatchTime.now()
            + deadlineSeconds + terminationGraceSeconds + 2
        if terminated.wait(timeout: hardStop) == .timedOut {
            state.markTimedOut()
            liveness?.revoke()
            if process.isRunning {
                if Darwin.kill(processIdentifier, SIGKILL) != 0,
                   errno != ESRCH {
                    state.markForceTerminationFailed()
                }
            }
        }
        timeoutWork.cancel()
        liveness?.revoke()

        if let liveness {
            let writerDeadline = DispatchTime.now() + 2
            while !liveness.writerCompleted(), DispatchTime.now() < writerDeadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            guard liveness.writerCompleted() else {
                throw NativeSessionProtocolError.rejected(
                    "native_process_input_writer_unreaped"
                )
            }
            if liveness.inputWriteFailed(), !state.snapshot().3 {
                throw NativeSessionProtocolError.rejected(
                    "native_process_input_write_failed"
                )
            }
        }

        let readerGrace = min(max(terminationGraceSeconds, 0.25), 2)
        if readerDone.wait(timeout: .now() + readerGrace) == .timedOut {
            state.markOutputCloseForced()
            outputRead.close()
            if readerDone.wait(timeout: .now() + 1) == .timedOut {
                throw NativeSessionProtocolError.rejected(
                    "native_process_output_close_failed"
                )
            }
        }
        outputRead.close()

        let snapshot = state.snapshot()
        if snapshot.4 {
            throw NativeSessionProtocolError.rejected(
                "native_process_force_termination_failed"
            )
        }
        if snapshot.3 {
            throw NativeSessionProtocolError.rejected(
                "native_process_deadline_exceeded"
            )
        }
        if snapshot.5 {
            throw NativeSessionProtocolError.rejected(
                "native_process_output_not_closed"
            )
        }
        if snapshot.1 {
            throw NativeSessionProtocolError.rejected(
                "native_process_output_oversized"
            )
        }
        if snapshot.2 {
            throw NativeSessionProtocolError.rejected(
                "native_process_output_read_failed"
            )
        }
        guard !process.isRunning else {
            throw NativeSessionProtocolError.rejected(
                "native_process_termination_unresolved"
            )
        }
        return NativeBoundedProcessResult(
            output: snapshot.0,
            terminationStatus: process.terminationStatus,
            terminationReason: process.terminationReason.rawValue
        )
    }

    private static func requireCloseOnExec(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0,
              fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0,
              fcntl(descriptor, F_GETFD) & FD_CLOEXEC == FD_CLOEXEC else {
            throw NativeSessionProtocolError.rejected(
                "native_process_pipe_cloexec_failed"
            )
        }
    }
}
