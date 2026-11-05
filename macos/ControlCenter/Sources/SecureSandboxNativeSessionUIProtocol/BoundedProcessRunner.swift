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
              !(parentLiveness && input != nil),
              maximumOutputBytes > 0,
              maximumOutputBytes <= 64 * 1_024 * 1_024 else {
            throw NativeSessionProtocolError.rejected(
                "native_process_limits_invalid"
            )
        }

        let anonymousInput = try input.map(NativeAnonymousProcessInput.init)
        defer { anonymousInput?.close() }
        let state = NativeBoundedProcessState()
        let terminated = DispatchSemaphore(value: 0)
        let readerDone = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        let spawned: (output: Pipe, livenessWrite: FileHandle?) = try
            NativeDescriptorInheritanceGate
            .withProcessSpawnGate {
                let candidate = Pipe()
                let liveness = parentLiveness ? Pipe() : nil
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
                        try requireCloseOnExec(
                            liveness.fileHandleForReading.fileDescriptor
                        )
                        try requireCloseOnExec(
                            liveness.fileHandleForWriting.fileDescriptor
                        )
                        environment["SECURE_SANDBOX_PARENT_LIVENESS_FD"] = "0"
                        process.standardInput = liveness.fileHandleForReading
                    } else {
                        environment.removeValue(
                            forKey: "SECURE_SANDBOX_PARENT_LIVENESS_FD"
                        )
                        process.standardInput = anonymousInput?.handle
                            ?? FileHandle.nullDevice
                    }
                    process.environment = environment
                    process.standardOutput = candidate
                    try process.run()
                    try? liveness?.fileHandleForReading.close()
                    return (candidate, liveness?.fileHandleForWriting)
                } catch {
                    try? candidate.fileHandleForReading.close()
                    try? candidate.fileHandleForWriting.close()
                    try? liveness?.fileHandleForReading.close()
                    try? liveness?.fileHandleForWriting.close()
                    throw error
                }
            }
        let outputPipe = spawned.output
        let livenessWrite = spawned.livenessWrite.map(NativeCloseOnceHandle.init)
        defer { livenessWrite?.close() }
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
            if process.isRunning {
                if Darwin.kill(processIdentifier, SIGKILL) != 0,
                   errno != ESRCH {
                    state.markForceTerminationFailed()
                }
            }
        }
        timeoutWork.cancel()

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
