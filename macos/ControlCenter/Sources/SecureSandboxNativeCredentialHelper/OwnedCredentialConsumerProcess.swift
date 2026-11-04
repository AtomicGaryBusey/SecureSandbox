import Darwin
import Foundation

/// Owns one direct child from `posix_spawn` through its sole `waitpid`.
/// No Foundation `Process` object or background reaper exists, so an exited
/// child remains a zombie and its PID cannot be reused between the exact
/// generation readback and a cleanup signal.
final class SystemOwnedCredentialConsumerProcess: @unchecked Sendable {
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64

    private let processIdentity: @Sendable (Int32)
        -> NativeCredentialProcessIdentityObservation
    private let signalProcess: @Sendable (Int32, Int32)
        -> (result: Int32, error: Int32)
    private let pollForProcess: @Sendable (Int32)
        -> (pid: Int32, status: Int32, error: Int32)
    private let waitForProcess: @Sendable (Int32) -> (pid: Int32, status: Int32)
    private let lock = NSLock()
    private var waitClaimed = false

    init(
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        processIdentity: @escaping @Sendable (Int32)
            -> NativeCredentialProcessIdentityObservation =
                nativeCredentialProcessIdentity,
        signalProcess: @escaping @Sendable (Int32, Int32)
            -> (result: Int32, error: Int32) = { identifier, signal in
                errno = 0
                let result = kill(identifier, signal)
                return (result, errno)
            },
        pollForProcess: @escaping @Sendable (Int32)
            -> (pid: Int32, status: Int32, error: Int32) = { identifier in
                var status: Int32 = 0
                errno = 0
                let observed = waitpid(identifier, &status, WNOHANG)
                return (observed, status, errno)
            },
        waitForProcess: @escaping @Sendable (Int32)
            -> (pid: Int32, status: Int32) = { identifier in
                var status: Int32 = 0
                var observed: pid_t
                repeat {
                    observed = waitpid(identifier, &status, 0)
                } while observed < 0 && errno == EINTR
                return (observed, status)
            }
    ) {
        self.processIdentifier = processIdentifier
        self.processStartTimeMicroseconds = processStartTimeMicroseconds
        self.processIdentity = processIdentity
        self.signalProcess = signalProcess
        self.pollForProcess = pollForProcess
        self.waitForProcess = waitForProcess
    }

    func waitForExitStatus() throws -> Int32 {
        try lock.withLock {
            try claimWait()
            let result = waitForProcess(processIdentifier)
            guard result.pid == processIdentifier else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            try proveOriginalGenerationAbsent()
            return result.status
        }
    }

    func terminateAndReap() throws {
        try lock.withLock {
            try claimWait()
            let existingExit = pollForProcess(processIdentifier)
            if existingExit.pid == processIdentifier {
                try proveOriginalGenerationAbsent()
                return
            }
            guard existingExit.pid == 0 else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            guard processIdentity(processIdentifier)
                    == .exact(processStartTimeMicroseconds) else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            // Because this object is the sole direct-child reaper, an exit
            // between the preceding readback and kill leaves a zombie that
            // still reserves this PID. The signal therefore cannot hit a
            // substituted process generation.
            let signalled = signalProcess(processIdentifier, SIGKILL)
            guard signalled.result == 0 || signalled.error == ESRCH else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            let result = waitForProcess(processIdentifier)
            guard result.pid == processIdentifier else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            try proveOriginalGenerationAbsent()
        }
    }

    private func claimWait() throws {
        guard !waitClaimed,
              processIdentifier > 0,
              processStartTimeMicroseconds > 0 else {
            throw NativeCredentialHelperError.consumerTerminationUnproven
        }
        waitClaimed = true
    }

    private func proveOriginalGenerationAbsent() throws {
        switch processIdentity(processIdentifier) {
        case .absent:
            return
        case .exact(let observed)
            where observed != processStartTimeMicroseconds:
            return
        case .exact, .unavailable:
            throw NativeCredentialHelperError.consumerTerminationUnproven
        }
    }
}

enum SystemCredentialConsumerSpawner {
    static func spawn(
        executableURL: URL,
        arguments: [String],
        environment: [String: String],
        standardInput: Int32,
        standardOutput: Int32
    ) throws -> Int32 {
        guard executableURL.isFileURL,
              executableURL.path.hasPrefix("/"),
              standardInput >= 0,
              standardOutput >= 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawn_file_actions_adddup2(
            &actions, standardInput, STDIN_FILENO
        ) == 0,
            posix_spawn_file_actions_adddup2(
                &actions, standardOutput, STDOUT_FILENO
            ) == 0,
            "/dev/null".withCString({ path in
                posix_spawn_file_actions_addopen(
                    &actions, STDERR_FILENO, path, O_WRONLY, 0
                )
            }) == 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }

        var attributes: posix_spawnattr_t?
        let flags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)
        guard posix_spawnattr_init(&attributes) == 0,
              posix_spawnattr_setflags(&attributes, flags) == 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        defer { posix_spawnattr_destroy(&attributes) }

        let argumentStrings = [executableURL.path] + arguments
        let environmentStrings = environment.keys.sorted().map {
            $0 + "=" + environment[$0]!
        }
        var identifier: pid_t = 0
        let result = try executableURL.path.withCString { executable in
            try withCStringVector(argumentStrings) { argumentVector in
                try withCStringVector(environmentStrings) { environmentVector in
                    posix_spawn(
                        &identifier,
                        executable,
                        &actions,
                        &attributes,
                        argumentVector,
                        environmentVector
                    )
                }
            }
        }
        guard result == 0, identifier > 0 else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        return identifier
    }

    static func terminateUnidentifiedDirectChild(_ identifier: Int32) throws {
        guard identifier > 0 else {
            throw NativeCredentialHelperError.consumerTerminationUnproven
        }
        errno = 0
        let signalled = kill(identifier, SIGKILL)
        guard signalled == 0 || errno == ESRCH else {
            throw NativeCredentialHelperError.consumerTerminationUnproven
        }
        var status: Int32 = 0
        var observed: pid_t
        repeat {
            observed = waitpid(identifier, &status, 0)
        } while observed < 0 && errno == EINTR
        guard observed == identifier else {
            throw NativeCredentialHelperError.consumerTerminationUnproven
        }
    }

    static func writeExact(
        _ data: Data,
        to descriptor: Int32,
        before deadline: NativeCredentialReleaseDeadline,
        wallClock: @escaping @Sendable () -> Date,
        monotonicClock:
            @escaping @Sendable () -> ContinuousClock.Instant,
        continuationCheck: @escaping @Sendable () throws -> Void = {}
    ) throws {
        guard descriptor >= 0, !data.isEmpty else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                try continuationCheck()
                try deadline.validate(
                    wallNow: wallClock(),
                    monotonicNow: monotonicClock()
                )
                try continuationCheck()
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0, errno == EINTR { continue }
                if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                    try waitUntilWritable(
                        descriptor,
                        before: deadline,
                        wallClock: wallClock,
                        monotonicClock: monotonicClock,
                        continuationCheck: continuationCheck
                    )
                    continue
                }
                guard count > 0 else {
                    throw NativeCredentialHelperError
                        .consumerTerminationUnproven
                }
                offset += count
            }
        }
    }

    private static func waitUntilWritable(
        _ descriptor: Int32,
        before deadline: NativeCredentialReleaseDeadline,
        wallClock: @escaping @Sendable () -> Date,
        monotonicClock:
            @escaping @Sendable () -> ContinuousClock.Instant,
        continuationCheck: @escaping @Sendable () throws -> Void
    ) throws {
        while true {
            try continuationCheck()
            try deadline.validate(
                wallNow: wallClock(),
                monotonicNow: monotonicClock()
            )
            var descriptorState = pollfd(
                fd: descriptor,
                events: Int16(POLLOUT),
                revents: 0
            )
            // A short bounded wait is retried against the one admission-time
            // monotonic deadline.  A backwards wall-clock step can therefore
            // never extend credential-release authority.
            let result = Darwin.poll(&descriptorState, 1, 10)
            if result < 0, errno == EINTR { continue }
            if result == 0 { continue }
            guard result > 0,
                  descriptorState.revents & Int16(POLLOUT) != 0,
                  descriptorState.revents
                    & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else {
                throw NativeCredentialHelperError.consumerTerminationUnproven
            }
            try continuationCheck()
            try deadline.validate(
                wallNow: wallClock(),
                monotonicNow: monotonicClock()
            )
            return
        }
    }

    private static func withCStringVector<Result>(
        _ strings: [String],
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws
            -> Result
    ) throws -> Result {
        let allocated = strings.map { strdup($0) }
        defer { allocated.forEach { free($0) } }
        guard allocated.allSatisfy({ $0 != nil }) else {
            throw NativeCredentialHelperError.consumerLaunchFailed
        }
        var vector = allocated.map { pointer in
            pointer.map { UnsafeMutablePointer<CChar>($0) }
        }
        vector.append(nil)
        return try vector.withUnsafeMutableBufferPointer { buffer in
            try body(buffer.baseAddress!)
        }
    }
}
