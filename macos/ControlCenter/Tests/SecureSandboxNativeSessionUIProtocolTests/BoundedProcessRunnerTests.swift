import Darwin
import Foundation
import Testing
@testable import SecureSandboxNativeSessionUIProtocol

private final class PipeIdentityBox: @unchecked Sendable {
    private let lock = NSLock()
    private var identities: [(Int32, UInt64, UInt64)] = []

    func capture(_ descriptors: [Int32]) throws {
        var captured: [(Int32, UInt64, UInt64)] = []
        for descriptor in descriptors {
            var value = stat()
            guard fstat(descriptor, &value) == 0 else {
                throw NativeSessionProtocolError.rejected(
                    "test_pipe_identity_unavailable"
                )
            }
            captured.append((
                descriptor, UInt64(value.st_dev), UInt64(value.st_ino)
            ))
        }
        lock.withLock { identities = captured }
    }

    func snapshot() -> [(Int32, UInt64, UInt64)] {
        lock.withLock { identities }
    }
}

private final class TestFlagBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() { lock.withLock { value = true } }
    func read() -> Bool { lock.withLock { value } }
}

private func waitForSemaphore(
    _ semaphore: DispatchSemaphore,
    timeout: DispatchTime
) async -> Bool {
    await withCheckedContinuation { continuation in
        DispatchQueue.global(qos: .utility).async {
            continuation.resume(
                returning: semaphore.wait(timeout: timeout) == .success
            )
        }
    }
}

@Suite struct BoundedProcessRunnerTests {
    @Test func exactInputAndOutputCompleteBeforeDeadline() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [
            "-I", "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ]
        process.standardError = FileHandle.nullDevice
        let input = Data("bounded-bridge\n".utf8)
        let result = try NativeBoundedProcessRunner.run(
            process,
            input: input,
            deadlineSeconds: 5,
            maximumOutputBytes: 1_024
        )
        #expect(result.output == input)
        #expect(result.terminationStatus == 0)
    }

    @Test func termIgnoringBridgeAndRetainedStdoutRemainBounded() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "secure-sandbox-bounded-process-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: temporary, withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: temporary) }
        let childPIDPath = temporary.appending(path: "child.pid")
        let script = """
        import os, signal, subprocess, sys, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen(
            [\"/bin/sleep\", \"30\"], stdout=sys.stdout,
            stderr=subprocess.DEVNULL
        )
        with open(sys.argv[1], \"x\", encoding=\"ascii\") as handle:
            handle.write(str(child.pid))
            handle.flush()
            os.fsync(handle.fileno())
        time.sleep(30)
        """
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-c", script, childPIDPath.path]
        process.standardError = FileHandle.nullDevice

        let started = DispatchTime.now().uptimeNanoseconds
        do {
            _ = try NativeBoundedProcessRunner.run(
                process,
                input: nil,
                deadlineSeconds: 0.5,
                terminationGraceSeconds: 0.1,
                maximumOutputBytes: 1_024
            )
            Issue.record("TERM-ignoring bridge unexpectedly completed")
        } catch NativeSessionProtocolError.rejected(let code) {
            #expect(code == "native_process_deadline_exceeded")
        }
        let elapsed = Double(
            DispatchTime.now().uptimeNanoseconds - started
        ) / 1_000_000_000
        #expect(elapsed < 3)

        if let raw = try? String(contentsOf: childPIDPath, encoding: .ascii),
           let childPID = pid_t(raw), childPID > 1 {
            _ = Darwin.kill(childPID, SIGKILL)
        }
    }

    @Test func normallyExitedBridgeCannotDelegateStdoutLifetime() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "secure-sandbox-retained-stdout-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: temporary, withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: temporary) }
        let childPIDPath = temporary.appending(path: "child.pid")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [
            "-I", "-c",
            """
            import subprocess, sys
            child = subprocess.Popen(
                [\"/bin/sleep\", \"30\"], stdout=sys.stdout,
                stderr=subprocess.DEVNULL
            )
            with open(sys.argv[1], \"x\", encoding=\"ascii\") as handle:
                handle.write(str(child.pid))
            """,
            childPIDPath.path,
        ]
        process.standardError = FileHandle.nullDevice
        let started = DispatchTime.now().uptimeNanoseconds
        do {
            _ = try NativeBoundedProcessRunner.run(
                process,
                input: nil,
                deadlineSeconds: 5,
                terminationGraceSeconds: 0.1,
                maximumOutputBytes: 1_024
            )
            Issue.record("descendant-retained stdout was accepted")
        } catch NativeSessionProtocolError.rejected(let code) {
            #expect(code == "native_process_output_not_closed")
        }
        let elapsed = Double(
            DispatchTime.now().uptimeNanoseconds - started
        ) / 1_000_000_000
        #expect(elapsed < 3)

        if let raw = try? String(contentsOf: childPIDPath, encoding: .ascii),
           let childPID = pid_t(raw), childPID > 1 {
            _ = Darwin.kill(childPID, SIGKILL)
        }
    }

    @Test func largeInputAndDescendantRetainedStdinCannotCrashOrBlock() throws {
        let temporary = FileManager.default.temporaryDirectory.appending(
            path: "secure-sandbox-retained-stdin-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: temporary, withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: temporary) }
        let childPIDPath = temporary.appending(path: "child.pid")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [
            "-I", "-c",
            """
            import signal, subprocess, sys, time
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            child = subprocess.Popen(
                [\"/bin/sleep\", \"30\"], stdin=sys.stdin,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            with open(sys.argv[1], \"x\", encoding=\"ascii\") as handle:
                handle.write(str(child.pid))
            time.sleep(30)
            """,
            childPIDPath.path,
        ]
        process.standardError = FileHandle.nullDevice
        let largeInput = Data(repeating: 0x61, count: 8 * 1_024 * 1_024)
        let started = DispatchTime.now().uptimeNanoseconds
        do {
            _ = try NativeBoundedProcessRunner.run(
                process,
                input: largeInput,
                deadlineSeconds: 0.5,
                terminationGraceSeconds: 0.1,
                maximumOutputBytes: 1_024
            )
            Issue.record("retained stdin unexpectedly completed")
        } catch NativeSessionProtocolError.rejected(let code) {
            #expect(code == "native_process_deadline_exceeded")
        }
        let elapsed = Double(
            DispatchTime.now().uptimeNanoseconds - started
        ) / 1_000_000_000
        #expect(elapsed < 3)

        if let raw = try? String(contentsOf: childPIDPath, encoding: .ascii),
           let childPID = pid_t(raw), childPID > 1 {
            _ = Darwin.kill(childPID, SIGKILL)
        }
    }

    @Test func concurrentExecCannotInheritEitherOutputPipeEndpoint() async throws {
        let pipeCreated = DispatchSemaphore(value: 0)
        let permitRunnerLaunch = DispatchSemaphore(value: 0)
        let probeStarted = DispatchSemaphore(value: 0)
        let probeFinished = TestFlagBox()
        let identities = PipeIdentityBox()

        let runnerTask = Task.detached {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            process.arguments = [
                "-I", "-c",
                "import sys,time;sys.stdout.write('intended\\n');sys.stdout.flush();time.sleep(0.3)",
            ]
            process.standardError = FileHandle.nullDevice
            return try NativeBoundedProcessRunner.run(
                process,
                input: nil,
                deadlineSeconds: 5,
                maximumOutputBytes: 1_024,
                beforeOutputCloseOnExec: { readDescriptor, writeDescriptor in
                    try identities.capture([readDescriptor, writeDescriptor])
                    pipeCreated.signal()
                    permitRunnerLaunch.wait()
                }
            )
        }

        let pipeReady = await waitForSemaphore(
            pipeCreated, timeout: .now() + 2
        )
        guard pipeReady else {
            permitRunnerLaunch.signal()
            throw NativeSessionProtocolError.rejected(
                "test_pipe_creation_timeout"
            )
        }
        let captured = identities.snapshot()
        #expect(captured.count == 2)
        let probeTask = Task.detached {
            defer { probeFinished.set() }
            let probe = Process()
            probe.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            let arguments = captured.flatMap {
                [String($0.0), String($0.1), String($0.2)]
            }
            probe.arguments = [
                "-I", "-c",
                """
                import os,sys
                values=sys.argv[1:]
                for index in range(0,len(values),3):
                    fd,dev,ino=map(int,values[index:index+3])
                    try: observed=os.fstat(fd)
                    except OSError: continue
                    if (observed.st_dev,observed.st_ino)==(dev,ino):
                        raise SystemExit(91)
                """,
            ] + arguments
            probe.standardOutput = FileHandle.nullDevice
            probe.standardError = FileHandle.nullDevice
            probeStarted.signal()
            try NativeDescriptorInheritanceGate.run(probe)
            probe.waitUntilExit()
            return probe.terminationStatus
        }

        let probeEntered = await waitForSemaphore(
            probeStarted, timeout: .now() + 2
        )
        #expect(probeEntered)
        try await Task.sleep(for: .milliseconds(50))
        #expect(!probeFinished.read())
        permitRunnerLaunch.signal()

        let probeStatus = try await probeTask.value
        let result = try await runnerTask.value
        #expect(probeStatus == 0)
        #expect(result.output == Data("intended\n".utf8))
        #expect(result.terminationStatus == 0)
    }
}
