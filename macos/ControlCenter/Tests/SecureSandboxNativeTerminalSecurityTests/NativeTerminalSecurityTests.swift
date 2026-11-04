import AppKit
import Foundation
import SwiftTerm
import Testing
@testable import SecureSandboxNativeSessionUIProtocol
@testable import SecureSandboxNativeTerminalSecurity

struct NativeTerminalSecurityTests {
    @Test func policyPinsTextOnlyBoundedTerminalFeatures() {
        let options = NativeTerminalSecurityPolicy.options
        #expect(options.scrollback == 500)
        #expect(options.maximumOscBytes == 64 * 1_024)
        #expect(options.enableSixelReported == false)
        #expect(options.enableOsc8Hyperlinks == false)
        #expect(options.kittyGraphics.storageLimitBytesPerScreen == 0)
        #expect(options.kittyGraphics.localMediaPolicy.isEmpty)
        #expect(options.kittyGraphics.trustedTemporaryDirectory == nil)
        #expect(options.kittyClipboardPolicy.isEmpty)
        #expect(options.featureReport == nil)
    }

    @Test func filterDropsChunkedDCSAndAPCWithoutAccumulatingPayload() {
        var filter = NativeTerminalOutputFilter()
        let prefix = filter.filter(Data("safe\u{1b}_Gf=32;".utf8))
        #expect(prefix == Data("safe".utf8))
        #expect(filter.isDroppingControlString)
        for _ in 0..<8 {
            #expect(filter.filter(Data(repeating: 0x41, count: 128 * 1_024)).isEmpty)
        }
        let resumed = filter.filter(Data("\u{1b}\\text\u{1b}Pqmore".utf8))
        #expect(resumed == Data("text".utf8))
        #expect(filter.isDroppingControlString)
        #expect(filter.filter(Data("\u{9c}done".utf8)) == Data("done".utf8))
        #expect(!filter.isDroppingControlString)
    }

    @Test func policyDoesNotAdvertiseSixelStoreKittyOrDeliverOversizeOSC() {
        let recorder = TerminalReplyRecorder()
        let terminal = Terminal(
            delegate: recorder,
            options: NativeTerminalSecurityPolicy.options
        )
        terminal.feed(text: "\u{1b}[c")
        let deviceAttributes = String(
            decoding: recorder.sent.flatMap { $0 }, as: UTF8.self
        )
        #expect(!deviceAttributes.contains(";4"))

        terminal.feed(
            text: "\u{1b}_Gf=32,s=1,v=1,i=1;AAAA/w==\u{1b}\\"
        )
        let snapshot = terminal.kittyGraphicsRenderSnapshot()
        #expect(snapshot.imagesById.isEmpty)
        #expect(snapshot.placements.isEmpty)

        var oversized = Data("\u{1b}]1337;".utf8)
        oversized.append(Data(
            repeating: 0x41,
            count: NativeTerminalSecurityPolicy.maximumOscBytes + 1
        ))
        oversized.append(0x07)
        terminal.feed(byteArray: Array(oversized))
        #expect(recorder.iTermCallbacks == 0)
        #expect(recorder.clipboardCallbacks == 0)
    }

    @MainActor
    @Test func surfaceDropsParserRepliesButPreservesExplicitUserInput() {
        let view = NativeClaudeSecureTerminalView(
            secureFrame: CGRect(x: 0, y: 0, width: 640, height: 480)
        )
        let delegate = TerminalViewRecorder()
        view.terminalDelegate = delegate
        #expect(view.allowMouseReporting == false)

        let userInput = Array("typed-by-user".utf8)
        view.send(data: userInput[...])
        #expect(delegate.sent == [userInput])
        delegate.sent.removeAll()

        let hostile = Array(
            ("\u{1b}[6n" +
             "\u{1b}[c" +
             "\u{1b}]10;?\u{7}" +
             "\u{1b}P$qm\u{1b}\\" +
             "\u{1b}_Ga=q,i=1;\u{1b}\\").utf8
        )
        view.feedSender.feed(byteArray: hostile[...])
        RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        #expect(delegate.sent.isEmpty)
    }

    @Test func forkPTYSpawnCannotEnterSocketCloseOnExecWindow() throws {
        let probe = ForkPTYDescriptorProbe()
        let spawnAttempted = DispatchSemaphore(value: 0)
        let spawnReturned = DispatchSemaphore(value: 0)
        let broker = try NativeDescriptorInheritanceGate.makeUnixStreamSocket {
            descriptor in
            DispatchQueue.global(qos: .userInitiated).async {
                spawnAttempted.signal()
                NativeDescriptorInheritanceGate.withProcessSpawnGate {
                    probe.start(checking: descriptor)
                }
                spawnReturned.signal()
            }
            #expect(spawnAttempted.wait(timeout: .now() + 2) == .success)
            // The real SwiftTerm forkpty call must still be blocked on the
            // process-wide gate while this descriptor lacks FD_CLOEXEC.
            #expect(spawnReturned.wait(timeout: .now() + 0.05) == .timedOut)
        }
        defer { Darwin.close(broker) }
        #expect(spawnReturned.wait(timeout: .now() + 2) == .success)
        let result = probe.waitForResult()
        #expect(result.exitCode == 0)
        #expect(result.output.contains("broker-fd-absent"))
        #expect(!result.output.contains("broker-fd-inherited"))
    }
}

private final class ForkPTYDescriptorProbe:
    LocalProcessDelegate, @unchecked Sendable
{
    private let lock = NSLock()
    private let terminated = DispatchSemaphore(value: 0)
    private lazy var process = LocalProcess(delegate: self)
    private var bytes = Data()
    private var exitCode: Int32?

    func start(checking descriptor: Int32) {
        process.startProcess(
            executable: "/usr/bin/python3",
            args: [
                "-I", "-c",
                "import fcntl,sys\n"
                    + "try: fcntl.fcntl(int(sys.argv[1]),fcntl.F_GETFD)\n"
                    + "except OSError: print('broker-fd-absent'); raise SystemExit(0)\n"
                    + "print('broker-fd-inherited'); raise SystemExit(91)",
                String(descriptor),
            ],
            environment: ["PATH=/usr/bin:/bin", "LANG=C"],
            currentDirectory: "/var/empty"
        )
    }

    func waitForResult() -> (output: String, exitCode: Int32?) {
        _ = terminated.wait(timeout: .now() + 5)
        return lock.withLock {
            (String(decoding: bytes, as: UTF8.self), exitCode)
        }
    }

    func processTerminated(_ source: LocalProcess, exitCode: Int32?) {
        lock.withLock { self.exitCode = exitCode }
        terminated.signal()
    }

    func processFailedToStart(_ source: LocalProcess, error: LocalProcessError) {
        lock.withLock {
            bytes.append(Data("launch-failed:\(error)".utf8))
            exitCode = -1
        }
        terminated.signal()
    }

    func dataReceived(slice: ArraySlice<UInt8>) {
        lock.withLock { bytes.append(contentsOf: slice) }
    }

    func getWindowSize() -> winsize {
        winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0)
    }
}

private final class TerminalReplyRecorder: TerminalDelegate {
    var sent: [[UInt8]] = []
    var iTermCallbacks = 0
    var clipboardCallbacks = 0

    func send(source: Terminal, data: ArraySlice<UInt8>) {
        sent.append(Array(data))
    }

    func iTermContent(source: Terminal, content: ArraySlice<UInt8>) {
        iTermCallbacks += 1
    }

    func clipboardCopy(source: Terminal, content: TerminalData) {
        clipboardCallbacks += 1
    }
}

@MainActor
private final class TerminalViewRecorder: TerminalViewDelegate {
    var sent: [[UInt8]] = []

    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {}
    func setTerminalTitle(source: TerminalView, title: String) {}
    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
    func send(source: TerminalView, data: ArraySlice<UInt8>) {
        sent.append(Array(data))
    }
    func scrolled(source: TerminalView, position: Double) {}
    func requestOpenLink(
        source: TerminalView, link: String, params: [String: String]
    ) {}
    func bell(source: TerminalView) {}
    func clipboardCopy(source: TerminalView, content: Data) {}
    func clipboardRead(source: TerminalView) -> Data? { nil }
    func kittyClipboardCapabilities(
        source: TerminalView
    ) -> KittyClipboardCapabilities { [] }
    func kittyClipboardAvailableMimeTypes(
        source: TerminalView, location: KittyClipboardLocation
    ) -> [String]? { [] }
    func kittyClipboardRead(
        source: TerminalView, location: KittyClipboardLocation,
        mimeType: String
    ) -> KittyClipboardReadResult? { nil }
    func kittyClipboardWrite(
        source: TerminalView, location: KittyClipboardLocation,
        content: KittyClipboardWriteContent
    ) -> KittyClipboardWriteResult { .unsupported }
    func kittyClipboardRequestPermission(
        source: TerminalView, request: KittyClipboardPermissionRequest
    ) -> KittyClipboardPermissionResult { .deny }
    func iTermContent(
        source: TerminalView, content: ArraySlice<UInt8>
    ) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}
