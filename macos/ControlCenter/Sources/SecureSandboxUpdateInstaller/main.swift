import Darwin
import Foundation
import LocalAuthentication
import SecureSandboxUpdateCore

private enum InstallerFailure: Error, LocalizedError {
    case usage
    case invalidRequest(String)
    case timeout

    var errorDescription: String? {
        switch self {
        case .usage: "usage: SecureSandboxUpdateInstaller --apply PARENT_PID | --rollback PARENT_PID"
        case .invalidRequest(let reason): "update request rejected: \(reason)"
        case .timeout: "the candidate did not report healthy startup"
        }
    }
}

@main
struct SecureSandboxUpdateInstaller {
    static func main() async {
        do {
            try await run()
        } catch {
            FileHandle.standardError.write(Data("SecureSandbox updater: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    private static func run() async throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 3, let parent = pid_t(arguments[2]), parent > 1 else {
            throw InstallerFailure.usage
        }
        let policy = try loadPolicy()
        try policy.validate()
        switch arguments[1] {
        case "--apply": try await apply(parent: parent, policy: policy)
        case "--rollback": try await rollback(parent: parent, policy: policy)
        default: throw InstallerFailure.usage
        }
    }

    private static func apply(parent: pid_t, policy: UpdatePolicy) async throws {
        try UpdateFileSecurity.prepareStateDirectory()
        let envelopeData = try boundedData(UpdatePaths.envelope, maximum: policy.maximumManifestBytes)
        var installed = try UpdateBundleVerifier.identity(at: UpdatePaths.installedApp)
        if FileManager.default.fileExists(atPath: UpdatePaths.sequenceFloor.path) {
            try UpdateFileSecurity.requireExactJSONKeys(
                UpdatePaths.sequenceFloor,
                expected: ["schema", "sequence", "accepted_envelope_digest"]
            )
            let floor = try UpdateFileSecurity.read(UpdateSequenceFloor.self, from: UpdatePaths.sequenceFloor)
            guard floor.schema == UpdateSequenceFloor.schema,
                  floor.acceptedEnvelopeDigest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
                throw InstallerFailure.invalidRequest("sequence floor is malformed")
            }
            installed = InstalledUpdateIdentity(
                sequence: max(installed.sequence, floor.sequence),
                version: installed.version,
                build: installed.build,
                macOSMajor: installed.macOSMajor
            )
        }
        let verified = try UpdateVerifier.verifyEnvelope(envelopeData, policy: policy, installed: installed)
        try UpdateFileSecurity.requireExactJSONKeys(
            UpdatePaths.request,
            expected: ["schema", "nonce", "envelope_digest", "sequence", "version", "build", "authorized_at"]
        )
        let request = try UpdateFileSecurity.read(UpdateInstallRequest.self, from: UpdatePaths.request)
        try validate(request: request, verified: verified)
        let artifact = try UpdateFileSecurity.sha256File(UpdatePaths.artifact, maximumBytes: policy.maximumArtifactBytes)
        guard artifact.size == verified.manifest.artifact.size else { throw UpdateProtocolError.sizeMismatch }
        guard artifact.digest == verified.manifest.artifact.sha256 else { throw UpdateProtocolError.digestMismatch }
        try UpdateBundleVerifier.verifyDistributionApp(UpdatePaths.candidateApp, policy: policy, manifest: verified.manifest)
        try UpdateBundleVerifier.verifyDistributionSignature(UpdatePaths.installedApp, policy: policy)
        try await requireTouchID(
            "Install SecureSandbox \(verified.manifest.version) sequence \(verified.manifest.sequence), manifest \(verified.envelopeDigest.prefix(16))"
        )

        var journal = UpdateInstallJournal(request: request, phase: "verified_waiting_for_exit")
        try UpdateFileSecurity.writeJSON(journal, to: UpdatePaths.journal)
        try waitForExit(parent, seconds: 60)
        try retirePreviousIfPresent(policy: policy)

        journal.phase = "swapping"
        journal.updatedAt = ISO8601DateFormatter().string(from: Date())
        try UpdateFileSecurity.writeJSON(journal, to: UpdatePaths.journal)
        guard renameatx_np(
            AT_FDCWD, UpdatePaths.candidateApp.path,
            AT_FDCWD, UpdatePaths.installedApp.path,
            UInt32(RENAME_SWAP)
        ) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try FileManager.default.moveItem(at: UpdatePaths.candidateApp, to: UpdatePaths.previousApp)

        journal.phase = "awaiting_health"
        journal.updatedAt = ISO8601DateFormatter().string(from: Date())
        try UpdateFileSecurity.writeJSON(journal, to: UpdatePaths.journal)
        try? FileManager.default.removeItem(at: UpdatePaths.health)
        try launch(UpdatePaths.installedApp)
        do {
            try waitForHealth(journal, seconds: 30)
            journal.phase = "accepted"
            journal.updatedAt = ISO8601DateFormatter().string(from: Date())
            try UpdateFileSecurity.writeJSON(journal, to: UpdatePaths.journal)
            try UpdateFileSecurity.writeJSON(
                UpdateSequenceFloor(sequence: journal.sequence, acceptedEnvelopeDigest: journal.envelopeDigest),
                to: UpdatePaths.sequenceFloor
            )
            try? FileManager.default.removeItem(at: UpdatePaths.artifact)
            try? FileManager.default.removeItem(at: UpdatePaths.request)
        } catch {
            try? terminateControlCenter()
            try rollbackFailedCandidate(journal: &journal)
            try launch(UpdatePaths.installedApp)
            throw error
        }
    }

    private static func rollback(parent: pid_t, policy: UpdatePolicy) async throws {
        try UpdateFileSecurity.requireExactJSONKeys(
            UpdatePaths.journal,
            expected: ["schema", "nonce", "envelope_digest", "sequence", "version", "build", "phase", "updated_at"]
        )
        let journal = try UpdateFileSecurity.read(UpdateInstallJournal.self, from: UpdatePaths.journal)
        guard journal.schema == UpdateInstallJournal.schema, journal.phase == "accepted" else {
            throw InstallerFailure.invalidRequest("no accepted update is available for rollback")
        }
        try UpdateFileSecurity.requireOwnedRegular(UpdatePaths.previousApp, directory: true)
        try UpdateBundleVerifier.requireSafeTree(UpdatePaths.previousApp, maximumEntries: 30_000)
        let previousIdentity = try UpdateBundleVerifier.identity(at: UpdatePaths.previousApp)
        guard previousIdentity.sequence < journal.sequence else {
            throw InstallerFailure.invalidRequest("rollback target does not precede the accepted update")
        }
        try UpdateBundleVerifier.verifyDistributionSignature(UpdatePaths.previousApp, policy: policy)
        try await requireTouchID(
            "Roll back SecureSandbox to \(previousIdentity.version) sequence \(previousIdentity.sequence)"
        )
        try waitForExit(parent, seconds: 60)
        guard renameatx_np(
            AT_FDCWD, UpdatePaths.previousApp.path,
            AT_FDCWD, UpdatePaths.installedApp.path,
            UInt32(RENAME_SWAP)
        ) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var rolledBack = journal
        rolledBack.phase = "operator_rollback"
        rolledBack.updatedAt = ISO8601DateFormatter().string(from: Date())
        try UpdateFileSecurity.writeJSON(rolledBack, to: UpdatePaths.journal)
        try launch(UpdatePaths.installedApp)
    }

    private static func validate(request: UpdateInstallRequest, verified: VerifiedUpdate) throws {
        guard request.schema == UpdateInstallRequest.schema,
              request.envelopeDigest == verified.envelopeDigest,
              request.sequence == verified.manifest.sequence,
              request.version == verified.manifest.version,
              request.build == verified.manifest.build,
              let date = ISO8601DateFormatter().date(from: request.authorizedAt),
              abs(date.timeIntervalSinceNow) <= 180 else {
            throw InstallerFailure.invalidRequest("Touch ID authorization is missing, expired, or mismatched")
        }
    }

    private static func rollbackFailedCandidate(journal: inout UpdateInstallJournal) throws {
        guard FileManager.default.fileExists(atPath: UpdatePaths.previousApp.path),
              FileManager.default.fileExists(atPath: UpdatePaths.installedApp.path) else {
            throw InstallerFailure.invalidRequest("automatic rollback paths are incomplete")
        }
        guard renameatx_np(
            AT_FDCWD, UpdatePaths.previousApp.path,
            AT_FDCWD, UpdatePaths.installedApp.path,
            UInt32(RENAME_SWAP)
        ) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        if FileManager.default.fileExists(atPath: UpdatePaths.candidateApp.path) {
            throw InstallerFailure.invalidRequest("failed-candidate path is occupied")
        }
        try FileManager.default.moveItem(at: UpdatePaths.previousApp, to: UpdatePaths.candidateApp)
        journal.phase = "automatic_rollback"
        journal.updatedAt = ISO8601DateFormatter().string(from: Date())
        try UpdateFileSecurity.writeJSON(journal, to: UpdatePaths.journal)
    }

    private static func retirePreviousIfPresent(policy: UpdatePolicy) throws {
        guard FileManager.default.fileExists(atPath: UpdatePaths.previousApp.path) else { return }
        try UpdateFileSecurity.requireOwnedRegular(UpdatePaths.previousApp, directory: true)
        try UpdateBundleVerifier.requireSafeTree(UpdatePaths.previousApp, maximumEntries: 30_000)
        let identity = try UpdateBundleVerifier.identity(at: UpdatePaths.previousApp)
        guard identity.sequence > 0 else { throw InstallerFailure.invalidRequest("invalid retained rollback app") }
        try UpdateBundleVerifier.verifyDistributionSignature(UpdatePaths.previousApp, policy: policy)
        try FileManager.default.removeItem(at: UpdatePaths.previousApp)
    }

    private static func waitForExit(_ pid: pid_t, seconds: Int) throws {
        for _ in 0..<(seconds * 10) {
            if kill(pid, 0) != 0 && errno == ESRCH { return }
            usleep(100_000)
        }
        throw InstallerFailure.timeout
    }

    private static func waitForHealth(_ journal: UpdateInstallJournal, seconds: Int) throws {
        for _ in 0..<(seconds * 10) {
            if let health = try? UpdateFileSecurity.read(UpdateInstallHealth.self, from: UpdatePaths.health),
               health.schema == UpdateInstallHealth.schema,
               health.nonce == journal.nonce,
               health.envelopeDigest == journal.envelopeDigest,
               health.sequence == journal.sequence,
               health.version == journal.version,
               health.build == journal.build {
                return
            }
            usleep(100_000)
        }
        throw InstallerFailure.timeout
    }

    private static func launch(_ app: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = ["-n", app.path]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw InstallerFailure.invalidRequest("launch failed") }
    }

    private static func terminateControlCenter() throws {
        _ = try runProcess("/usr/bin/pkill", ["-x", "SecureSandboxControlCenter"])
    }

    private static func runProcess(_ path: String, _ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    private static func boundedData(_ url: URL, maximum: Int) throws -> Data {
        try UpdateFileSecurity.requireOwnedRegular(url, directory: false)
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        guard data.count <= maximum else { throw UpdateProtocolError.malformed("manifest exceeds bound") }
        return data
    }

    private static func loadPolicy() throws -> UpdatePolicy {
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        let contentsDirectory = executable.deletingLastPathComponent().deletingLastPathComponent()
        let policyURL = contentsDirectory.appendingPathComponent("Resources/UpdatePolicy.json")
        let data = try Data(contentsOf: policyURL)
        guard data.count <= 65_536 else { throw UpdateProtocolError.malformed("policy exceeds bound") }
        return try JSONDecoder().decode(UpdatePolicy.self, from: data)
    }

    private static func requireTouchID(_ reason: String) async throws {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.localizedFallbackTitle = ""
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw error ?? InstallerFailure.invalidRequest("Touch ID is unavailable")
        }
        guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
            throw InstallerFailure.invalidRequest("Touch ID was not approved")
        }
    }
}
