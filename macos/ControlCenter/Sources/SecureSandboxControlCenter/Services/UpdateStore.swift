import AppKit
import Foundation
import Observation
import SecureSandboxUpdateCore
import UserNotifications

enum ControlCenterUpdateState: Equatable {
    case idle
    case checking
    case unavailable(String)
    case current
    case available
    case downloading
    case downloaded
    case installing
    case rejected(String)
}

@MainActor
@Observable
final class UpdateStore {
    private(set) var state: ControlCenterUpdateState = .idle
    private(set) var verifiedUpdate: VerifiedUpdate?
    private(set) var lastCheckedAt: Date?
    private var envelopeData: Data?

    var installedVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
        return "\(version) (\(build))"
    }

    var automaticInstallInvariant: String {
        "Automatic download and installation are not implemented and cannot be enabled."
    }

    var hasRetainedRollback: Bool {
        FileManager.default.fileExists(atPath: UpdatePaths.previousApp.path)
    }

    func automaticCheckIfDue() async {
        guard UserDefaults.standard.bool(forKey: "automaticUpdateChecks") else { return }
        let previous = UserDefaults.standard.object(forKey: "lastAutomaticUpdateCheck") as? Date
        guard previous == nil || Date().timeIntervalSince(previous!) >= 86_400 else { return }
        await check(trigger: .scheduled)
        UserDefaults.standard.set(Date(), forKey: "lastAutomaticUpdateCheck")
        if state == .available { await notifyAvailableUpdate() }
    }

    func requestNotificationPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge])
    }

    func check(trigger: UpdateTrigger = .manualCheck) async {
        guard UpdateAuthority.capabilities(for: trigger) == [.fetchSignedMetadata] else {
            state = .rejected("The requested operation is not a metadata-only check.")
            return
        }
        state = .checking
        verifiedUpdate = nil
        envelopeData = nil
        do {
            let policy = try loadPolicy()
            try policy.validate()
            guard let manifestURL = policy.manifestURL else {
                throw UpdateProtocolError.malformed("manifest URL")
            }
            let request = URLRequest(
                url: manifestURL,
                cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                timeoutInterval: 20
            )
            let envelope = try await BoundedMetadataFetcher.fetch(request, maximumBytes: policy.maximumManifestBytes)
            let verified = try UpdateVerifier.verifyEnvelope(
                envelope,
                policy: policy,
                installed: try installedIdentity()
            )
            envelopeData = envelope
            verifiedUpdate = verified
            lastCheckedAt = Date()
            state = .available
        } catch UpdateProtocolError.rollback(let current, let offered) {
            lastCheckedAt = Date()
            state = offered == current ? .current : .rejected("Signed rollback rejected: sequence \(offered) is below floor \(current).")
        } catch UpdateProtocolError.policyDisabled(let reason) {
            state = .unavailable(reason)
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func download() async {
        guard UpdateAuthority.capabilities(for: .manualDownload) == [.fetchArtifact],
              state == .available, let verified = verifiedUpdate, let envelopeData else {
            state = .rejected("No manually reviewed signed update is ready to download.")
            return
        }
        state = .downloading
        do {
            let policy = try loadPolicy()
            try policy.validate()
            try UpdateFileSecurity.write(envelopeData, to: UpdatePaths.envelope)
            let temporary = UpdatePaths.stateDirectory.appendingPathComponent("artifact-\(UUID().uuidString).download")
            defer { try? FileManager.default.removeItem(at: temporary) }
            try await BoundedArtifactFetcher.fetch(
                verified.manifest.artifact.url,
                to: temporary,
                maximumBytes: policy.maximumArtifactBytes,
                redirectHosts: Set(policy.artifactRedirectHosts)
            )
            let artifact = try UpdateFileSecurity.sha256File(temporary, maximumBytes: policy.maximumArtifactBytes)
            guard artifact.size == verified.manifest.artifact.size else { throw UpdateProtocolError.sizeMismatch }
            guard artifact.digest == verified.manifest.artifact.sha256 else { throw UpdateProtocolError.digestMismatch }
            try replacePendingArtifact(with: temporary)
            try await stageCandidate(verified: verified, policy: policy)
            state = .downloaded
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func install() async {
        guard UpdateAuthority.capabilities(for: .touchIDInstall) == [.installVerifiedArtifact],
              state == .downloaded, let verified = verifiedUpdate else {
            state = .rejected("No verified manually downloaded update is ready to install.")
            return
        }
        guard Bundle.main.bundleURL.standardizedFileURL == UpdatePaths.installedApp.standardizedFileURL else {
            state = .rejected("Install is available only from ~/Applications/SecureSandbox.app.")
            return
        }
        do {
            let request = UpdateInstallRequest(verified: verified)
            try UpdateFileSecurity.writeJSON(request, to: UpdatePaths.request)
            state = .installing
            try launchHelper("--apply")
            NSApp.terminate(nil)
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func rollback() async {
        guard FileManager.default.fileExists(atPath: UpdatePaths.previousApp.path) else {
            state = .rejected("No retained accepted predecessor is available.")
            return
        }
        do {
            state = .installing
            try launchHelper("--rollback")
            NSApp.terminate(nil)
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    private func installedIdentity() throws -> InstalledUpdateIdentity {
        var identity = try UpdateBundleVerifier.identity(at: Bundle.main.bundleURL)
        if FileManager.default.fileExists(atPath: UpdatePaths.sequenceFloor.path) {
            try UpdateFileSecurity.requireExactJSONKeys(
                UpdatePaths.sequenceFloor,
                expected: ["schema", "sequence", "accepted_envelope_digest"]
            )
            let floor = try UpdateFileSecurity.read(UpdateSequenceFloor.self, from: UpdatePaths.sequenceFloor)
            guard floor.schema == UpdateSequenceFloor.schema,
                  floor.acceptedEnvelopeDigest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
                throw UpdateProtocolError.malformed("sequence floor")
            }
            identity = InstalledUpdateIdentity(
                sequence: max(identity.sequence, floor.sequence),
                version: identity.version,
                build: identity.build,
                macOSMajor: identity.macOSMajor
            )
        }
        return identity
    }

    private func loadPolicy() throws -> UpdatePolicy {
        guard let url = Bundle.main.url(forResource: "UpdatePolicy", withExtension: "json") else {
            throw UpdateProtocolError.malformed("signed update policy is missing")
        }
        let data = try Data(contentsOf: url)
        guard data.count <= 65_536 else { throw UpdateProtocolError.malformed("policy exceeds bound") }
        return try JSONDecoder().decode(UpdatePolicy.self, from: data)
    }

    private func replacePendingArtifact(with temporary: URL) throws {
        try UpdateFileSecurity.prepareStateDirectory()
        if FileManager.default.fileExists(atPath: UpdatePaths.artifact.path) {
            try UpdateFileSecurity.requireOwnedRegular(UpdatePaths.artifact, directory: false)
            try FileManager.default.removeItem(at: UpdatePaths.artifact)
        }
        try FileManager.default.moveItem(at: temporary, to: UpdatePaths.artifact)
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: UpdatePaths.artifact.path)
    }

    private func stageCandidate(verified: VerifiedUpdate, policy: UpdatePolicy) async throws {
        try await Task.detached {
            try UpdateFileSecurity.prepareStateDirectory()
            guard !FileManager.default.fileExists(atPath: UpdatePaths.candidateApp.path) else {
                throw UpdateProtocolError.malformed("a prior candidate requires inspection")
            }
            let extraction = UpdatePaths.applications.appendingPathComponent(".SecureSandbox.extract.\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: extraction, withIntermediateDirectories: false, attributes: [
                .posixPermissions: NSNumber(value: 0o700),
            ])
            defer { try? FileManager.default.removeItem(at: extraction) }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
            process.arguments = ["-x", "-k", UpdatePaths.artifact.path, extraction.path]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                throw UpdateProtocolError.malformed("artifact extraction failed")
            }
            let entries = try FileManager.default.contentsOfDirectory(atPath: extraction.path)
            guard entries == ["SecureSandbox.app"] else {
                throw UpdateProtocolError.malformed("artifact must contain exactly SecureSandbox.app")
            }
            let extracted = extraction.appendingPathComponent("SecureSandbox.app", isDirectory: true)
            try UpdateBundleVerifier.verifyDistributionApp(extracted, policy: policy, manifest: verified.manifest)
            try FileManager.default.moveItem(at: extracted, to: UpdatePaths.candidateApp)
        }.value
    }

    private func launchHelper(_ operation: String) throws {
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/SecureSandboxUpdateInstaller")
        try UpdateFileSecurity.requireOwnedRegular(helper, directory: false)
        let process = Process()
        process.executableURL = helper
        process.arguments = [operation, String(ProcessInfo.processInfo.processIdentifier)]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
    }

    private func notifyAvailableUpdate() async {
        guard let update = verifiedUpdate else { return }
        let content = UNMutableNotificationContent()
        content.title = "SecureSandbox update available"
        content.body = "Version \(update.manifest.version) is ready for review. It will not download or install automatically."
        let request = UNNotificationRequest(identifier: "secure-sandbox-update-\(update.manifest.sequence)", content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }
}

enum UpdateHealthCommitter {
    static func commitIfAwaitingHealth() {
        guard Bundle.main.bundleURL.standardizedFileURL == UpdatePaths.installedApp.standardizedFileURL,
              let journal = try? UpdateFileSecurity.read(UpdateInstallJournal.self, from: UpdatePaths.journal),
              journal.schema == UpdateInstallJournal.schema,
              journal.phase == "awaiting_health",
              let identity = try? UpdateBundleVerifier.identity(at: Bundle.main.bundleURL),
              identity.sequence == journal.sequence,
              identity.version == journal.version,
              identity.build == journal.build else { return }
        try? UpdateFileSecurity.writeJSON(UpdateInstallHealth(journal: journal), to: UpdatePaths.health)
    }
}

private final class MetadataDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let maximumBytes: Int
    private let lock = NSLock()
    private var data = Data()
    private var continuation: CheckedContinuation<Data, Error>?
    private var completed = false

    init(maximumBytes: Int, continuation: CheckedContinuation<Data, Error>) {
        self.maximumBytes = maximumBytes
        self.continuation = continuation
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) { completionHandler(nil) }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              response.expectedContentLength <= Int64(maximumBytes) else {
            completionHandler(.cancel)
            finish(.failure(UpdateProtocolError.malformed("metadata HTTP response")))
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        lock.lock()
        data.append(bytes)
        let tooLarge = data.count > maximumBytes
        lock.unlock()
        if tooLarge {
            dataTask.cancel()
            finish(.failure(UpdateProtocolError.malformed("metadata exceeds bound")))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        if let error { finish(.failure(error)) }
        else {
            lock.lock(); let result = data; lock.unlock()
            finish(.success(result))
        }
        session.finishTasksAndInvalidate()
    }

    private func finish(_ result: Result<Data, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let callback = continuation
        continuation = nil
        lock.unlock()
        callback?.resume(with: result)
    }
}

private enum BoundedMetadataFetcher {
    static func fetch(_ request: URLRequest, maximumBytes: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpShouldSetCookies = false
            configuration.urlCache = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            let delegate = MetadataDelegate(maximumBytes: maximumBytes, continuation: continuation)
            let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
            session.dataTask(with: request).resume()
        }
    }
}

private final class ArtifactDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let destination: URL
    private let maximumBytes: Int64
    private let redirectHosts: Set<String>
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var completed = false
    private var redirects = 0

    init(destination: URL, maximumBytes: Int64, redirectHosts: Set<String>, continuation: CheckedContinuation<Void, Error>) {
        self.destination = destination
        self.maximumBytes = maximumBytes
        self.redirectHosts = redirectHosts
        self.continuation = continuation
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        lock.lock()
        redirects += 1
        let count = redirects
        lock.unlock()
        guard count <= 3, let url = request.url,
              url.scheme == "https", let host = url.host,
              redirectHosts.contains(host), url.user == nil, url.password == nil,
              url.fragment == nil else {
            completionHandler(nil)
            finish(.failure(UpdateProtocolError.malformed("artifact redirect rejected")))
            return
        }
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        if totalBytesWritten > maximumBytes || totalBytesExpectedToWrite > maximumBytes {
            downloadTask.cancel()
            finish(.failure(UpdateProtocolError.sizeMismatch))
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        do {
            guard let response = downloadTask.response as? HTTPURLResponse, response.statusCode == 200 else {
                throw UpdateProtocolError.malformed("artifact HTTP response")
            }
            try FileManager.default.moveItem(at: location, to: destination)
            try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: destination.path)
            finish(.success(()))
        } catch { finish(.failure(error)) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        if let error { finish(.failure(error)) }
        session.finishTasksAndInvalidate()
    }

    private func finish(_ result: Result<Void, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let callback = continuation
        continuation = nil
        lock.unlock()
        callback?.resume(with: result)
    }
}

private enum BoundedArtifactFetcher {
    static func fetch(_ url: URL, to destination: URL, maximumBytes: Int64, redirectHosts: Set<String>) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpShouldSetCookies = false
            configuration.urlCache = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            configuration.timeoutIntervalForRequest = 30
            configuration.timeoutIntervalForResource = 600
            let delegate = ArtifactDelegate(
                destination: destination,
                maximumBytes: maximumBytes,
                redirectHosts: redirectHosts,
                continuation: continuation
            )
            let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
            session.downloadTask(with: url).resume()
        }
    }
}
