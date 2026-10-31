import CryptoKit
import Darwin
import Foundation

public struct UpdateInstallRequest: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-install-request-v1"
    public let schema: String
    public let nonce: UUID
    public let envelopeDigest: String
    public let sequence: UInt64
    public let version: String
    public let build: UInt64
    public let authorizedAt: String

    enum CodingKeys: String, CodingKey {
        case schema, nonce, sequence, version, build
        case envelopeDigest = "envelope_digest"
        case authorizedAt = "authorized_at"
    }

    public init(verified: VerifiedUpdate, nonce: UUID = UUID(), authorizedAt: Date = Date()) {
        schema = Self.schema
        self.nonce = nonce
        envelopeDigest = verified.envelopeDigest
        sequence = verified.manifest.sequence
        version = verified.manifest.version
        build = verified.manifest.build
        self.authorizedAt = ISO8601DateFormatter().string(from: authorizedAt)
    }
}

public struct UpdateInstallJournal: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-install-journal-v1"
    public let schema: String
    public let nonce: UUID
    public let envelopeDigest: String
    public let sequence: UInt64
    public let version: String
    public let build: UInt64
    public var phase: String
    public var updatedAt: String

    enum CodingKeys: String, CodingKey {
        case schema, nonce, sequence, version, build, phase
        case envelopeDigest = "envelope_digest"
        case updatedAt = "updated_at"
    }

    public init(request: UpdateInstallRequest, phase: String) {
        schema = Self.schema
        nonce = request.nonce
        envelopeDigest = request.envelopeDigest
        sequence = request.sequence
        version = request.version
        build = request.build
        self.phase = phase
        updatedAt = ISO8601DateFormatter().string(from: Date())
    }
}

public struct UpdateInstallHealth: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-install-health-v1"
    public let schema: String
    public let nonce: UUID
    public let envelopeDigest: String
    public let sequence: UInt64
    public let version: String
    public let build: UInt64
    public let healthyAt: String

    enum CodingKeys: String, CodingKey {
        case schema, nonce, sequence, version, build
        case envelopeDigest = "envelope_digest"
        case healthyAt = "healthy_at"
    }

    public init(journal: UpdateInstallJournal) {
        schema = Self.schema
        nonce = journal.nonce
        envelopeDigest = journal.envelopeDigest
        sequence = journal.sequence
        version = journal.version
        build = journal.build
        healthyAt = ISO8601DateFormatter().string(from: Date())
    }
}

public struct UpdateSequenceFloor: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-sequence-floor-v1"
    public let schema: String
    public let sequence: UInt64
    public let acceptedEnvelopeDigest: String

    enum CodingKeys: String, CodingKey {
        case schema, sequence
        case acceptedEnvelopeDigest = "accepted_envelope_digest"
    }

    public init(sequence: UInt64, acceptedEnvelopeDigest: String) {
        schema = Self.schema
        self.sequence = sequence
        self.acceptedEnvelopeDigest = acceptedEnvelopeDigest
    }
}

public enum UpdatePaths {
    public static var applications: URL {
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Applications", isDirectory: true)
    }
    public static var installedApp: URL { applications.appendingPathComponent("SecureSandbox.app", isDirectory: true) }
    public static var previousApp: URL { applications.appendingPathComponent(".SecureSandbox.previous.app", isDirectory: true) }
    public static var candidateApp: URL { applications.appendingPathComponent(".SecureSandbox.update-candidate.app", isDirectory: true) }
    public static var stateDirectory: URL {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/SecureSandbox/Updates", isDirectory: true)
    }
    public static var envelope: URL { stateDirectory.appendingPathComponent("pending-envelope.json") }
    public static var artifact: URL { stateDirectory.appendingPathComponent("pending-artifact.zip") }
    public static var request: URL { stateDirectory.appendingPathComponent("install-request.json") }
    public static var journal: URL { stateDirectory.appendingPathComponent("install-journal.json") }
    public static var health: URL { stateDirectory.appendingPathComponent("install-health.json") }
    public static var sequenceFloor: URL { stateDirectory.appendingPathComponent("sequence-floor.json") }
}

public enum UpdateFileSecurity {
    public static func prepareStateDirectory() throws {
        try prepareDirectory(UpdatePaths.stateDirectory)
        try prepareDirectory(UpdatePaths.applications, permissions: 0o755)
    }

    public static func prepareDirectory(_ url: URL, permissions: Int = 0o700) throws {
        let manager = FileManager.default
        if !manager.fileExists(atPath: url.path) {
            try manager.createDirectory(at: url, withIntermediateDirectories: true, attributes: [
                .posixPermissions: NSNumber(value: permissions),
            ])
        }
        try requireOwnedRegular(url, directory: true)
        try manager.setAttributes([.posixPermissions: NSNumber(value: permissions)], ofItemAtPath: url.path)
    }

    public static func requireOwnedRegular(_ url: URL, directory: Bool) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              info.st_uid == geteuid(),
              info.st_mode & mode_t(S_IFMT) == mode_t(directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o022 == 0,
              directory || info.st_nlink == 1 else {
            throw UpdateProtocolError.malformed("untrusted path: \(url.lastPathComponent)")
        }
    }

    public static func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        try write(data, to: url)
    }

    public static func write(_ data: Data, to url: URL) throws {
        try prepareStateDirectory()
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: temporary.path, contents: data, attributes: [
            .posixPermissions: NSNumber(value: 0o600),
        ]) else { throw UpdateProtocolError.malformed("cannot create update state") }
        if FileManager.default.fileExists(atPath: url.path) {
            try requireOwnedRegular(url, directory: false)
            guard rename(temporary.path, url.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } else {
            try FileManager.default.moveItem(at: temporary, to: url)
        }
    }

    public static func read<T: Decodable>(_ type: T.Type, from url: URL, maximumBytes: Int = 131_072) throws -> T {
        try requireOwnedRegular(url, directory: false)
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= maximumBytes else {
            throw UpdateProtocolError.malformed("state file exceeds bound")
        }
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url, options: .mappedIfSafe))
    }

    public static func requireExactJSONKeys(
        _ url: URL,
        expected: Set<String>,
        maximumBytes: Int = 131_072
    ) throws {
        try requireOwnedRegular(url, directory: false)
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        guard data.count <= maximumBytes,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == expected else {
            throw UpdateProtocolError.malformed("unknown or missing state fields")
        }
    }

    public static func sha256File(_ url: URL, maximumBytes: Int64) throws -> (digest: String, size: Int64) {
        try requireOwnedRegular(url, directory: false)
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        var total: Int64 = 0
        while true {
            let chunk = try handle.read(upToCount: 1_048_576) ?? Data()
            if chunk.isEmpty { break }
            total += Int64(chunk.count)
            guard total <= maximumBytes else { throw UpdateProtocolError.sizeMismatch }
            hasher.update(data: chunk)
        }
        return (hasher.finalize().map { String(format: "%02x", $0) }.joined(), total)
    }
}

public enum UpdateBundleVerifier {
    public static func identity(at app: URL) throws -> InstalledUpdateIdentity {
        let plistURL = app.appendingPathComponent("Contents/Info.plist")
        try UpdateFileSecurity.requireOwnedRegular(plistURL, directory: false)
        let data = try Data(contentsOf: plistURL)
        guard data.count <= 65_536,
              let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              plist["CFBundleIdentifier"] as? String == "org.zebeth.SecureSandbox.ControlCenter",
              let version = plist["CFBundleShortVersionString"] as? String,
              let buildText = plist["CFBundleVersion"] as? String,
              let build = UInt64(buildText),
              let sequenceNumber = plist["SSUpdateSequence"] as? NSNumber else {
            throw UpdateProtocolError.malformed("bundle identity")
        }
        return InstalledUpdateIdentity(
            sequence: sequenceNumber.uint64Value,
            version: version,
            build: build,
            macOSMajor: ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        )
    }

    public static func verifyDistributionApp(_ app: URL, policy: UpdatePolicy, manifest: UpdateManifest) throws {
        let identity = try identity(at: app)
        guard identity.sequence == manifest.sequence, identity.version == manifest.version,
              identity.build == manifest.build else {
            throw UpdateProtocolError.malformed("bundle and manifest versions disagree")
        }
        try verifyDistributionSignature(app, policy: policy)
    }

    public static func verifyDistributionSignature(_ app: URL, policy: UpdatePolicy) throws {
        try UpdateFileSecurity.requireOwnedRegular(app, directory: true)
        try requireSafeTree(app, maximumEntries: 30_000)
        let verify = try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
        guard verify.status == 0 else { throw UpdateProtocolError.malformed("code signature rejected") }
        let details = try run("/usr/bin/codesign", ["-dv", "--verbose=4", app.path])
        let text = String(decoding: details.stderr + details.stdout, as: UTF8.self)
        guard details.status == 0,
              text.contains("Identifier=\(policy.bundleIdentifier)"),
              text.contains("TeamIdentifier=\(policy.teamIdentifier ?? "")"),
              text.contains("Authority=Developer ID Application:"),
              text.contains("flags=0x10000(runtime)"),
              !text.contains("Signature=adhoc") else {
            throw UpdateProtocolError.malformed("Developer ID identity or hardened runtime missing")
        }
        let gatekeeper = try run("/usr/sbin/spctl", ["-a", "-t", "exec", "-vv", app.path])
        guard gatekeeper.status == 0 else { throw UpdateProtocolError.malformed("Gatekeeper rejected candidate") }
    }

    public static func requireSafeTree(_ root: URL, maximumEntries: Int) throws {
        let keys: [URLResourceKey] = [.isSymbolicLinkKey, .isRegularFileKey, .isDirectoryKey]
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: keys,
            options: []
        ) else { throw UpdateProtocolError.malformed("cannot enumerate candidate") }
        var count = 0
        while let item = enumerator.nextObject() as? URL {
            count += 1
            guard count <= maximumEntries else { throw UpdateProtocolError.malformed("candidate entry bound") }
            let values = try item.resourceValues(forKeys: Set(keys))
            guard values.isSymbolicLink != true,
                  values.isRegularFile == true || values.isDirectory == true else {
                throw UpdateProtocolError.malformed("candidate contains unsupported file type")
            }
            try UpdateFileSecurity.requireOwnedRegular(item, directory: values.isDirectory == true)
        }
    }

    private static func run(_ executable: String, _ arguments: [String]) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        let stdout = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = error.fileHandleForReading.readDataToEndOfFile()
        guard stdout.count + stderr.count <= 1_048_576 else {
            throw UpdateProtocolError.malformed("verification output bound")
        }
        return (process.terminationStatus, stdout, stderr)
    }
}
