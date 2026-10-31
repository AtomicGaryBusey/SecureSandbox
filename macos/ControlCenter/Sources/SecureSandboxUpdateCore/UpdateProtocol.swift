import CryptoKit
import Foundation

public enum UpdateProtocolError: Error, Equatable, LocalizedError {
    case malformed(String)
    case policyDisabled(String)
    case signatureInvalid
    case rollback(current: UInt64, offered: UInt64)
    case incompatible(String)
    case digestMismatch
    case sizeMismatch

    public var errorDescription: String? {
        switch self {
        case .malformed(let reason): "Invalid update data: \(reason)"
        case .policyDisabled(let reason): "Updates are not provisioned: \(reason)"
        case .signatureInvalid: "The update signature is invalid."
        case .rollback(let current, let offered):
            "The offered release sequence \(offered) does not advance the installed sequence \(current)."
        case .incompatible(let reason): "The update is incompatible: \(reason)"
        case .digestMismatch: "The downloaded artifact digest does not match the signed manifest."
        case .sizeMismatch: "The downloaded artifact size does not match the signed manifest."
        }
    }
}

public struct UpdatePolicy: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-update-policy-v1"

    public let schema: String
    public let enabled: Bool
    public let disabledReason: String?
    public let channel: String
    public let manifestURL: URL?
    public let keyID: String?
    public let publicKeyBase64: String?
    public let artifactOrigin: URL?
    public let artifactRedirectHosts: [String]
    public let teamIdentifier: String?
    public let bundleIdentifier: String
    public let maximumManifestBytes: Int
    public let maximumArtifactBytes: Int64

    enum CodingKeys: String, CodingKey {
        case schema, enabled, channel
        case disabledReason = "disabled_reason"
        case manifestURL = "manifest_url"
        case keyID = "key_id"
        case publicKeyBase64 = "public_key_base64"
        case artifactOrigin = "artifact_origin"
        case artifactRedirectHosts = "artifact_redirect_hosts"
        case teamIdentifier = "team_identifier"
        case bundleIdentifier = "bundle_identifier"
        case maximumManifestBytes = "maximum_manifest_bytes"
        case maximumArtifactBytes = "maximum_artifact_bytes"
    }

    public init(
        schema: String,
        enabled: Bool,
        disabledReason: String?,
        channel: String,
        manifestURL: URL?,
        keyID: String?,
        publicKeyBase64: String?,
        artifactOrigin: URL?,
        artifactRedirectHosts: [String],
        teamIdentifier: String?,
        bundleIdentifier: String,
        maximumManifestBytes: Int,
        maximumArtifactBytes: Int64
    ) {
        self.schema = schema
        self.enabled = enabled
        self.disabledReason = disabledReason
        self.channel = channel
        self.manifestURL = manifestURL
        self.keyID = keyID
        self.publicKeyBase64 = publicKeyBase64
        self.artifactOrigin = artifactOrigin
        self.artifactRedirectHosts = artifactRedirectHosts
        self.teamIdentifier = teamIdentifier
        self.bundleIdentifier = bundleIdentifier
        self.maximumManifestBytes = maximumManifestBytes
        self.maximumArtifactBytes = maximumArtifactBytes
    }

    public func validate() throws {
        guard schema == Self.schema else { throw UpdateProtocolError.malformed("policy schema") }
        guard channel.range(of: #"^[a-z0-9-]{1,32}$"#, options: .regularExpression) != nil else {
            throw UpdateProtocolError.malformed("channel")
        }
        guard bundleIdentifier == "org.zebeth.SecureSandbox.ControlCenter" else {
            throw UpdateProtocolError.malformed("bundle identifier")
        }
        guard (1...131_072).contains(maximumManifestBytes),
              (1...536_870_912).contains(maximumArtifactBytes) else {
            throw UpdateProtocolError.malformed("resource bounds")
        }
        guard enabled else {
            throw UpdateProtocolError.policyDisabled(disabledReason ?? "release trust root unavailable")
        }
        guard let manifestURL, manifestURL.scheme == "https", manifestURL.user == nil,
              manifestURL.password == nil, manifestURL.query == nil, manifestURL.fragment == nil,
              let artifactOrigin, artifactOrigin.scheme == "https", artifactOrigin.path.isEmpty,
              artifactOrigin.user == nil, artifactOrigin.password == nil,
              (1...8).contains(artifactRedirectHosts.count),
              Set(artifactRedirectHosts).count == artifactRedirectHosts.count,
              artifactRedirectHosts.allSatisfy({ host in
                  host.range(of: #"^[a-z0-9.-]{1,253}$"#, options: .regularExpression) != nil
              }),
              artifactRedirectHosts.contains(artifactOrigin.host ?? ""),
              let keyID, keyID.range(of: #"^[A-Za-z0-9._-]{1,64}$"#, options: .regularExpression) != nil,
              let publicKeyBase64, let key = Data(base64Encoded: publicKeyBase64), key.count == 32,
              let teamIdentifier,
              teamIdentifier.range(of: #"^[A-Z0-9]{10}$"#, options: .regularExpression) != nil else {
            throw UpdateProtocolError.malformed("enabled policy trust fields")
        }
    }
}

public struct SignedUpdateEnvelope: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-update-envelope-v1"

    public let schema: String
    public let keyID: String
    public let payloadBase64: String
    public let signatureBase64: String

    enum CodingKeys: String, CodingKey {
        case schema
        case keyID = "key_id"
        case payloadBase64 = "payload_base64"
        case signatureBase64 = "signature_base64"
    }

    public init(schema: String, keyID: String, payloadBase64: String, signatureBase64: String) {
        self.schema = schema
        self.keyID = keyID
        self.payloadBase64 = payloadBase64
        self.signatureBase64 = signatureBase64
    }
}

public struct UpdateManifest: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-control-center-update-manifest-v1"

    public let schema: String
    public let channel: String
    public let sequence: UInt64
    public let version: String
    public let build: UInt64
    public let publishedAt: String
    public let minimumMacOS: String
    public let minimumCurrentSequence: UInt64
    public let releaseCommit: String
    public let artifact: UpdateArtifact
    public let security: UpdateSecurityImpact
    public let compatibility: UpdateCompatibility

    enum CodingKeys: String, CodingKey {
        case schema, channel, sequence, version, build, artifact, security, compatibility
        case publishedAt = "published_at"
        case minimumMacOS = "minimum_macos"
        case minimumCurrentSequence = "minimum_current_sequence"
        case releaseCommit = "release_commit"
    }
}

public struct UpdateArtifact: Codable, Equatable, Sendable {
    public let url: URL
    public let size: Int64
    public let sha256: String
}

public struct UpdateSecurityImpact: Codable, Equatable, Sendable {
    public let classification: String
    public let summary: String
}

public struct UpdateCompatibility: Codable, Equatable, Sendable {
    public let controlCenter: String
    public let protectedEnvironment: String

    enum CodingKeys: String, CodingKey {
        case controlCenter = "control_center"
        case protectedEnvironment = "protected_environment"
    }
}

public struct InstalledUpdateIdentity: Equatable, Sendable {
    public let sequence: UInt64
    public let version: String
    public let build: UInt64
    public let macOSMajor: Int

    public init(sequence: UInt64, version: String, build: UInt64, macOSMajor: Int) {
        self.sequence = sequence
        self.version = version
        self.build = build
        self.macOSMajor = macOSMajor
    }
}

public struct VerifiedUpdate: Equatable, Sendable {
    public let manifest: UpdateManifest
    public let envelopeDigest: String
    public let payload: Data
}

public enum UpdateTrigger: Sendable {
    case scheduled
    case manualCheck
    case manualDownload
    case touchIDInstall
}

public enum UpdateCapability: Equatable, Hashable, Sendable {
    case fetchSignedMetadata
    case fetchArtifact
    case installVerifiedArtifact
}

public enum UpdateAuthority {
    public static func capabilities(for trigger: UpdateTrigger) -> Set<UpdateCapability> {
        switch trigger {
        case .scheduled, .manualCheck: [.fetchSignedMetadata]
        case .manualDownload: [.fetchArtifact]
        case .touchIDInstall: [.installVerifiedArtifact]
        }
    }
}

public enum UpdateVerifier {
    private static let envelopeKeys: Set<String> = ["schema", "key_id", "payload_base64", "signature_base64"]
    private static let manifestKeys: Set<String> = [
        "schema", "channel", "sequence", "version", "build", "published_at", "minimum_macos",
        "minimum_current_sequence", "release_commit", "artifact", "security", "compatibility",
    ]

    public static func verifyEnvelope(
        _ data: Data,
        policy: UpdatePolicy,
        installed: InstalledUpdateIdentity
    ) throws -> VerifiedUpdate {
        try policy.validate()
        guard data.count <= policy.maximumManifestBytes else {
            throw UpdateProtocolError.malformed("manifest exceeds policy bound")
        }
        try requireExactKeys(data, expected: envelopeKeys, label: "envelope")
        let decoder = JSONDecoder()
        let envelope: SignedUpdateEnvelope
        do { envelope = try decoder.decode(SignedUpdateEnvelope.self, from: data) }
        catch { throw UpdateProtocolError.malformed("envelope JSON") }
        guard envelope.schema == SignedUpdateEnvelope.schema, envelope.keyID == policy.keyID,
              let payload = Data(base64Encoded: envelope.payloadBase64),
              let signature = Data(base64Encoded: envelope.signatureBase64), signature.count == 64,
              let keyData = Data(base64Encoded: policy.publicKeyBase64 ?? "") else {
            throw UpdateProtocolError.malformed("envelope fields")
        }
        let key: Curve25519.Signing.PublicKey
        do { key = try Curve25519.Signing.PublicKey(rawRepresentation: keyData) }
        catch { throw UpdateProtocolError.malformed("public key") }
        guard key.isValidSignature(signature, for: payload) else {
            throw UpdateProtocolError.signatureInvalid
        }
        try requireExactKeys(payload, expected: manifestKeys, label: "manifest")
        let manifest: UpdateManifest
        do { manifest = try decoder.decode(UpdateManifest.self, from: payload) }
        catch { throw UpdateProtocolError.malformed("manifest JSON") }
        try validate(manifest, policy: policy, installed: installed)
        return VerifiedUpdate(
            manifest: manifest,
            envelopeDigest: sha256(data),
            payload: payload
        )
    }

    public static func verifyArtifact(_ data: Data, manifest: UpdateManifest) throws {
        guard Int64(data.count) == manifest.artifact.size else { throw UpdateProtocolError.sizeMismatch }
        guard sha256(data) == manifest.artifact.sha256 else { throw UpdateProtocolError.digestMismatch }
    }

    public static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func validate(
        _ manifest: UpdateManifest,
        policy: UpdatePolicy,
        installed: InstalledUpdateIdentity
    ) throws {
        guard manifest.schema == UpdateManifest.schema, manifest.channel == policy.channel else {
            throw UpdateProtocolError.malformed("manifest schema or channel")
        }
        guard manifest.sequence > installed.sequence else {
            throw UpdateProtocolError.rollback(current: installed.sequence, offered: manifest.sequence)
        }
        guard manifest.minimumCurrentSequence <= installed.sequence else {
            throw UpdateProtocolError.incompatible("the installed release is too old for direct update")
        }
        guard manifest.version.range(of: #"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$"#, options: .regularExpression) != nil,
              manifest.build > 0,
              manifest.releaseCommit.range(of: #"^[0-9a-f]{40}$"#, options: .regularExpression) != nil,
              manifest.artifact.size > 0,
              manifest.artifact.size <= policy.maximumArtifactBytes,
              manifest.artifact.sha256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
              manifest.security.classification.range(of: #"^(none|maintenance|security|critical-security)$"#, options: .regularExpression) != nil,
              (1...2_000).contains(manifest.security.summary.utf8.count),
              (1...2_000).contains(manifest.compatibility.controlCenter.utf8.count),
              (1...2_000).contains(manifest.compatibility.protectedEnvironment.utf8.count) else {
            throw UpdateProtocolError.malformed("manifest values")
        }
        guard let origin = policy.artifactOrigin,
              manifest.artifact.url.scheme == "https",
              manifest.artifact.url.user == nil,
              manifest.artifact.url.password == nil,
              manifest.artifact.url.fragment == nil,
              manifest.artifact.url.scheme == origin.scheme,
              manifest.artifact.url.host == origin.host,
              manifest.artifact.url.port == origin.port else {
            throw UpdateProtocolError.malformed("artifact origin")
        }
        let minimumComponents = manifest.minimumMacOS.split(separator: ".")
        guard let minimumMajorText = minimumComponents.first,
              let minimumMajor = Int(minimumMajorText), minimumMajor <= installed.macOSMajor else {
            throw UpdateProtocolError.incompatible("requires macOS \(manifest.minimumMacOS)")
        }
        guard ISO8601DateFormatter().date(from: manifest.publishedAt) != nil else {
            throw UpdateProtocolError.malformed("published timestamp")
        }
    }

    private static func requireExactKeys(_ data: Data, expected: Set<String>, label: String) throws {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let dictionary = object as? [String: Any], Set(dictionary.keys) == expected else {
            throw UpdateProtocolError.malformed("unknown or missing \(label) fields")
        }
        if label == "manifest" {
            guard exactKeys(dictionary["artifact"], ["url", "size", "sha256"]),
                  exactKeys(dictionary["security"], ["classification", "summary"]),
                  exactKeys(dictionary["compatibility"], ["control_center", "protected_environment"]) else {
                throw UpdateProtocolError.malformed("unknown or missing nested manifest fields")
            }
        }
    }

    private static func exactKeys(_ object: Any?, _ expected: Set<String>) -> Bool {
        guard let dictionary = object as? [String: Any] else { return false }
        return Set(dictionary.keys) == expected
    }
}
