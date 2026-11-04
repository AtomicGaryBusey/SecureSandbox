import CryptoKit
import Darwin
import Foundation

struct RootOwnedNativeProjectionPolicy: Codable, Sendable {
    static let schemaName = "secure-sandbox-native-projection-policy-v1"
    static let defaultURL = URL(
        fileURLWithPath:
            "/Library/Application Support/SecureSandbox/native-projection-policy.json"
    )
    static let defaultReleaseRoot = URL(
        fileURLWithPath: "/usr/local/libexec/secure-sandbox-host/releases",
        isDirectory: true
    )
    static let defaultCurrentURL = URL(
        fileURLWithPath: "/usr/local/libexec/secure-sandbox-host/current"
    )
    static let defaultResearchReadbackURL = URL(
        fileURLWithPath:
            "/usr/local/var/lib/secure-sandbox/native-research-projection-readback.json"
    )

    let schema: String
    let executablePath: String
    let executableSHA256: String
    let hostReleaseID: String
    let researchReleaseID: String
    let researchIsolationAttestationSHA256: String
    let policySHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case executablePath = "executable_path"
        case executableSHA256 = "executable_sha256"
        case hostReleaseID = "host_release_id"
        case researchReleaseID = "research_release_id"
        case researchIsolationAttestationSHA256 =
            "research_isolation_attestation_sha256"
        case policySHA256 = "policy_sha256"
    }

    private struct DigestBody: Codable {
        let executablePath: String
        let executableSHA256: String
        let hostReleaseID: String
        let researchReleaseID: String
        let researchIsolationAttestationSHA256: String

        enum CodingKeys: String, CodingKey {
            case executablePath = "executable_path"
            case executableSHA256 = "executable_sha256"
            case hostReleaseID = "host_release_id"
            case researchReleaseID = "research_release_id"
            case researchIsolationAttestationSHA256 =
                "research_isolation_attestation_sha256"
        }
    }

    static func load(
        url: URL = defaultURL,
        releaseRoot: URL = defaultReleaseRoot,
        currentURL: URL = defaultCurrentURL,
        researchReadbackURL: URL = defaultResearchReadbackURL,
        teamIdentifier: String,
        now: Date = Date(),
        expectedOwner: uid_t = 0,
        expectedGroup: gid_t = 0
    ) throws -> CredentialConsumerPolicy {
        let data = try readProtected(
            url: url, expectedOwner: expectedOwner, expectedGroup: expectedGroup
        )
        guard let object = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "executable_path", "executable_sha256",
                  "host_release_id", "research_release_id",
                  "research_isolation_attestation_sha256", "policy_sha256",
              ]),
              let document = try? JSONDecoder().decode(Self.self, from: data),
              data == (try? document.encoded()),
              document.schema == schemaName,
              isSHA256(document.executableSHA256),
              isSHA256(document.hostReleaseID),
              isSHA256(document.researchReleaseID),
              isSHA256(document.researchIsolationAttestationSHA256),
              document.policySHA256 == sha256(try document.digestBodyData()),
              document.executablePath == releaseRoot
                .appendingPathComponent(document.hostReleaseID, isDirectory: true)
                .appendingPathComponent("native_projection_consumer").path
        else {
            throw NativeCredentialHelperError.projectionRejected
        }
        guard releaseRoot.deletingLastPathComponent().standardizedFileURL
                == currentURL.deletingLastPathComponent().standardizedFileURL,
              releaseRoot.lastPathComponent == "releases" else {
            throw NativeCredentialHelperError.projectionRejected
        }
        let hostRootDescriptor = try openTrustedDirectory(
            releaseRoot.deletingLastPathComponent(),
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup
        )
        defer { close(hostRootDescriptor) }
        let destination = try readStableSymlink(
            parentDescriptor: hostRootDescriptor,
            name: currentURL.lastPathComponent,
            expectedOwner: expectedOwner
        )
        guard destination == "releases/" + document.hostReleaseID else {
            throw NativeCredentialHelperError.projectionRejected
        }
        let releasesDescriptor = try openTrustedDirectoryAt(
            parentDescriptor: hostRootDescriptor,
            name: releaseRoot.lastPathComponent,
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup
        )
        defer { close(releasesDescriptor) }
        let selectedReleaseDescriptor = try openTrustedDirectoryAt(
            parentDescriptor: releasesDescriptor,
            name: document.hostReleaseID,
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup
        )
        close(selectedReleaseDescriptor)
        let readback = try RootOwnedNativeResearchProjectionReadback.load(
            url: researchReadbackURL,
            now: now,
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup
        )
        guard readback.researchReleaseID == document.researchReleaseID,
              readback.researchIsolationAttestationSHA256
                == document.researchIsolationAttestationSHA256 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        let requirement = try NativeCredentialXPCSigningPolicy.consumerRequirement(
            teamIdentifier: teamIdentifier
        )
        return try CredentialConsumerPolicy(
            executableURL: URL(fileURLWithPath: document.executablePath),
            executableSHA256: document.executableSHA256,
            designatedRequirement: requirement,
            fixedArguments: []
        )
    }

    static func readProtected(
        url: URL, expectedOwner: uid_t, expectedGroup: gid_t
    ) throws -> Data {
        let name = url.lastPathComponent
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
            throw NativeCredentialHelperError.projectionRejected
        }
        let parentDescriptor = try openTrustedDirectory(
            url.deletingLastPathComponent(),
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup,
            exactMode: 0o755
        )
        defer { close(parentDescriptor) }
        var before = stat()
        guard fstatat(
                  parentDescriptor, name, &before, AT_SYMLINK_NOFOLLOW
              ) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_nlink == 1, before.st_uid == expectedOwner,
              before.st_gid == expectedGroup,
              before.st_mode & mode_t(0o777) == mode_t(0o444),
              (2...16_384).contains(Int(before.st_size)) else {
            throw NativeCredentialHelperError.projectionRejected
        }
        let descriptor = openat(
            parentDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              before.st_dev == opened.st_dev, before.st_ino == opened.st_ino,
              before.st_size == opened.st_size,
              before.st_mtimespec.tv_sec == opened.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == opened.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == opened.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == opened.st_ctimespec.tv_nsec else {
            throw NativeCredentialHelperError.projectionRejected
        }
        var output = Data()
        while output.count < before.st_size {
            var buffer = [UInt8](
                repeating: 0,
                count: min(4096, Int(before.st_size) - output.count)
            )
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            guard count > 0 else {
                throw NativeCredentialHelperError.projectionRejected
            }
            output.append(buffer, count: count)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              opened.st_dev == after.st_dev, opened.st_ino == after.st_ino,
              opened.st_size == after.st_size,
              opened.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              opened.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              opened.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              opened.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw NativeCredentialHelperError.projectionRejected
        }
        return output
    }

    private static func openTrustedDirectory(
        _ url: URL,
        expectedOwner: uid_t,
        expectedGroup: gid_t,
        exactMode: mode_t? = nil
    ) throws -> Int32 {
        let descriptor = open(
            url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        do {
            try validateDirectoryDescriptor(
                descriptor,
                expectedOwner: expectedOwner,
                expectedGroup: expectedGroup,
                exactMode: exactMode
            )
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private static func openTrustedDirectoryAt(
        parentDescriptor: Int32,
        name: String,
        expectedOwner: uid_t,
        expectedGroup: gid_t
    ) throws -> Int32 {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
            throw NativeCredentialHelperError.projectionRejected
        }
        let descriptor = openat(
            parentDescriptor, name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        do {
            try validateDirectoryDescriptor(
                descriptor,
                expectedOwner: expectedOwner,
                expectedGroup: expectedGroup,
                exactMode: nil
            )
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private static func validateDirectoryDescriptor(
        _ descriptor: Int32,
        expectedOwner: uid_t,
        expectedGroup: gid_t,
        exactMode: mode_t?
    ) throws {
        var information = stat()
        guard fstat(descriptor, &information) == 0,
              information.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              information.st_uid == expectedOwner,
              information.st_gid == expectedGroup,
              information.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0,
              exactMode.map({
                  information.st_mode & mode_t(0o777) == $0
              }) ?? true else {
            throw NativeCredentialHelperError.projectionRejected
        }
    }

    private static func readStableSymlink(
        parentDescriptor: Int32,
        name: String,
        expectedOwner: uid_t
    ) throws -> String {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
            throw NativeCredentialHelperError.projectionRejected
        }
        var before = stat()
        guard fstatat(
                  parentDescriptor, name, &before, AT_SYMLINK_NOFOLLOW
              ) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFLNK),
              before.st_uid == expectedOwner,
              before.st_nlink == 1 else {
            throw NativeCredentialHelperError.projectionRejected
        }
        var buffer = [UInt8](repeating: 0, count: 1_025)
        let count = readlinkat(parentDescriptor, name, &buffer, buffer.count)
        guard count > 0, count < buffer.count,
              let destination = String(
                  bytes: buffer.prefix(count), encoding: .utf8
              ), !destination.contains("\0") else {
            throw NativeCredentialHelperError.projectionRejected
        }
        var after = stat()
        guard fstatat(
                  parentDescriptor, name, &after, AT_SYMLINK_NOFOLLOW
              ) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_mode == after.st_mode,
              before.st_uid == after.st_uid,
              before.st_size == after.st_size,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw NativeCredentialHelperError.projectionRejected
        }
        return destination
    }

    private var digestBody: DigestBody {
        DigestBody(
            executablePath: executablePath,
            executableSHA256: executableSHA256,
            hostReleaseID: hostReleaseID,
            researchReleaseID: researchReleaseID,
            researchIsolationAttestationSHA256:
                researchIsolationAttestationSHA256
        )
    }

    private func digestBodyData() throws -> Data { try Self.canonical(digestBody) }
    private func encoded() throws -> Data { try Self.canonical(self) }

    private static func canonical<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
    }
}

struct RootOwnedNativeResearchProjectionReadback: Codable, Equatable, Sendable {
    static let schemaName = "secure-sandbox-native-research-projection-readback-v1"
    static let maximumLifetimeSeconds: Int64 = 120

    let schema: String
    let researchReleaseID: String
    let researchIsolationAttestationSHA256: String
    let observedAt: Int64
    let expiresAt: Int64
    let readbackSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case researchReleaseID = "research_release_id"
        case researchIsolationAttestationSHA256 =
            "research_isolation_attestation_sha256"
        case observedAt = "observed_at"
        case expiresAt = "expires_at"
        case readbackSHA256 = "readback_sha256"
    }

    private struct DigestBody: Codable {
        let researchReleaseID: String
        let researchIsolationAttestationSHA256: String
        let observedAt: Int64
        let expiresAt: Int64

        enum CodingKeys: String, CodingKey {
            case researchReleaseID = "research_release_id"
            case researchIsolationAttestationSHA256 =
                "research_isolation_attestation_sha256"
            case observedAt = "observed_at"
            case expiresAt = "expires_at"
        }
    }

    static func load(
        url: URL,
        now: Date,
        expectedOwner: uid_t,
        expectedGroup: gid_t
    ) throws -> Self {
        let data = try RootOwnedNativeProjectionPolicy.readProtected(
            url: url,
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup
        )
        guard let object = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "research_release_id",
                  "research_isolation_attestation_sha256", "observed_at",
                  "expires_at", "readback_sha256",
              ]),
              let document = try? JSONDecoder().decode(Self.self, from: data),
              data == (try? canonical(document)),
              document.schema == schemaName,
              isSHA256(document.researchReleaseID),
              isSHA256(document.researchIsolationAttestationSHA256),
              isSHA256(document.readbackSHA256),
              document.observedAt > 0,
              document.expiresAt > document.observedAt,
              document.expiresAt <= document.observedAt + maximumLifetimeSeconds,
              Int64(now.timeIntervalSince1970) >= document.observedAt,
              Int64(now.timeIntervalSince1970) < document.expiresAt,
              document.readbackSHA256 == sha256(try canonical(document.digestBody))
        else {
            throw NativeCredentialHelperError.projectionRejected
        }
        return document
    }

    private var digestBody: DigestBody {
        DigestBody(
            researchReleaseID: researchReleaseID,
            researchIsolationAttestationSHA256: researchIsolationAttestationSHA256,
            observedAt: observedAt,
            expiresAt: expiresAt
        )
    }

    private static func canonical<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
    }
}
