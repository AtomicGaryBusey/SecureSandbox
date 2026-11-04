import Darwin
import Foundation

/// Resolves the immutable, ticket-carried projection authority against the
/// live root-owned release selector. There is deliberately no mutable helper
/// policy/readback file: a single-use authorization ticket is the complete
/// projection authority, and this resolver independently proves that its
/// selected release is still current immediately before spawn and release.
struct RootOwnedNativeProjectionConsumerResolver: Sendable {
    static let defaultReleaseRoot = URL(
        fileURLWithPath: "/usr/local/libexec/secure-sandbox-host/releases",
        isDirectory: true
    )
    static let defaultCurrentURL = URL(
        fileURLWithPath: "/usr/local/libexec/secure-sandbox-host/current"
    )
    static func resolve(
        authority: NativeCredentialProjectionAuthority,
        releaseRoot: URL = defaultReleaseRoot,
        currentURL: URL = defaultCurrentURL,
        teamIdentifier: String,
        expectedOwner: uid_t = 0,
        expectedGroup: gid_t = 0
    ) throws -> CredentialConsumerPolicy {
        guard releaseRoot.deletingLastPathComponent().standardizedFileURL
                == currentURL.deletingLastPathComponent().standardizedFileURL,
              releaseRoot.lastPathComponent == "releases",
              authority.consumerExecutablePath == releaseRoot
                .appendingPathComponent(
                    authority.hostReleaseID, isDirectory: true
                )
                .appendingPathComponent("native_projection_consumer").path
        else {
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
        guard destination == "releases/" + authority.hostReleaseID else {
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
            name: authority.hostReleaseID,
            expectedOwner: expectedOwner,
            expectedGroup: expectedGroup
        )
        close(selectedReleaseDescriptor)
        return try CredentialConsumerPolicy(
            executableURL: URL(
                fileURLWithPath: authority.consumerExecutablePath
            ),
            executableSHA256: authority.consumerExecutableSHA256,
            designatedRequirement:
                try NativeCredentialXPCSigningPolicy.consumerRequirement(
                    teamIdentifier: teamIdentifier
                ),
            fixedArguments: []
        )
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

}
