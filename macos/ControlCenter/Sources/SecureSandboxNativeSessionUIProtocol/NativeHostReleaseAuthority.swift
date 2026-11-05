import Foundation

/// Keeps immutable publication provenance distinct from current execution
/// authority. Historical Host A may have published the live catalog while
/// current Host B is the only release allowed to authorize a new operation.
public struct NativeHostReleaseAuthority: Hashable, Sendable {
    public let currentHostReleaseID: String
    public let historicalPublicationHostReleaseID: String

    public init(
        currentHostReleaseID: String,
        historicalPublicationHostReleaseID: String
    ) throws {
        guard CanonicalNativeJSON.isSHA256(currentHostReleaseID),
              CanonicalNativeJSON.isSHA256(
                  historicalPublicationHostReleaseID
              ) else {
            throw NativeSessionProtocolError.rejected(
                "native_host_release_authority_invalid"
            )
        }
        self.currentHostReleaseID = currentHostReleaseID
        self.historicalPublicationHostReleaseID =
            historicalPublicationHostReleaseID
    }

    public func requireCurrent(_ proposedHostReleaseID: String) throws {
        guard proposedHostReleaseID == currentHostReleaseID else {
            throw NativeSessionProtocolError.rejected(
                "native_host_release_not_current"
            )
        }
    }
}
