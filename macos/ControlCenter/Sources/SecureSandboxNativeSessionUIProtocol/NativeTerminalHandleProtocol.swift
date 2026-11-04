import Foundation

public struct NativeTerminalHandle: Codable, Hashable, Sendable, Identifiable {
    public static let publicSchema = "secure-sandbox-native-terminal-handle-public-v1"
    public static let claimSchema = "secure-sandbox-native-terminal-handle-claim-v1"
    public static let claudeKinds: Set<String> = ["claude-login", "claude-session"]

    public let schema: String
    public let handleID: String
    public let kind: String
    public let operationID: String
    public let sessionID: String
    public let handleSHA256: String
    public let expiresAt: Int
    public let replySHA256: String

    public var id: String { handleID }

    enum CodingKeys: String, CodingKey {
        case schema
        case handleID = "handle_id"
        case kind
        case operationID = "operation_id"
        case sessionID = "session_id"
        case handleSHA256 = "handle_sha256"
        case expiresAt = "expires_at"
        case replySHA256 = "reply_sha256"
    }

    public static func decode(
        _ data: Data,
        expectedKinds: Set<String> = claudeKinds,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> Self {
        let value = try CanonicalNativeJSON.parseLine(data, maximumBytes: 32 * 1024)
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "handle_id", "kind", "operation_id", "session_id",
            "handle_sha256", "expires_at", "reply_sha256",
        ], "native_terminal_handle_public_fields_invalid")
        guard value["schema"] as? String == publicSchema,
              let handleID = value["handle_id"] as? String,
              CanonicalNativeJSON.isUUID4(handleID),
              let kind = value["kind"] as? String, expectedKinds.contains(kind),
              let operationID = value["operation_id"] as? String,
              CanonicalNativeJSON.isUUID4(operationID),
              let sessionID = value["session_id"] as? String,
              CanonicalNativeJSON.isUUID4(sessionID),
              let handleSHA256 = value["handle_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(handleSHA256),
              let expiresAt = CanonicalNativeJSON.exactInteger(value["expires_at"]),
              now < expiresAt, expiresAt <= now + 180,
              let replySHA256 = value["reply_sha256"] as? String,
              CanonicalNativeJSON.isSHA256(replySHA256) else {
            throw NativeSessionProtocolError.rejected("native_terminal_handle_public_invalid")
        }
        let result = Self(
            schema: publicSchema, handleID: handleID, kind: kind, operationID: operationID,
            sessionID: sessionID, handleSHA256: handleSHA256,
            expiresAt: expiresAt, replySHA256: replySHA256
        )
        try result.validate(expectedKinds: expectedKinds, now: now)
        return result
    }

    public func validate(
        expectedKinds: Set<String> = claudeKinds,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws {
        guard schema == Self.publicSchema,
              CanonicalNativeJSON.isUUID4(handleID),
              expectedKinds.contains(kind),
              CanonicalNativeJSON.isUUID4(operationID),
              CanonicalNativeJSON.isUUID4(sessionID),
              CanonicalNativeJSON.isSHA256(handleSHA256),
              now < expiresAt, expiresAt <= now + 180,
              CanonicalNativeJSON.isSHA256(replySHA256) else {
            throw NativeSessionProtocolError.rejected(
                "native_terminal_handle_public_invalid"
            )
        }
        let body: [String: Any] = [
            "expires_at": expiresAt,
            "handle_id": handleID,
            "handle_sha256": handleSHA256,
            "kind": kind,
            "operation_id": operationID,
            "session_id": sessionID,
        ]
        guard replySHA256 == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_terminal_handle_public_digest_mismatch"
            )
        }
    }

    public func claimData(expectedKind: String) throws -> Data {
        guard kind == expectedKind, Self.claudeKinds.contains(expectedKind) else {
            throw NativeSessionProtocolError.rejected("native_terminal_handle_kind_mismatch")
        }
        let body: [String: Any] = [
            "handle_id": handleID,
            "handle_sha256": handleSHA256,
            "kind": kind,
        ]
        return try CanonicalNativeJSON.encodeLine([
            "schema": Self.claimSchema,
            "handle_id": handleID,
            "handle_sha256": handleSHA256,
            "kind": kind,
            "request_sha256": CanonicalNativeJSON.digest(body),
        ])
    }
}
