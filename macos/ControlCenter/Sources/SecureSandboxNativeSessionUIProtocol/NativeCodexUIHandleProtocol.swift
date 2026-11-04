import Foundation

public struct NativeCodexUIHandle: Codable, Hashable, Sendable, Identifiable {
    public static let publicSchema = "secure-sandbox-native-codex-ui-handle-public-v1"
    public static let claimSchema = "secure-sandbox-native-codex-ui-handle-claim-v1"
    public static let kindName = "codex-typed-ui"

    public let schema: String
    public let handleID: String
    public let kind: String
    public let operationID: String
    public let sessionID: String
    public let runtimeAuthoritySHA256: String
    public let sessionLeaseSHA256: String
    public let sessionExpiresAt: Int
    public let handleSHA256: String
    public let expiresAt: Int
    public let replySHA256: String

    public var id: String { handleID }

    enum CodingKeys: String, CodingKey {
        case schema, kind
        case handleID = "handle_id"
        case operationID = "operation_id"
        case sessionID = "session_id"
        case runtimeAuthoritySHA256 = "runtime_authority_sha256"
        case sessionLeaseSHA256 = "session_lease_sha256"
        case sessionExpiresAt = "session_expires_at"
        case handleSHA256 = "handle_sha256"
        case expiresAt = "expires_at"
        case replySHA256 = "reply_sha256"
    }

    public static func decode(
        _ data: Data,
        plan: NativeSessionPlan,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> Self {
        let value = try CanonicalNativeJSON.parseLine(data, maximumBytes: 32 * 1_024)
        try CanonicalNativeJSON.requireKeys(value, [
            "schema", "handle_id", "kind", "operation_id", "session_id",
            "runtime_authority_sha256", "session_lease_sha256",
            "session_expires_at", "handle_sha256", "expires_at", "reply_sha256",
        ], "native_codex_ui_handle_public_fields_invalid")
        guard let schema = value["schema"] as? String,
              let handleID = value["handle_id"] as? String,
              let kind = value["kind"] as? String,
              let operationID = value["operation_id"] as? String,
              let sessionID = value["session_id"] as? String,
              let runtime = value["runtime_authority_sha256"] as? String,
              let lease = value["session_lease_sha256"] as? String,
              let sessionExpires = CanonicalNativeJSON.exactInteger(
                value["session_expires_at"]
              ),
              let handleDigest = value["handle_sha256"] as? String,
              let expires = CanonicalNativeJSON.exactInteger(value["expires_at"]),
              let replyDigest = value["reply_sha256"] as? String else {
            throw NativeSessionProtocolError.rejected(
                "native_codex_ui_handle_public_invalid"
            )
        }
        let result = Self(
            schema: schema, handleID: handleID, kind: kind,
            operationID: operationID, sessionID: sessionID,
            runtimeAuthoritySHA256: runtime, sessionLeaseSHA256: lease,
            sessionExpiresAt: sessionExpires, handleSHA256: handleDigest,
            expiresAt: expires, replySHA256: replyDigest
        )
        try result.validate(plan: plan, now: now)
        return result
    }

    public func validate(
        plan: NativeSessionPlan,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws {
        let leaseDuration = switch plan.leaseProfileID {
        case "interactive": 60 * 60
        case "extended": 4 * 60 * 60
        default: 0
        }
        guard schema == Self.publicSchema, kind == Self.kindName,
              plan.action == .start, leaseDuration > 0,
              CanonicalNativeJSON.isUUID4(handleID),
              operationID == plan.actionID,
              sessionID == plan.sessionID,
              runtimeAuthoritySHA256 == plan.runtimeAuthoritySHA256,
              CanonicalNativeJSON.isSHA256(sessionLeaseSHA256),
              now < sessionExpiresAt,
              sessionExpiresAt <= now + leaseDuration,
              CanonicalNativeJSON.isSHA256(handleSHA256),
              now < expiresAt, expiresAt <= now + 180,
              expiresAt <= sessionExpiresAt,
              CanonicalNativeJSON.isSHA256(replySHA256) else {
            throw NativeSessionProtocolError.rejected(
                "native_codex_ui_handle_public_invalid"
            )
        }
        let body: [String: Any] = [
            "expires_at": expiresAt,
            "handle_id": handleID,
            "handle_sha256": handleSHA256,
            "kind": kind,
            "operation_id": operationID,
            "runtime_authority_sha256": runtimeAuthoritySHA256,
            "session_expires_at": sessionExpiresAt,
            "session_id": sessionID,
            "session_lease_sha256": sessionLeaseSHA256,
        ]
        guard replySHA256 == (try CanonicalNativeJSON.digest(body)) else {
            throw NativeSessionProtocolError.rejected(
                "native_codex_ui_handle_public_digest_mismatch"
            )
        }
    }

    public func claimData(
        plan: NativeSessionPlan,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> Data {
        try validate(plan: plan, now: now)
        let body: [String: Any] = [
            "handle_id": handleID,
            "handle_sha256": handleSHA256,
        ]
        return try CanonicalNativeJSON.encodeLine([
            "schema": Self.claimSchema,
            "handle_id": handleID,
            "handle_sha256": handleSHA256,
            "request_sha256": CanonicalNativeJSON.digest(body),
        ])
    }
}
