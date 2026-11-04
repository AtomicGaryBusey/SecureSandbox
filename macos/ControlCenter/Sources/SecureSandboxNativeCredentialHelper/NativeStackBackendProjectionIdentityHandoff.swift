import CryptoKit
import Foundation

public struct NativeStackBackendProjectionIdentityHandoff: Sendable {
    public let ticketID: UUID
    public let recoveryOperationID: UUID
    public let originalOperationID: UUID
    public let sessionAuthoritySHA256: String
    public let stackSHA256: String
    public let recoveryPlanSHA256: String
    public let hostReleaseID: String
    public let recoveryRequestSHA256: String
    public let recoveryReceiptSHA256: String
}

public enum NativeStackBackendProjectionIdentityHandoffCodec {
    public static let schema =
        "secure-sandbox-native-projection-identity-recovery-handoff-v1"
    public static let maximumBytes = 32 * 1_024

    private static let fields: Set<String> = [
        "schema", "ticket_id", "recovery_operation_id",
        "original_operation_id", "session_authority_sha256",
        "stack_sha256", "recovery_plan_sha256", "host_release_id",
        "recovery_request_sha256", "recovery_receipt_sha256",
        "handoff_sha256",
    ]
    private static let forbiddenNames = [
        "access_token", "refresh_token", "authorization_code",
        "code_verifier", "pkce", "provider_response", "credential_path",
        "client_secret",
    ]

    public static func decode(
        _ data: Data
    ) throws -> NativeStackBackendProjectionIdentityHandoff {
        guard (2...maximumBytes).contains(data.count), data.last == 0x0a,
              let lowercased = String(data: data, encoding: .ascii),
              !forbiddenNames.contains(where: {
                  lowercased.lowercased().contains($0)
              }),
              let object = try JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == fields,
              object["schema"] as? String == schema,
              data == (try? canonical(object)),
              let ticketIDString = object["ticket_id"] as? String,
              let recoveryIDString = object["recovery_operation_id"] as? String,
              let originalIDString = object["original_operation_id"] as? String,
              let ticketID = UUID(uuidString: ticketIDString),
              let recoveryID = UUID(uuidString: recoveryIDString),
              let originalID = UUID(uuidString: originalIDString),
              ticketID.uuidString.lowercased() == ticketIDString,
              recoveryID.uuidString.lowercased() == recoveryIDString,
              originalID.uuidString.lowercased() == originalIDString,
              isUUID4(ticketIDString), isUUID4(recoveryIDString),
              isUUID4(originalIDString), recoveryID != originalID,
              let authority = object["session_authority_sha256"] as? String,
              let stack = object["stack_sha256"] as? String,
              let plan = object["recovery_plan_sha256"] as? String,
              let release = object["host_release_id"] as? String,
              let request = object["recovery_request_sha256"] as? String,
              let receipt = object["recovery_receipt_sha256"] as? String,
              [authority, stack, plan, release, request, receipt]
                .allSatisfy(isSHA256),
              let supplied = object["handoff_sha256"] as? String,
              isSHA256(supplied) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        var body = object
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "handoff_sha256")
        guard supplied == sha256(try canonical(body)) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        return NativeStackBackendProjectionIdentityHandoff(
            ticketID: ticketID,
            recoveryOperationID: recoveryID,
            originalOperationID: originalID,
            sessionAuthoritySHA256: authority,
            stackSHA256: stack,
            recoveryPlanSHA256: plan,
            hostReleaseID: release,
            recoveryRequestSHA256: request,
            recoveryReceiptSHA256: receipt
        )
    }

    private static func canonical(_ value: Any) throws -> Data {
        guard JSONSerialization.isValidJSONObject(value) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        var data = try JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        data.append(0x0a)
        guard data.count <= maximumBytes else {
            throw NativeCredentialXPCError.invalidRequest
        }
        return data
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.range(
            of: #"^[0-9a-f]{64}$"#, options: .regularExpression
        ) != nil
    }

    private static func isUUID4(_ value: String) -> Bool {
        value.range(
            of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
            options: .regularExpression
        ) != nil
    }
}
