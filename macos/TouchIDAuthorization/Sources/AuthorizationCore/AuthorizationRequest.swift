import CryptoKit
import Foundation

public enum AuthorizationDocumentError: Error, Equatable {
    case tooLarge
    case invalidJSON
    case notCanonical
    case digestMismatch
    case invalidField(String)
}

public struct AuthorizationRequest: Equatable, Sendable {
    public let requestID: String
    public let requestSHA256: String
    public let declaredAgent: String
    public let declaredSession: String
    public let purpose: String
    public let resource: String
    public let operation: String
    public let expiresAt: Int
    public let details: String
    public let parametersCanonical: Data

    public static let maximumBytes = 65_536

    public static func parse(_ data: Data, expectedSHA256: String) throws -> AuthorizationRequest {
        guard data.count <= maximumBytes else { throw AuthorizationDocumentError.tooLarge }
        guard expectedSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw AuthorizationDocumentError.invalidField("request_sha256")
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard actual == expectedSHA256 else { throw AuthorizationDocumentError.digestMismatch }
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any] else {
            throw AuthorizationDocumentError.invalidJSON
        }
        let canonical = try JSONSerialization.data(
            withJSONObject: dictionary,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) + Data([0x0a])
        guard canonical == data else { throw AuthorizationDocumentError.notCanonical }

        func string(_ name: String, maximum: Int) throws -> String {
            guard let value = dictionary[name] as? String,
                  !value.isEmpty,
                  value.utf8.count <= maximum,
                  value.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value <= 126 }) else {
                throw AuthorizationDocumentError.invalidField(name)
            }
            return value
        }
        guard let expires = dictionary["expires_at"] as? Int else {
            throw AuthorizationDocumentError.invalidField("expires_at")
        }
        let requestID = try string("request_id", maximum: 36)
        guard UUID(uuidString: requestID)?.uuidString.lowercased() == requestID else {
            throw AuthorizationDocumentError.invalidField("request_id")
        }
        let parameters = dictionary["parameters"] ?? [:]
        let parameterData = try JSONSerialization.data(
            withJSONObject: parameters,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let prettyParameterData = try JSONSerialization.data(
            withJSONObject: parameters,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        guard let detailText = String(data: prettyParameterData, encoding: .utf8) else {
            throw AuthorizationDocumentError.invalidField("parameters")
        }
        return AuthorizationRequest(
            requestID: requestID,
            requestSHA256: expectedSHA256,
            declaredAgent: try string("declared_agent", maximum: 80),
            declaredSession: try string("declared_session", maximum: 128),
            purpose: try string("purpose", maximum: 240),
            resource: try string("resource", maximum: 240),
            operation: try string("operation", maximum: 80),
            expiresAt: expires,
            details: detailText,
            parametersCanonical: parameterData
        )
    }

    public var displayText: String {
        [
            "Declared agent: \(declaredAgent)",
            "Declared session: \(declaredSession)",
            "Purpose: \(purpose)",
            "Resource: \(resource)",
            "Operation: \(operation)",
            "Request digest: \(requestSHA256)",
            "One-time nonce: \(requestID)",
            "Expires (Unix): \(expiresAt)",
            "",
            "Bound parameters:",
            details,
        ].joined(separator: "\n")
    }

    public var requiresBiometricApproval: Bool {
        [
            "execution-approval-key-init",
            "execution-approval-sign",
            "execution-approval-migration-activate",
            "execution-approval-migration-authorize-acceptance",
            "execution-approval-migration-verify-acceptance",
            "execution-approval-migration-commit",
            "execution-approval-software-retire",
        ].contains(operation)
    }

    public var isExecutionApprovalSigning: Bool {
        operation == "execution-approval-sign"
    }

    public var isExecutionApprovalKeyInitialization: Bool {
        operation == "execution-approval-key-init"
    }
}
