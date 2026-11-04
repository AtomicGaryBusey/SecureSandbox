import Foundation

public enum NativeCredentialProvider: String, Codable, Sendable {
    case openAIChatGPT
}

public enum NativeCredentialOperation: String, Codable, Sendable {
    case status
    case login
    case refresh
    case logout
    case destroyLocalCredential
    case recoverLocalState
    case projectForSession
    case reconcileProjection
}

public struct NativeCredentialCommand: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-native-credential-command-v1"

    public let schema: String
    public let operationID: UUID
    public let operation: NativeCredentialOperation
    public let provider: NativeCredentialProvider
    public let sessionAuthoritySHA256: String?
    public let authorizationReceiptSHA256: String?

    public init(
        operationID: UUID,
        operation: NativeCredentialOperation,
        provider: NativeCredentialProvider,
        sessionAuthoritySHA256: String? = nil,
        authorizationReceiptSHA256: String? = nil
    ) throws {
        self.schema = Self.schema
        self.operationID = operationID
        self.operation = operation
        self.provider = provider
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
        self.authorizationReceiptSHA256 = authorizationReceiptSHA256
        try validate()
    }

    public static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: [
                  "schema", "operationID", "operation", "provider",
                  "sessionAuthoritySHA256", "authorizationReceiptSHA256",
              ]),
              Set(["schema", "operationID", "operation", "provider"]).isSubset(of: object.keys),
              let decoded = try? JSONDecoder().decode(Self.self, from: data) else {
            throw NativeCredentialHelperError.invalidCommand
        }
        try decoded.validate()
        return decoded
    }

    func validate() throws {
        guard schema == Self.schema else { throw NativeCredentialHelperError.invalidCommand }
        for digest in [sessionAuthoritySHA256, authorizationReceiptSHA256].compactMap({ $0 }) {
            guard digest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
                throw NativeCredentialHelperError.invalidCommand
            }
        }
        switch operation {
        case .status:
            guard sessionAuthoritySHA256 == nil, authorizationReceiptSHA256 == nil else {
                throw NativeCredentialHelperError.invalidCommand
            }
        case .refresh:
            guard sessionAuthoritySHA256 == nil, authorizationReceiptSHA256 != nil else {
                throw NativeCredentialHelperError.invalidCommand
            }
        case .login, .logout, .destroyLocalCredential, .recoverLocalState:
            guard sessionAuthoritySHA256 == nil, authorizationReceiptSHA256 != nil else {
                throw NativeCredentialHelperError.invalidCommand
            }
        case .projectForSession:
            guard sessionAuthoritySHA256 != nil, authorizationReceiptSHA256 != nil else {
                throw NativeCredentialHelperError.invalidCommand
            }
        case .reconcileProjection:
            // Projection reconciliation has a distinct exact IPC schema and
            // can never be expressed through this general command envelope.
            throw NativeCredentialHelperError.invalidCommand
        }
    }
}

public enum NativeCredentialState: String, Codable, Sendable {
    case loggedOut
    case ready
    case refreshRequired
    case blocked
}

public enum NativeCredentialCustodyState: String, Codable, Sendable {
    case absent
    case retained
    case sessionProjected = "session-projected"
    case ambiguous
}

public struct NativeCredentialStatus: Codable, Equatable, Sendable {
    public static let schema = "secure-sandbox-native-credential-status-v1"

    public let schema: String
    public let provider: NativeCredentialProvider
    public let state: NativeCredentialState
    public let clientIDHash: String?
    public let accountSubjectSHA256: String?
    public let workspaceSHA256: String?
    public let scopeSHA256: String?
    public let accessExpiresAt: Date?
    public let earliestRefreshAt: Date?
    public let refreshExpiresAt: Date?
    public let custodyState: NativeCredentialCustodyState
    public let custodyTombstoneSHA256: String?
    public let custodyProjectionCount: Int?

    public init(
        provider: NativeCredentialProvider,
        state: NativeCredentialState,
        clientIDHash: String? = nil,
        accountSubjectSHA256: String? = nil,
        workspaceSHA256: String? = nil,
        scopeSHA256: String? = nil,
        accessExpiresAt: Date? = nil,
        earliestRefreshAt: Date? = nil,
        refreshExpiresAt: Date? = nil,
        custodyState: NativeCredentialCustodyState? = nil,
        custodyTombstoneSHA256: String? = nil,
        custodyProjectionCount: Int? = nil
    ) throws {
        schema = Self.schema
        self.provider = provider
        self.state = state
        self.clientIDHash = clientIDHash
        self.accountSubjectSHA256 = accountSubjectSHA256
        self.workspaceSHA256 = workspaceSHA256
        self.scopeSHA256 = scopeSHA256
        self.accessExpiresAt = accessExpiresAt
        self.earliestRefreshAt = earliestRefreshAt
        self.refreshExpiresAt = refreshExpiresAt
        self.custodyState = custodyState ?? (state == .loggedOut ? .ambiguous : .retained)
        self.custodyTombstoneSHA256 = custodyTombstoneSHA256
        self.custodyProjectionCount = custodyProjectionCount
            ?? (self.custodyState == .ambiguous ? nil : 0)
        try validate()
    }

    public static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: [
                  "schema", "provider", "state", "clientIDHash", "accountSubjectSHA256",
                  "workspaceSHA256", "scopeSHA256", "accessExpiresAt",
                  "earliestRefreshAt", "refreshExpiresAt", "custodyState",
                  "custodyTombstoneSHA256", "custodyProjectionCount",
              ]),
              Set(["schema", "provider", "state"]).isSubset(of: object.keys),
              let decoded = try? JSONDecoder().decode(Self.self, from: data) else {
            throw NativeCredentialHelperError.invalidStatus
        }
        try decoded.validate()
        return decoded
    }

    private func validate() throws {
        let digests = [clientIDHash, accountSubjectSHA256, workspaceSHA256, scopeSHA256]
        for digest in digests.compactMap({ $0 }) {
            guard digest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
                throw NativeCredentialHelperError.invalidStatus
            }
        }
        switch state {
        case .loggedOut:
            guard digests.allSatisfy({ $0 == nil }), accessExpiresAt == nil,
                  earliestRefreshAt == nil, refreshExpiresAt == nil else {
                throw NativeCredentialHelperError.invalidStatus
            }
        case .ready, .refreshRequired:
            guard digests.allSatisfy({ $0 != nil }), accessExpiresAt != nil,
                  earliestRefreshAt != nil, refreshExpiresAt != nil else {
                throw NativeCredentialHelperError.invalidStatus
            }
        case .blocked:
            break
        }
        guard custodyTombstoneSHA256.map({
            $0.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
        }) ?? true else { throw NativeCredentialHelperError.invalidStatus }
        switch custodyState {
        case .absent:
            guard state == .loggedOut, custodyTombstoneSHA256 != nil,
                  custodyProjectionCount == 0 else {
                throw NativeCredentialHelperError.invalidStatus
            }
        case .retained:
            guard state != .loggedOut, custodyTombstoneSHA256 == nil,
                  custodyProjectionCount == 0 else {
                throw NativeCredentialHelperError.invalidStatus
            }
        case .sessionProjected:
            guard state != .loggedOut, custodyTombstoneSHA256 == nil,
                  let custodyProjectionCount, custodyProjectionCount >= 1 else {
                throw NativeCredentialHelperError.invalidStatus
            }
        case .ambiguous:
            guard custodyTombstoneSHA256 == nil, custodyProjectionCount == nil else {
                throw NativeCredentialHelperError.invalidStatus
            }
        }
    }
}

public enum NativeCredentialHelperError: Error, Equatable, LocalizedError, Sendable {
    case invalidCommand
    case invalidStatus
    case operationInProgress
    case secureEnclaveUnavailable
    case hostIdentityUnavailable
    case loopbackUnavailable
    case callbackRejected
    case browserLaunchFailed
    case providerTransportFailed
    case providerResponseRejected
    case credentialStoreFailed
    case credentialNotFound
    case refreshValidationUnavailable
    case revocationFailed
    case projectionRejected
    case consumerLaunchFailed
    case consumerTerminationUnproven

    public var errorDescription: String? {
        switch self {
        case .invalidCommand: "The credential-helper command was rejected."
        case .invalidStatus: "The credential-helper status was invalid."
        case .operationInProgress: "A credential operation is already in progress."
        case .secureEnclaveUnavailable: "The Secure Enclave is unavailable."
        case .hostIdentityUnavailable: "The device-bound host identity is unavailable."
        case .loopbackUnavailable: "The local authorization callback is unavailable."
        case .callbackRejected: "The authorization callback was rejected."
        case .browserLaunchFailed: "The system browser could not be opened."
        case .providerTransportFailed: "The provider connection failed closed."
        case .providerResponseRejected: "The provider response failed validation."
        case .credentialStoreFailed: "The protected credential store failed closed."
        case .credentialNotFound: "No protected credential is available."
        case .refreshValidationUnavailable: "Credential refresh validation is unavailable."
        case .revocationFailed: "Provider revocation failed; local credentials were retained."
        case .projectionRejected: "Credential projection was rejected."
        case .consumerLaunchFailed: "The approved credential consumer could not be launched."
        case .consumerTerminationUnproven:
            "The credential consumer may still be running; custody remains ambiguous."
        }
    }
}
