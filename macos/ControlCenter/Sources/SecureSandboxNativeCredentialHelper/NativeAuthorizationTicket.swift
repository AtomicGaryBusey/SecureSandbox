import CryptoKit
import Darwin
import Foundation

enum NativeAuthorizationAction: String, Codable, Sendable {
    case signinBegin = "signin-begin"
    case entitlementVerify = "entitlement-verify"
    case sessionStart = "session-start"
    case logout
    case credentialDestroy = "credential-destroy"
    case recover
}

struct NativeAuthorizationTicket: Codable, Equatable, Sendable {
    static let schemaName = "secure-sandbox-native-credential-authorization-ticket-v1"
    static let maximumBytes = 32 * 1024

    let schema: String
    let ticketID: String
    let operationID: String
    let requestID: String
    let operation: NativeCredentialOperation
    let action: NativeAuthorizationAction
    let provider: NativeCredentialProvider
    let planSHA256: String
    let stackSHA256: String
    let sessionAuthoritySHA256: String?
    let requestSHA256: String
    let authorizationReceiptSHA256: String
    let issuedAt: Int64
    let expiresAt: Int64
    let status: String
    let ticketSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case ticketID = "ticket_id"
        case operationID = "operation_id"
        case requestID = "request_id"
        case operation
        case action
        case provider
        case planSHA256 = "plan_sha256"
        case stackSHA256 = "stack_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case requestSHA256 = "request_sha256"
        case authorizationReceiptSHA256 = "authorization_receipt_sha256"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case status
        case ticketSHA256 = "ticket_sha256"
    }

    private struct DigestBody: Codable {
        let ticketID: String
        let operationID: String
        let requestID: String
        let operation: NativeCredentialOperation
        let action: NativeAuthorizationAction
        let provider: NativeCredentialProvider
        let planSHA256: String
        let stackSHA256: String
        let sessionAuthoritySHA256: String?
        let requestSHA256: String
        let authorizationReceiptSHA256: String
        let issuedAt: Int64
        let expiresAt: Int64
        let status: String

        enum CodingKeys: String, CodingKey {
            case ticketID = "ticket_id"
            case operationID = "operation_id"
            case requestID = "request_id"
            case operation
            case action
            case provider
            case planSHA256 = "plan_sha256"
            case stackSHA256 = "stack_sha256"
            case sessionAuthoritySHA256 = "session_authority_sha256"
            case requestSHA256 = "request_sha256"
            case authorizationReceiptSHA256 = "authorization_receipt_sha256"
            case issuedAt = "issued_at"
            case expiresAt = "expires_at"
            case status
        }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(ticketID, forKey: .ticketID)
            try values.encode(operationID, forKey: .operationID)
            try values.encode(requestID, forKey: .requestID)
            try values.encode(operation, forKey: .operation)
            try values.encode(action, forKey: .action)
            try values.encode(provider, forKey: .provider)
            try values.encode(planSHA256, forKey: .planSHA256)
            try values.encode(stackSHA256, forKey: .stackSHA256)
            try values.encode(sessionAuthoritySHA256, forKey: .sessionAuthoritySHA256)
            try values.encode(requestSHA256, forKey: .requestSHA256)
            try values.encode(authorizationReceiptSHA256, forKey: .authorizationReceiptSHA256)
            try values.encode(issuedAt, forKey: .issuedAt)
            try values.encode(expiresAt, forKey: .expiresAt)
            try values.encode(status, forKey: .status)
        }
    }

    func validate(now: Date) throws {
        guard schema == Self.schemaName,
              Self.isUUID4(ticketID), Self.isUUID4(operationID), Self.isUUID4(requestID),
              [planSHA256, stackSHA256, requestSHA256, authorizationReceiptSHA256]
                .allSatisfy(Self.isSHA256),
              sessionAuthoritySHA256.map(Self.isSHA256) ?? true,
              status == "authorized",
              issuedAt > 0,
              expiresAt > issuedAt,
              expiresAt <= issuedAt + 180,
              Int64(now.timeIntervalSince1970) >= issuedAt,
              Int64(now.timeIntervalSince1970) < expiresAt,
              ticketSHA256 == Self.sha256(try Self.canonicalData(digestBody)) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        let expected: (NativeAuthorizationAction, Bool) = switch operation {
        case .login: (.signinBegin, false)
        case .refresh: (.entitlementVerify, false)
        case .projectForSession: (.sessionStart, true)
        case .logout: (.logout, false)
        case .destroyLocalCredential: (.credentialDestroy, false)
        case .recoverLocalState: (.recover, false)
        case .status: throw NativeCredentialXPCError.authorizationTicketRejected
        }
        guard action == expected.0,
              (sessionAuthoritySHA256 != nil) == expected.1 else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
    }

    func matches(request: NativeCredentialIPCRequest, now: Date) throws {
        try validate(now: now)
        guard ticketID == request.authorizationTicketID,
              operationID == request.command.operationID.uuidString.lowercased(),
              operation == request.command.operation,
              provider == request.command.provider,
              planSHA256 == request.planSHA256,
              stackSHA256 == request.stackSHA256,
              sessionAuthoritySHA256 == request.command.sessionAuthoritySHA256,
              requestSHA256 == request.operatorRequestSHA256,
              authorizationReceiptSHA256 == request.command.authorizationReceiptSHA256 else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
    }

    private var digestBody: DigestBody {
        DigestBody(
            ticketID: ticketID,
            operationID: operationID,
            requestID: requestID,
            operation: operation,
            action: action,
            provider: provider,
            planSHA256: planSHA256,
            stackSHA256: stackSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            requestSHA256: requestSHA256,
            authorizationReceiptSHA256: authorizationReceiptSHA256,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            status: status
        )
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(ticketID, forKey: .ticketID)
        try values.encode(operationID, forKey: .operationID)
        try values.encode(requestID, forKey: .requestID)
        try values.encode(operation, forKey: .operation)
        try values.encode(action, forKey: .action)
        try values.encode(provider, forKey: .provider)
        try values.encode(planSHA256, forKey: .planSHA256)
        try values.encode(stackSHA256, forKey: .stackSHA256)
        try values.encode(sessionAuthoritySHA256, forKey: .sessionAuthoritySHA256)
        try values.encode(requestSHA256, forKey: .requestSHA256)
        try values.encode(authorizationReceiptSHA256, forKey: .authorizationReceiptSHA256)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(status, forKey: .status)
        try values.encode(ticketSHA256, forKey: .ticketSHA256)
    }

    static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func isSHA256(_ value: String) -> Bool {
        value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
    }

    static func isUUID4(_ value: String) -> Bool {
        value.range(
            of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
            options: .regularExpression
        ) != nil
    }
}

protocol NativeAuthorizationTicketReading: Sendable {
    func read(ticketID: String, now: Date) throws -> NativeAuthorizationTicket
}

struct RootOwnedNativeAuthorizationTicketReader: NativeAuthorizationTicketReading, Sendable {
    let root: URL
    let expectedOwner: uid_t

    init(
        root: URL = URL(
            fileURLWithPath: "/usr/local/var/lib/secure-sandbox/native-credential-tickets",
            isDirectory: true
        ),
        expectedOwner: uid_t = 0
    ) {
        self.root = root
        self.expectedOwner = expectedOwner
    }

    func read(ticketID: String, now: Date) throws -> NativeAuthorizationTicket {
        guard root.isFileURL, root.path.hasPrefix("/"),
              NativeAuthorizationTicket.isUUID4(ticketID) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        let path = root.appendingPathComponent(ticketID + ".json", isDirectory: false)
        var parentInfo = stat()
        var pathInfo = stat()
        guard lstat(root.path, &parentInfo) == 0,
              (parentInfo.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              parentInfo.st_uid == expectedOwner,
              parentInfo.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0,
              lstat(path.path, &pathInfo) == 0,
              (pathInfo.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              pathInfo.st_uid == expectedOwner,
              pathInfo.st_nlink == 1,
              pathInfo.st_mode & mode_t(0o777) == mode_t(0o644),
              pathInfo.st_size >= 2,
              pathInfo.st_size <= NativeAuthorizationTicket.maximumBytes else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        let descriptor = Darwin.open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_dev == pathInfo.st_dev,
              opened.st_ino == pathInfo.st_ino,
              opened.st_uid == expectedOwner,
              opened.st_nlink == 1,
              opened.st_mode & mode_t(0o777) == mode_t(0o644),
              opened.st_size == pathInfo.st_size else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        var data = Data(count: Int(opened.st_size))
        let count = data.withUnsafeMutableBytes { bytes in
            Darwin.read(descriptor, bytes.baseAddress, bytes.count)
        }
        guard count == data.count,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "ticket_id", "operation_id", "request_id", "operation",
                  "action", "provider", "plan_sha256", "stack_sha256",
                  "session_authority_sha256", "request_sha256",
                  "authorization_receipt_sha256", "issued_at", "expires_at", "status",
                  "ticket_sha256",
              ]),
              let ticket = try? JSONDecoder().decode(NativeAuthorizationTicket.self, from: data),
              data == (try? NativeAuthorizationTicket.canonicalData(ticket)) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        try ticket.validate(now: now)
        return ticket
    }
}
