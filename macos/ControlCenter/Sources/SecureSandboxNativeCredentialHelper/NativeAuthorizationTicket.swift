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
    let consumerExecutablePath: String?
    let consumerExecutableSHA256: String?
    let hostReleaseID: String?
    let sessionID: String?
    let runtimeAuthoritySHA256: String?
    let nativeStackBindingSHA256: String?
    let harnessBindingSHA256: String?
    let harnessGenerationID: String?
    let harnessExecutableSHA256: String?
    let modelID: String?
    let reasoningEffort: String?
    let cyberAccessProgram: String?
    let policyManifestSHA256: String?
    let probeExecutableSHA256: String?
    let protocolVersion: String?
    let launchDescriptorSHA256: String?
    let researchReleaseID: String?
    let bootIDSHA256: String?
    let qualificationSubjectSHA256: String?
    let qualificationEvidenceSHA256: String?
    let qualificationObservedAt: Int64?
    let qualificationExpiresAt: Int64?
    let qualificationReadbackSHA256: String?
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
        case consumerExecutablePath = "consumer_executable_path"
        case consumerExecutableSHA256 = "consumer_executable_sha256"
        case hostReleaseID = "host_release_id"
        case sessionID = "session_id"
        case runtimeAuthoritySHA256 = "runtime_authority_sha256"
        case nativeStackBindingSHA256 = "native_stack_binding_sha256"
        case harnessBindingSHA256 = "harness_binding_sha256"
        case harnessGenerationID = "harness_generation_id"
        case harnessExecutableSHA256 = "harness_executable_sha256"
        case modelID = "model_id"
        case reasoningEffort = "reasoning_effort"
        case cyberAccessProgram = "cyber_access_program"
        case policyManifestSHA256 = "policy_manifest_sha256"
        case probeExecutableSHA256 = "probe_executable_sha256"
        case protocolVersion = "protocol_version"
        case launchDescriptorSHA256 = "launch_descriptor_sha256"
        case researchReleaseID = "research_release_id"
        case bootIDSHA256 = "boot_id_sha256"
        case qualificationSubjectSHA256 = "qualification_subject_sha256"
        case qualificationEvidenceSHA256 = "qualification_evidence_sha256"
        case qualificationObservedAt = "qualification_observed_at"
        case qualificationExpiresAt = "qualification_expires_at"
        case qualificationReadbackSHA256 = "qualification_readback_sha256"
        case requestSHA256 = "request_sha256"
        case authorizationReceiptSHA256 = "authorization_receipt_sha256"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case status
        case ticketSHA256 = "ticket_sha256"
    }

    private struct DigestBody: Encodable {
        let ticketID: String
        let operationID: String
        let requestID: String
        let operation: NativeCredentialOperation
        let action: NativeAuthorizationAction
        let provider: NativeCredentialProvider
        let planSHA256: String
        let stackSHA256: String
        let sessionAuthoritySHA256: String?
        let projectionAuthority: NativeCredentialProjectionAuthority?
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
            case consumerExecutablePath = "consumer_executable_path"
            case consumerExecutableSHA256 = "consumer_executable_sha256"
            case hostReleaseID = "host_release_id"
            case sessionID = "session_id"
            case runtimeAuthoritySHA256 = "runtime_authority_sha256"
            case nativeStackBindingSHA256 = "native_stack_binding_sha256"
            case harnessBindingSHA256 = "harness_binding_sha256"
            case harnessGenerationID = "harness_generation_id"
            case harnessExecutableSHA256 = "harness_executable_sha256"
            case modelID = "model_id"
            case reasoningEffort = "reasoning_effort"
            case cyberAccessProgram = "cyber_access_program"
            case policyManifestSHA256 = "policy_manifest_sha256"
            case probeExecutableSHA256 = "probe_executable_sha256"
            case protocolVersion = "protocol_version"
            case launchDescriptorSHA256 = "launch_descriptor_sha256"
            case researchReleaseID = "research_release_id"
            case bootIDSHA256 = "boot_id_sha256"
            case qualificationSubjectSHA256 = "qualification_subject_sha256"
            case qualificationEvidenceSHA256 = "qualification_evidence_sha256"
            case qualificationObservedAt = "qualification_observed_at"
            case qualificationExpiresAt = "qualification_expires_at"
            case qualificationReadbackSHA256 = "qualification_readback_sha256"
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
            try Self.encode(
                projectionAuthority, to: &values
            )
            try values.encode(requestSHA256, forKey: .requestSHA256)
            try values.encode(authorizationReceiptSHA256, forKey: .authorizationReceiptSHA256)
            try values.encode(issuedAt, forKey: .issuedAt)
            try values.encode(expiresAt, forKey: .expiresAt)
            try values.encode(status, forKey: .status)
        }

        private static func encode(
            _ authority: NativeCredentialProjectionAuthority?,
            to values: inout KeyedEncodingContainer<CodingKeys>
        ) throws {
            try values.encode(authority?.consumerExecutablePath, forKey: .consumerExecutablePath)
            try values.encode(authority?.consumerExecutableSHA256, forKey: .consumerExecutableSHA256)
            try values.encode(authority?.hostReleaseID, forKey: .hostReleaseID)
            try values.encode(authority?.sessionID, forKey: .sessionID)
            try values.encode(authority?.runtimeAuthoritySHA256, forKey: .runtimeAuthoritySHA256)
            try values.encode(authority?.nativeStackBindingSHA256, forKey: .nativeStackBindingSHA256)
            try values.encode(authority?.harnessBindingSHA256, forKey: .harnessBindingSHA256)
            try values.encode(authority?.harnessGenerationID, forKey: .harnessGenerationID)
            try values.encode(authority?.harnessExecutableSHA256, forKey: .harnessExecutableSHA256)
            try values.encode(authority?.modelID, forKey: .modelID)
            try values.encode(authority?.reasoningEffort, forKey: .reasoningEffort)
            try values.encode(authority?.cyberAccessProgram, forKey: .cyberAccessProgram)
            try values.encode(authority?.policyManifestSHA256, forKey: .policyManifestSHA256)
            try values.encode(authority?.probeExecutableSHA256, forKey: .probeExecutableSHA256)
            try values.encode(authority?.protocolVersion, forKey: .protocolVersion)
            try values.encode(authority?.launchDescriptorSHA256, forKey: .launchDescriptorSHA256)
            try values.encode(authority?.researchReleaseID, forKey: .researchReleaseID)
            try values.encode(authority?.bootIDSHA256, forKey: .bootIDSHA256)
            try values.encode(authority?.qualificationSubjectSHA256, forKey: .qualificationSubjectSHA256)
            try values.encode(authority?.qualificationEvidenceSHA256, forKey: .qualificationEvidenceSHA256)
            try values.encode(authority?.qualificationObservedAt, forKey: .qualificationObservedAt)
            try values.encode(authority?.qualificationExpiresAt, forKey: .qualificationExpiresAt)
            try values.encode(authority?.qualificationReadbackSHA256, forKey: .qualificationReadbackSHA256)
        }
    }

    init(
        schema: String,
        ticketID: String,
        operationID: String,
        requestID: String,
        operation: NativeCredentialOperation,
        action: NativeAuthorizationAction,
        provider: NativeCredentialProvider,
        planSHA256: String,
        stackSHA256: String,
        sessionAuthoritySHA256: String?,
        requestSHA256: String,
        authorizationReceiptSHA256: String,
        issuedAt: Int64,
        expiresAt: Int64,
        status: String,
        ticketSHA256: String,
        projectionAuthority: NativeCredentialProjectionAuthority? = nil
    ) {
        self.schema = schema
        self.ticketID = ticketID
        self.operationID = operationID
        self.requestID = requestID
        self.operation = operation
        self.action = action
        self.provider = provider
        self.planSHA256 = planSHA256
        self.stackSHA256 = stackSHA256
        self.sessionAuthoritySHA256 = sessionAuthoritySHA256
        consumerExecutablePath = projectionAuthority?.consumerExecutablePath
        consumerExecutableSHA256 = projectionAuthority?.consumerExecutableSHA256
        hostReleaseID = projectionAuthority?.hostReleaseID
        sessionID = projectionAuthority?.sessionID
        runtimeAuthoritySHA256 = projectionAuthority?.runtimeAuthoritySHA256
        nativeStackBindingSHA256 = projectionAuthority?.nativeStackBindingSHA256
        harnessBindingSHA256 = projectionAuthority?.harnessBindingSHA256
        harnessGenerationID = projectionAuthority?.harnessGenerationID
        harnessExecutableSHA256 = projectionAuthority?.harnessExecutableSHA256
        modelID = projectionAuthority?.modelID
        reasoningEffort = projectionAuthority?.reasoningEffort
        cyberAccessProgram = projectionAuthority?.cyberAccessProgram
        policyManifestSHA256 = projectionAuthority?.policyManifestSHA256
        probeExecutableSHA256 = projectionAuthority?.probeExecutableSHA256
        protocolVersion = projectionAuthority?.protocolVersion
        launchDescriptorSHA256 = projectionAuthority?.launchDescriptorSHA256
        researchReleaseID = projectionAuthority?.researchReleaseID
        bootIDSHA256 = projectionAuthority?.bootIDSHA256
        qualificationSubjectSHA256 = projectionAuthority?.qualificationSubjectSHA256
        qualificationEvidenceSHA256 = projectionAuthority?.qualificationEvidenceSHA256
        qualificationObservedAt = projectionAuthority?.qualificationObservedAt
        qualificationExpiresAt = projectionAuthority?.qualificationExpiresAt
        qualificationReadbackSHA256 = projectionAuthority?.qualificationReadbackSHA256
        self.requestSHA256 = requestSHA256
        self.authorizationReceiptSHA256 = authorizationReceiptSHA256
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.status = status
        self.ticketSHA256 = ticketSHA256
    }

    var projectionAuthority: NativeCredentialProjectionAuthority? {
        guard let consumerExecutablePath,
              let consumerExecutableSHA256,
              let hostReleaseID,
              let sessionID,
              let runtimeAuthoritySHA256,
              let nativeStackBindingSHA256,
              let harnessBindingSHA256,
              let harnessGenerationID,
              let harnessExecutableSHA256,
              let modelID,
              let reasoningEffort,
              let cyberAccessProgram,
              let policyManifestSHA256,
              let probeExecutableSHA256,
              let protocolVersion,
              let launchDescriptorSHA256,
              let researchReleaseID,
              let bootIDSHA256,
              let qualificationSubjectSHA256,
              let qualificationEvidenceSHA256,
              let qualificationObservedAt,
              let qualificationExpiresAt,
              let qualificationReadbackSHA256 else {
            return nil
        }
        return NativeCredentialProjectionAuthority(
            consumerExecutablePath: consumerExecutablePath,
            consumerExecutableSHA256: consumerExecutableSHA256,
            hostReleaseID: hostReleaseID,
            sessionID: sessionID,
            runtimeAuthoritySHA256: runtimeAuthoritySHA256,
            nativeStackBindingSHA256: nativeStackBindingSHA256,
            harnessBindingSHA256: harnessBindingSHA256,
            harnessGenerationID: harnessGenerationID,
            harnessExecutableSHA256: harnessExecutableSHA256,
            modelID: modelID,
            reasoningEffort: reasoningEffort,
            cyberAccessProgram: cyberAccessProgram,
            policyManifestSHA256: policyManifestSHA256,
            probeExecutableSHA256: probeExecutableSHA256,
            protocolVersion: protocolVersion,
            launchDescriptorSHA256: launchDescriptorSHA256,
            researchReleaseID: researchReleaseID,
            bootIDSHA256: bootIDSHA256,
            qualificationSubjectSHA256: qualificationSubjectSHA256,
            qualificationEvidenceSHA256: qualificationEvidenceSHA256,
            qualificationObservedAt: qualificationObservedAt,
            qualificationExpiresAt: qualificationExpiresAt,
            qualificationReadbackSHA256: qualificationReadbackSHA256
        )
    }

    private var hasAnyProjectionAuthorityField: Bool {
        [consumerExecutablePath, consumerExecutableSHA256, hostReleaseID,
         sessionID, runtimeAuthoritySHA256, nativeStackBindingSHA256,
         harnessBindingSHA256, harnessGenerationID,
         harnessExecutableSHA256, modelID, reasoningEffort,
         cyberAccessProgram, policyManifestSHA256,
         probeExecutableSHA256, protocolVersion,
         launchDescriptorSHA256, researchReleaseID, bootIDSHA256,
         qualificationSubjectSHA256, qualificationEvidenceSHA256,
         qualificationReadbackSHA256].contains { $0 != nil }
            || qualificationObservedAt != nil || qualificationExpiresAt != nil
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
              ticketSHA256 == (try computedTicketSHA256) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        let expected: (NativeAuthorizationAction, Bool) = switch operation {
        case .login: (.signinBegin, false)
        case .refresh: (.entitlementVerify, false)
        case .projectForSession: (.sessionStart, true)
        case .logout: (.logout, false)
        case .destroyLocalCredential: (.credentialDestroy, false)
        case .recoverLocalState: (.recover, false)
        case .reconcileProjection, .inspectProjectionIdentity:
            throw NativeCredentialXPCError.authorizationTicketRejected
        case .status: throw NativeCredentialXPCError.authorizationTicketRejected
        }
        guard action == expected.0,
              (sessionAuthoritySHA256 != nil) == expected.1 else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
        if operation == .projectForSession {
            guard let sessionAuthoritySHA256,
                  let projectionAuthority else {
                throw NativeCredentialXPCError.authorizationTicketRejected
            }
            try projectionAuthority.validate(
                operationID: operationID,
                requestSHA256: requestSHA256,
                stackSHA256: stackSHA256,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                ticketIssuedAt: issuedAt,
                ticketExpiresAt: expiresAt,
                now: now
            )
        } else if hasAnyProjectionAuthorityField {
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
              projectionAuthority == request.projectionAuthority,
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
            projectionAuthority: projectionAuthority,
            requestSHA256: requestSHA256,
            authorizationReceiptSHA256: authorizationReceiptSHA256,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            status: status
        )
    }

    var computedTicketSHA256: String {
        get throws {
            Self.sha256(try computedTicketCanonicalData)
        }
    }

    var computedTicketCanonicalData: Data {
        get throws { try Self.canonicalData(digestBody) }
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
        try values.encode(consumerExecutablePath, forKey: .consumerExecutablePath)
        try values.encode(consumerExecutableSHA256, forKey: .consumerExecutableSHA256)
        try values.encode(hostReleaseID, forKey: .hostReleaseID)
        try values.encode(sessionID, forKey: .sessionID)
        try values.encode(runtimeAuthoritySHA256, forKey: .runtimeAuthoritySHA256)
        try values.encode(nativeStackBindingSHA256, forKey: .nativeStackBindingSHA256)
        try values.encode(harnessBindingSHA256, forKey: .harnessBindingSHA256)
        try values.encode(harnessGenerationID, forKey: .harnessGenerationID)
        try values.encode(harnessExecutableSHA256, forKey: .harnessExecutableSHA256)
        try values.encode(modelID, forKey: .modelID)
        try values.encode(reasoningEffort, forKey: .reasoningEffort)
        try values.encode(cyberAccessProgram, forKey: .cyberAccessProgram)
        try values.encode(policyManifestSHA256, forKey: .policyManifestSHA256)
        try values.encode(probeExecutableSHA256, forKey: .probeExecutableSHA256)
        try values.encode(protocolVersion, forKey: .protocolVersion)
        try values.encode(launchDescriptorSHA256, forKey: .launchDescriptorSHA256)
        try values.encode(researchReleaseID, forKey: .researchReleaseID)
        try values.encode(bootIDSHA256, forKey: .bootIDSHA256)
        try values.encode(qualificationSubjectSHA256, forKey: .qualificationSubjectSHA256)
        try values.encode(qualificationEvidenceSHA256, forKey: .qualificationEvidenceSHA256)
        try values.encode(qualificationObservedAt, forKey: .qualificationObservedAt)
        try values.encode(qualificationExpiresAt, forKey: .qualificationExpiresAt)
        try values.encode(qualificationReadbackSHA256, forKey: .qualificationReadbackSHA256)
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
                  "consumer_executable_path", "consumer_executable_sha256",
                  "host_release_id", "session_id", "runtime_authority_sha256",
                  "native_stack_binding_sha256", "harness_binding_sha256",
                  "harness_generation_id", "harness_executable_sha256",
                  "model_id", "reasoning_effort", "cyber_access_program",
                  "policy_manifest_sha256", "probe_executable_sha256",
                  "protocol_version", "launch_descriptor_sha256",
                  "research_release_id", "boot_id_sha256",
                  "qualification_subject_sha256",
                  "qualification_evidence_sha256",
                  "qualification_observed_at", "qualification_expires_at",
                  "qualification_readback_sha256",
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
