import CryptoKit
import Darwin
import Foundation

enum NativeCredentialXPCError: Error, Equatable, Sendable {
    case invalidRequest
    case callerIdentityRejected
    case authorizationTicketRejected
    case authorizationTicketReplayed
    case ticketReplayStoreFailed
    case operationRejected
}

struct NativeCredentialIPCRequest: Codable, Equatable, Sendable {
    static let schemaName = "secure-sandbox-native-credential-ipc-request-v1"
    static let maximumBytes = 32 * 1024

    let schema: String
    let command: NativeCredentialCommand
    let authorizationTicketID: String?
    let planSHA256: String?
    let operatorRequestSHA256: String?
    let stackSHA256: String?
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
    let ipcRequestSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case command
        case authorizationTicketID = "authorization_ticket_id"
        case planSHA256 = "plan_sha256"
        case operatorRequestSHA256 = "operator_request_sha256"
        case stackSHA256 = "stack_sha256"
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
        case ipcRequestSHA256 = "ipc_request_sha256"
    }

    private struct DigestBody: Encodable {
        let command: NativeCredentialCommand
        let authorizationTicketID: String?
        let planSHA256: String?
        let operatorRequestSHA256: String?
        let stackSHA256: String?
        let projectionAuthority: NativeCredentialProjectionAuthority?

        enum CodingKeys: String, CodingKey {
            case command
            case authorizationTicketID = "authorization_ticket_id"
            case planSHA256 = "plan_sha256"
            case operatorRequestSHA256 = "operator_request_sha256"
            case stackSHA256 = "stack_sha256"
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
        }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(command, forKey: .command)
            try values.encode(authorizationTicketID, forKey: .authorizationTicketID)
            try values.encode(planSHA256, forKey: .planSHA256)
            try values.encode(operatorRequestSHA256, forKey: .operatorRequestSHA256)
            try values.encode(stackSHA256, forKey: .stackSHA256)
            let authority = projectionAuthority
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
        command: NativeCredentialCommand,
        authorizationTicketID: String? = nil,
        planSHA256: String? = nil,
        operatorRequestSHA256: String? = nil,
        stackSHA256: String? = nil,
        projectionAuthority: NativeCredentialProjectionAuthority? = nil
    ) throws {
        self.schema = Self.schemaName
        self.command = command
        self.authorizationTicketID = authorizationTicketID
        self.planSHA256 = planSHA256
        self.operatorRequestSHA256 = operatorRequestSHA256
        self.stackSHA256 = stackSHA256
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
        self.ipcRequestSHA256 = Self.sha256(try Self.canonicalData(DigestBody(
            command: command,
            authorizationTicketID: authorizationTicketID,
            planSHA256: planSHA256,
            operatorRequestSHA256: operatorRequestSHA256,
            stackSHA256: stackSHA256,
            projectionAuthority: projectionAuthority
        )))
        try validate()
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
              let qualificationReadbackSHA256 else { return nil }
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

    static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= maximumBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "command", "authorization_ticket_id", "plan_sha256",
                  "operator_request_sha256", "stack_sha256",
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
                  "qualification_readback_sha256", "ipc_request_sha256",
              ]),
              let request = try? Self.decoder.decode(Self.self, from: data),
              data == (try? request.encoded()) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        try request.validate()
        return request
    }

    func encoded() throws -> Data {
        try Self.canonicalData(self)
    }

    func validate() throws {
        try command.validate()
        guard schema == Self.schemaName,
              NativeAuthorizationTicket.isSHA256(ipcRequestSHA256),
              ipcRequestSHA256 == Self.sha256(try Self.canonicalData(DigestBody(
                  command: command,
                  authorizationTicketID: authorizationTicketID,
                  planSHA256: planSHA256,
                  operatorRequestSHA256: operatorRequestSHA256,
                  stackSHA256: stackSHA256,
                  projectionAuthority: projectionAuthority
              ))) else {
            throw NativeCredentialXPCError.invalidRequest
        }
        if command.operation == .status {
            guard authorizationTicketID == nil, planSHA256 == nil,
                  operatorRequestSHA256 == nil, stackSHA256 == nil,
                  !hasAnyProjectionAuthorityField else {
                throw NativeCredentialXPCError.invalidRequest
            }
        } else {
            guard let authorizationTicketID,
                  NativeAuthorizationTicket.isUUID4(authorizationTicketID),
                  let planSHA256,
                  NativeAuthorizationTicket.isSHA256(planSHA256),
                  let operatorRequestSHA256,
                  NativeAuthorizationTicket.isSHA256(operatorRequestSHA256),
                  let stackSHA256,
                  NativeAuthorizationTicket.isSHA256(stackSHA256) else {
                throw NativeCredentialXPCError.invalidRequest
            }
            if command.operation == .projectForSession {
                guard projectionAuthority != nil else {
                    throw NativeCredentialXPCError.invalidRequest
                }
            } else if hasAnyProjectionAuthorityField {
                throw NativeCredentialXPCError.invalidRequest
            }
        }
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(command, forKey: .command)
        try values.encode(authorizationTicketID, forKey: .authorizationTicketID)
        try values.encode(planSHA256, forKey: .planSHA256)
        try values.encode(operatorRequestSHA256, forKey: .operatorRequestSHA256)
        try values.encode(stackSHA256, forKey: .stackSHA256)
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
        try values.encode(ipcRequestSHA256, forKey: .ipcRequestSHA256)
    }

    private static var decoder: JSONDecoder { JSONDecoder() }

    private static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct NativeCredentialProjectionStatus: Codable, Equatable, Sendable {
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let executableSHA256: String
    let sessionAuthoritySHA256: String
    let startedAtMilliseconds: Int64

    enum CodingKeys: String, CodingKey {
        case processIdentifier = "process_identifier"
        case processStartTimeMicroseconds = "process_start_time_us"
        case executableSHA256 = "executable_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case startedAtMilliseconds = "started_at_milliseconds"
    }

    init(_ launched: LaunchedCredentialConsumer) throws {
        guard launched.processIdentifier > 0,
              launched.processStartTimeMicroseconds > 0,
              NativeAuthorizationTicket.isSHA256(launched.executableSHA256),
              NativeAuthorizationTicket.isSHA256(launched.sessionAuthoritySHA256) else {
            throw NativeCredentialXPCError.operationRejected
        }
        processIdentifier = launched.processIdentifier
        processStartTimeMicroseconds = launched.processStartTimeMicroseconds
        executableSHA256 = launched.executableSHA256
        sessionAuthoritySHA256 = launched.sessionAuthoritySHA256
        startedAtMilliseconds = Int64(launched.startedAt.timeIntervalSince1970 * 1_000)
    }

    func validate() throws {
        guard processIdentifier > 0, processStartTimeMicroseconds > 0,
              NativeAuthorizationTicket.isSHA256(executableSHA256),
              NativeAuthorizationTicket.isSHA256(sessionAuthoritySHA256),
              startedAtMilliseconds > 0 else {
            throw NativeCredentialXPCError.operationRejected
        }
    }
}

enum NativeCredentialIPCOutcome: String, Codable, Sendable {
    case verified
    case rejected
}

enum NativeCredentialIPCErrorCode: String, Codable, Sendable {
    case invalidRequest = "invalid-request"
    case callerRejected = "caller-rejected"
    case ticketRejected = "authorization-ticket-rejected"
    case ticketReplayed = "authorization-ticket-replayed"
    case credentialUnavailable = "credential-unavailable"
    case providerUnavailable = "provider-unavailable"
    case operationInProgress = "operation-in-progress"
    case operationRejected = "operation-rejected"
    case internalFailure = "internal-failure"
}

struct NativeCredentialIPCReply: Codable, Equatable, Sendable {
    static let schemaName = "secure-sandbox-native-credential-ipc-reply-v1"

    let schema: String
    let operationID: String?
    let outcome: NativeCredentialIPCOutcome
    let status: NativeCredentialStatus?
    let projection: NativeCredentialProjectionStatus?
    let errorCode: NativeCredentialIPCErrorCode?
    let responseSHA256: String

    enum CodingKeys: String, CodingKey {
        case schema
        case operationID = "operation_id"
        case outcome
        case status
        case projection
        case errorCode = "error_code"
        case responseSHA256 = "response_sha256"
    }

    private struct DigestBody: Encodable {
        let operationID: String?
        let outcome: NativeCredentialIPCOutcome
        let status: NativeCredentialStatus?
        let projection: NativeCredentialProjectionStatus?
        let errorCode: NativeCredentialIPCErrorCode?

        enum CodingKeys: String, CodingKey {
            case operationID = "operation_id"
            case outcome
            case status
            case projection
            case errorCode = "error_code"
        }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(operationID, forKey: .operationID)
            try values.encode(outcome, forKey: .outcome)
            try values.encode(status, forKey: .status)
            try values.encode(projection, forKey: .projection)
            try values.encode(errorCode, forKey: .errorCode)
        }
    }

    static func success(
        operationID: UUID,
        status: NativeCredentialStatus? = nil,
        projection: NativeCredentialProjectionStatus? = nil
    ) throws -> Self {
        try make(
            operationID: operationID.uuidString.lowercased(),
            outcome: .verified,
            status: status,
            projection: projection,
            errorCode: nil
        )
    }

    static func failure(operationID: UUID?, code: NativeCredentialIPCErrorCode) -> Self {
        // Every member is already bounded and encodable; construction failure
        // would indicate a programmer error, not provider-controlled input.
        try! make(
            operationID: operationID?.uuidString.lowercased(),
            outcome: .rejected,
            status: nil,
            projection: nil,
            errorCode: code
        )
    }

    private static func make(
        operationID: String?,
        outcome: NativeCredentialIPCOutcome,
        status: NativeCredentialStatus?,
        projection: NativeCredentialProjectionStatus?,
        errorCode: NativeCredentialIPCErrorCode?
    ) throws -> Self {
        guard (outcome == .verified) == (errorCode == nil),
              (outcome == .verified
                   ? ((status != nil) != (projection != nil)) && operationID != nil
                   : status == nil && projection == nil),
              operationID.map(NativeAuthorizationTicket.isUUID4) ?? true else {
            throw NativeCredentialXPCError.operationRejected
        }
        let body = DigestBody(
            operationID: operationID,
            outcome: outcome,
            status: status,
            projection: projection,
            errorCode: errorCode
        )
        return Self(
            schema: schemaName,
            operationID: operationID,
            outcome: outcome,
            status: status,
            projection: projection,
            errorCode: errorCode,
            responseSHA256: NativeAuthorizationTicket.sha256(try canonicalData(body))
        )
    }

    func encoded() throws -> Data { try Self.canonicalData(self) }

    static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 32 * 1024,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "operation_id", "outcome", "status", "projection",
                  "error_code", "response_sha256",
              ]),
              let reply = try? decoder.decode(Self.self, from: data),
              data == (try? reply.encoded()),
              reply.schema == schemaName,
              (reply.outcome == .verified) == (reply.errorCode == nil),
              (reply.outcome == .verified
                   ? ((reply.status != nil) != (reply.projection != nil))
                       && reply.operationID != nil
                   : reply.status == nil && reply.projection == nil),
              reply.operationID.map(NativeAuthorizationTicket.isUUID4) ?? true,
              NativeAuthorizationTicket.isSHA256(reply.responseSHA256),
              reply.responseSHA256 == NativeAuthorizationTicket.sha256(
                  try canonicalData(DigestBody(
                      operationID: reply.operationID,
                      outcome: reply.outcome,
                      status: reply.status,
                      projection: reply.projection,
                      errorCode: reply.errorCode
                  ))
              ) else {
            throw NativeCredentialXPCError.operationRejected
        }
        if let status = reply.status {
            _ = try NativeCredentialStatus(
                provider: status.provider,
                state: status.state,
                clientIDHash: status.clientIDHash,
                accountSubjectSHA256: status.accountSubjectSHA256,
                workspaceSHA256: status.workspaceSHA256,
                scopeSHA256: status.scopeSHA256,
                accessExpiresAt: status.accessExpiresAt,
                earliestRefreshAt: status.earliestRefreshAt,
                refreshExpiresAt: status.refreshExpiresAt,
                custodyState: status.custodyState,
                custodyTombstoneSHA256: status.custodyTombstoneSHA256,
                custodyProjectionCount: status.custodyProjectionCount
            )
        }
        try reply.projection?.validate()
        return reply
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schema, forKey: .schema)
        try values.encode(operationID, forKey: .operationID)
        try values.encode(outcome, forKey: .outcome)
        try values.encode(status, forKey: .status)
        try values.encode(projection, forKey: .projection)
        try values.encode(errorCode, forKey: .errorCode)
        try values.encode(responseSHA256, forKey: .responseSHA256)
    }

    private static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var result = try encoder.encode(value)
        result.append(0x0a)
        return result
    }

    private static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}

protocol NativeCredentialCoordinating: Sendable {
    func status(now: Date) async throws -> NativeCredentialStatus
    func login(now: Date) async throws -> NativeCredentialStatus
    func refresh(now: Date) async throws -> NativeCredentialStatus
    func logout() async throws -> NativeCredentialStatus
    func destroyLocalCredential() async throws -> NativeCredentialStatus
    func recoverLocalState() async throws -> NativeCredentialStatus
    func prepareProjection(
        _ request: CredentialProjectionRequest,
        now: Date
    ) async throws -> PreparedCredentialConsumer
}

extension NativeCredentialCoordinator: NativeCredentialCoordinating {}

protocol NativeCredentialCancellationChecking: Sendable {
    func checkCancellation() throws
}

struct NativeCredentialNeverCancelled: NativeCredentialCancellationChecking {
    func checkCancellation() throws { try Task.checkCancellation() }
}

struct NativeCredentialXPCPeerRequirementProof: Sendable {
    fileprivate let requirementSHA256: String

    init(requirementSHA256: String) throws {
        guard NativeAuthorizationTicket.isSHA256(requirementSHA256) else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        self.requirementSHA256 = requirementSHA256
    }
}

protocol NativeCredentialProjectionChannelValidating: Sendable {
    func validate(_ descriptor: Int32) throws
}

struct SystemNativeCredentialProjectionChannelValidator:
    NativeCredentialProjectionChannelValidating, Sendable
{
    func validate(_ descriptor: Int32) throws {
        var information = stat()
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        var socketType: Int32 = 0
        var socketTypeSize = socklen_t(MemoryLayout<Int32>.size)
        var localAddress = sockaddr_storage()
        var localAddressSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        var peerAddress = sockaddr_storage()
        var peerAddressSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        guard descriptor >= 0,
              fstat(descriptor, &information) == 0,
              information.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
              isatty(descriptor) == 0,
              getsockopt(
                  descriptor, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeSize
              ) == 0,
              socketTypeSize == socklen_t(MemoryLayout<Int32>.size),
              socketType == SOCK_STREAM,
              withUnsafeMutablePointer(to: &localAddress, {
                  $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                      getsockname(descriptor, $0, &localAddressSize)
                  }
              }) == 0,
              localAddress.ss_family == sa_family_t(AF_UNIX),
              withUnsafeMutablePointer(to: &peerAddress, {
                  $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                      getpeername(descriptor, $0, &peerAddressSize)
                  }
              }) == 0,
              peerAddress.ss_family == sa_family_t(AF_UNIX),
              getpeereid(descriptor, &peerUID, &peerGID) == 0,
              peerUID == 0, peerGID == 0 else {
            throw NativeCredentialXPCError.invalidRequest
        }
    }
}

actor NativeCredentialXPCServiceCore {
    private let callerValidator: any NativeCredentialCallerIdentityValidating
    private let ticketReader: any NativeAuthorizationTicketReading
    private let reconciliationTicketReader:
        any NativeProjectionReconciliationTicketReading
    private let identityRecoveryTicketReader:
        any NativeProjectionIdentityRecoveryTicketReading
    private let replayStore: any NativeAuthorizationTicketReplayProtecting
    private let custodyLedger: any NativeCredentialCustodyTracking
    private let projectionCompletionMonitor:
        NativeCredentialProjectionCompletionMonitor
    private let projectionChannelValidator:
        any NativeCredentialProjectionChannelValidating
    private let coordinator: any NativeCredentialCoordinating
    private let projectionClock: @Sendable () -> Date
    private let projectionMonotonicClock:
        @Sendable () -> ContinuousClock.Instant
    private let expectedXPCPeerRequirementSHA256: String?
    private var requestActive = false
    private var projectionReservations: Set<UUID> = []

    init(
        callerValidator: any NativeCredentialCallerIdentityValidating,
        ticketReader: any NativeAuthorizationTicketReading,
        reconciliationTicketReader:
            any NativeProjectionReconciliationTicketReading =
                RootOwnedNativeProjectionReconciliationTicketReader(),
        identityRecoveryTicketReader:
            any NativeProjectionIdentityRecoveryTicketReading =
                RootOwnedNativeProjectionIdentityRecoveryTicketReader(),
        replayStore: any NativeAuthorizationTicketReplayProtecting,
        coordinator: any NativeCredentialCoordinating,
        custodyLedger: any NativeCredentialCustodyTracking = UnknownNativeCredentialCustodyLedger(),
        projectionChannelValidator:
            any NativeCredentialProjectionChannelValidating =
                SystemNativeCredentialProjectionChannelValidator(),
        expectedXPCPeerRequirementSHA256: String? = nil,
        projectionClock: @escaping @Sendable () -> Date = Date.init,
        projectionMonotonicClock:
            @escaping @Sendable () -> ContinuousClock.Instant = {
                ContinuousClock.now
            }
    ) {
        self.callerValidator = callerValidator
        self.ticketReader = ticketReader
        self.reconciliationTicketReader = reconciliationTicketReader
        self.identityRecoveryTicketReader = identityRecoveryTicketReader
        self.replayStore = replayStore
        self.custodyLedger = custodyLedger
        projectionCompletionMonitor = NativeCredentialProjectionCompletionMonitor(
            custodyLedger: custodyLedger
        )
        self.projectionChannelValidator = projectionChannelValidator
        self.coordinator = coordinator
        self.expectedXPCPeerRequirementSHA256 = expectedXPCPeerRequirementSHA256
        self.projectionClock = projectionClock
        self.projectionMonotonicClock = projectionMonotonicClock
    }

    func handle(
        requestData: Data,
        caller: CallerAuditEvidence,
        projectionFD: Int32 = -1,
        now: Date = Date()
    ) async -> Data {
        do {
            try callerValidator.validate(caller)
        } catch {
            return Self.failureData(operationID: nil, error: error)
        }
        return await handleVerified(
            requestData: requestData,
            cancellation: NativeCredentialNeverCancelled(),
            projectionFD: projectionFD,
            now: now
        )
    }

    func handleSystemXPC(
        requestData: Data,
        proof: NativeCredentialXPCPeerRequirementProof,
        projectionFD: Int32 = -1,
        cancellation: any NativeCredentialCancellationChecking,
        now: Date = Date()
    ) async -> Data {
        guard let expectedXPCPeerRequirementSHA256,
              proof.requirementSHA256 == expectedXPCPeerRequirementSHA256 else {
            return Self.failureData(
                operationID: nil,
                error: NativeCredentialXPCError.callerIdentityRejected
            )
        }
        return await handleVerified(
            requestData: requestData,
            cancellation: cancellation,
            projectionFD: projectionFD,
            now: now
        )
    }

    private func handleVerified(
        requestData: Data,
        cancellation: any NativeCredentialCancellationChecking,
        projectionFD: Int32,
        now: Date
    ) async -> Data {
        guard !requestActive else {
            return Self.failureData(
                operationID: nil,
                error: NativeCredentialHelperError.operationInProgress
            )
        }
        requestActive = true
        defer { requestActive = false }
        var operationID: UUID?
        do {
            try cancellation.checkCancellation()
            if try Self.requestSchema(requestData)
                    == NativeProjectionIdentityRecoveryIPCRequest.schemaName {
                guard projectionFD == -1 else {
                    throw NativeCredentialXPCError.invalidRequest
                }
                let request = try NativeProjectionIdentityRecoveryIPCRequest
                    .decodeExact(requestData)
                guard let recoveryOperationID = UUID(
                    uuidString: request.recoveryOperationID
                ) else {
                    throw NativeCredentialXPCError.invalidRequest
                }
                operationID = recoveryOperationID
                let ticket = try identityRecoveryTicketReader.read(
                    ticketID: request.ticketID,
                    now: now
                )
                try ticket.matches(request: request, now: now)
                try replayStore.claim(ticket, now: now)
                // The one-shot authorization is consumed before any durable
                // identity is disclosed. This path never clears custody.
                try cancellation.checkCancellation()
                let completion = try custodyLedger
                    .inspectProjectionIdentity(ticket: ticket, now: now)
                let reply = try NativeProjectionIdentityRecoveryIPCReply(
                    request: request,
                    completion: completion
                )
                try cancellation.checkCancellation()
                return try reply.encoded()
            }
            if try Self.requestSchema(requestData)
                    == NativeProjectionReconciliationIPCRequest.schemaName {
                guard projectionFD == -1 else {
                    throw NativeCredentialXPCError.invalidRequest
                }
                let request = try NativeProjectionReconciliationIPCRequest
                    .decodeExact(requestData)
                guard let recoveryOperationID = UUID(
                    uuidString: request.recoveryOperationID
                ) else {
                    throw NativeCredentialXPCError.invalidRequest
                }
                operationID = recoveryOperationID
                let ticket = try reconciliationTicketReader.read(
                    ticketID: request.ticketID,
                    now: now
                )
                try ticket.matches(request: request, now: now)
                try replayStore.claim(ticket, now: now)
                // Ticket replay is durably consumed before custody mutation.
                try cancellation.checkCancellation()
                let completion = try custodyLedger.reconcileProjection(
                    ticket: ticket,
                    now: now
                )
                let reply = try NativeProjectionReconciliationIPCReply(
                    request: request,
                    completion: completion
                )
                try cancellation.checkCancellation()
                return try reply.encoded()
            }
            let request = try NativeCredentialIPCRequest.decodeExact(requestData)
            operationID = request.command.operationID
            if request.command.operation == .projectForSession {
                try projectionChannelValidator.validate(projectionFD)
            } else if projectionFD != -1 {
                throw NativeCredentialXPCError.invalidRequest
            }
            var authorizedTicket: NativeAuthorizationTicket?
            if request.command.operation != .status {
                guard let ticketID = request.authorizationTicketID else {
                    throw NativeCredentialXPCError.authorizationTicketRejected
                }
                let ticket = try ticketReader.read(ticketID: ticketID, now: now)
                try ticket.matches(request: request, now: now)
                try replayStore.claim(ticket, now: now)
                authorizedTicket = ticket
            }
            // A lost peer after durable ticket consumption must never start a
            // credential mutation. The consumed tombstone remains fail-closed.
            try cancellation.checkCancellation()
            let reply: NativeCredentialIPCReply
            switch request.command.operation {
            case .status:
                let status = try await coordinator.status(now: now)
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try statusWithCustody(status, now: now)
                )
            case .login:
                let status = try await coordinator.login(now: now)
                try custodyLedger.clear()
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try statusWithCustody(status, now: now)
                )
            case .refresh:
                let status = try await coordinator.refresh(now: now)
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try statusWithCustody(status, now: now)
                )
            case .logout:
                let status = try await coordinator.logout()
                try custodyLedger.clear()
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try statusWithCustody(status, now: now)
                )
            case .destroyLocalCredential:
                let status = try await coordinator.destroyLocalCredential()
                guard let authorizedTicket else {
                    throw NativeCredentialXPCError.authorizationTicketRejected
                }
                try custodyLedger.recordDestruction(
                    ticketSHA256: authorizedTicket.ticketSHA256
                )
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try statusWithCustody(status, now: now)
                )
            case .recoverLocalState:
                let status = try await coordinator.recoverLocalState()
                guard let authorizedTicket else {
                    throw NativeCredentialXPCError.authorizationTicketRejected
                }
                try custodyLedger.recordDestruction(
                    ticketSHA256: authorizedTicket.ticketSHA256
                )
                reply = try .success(
                    operationID: request.command.operationID,
                    status: try statusWithCustody(status, now: now)
                )
            case .projectForSession:
                guard let session = request.command.sessionAuthoritySHA256,
                      let receipt = request.command.authorizationReceiptSHA256,
                      let ticket = authorizedTicket,
                      let authority = ticket.projectionAuthority,
                      let stackSHA256 = request.stackSHA256,
                      let operatorRequestSHA256 = request.operatorRequestSHA256
                else {
                    throw NativeCredentialXPCError.authorizationTicketRejected
                }
                let projectionRequest = try CredentialProjectionRequest(
                    operationID: request.command.operationID,
                    sessionAuthoritySHA256: session,
                    authorizationReceiptSHA256: receipt,
                    authorizationTicketSHA256: ticket.ticketSHA256,
                    stackSHA256: stackSHA256,
                    operatorRequestSHA256: operatorRequestSHA256,
                    ticketIssuedAt: ticket.issuedAt,
                    ticketExpiresAt: ticket.expiresAt,
                    projectionAuthority: authority,
                    expiresAt: min(
                        Date(timeIntervalSince1970: TimeInterval(
                            min(ticket.expiresAt,
                                authority.qualificationExpiresAt)
                        )),
                        now.addingTimeInterval(120)
                    ),
                    projectionChannelFD: projectionFD
                )
                let admissionWallNow = max(now, projectionClock())
                try projectionRequest.validate(now: admissionWallNow)
                let releaseDeadline = try NativeCredentialReleaseDeadline(
                    wallExpiresAt: projectionRequest.expiresAt,
                    admittedWallNow: admissionWallNow,
                    admittedMonotonicNow: projectionMonotonicClock()
                )
                guard projectionReservations.insert(
                    request.command.operationID
                ).inserted else {
                    throw NativeCredentialXPCError.operationRejected
                }
                defer {
                    projectionReservations.remove(request.command.operationID)
                }
                var prepared: PreparedCredentialConsumer?
                do {
                    prepared = try await coordinator.prepareProjection(
                        projectionRequest, now: admissionWallNow
                    )
                    guard let prepared else {
                        throw NativeCredentialXPCError.operationRejected
                    }
                    let launched = prepared.consumer
                    guard let termination = launched.termination else {
                        throw NativeCredentialXPCError.operationRejected
                    }
                    let commitNow = max(now, projectionClock())
                    try projectionRequest.validate(now: commitNow)
                    try releaseDeadline.validate(
                        wallNow: commitNow,
                        monotonicNow: projectionMonotonicClock()
                    )
                    try custodyLedger.commitProjection(
                        operationID: request.command.operationID,
                        consumer: launched,
                        binding: projectionRequest.custodyBinding,
                        expiresAt: projectionRequest.expiresAt,
                        now: commitNow
                    )
                    // A disconnected authorized caller may not cause token
                    // release merely because its ticket was already consumed.
                    try cancellation.checkCancellation()
                    try prepared.releaseCredential(
                        before: releaseDeadline,
                        wallClock: projectionClock,
                        monotonicClock: projectionMonotonicClock,
                        continuationCheck: {
                            try cancellation.checkCancellation()
                        }
                    )
                    projectionCompletionMonitor.start(
                        operationID: request.command.operationID,
                        consumer: launched,
                        termination: termination
                    )
                } catch {
                    prepared?.abortWithoutRelease()
                    if let prepared {
                        let launched = prepared.consumer
                        guard let termination = launched.termination else {
                            throw NativeCredentialHelperError
                                .consumerTerminationUnproven
                        }
                        do {
                            try await termination.terminateAndReap()
                        } catch {
                            // Once identity is committed, neither a delivery
                            // ambiguity nor failed termination may erase it.
                            throw NativeCredentialHelperError
                                .consumerTerminationUnproven
                        }
                    }
                    throw error
                }
                guard let launched = prepared?.consumer else {
                    throw NativeCredentialXPCError.operationRejected
                }
                reply = try .success(
                    operationID: request.command.operationID,
                    projection: NativeCredentialProjectionStatus(launched)
                )
            case .reconcileProjection, .inspectProjectionIdentity:
                throw NativeCredentialXPCError.invalidRequest
            }
            try cancellation.checkCancellation()
            return try reply.encoded()
        } catch {
            return Self.failureData(operationID: operationID, error: error)
        }
    }

    private static func requestSchema(_ data: Data) throws -> String {
        guard data.count <= NativeCredentialIPCRequest.maximumBytes,
              let object = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              let schema = object["schema"] as? String,
              schema.utf8.count <= 256 else {
            throw NativeCredentialXPCError.invalidRequest
        }
        return schema
    }


    private func statusWithCustody(
        _ status: NativeCredentialStatus,
        now: Date
    ) throws -> NativeCredentialStatus {
        let observation = try custodyLedger.observe(
            hasCredential: status.state != .loggedOut,
            now: now
        )
        return try NativeCredentialStatus(
            provider: status.provider,
            state: status.state,
            clientIDHash: status.clientIDHash,
            accountSubjectSHA256: status.accountSubjectSHA256,
            workspaceSHA256: status.workspaceSHA256,
            scopeSHA256: status.scopeSHA256,
            accessExpiresAt: status.accessExpiresAt,
            earliestRefreshAt: status.earliestRefreshAt,
            refreshExpiresAt: status.refreshExpiresAt,
            custodyState: observation.state,
            custodyTombstoneSHA256: observation.tombstoneSHA256,
            custodyProjectionCount: observation.projectionCount
        )
    }

    private static func failureData(operationID: UUID?, error: any Error) -> Data {
        // NativeCredentialIPCReply.failure is total for these bounded enum and
        // UUID inputs; no provider-controlled content reaches this path.
        try! NativeCredentialIPCReply.failure(
            operationID: operationID,
            code: errorCode(error)
        ).encoded()
    }

    private static func errorCode(_ error: any Error) -> NativeCredentialIPCErrorCode {
        switch error {
        case NativeCredentialXPCError.callerIdentityRejected:
            .callerRejected
        case NativeCredentialXPCError.invalidRequest:
            .invalidRequest
        case NativeCredentialXPCError.authorizationTicketReplayed:
            .ticketReplayed
        case NativeCredentialXPCError.authorizationTicketRejected,
             NativeCredentialXPCError.ticketReplayStoreFailed:
            .ticketRejected
        case NativeCredentialHelperError.credentialNotFound,
             NativeCredentialHelperError.credentialStoreFailed,
             NativeCredentialHelperError.secureEnclaveUnavailable,
             NativeCredentialHelperError.hostIdentityUnavailable:
            .credentialUnavailable
        case NativeCredentialHelperError.providerTransportFailed,
             NativeCredentialHelperError.revocationFailed,
             NativeCredentialHelperError.refreshValidationUnavailable:
            .providerUnavailable
        case NativeCredentialHelperError.operationInProgress:
            .operationInProgress
        default:
            .operationRejected
        }
    }
}

// The bundle-facing XPC target exports only this one bounded Data method.  Its
// connection adapter must obtain an audit token from the accepted Mach/XPC
// connection and construct CallerAuditEvidence before invoking the service
// core; PID-only identity is explicitly not an admissible substitute.
@objc protocol SecureSandboxNativeCredentialXPCProtocol {
    func perform(_ request: Data, withReply reply: @escaping (Data) -> Void)
}
