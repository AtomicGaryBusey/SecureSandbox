import CryptoKit
import Foundation

public struct NativeCredentialProjectionAuthority: Codable, Equatable, Sendable {
    public let consumerExecutablePath: String
    public let consumerExecutableSHA256: String
    public let hostReleaseID: String
    public let sessionID: String
    public let runtimeAuthoritySHA256: String
    public let nativeStackBindingSHA256: String
    public let harnessBindingSHA256: String
    public let harnessGenerationID: String
    public let harnessExecutableSHA256: String
    public let modelID: String
    public let reasoningEffort: String
    public let cyberAccessProgram: String
    public let policyManifestSHA256: String
    public let probeExecutableSHA256: String
    public let protocolVersion: String
    public let launchDescriptorSHA256: String
    public let researchReleaseID: String
    public let bootIDSHA256: String
    public let qualificationSubjectSHA256: String
    public let qualificationEvidenceSHA256: String
    public let qualificationObservedAt: Int64
    public let qualificationExpiresAt: Int64
    public let qualificationReadbackSHA256: String

    enum CodingKeys: String, CodingKey {
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

    public init(
        consumerExecutablePath: String,
        consumerExecutableSHA256: String,
        hostReleaseID: String,
        sessionID: String,
        runtimeAuthoritySHA256: String,
        nativeStackBindingSHA256: String,
        harnessBindingSHA256: String,
        harnessGenerationID: String,
        harnessExecutableSHA256: String,
        modelID: String,
        reasoningEffort: String,
        cyberAccessProgram: String,
        policyManifestSHA256: String,
        probeExecutableSHA256: String,
        protocolVersion: String,
        launchDescriptorSHA256: String,
        researchReleaseID: String,
        bootIDSHA256: String,
        qualificationSubjectSHA256: String,
        qualificationEvidenceSHA256: String,
        qualificationObservedAt: Int64,
        qualificationExpiresAt: Int64,
        qualificationReadbackSHA256: String
    ) {
        self.consumerExecutablePath = consumerExecutablePath
        self.consumerExecutableSHA256 = consumerExecutableSHA256
        self.hostReleaseID = hostReleaseID
        self.sessionID = sessionID
        self.runtimeAuthoritySHA256 = runtimeAuthoritySHA256
        self.nativeStackBindingSHA256 = nativeStackBindingSHA256
        self.harnessBindingSHA256 = harnessBindingSHA256
        self.harnessGenerationID = harnessGenerationID
        self.harnessExecutableSHA256 = harnessExecutableSHA256
        self.modelID = modelID
        self.reasoningEffort = reasoningEffort
        self.cyberAccessProgram = cyberAccessProgram
        self.policyManifestSHA256 = policyManifestSHA256
        self.probeExecutableSHA256 = probeExecutableSHA256
        self.protocolVersion = protocolVersion
        self.launchDescriptorSHA256 = launchDescriptorSHA256
        self.researchReleaseID = researchReleaseID
        self.bootIDSHA256 = bootIDSHA256
        self.qualificationSubjectSHA256 = qualificationSubjectSHA256
        self.qualificationEvidenceSHA256 = qualificationEvidenceSHA256
        self.qualificationObservedAt = qualificationObservedAt
        self.qualificationExpiresAt = qualificationExpiresAt
        self.qualificationReadbackSHA256 = qualificationReadbackSHA256
    }

    func validate(
        operationID: String,
        requestSHA256: String,
        stackSHA256: String,
        sessionAuthoritySHA256: String,
        ticketIssuedAt: Int64,
        ticketExpiresAt: Int64,
        now: Date
    ) throws {
        let digests = [
            consumerExecutableSHA256, hostReleaseID,
            runtimeAuthoritySHA256, nativeStackBindingSHA256,
            harnessBindingSHA256, harnessGenerationID,
            harnessExecutableSHA256, policyManifestSHA256,
            probeExecutableSHA256, launchDescriptorSHA256,
            researchReleaseID, bootIDSHA256,
            qualificationSubjectSHA256, qualificationEvidenceSHA256,
            qualificationReadbackSHA256, stackSHA256,
            sessionAuthoritySHA256,
            requestSHA256,
        ]
        let expectedPath =
            "/usr/local/libexec/secure-sandbox-host/releases/"
            + hostReleaseID + "/native_projection_consumer"
        guard digests.allSatisfy(NativeAuthorizationTicket.isSHA256),
              NativeAuthorizationTicket.isUUID4(sessionID),
              NativeAuthorizationTicket.isUUID4(operationID),
              consumerExecutablePath == expectedPath,
              runtimeAuthoritySHA256 == sessionAuthoritySHA256,
              ["gpt-6-sol", "gpt-6-luna", "gpt-6.1-sol"].contains(modelID),
              ["low", "medium", "high", "xhigh"].contains(reasoningEffort),
              cyberAccessProgram == "daybreakBlue",
              protocolVersion.range(
                  of: #"^[A-Za-z0-9._-]{1,64}$"#,
                  options: .regularExpression
              ) != nil,
              qualificationObservedAt > 0,
              qualificationExpiresAt > qualificationObservedAt,
              qualificationExpiresAt <= qualificationObservedAt + 120,
              qualificationObservedAt <= ticketIssuedAt,
              ticketExpiresAt <= qualificationExpiresAt,
              Int64(now.timeIntervalSince1970) >= qualificationObservedAt,
              Int64(now.timeIntervalSince1970) < qualificationExpiresAt,
              launchDescriptorSHA256 == (try computedLaunchDescriptorSHA256),
              qualificationSubjectSHA256
                == (try computedQualificationSubjectSHA256),
              qualificationReadbackSHA256 == Self.sha256(
                  try NativeAuthorizationTicket.canonicalData(
                      QualificationReadbackBody(
                          operationID: operationID,
                          requestSHA256: requestSHA256,
                          stackSHA256: stackSHA256,
                          sessionID: sessionID,
                          runtimeAuthoritySHA256: runtimeAuthoritySHA256,
                          launchDescriptorSHA256: launchDescriptorSHA256,
                          researchReleaseID: researchReleaseID,
                          bootIDSHA256: bootIDSHA256,
                          qualificationSubjectSHA256:
                              qualificationSubjectSHA256,
                          qualificationEvidenceSHA256:
                              qualificationEvidenceSHA256,
                          qualificationObservedAt:
                              qualificationObservedAt,
                          qualificationExpiresAt:
                              qualificationExpiresAt
                      )
                  )
              ) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
    }

    var computedLaunchDescriptorSHA256: String {
        get throws {
            Self.sha256(
                try NativeAuthorizationTicket.canonicalData(
                    launchDescriptorBody
                )
            )
        }
    }

    var computedQualificationSubjectSHA256: String {
        get throws {
            Self.sha256(
                try NativeAuthorizationTicket.canonicalData(
                    qualificationSubjectBody
                )
            )
        }
    }

    var policySHA256: String {
        get throws {
            Self.sha256(try NativeAuthorizationTicket.canonicalData(self))
        }
    }

    private struct LaunchDescriptorBody: Encodable {
        let runtimeAuthoritySHA256: String
        let sessionID: String
        let nativeStackBindingSHA256: String
        let harnessBindingSHA256: String
        let harnessGenerationID: String
        let harnessExecutableSHA256: String
        let modelID: String
        let reasoningEffort: String
        let cyberAccessProgram: String
        enum CodingKeys: String, CodingKey {
            case runtimeAuthoritySHA256 = "runtime_authority_sha256"
            case sessionID = "session_id"
            case nativeStackBindingSHA256 = "native_stack_binding_sha256"
            case harnessBindingSHA256 = "harness_binding_sha256"
            case harnessGenerationID = "harness_generation_id"
            case harnessExecutableSHA256 = "harness_executable_sha256"
            case modelID = "model_id"
            case reasoningEffort = "reasoning_effort"
            case cyberAccessProgram = "cyber_access_program"
        }
    }

    private struct QualificationSubjectBody: Encodable {
        let provider: String
        let harnessGenerationID: String
        let harnessExecutableSHA256: String
        let modelID: String
        let reasoningEffort: String
        let cyberAccessProgram: String
        let policyManifestSHA256: String
        let probeExecutableSHA256: String
        let protocolVersion: String
        enum CodingKeys: String, CodingKey {
            case provider
            case harnessGenerationID = "harness_generation_id"
            case harnessExecutableSHA256 = "harness_executable_sha256"
            case modelID = "model_id"
            case reasoningEffort = "reasoning_effort"
            case cyberAccessProgram = "cyber_access_program"
            case policyManifestSHA256 = "policy_manifest_sha256"
            case probeExecutableSHA256 = "probe_executable_sha256"
            case protocolVersion = "protocol_version"
        }
    }

    private struct QualificationReadbackBody: Encodable {
        let operationID: String
        let requestSHA256: String
        let stackSHA256: String
        let sessionID: String
        let runtimeAuthoritySHA256: String
        let launchDescriptorSHA256: String
        let researchReleaseID: String
        let bootIDSHA256: String
        let qualificationSubjectSHA256: String
        let qualificationEvidenceSHA256: String
        let qualificationObservedAt: Int64
        let qualificationExpiresAt: Int64
        enum CodingKeys: String, CodingKey {
            case operationID = "operation_id"
            case requestSHA256 = "request_sha256"
            case stackSHA256 = "stack_sha256"
            case sessionID = "session_id"
            case runtimeAuthoritySHA256 = "runtime_authority_sha256"
            case launchDescriptorSHA256 = "launch_descriptor_sha256"
            case researchReleaseID = "research_release_id"
            case bootIDSHA256 = "boot_id_sha256"
            case qualificationSubjectSHA256 = "qualification_subject_sha256"
            case qualificationEvidenceSHA256 = "qualification_evidence_sha256"
            case qualificationObservedAt = "qualification_observed_at"
            case qualificationExpiresAt = "qualification_expires_at"
        }
    }

    private var launchDescriptorBody: LaunchDescriptorBody {
        LaunchDescriptorBody(
            runtimeAuthoritySHA256: runtimeAuthoritySHA256,
            sessionID: sessionID,
            nativeStackBindingSHA256: nativeStackBindingSHA256,
            harnessBindingSHA256: harnessBindingSHA256,
            harnessGenerationID: harnessGenerationID,
            harnessExecutableSHA256: harnessExecutableSHA256,
            modelID: modelID,
            reasoningEffort: reasoningEffort,
            cyberAccessProgram: cyberAccessProgram
        )
    }

    private var qualificationSubjectBody: QualificationSubjectBody {
        QualificationSubjectBody(
            provider: "codex",
            harnessGenerationID: harnessGenerationID,
            harnessExecutableSHA256: harnessExecutableSHA256,
            modelID: modelID,
            reasoningEffort: reasoningEffort,
            cyberAccessProgram: cyberAccessProgram,
            policyManifestSHA256: policyManifestSHA256,
            probeExecutableSHA256: probeExecutableSHA256,
            protocolVersion: protocolVersion
        )
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct NativeCredentialProjectionCustodyBinding: Equatable, Sendable {
    let provider: NativeCredentialProvider
    let stackSHA256: String
    let ticketSHA256: String
    let policySHA256: String
    let qualificationSubjectSHA256: String
    let qualificationEvidenceSHA256: String
    let researchReleaseID: String

    init(
        ticketSHA256: String,
        stackSHA256: String,
        authority: NativeCredentialProjectionAuthority
    ) throws {
        provider = .openAIChatGPT
        self.stackSHA256 = stackSHA256
        self.ticketSHA256 = ticketSHA256
        policySHA256 = try authority.policySHA256
        qualificationSubjectSHA256 = authority.qualificationSubjectSHA256
        qualificationEvidenceSHA256 = authority.qualificationEvidenceSHA256
        researchReleaseID = authority.researchReleaseID
        guard [self.stackSHA256, self.ticketSHA256, policySHA256,
               qualificationSubjectSHA256, qualificationEvidenceSHA256,
               researchReleaseID]
            .allSatisfy(NativeAuthorizationTicket.isSHA256) else {
            throw NativeCredentialXPCError.authorizationTicketRejected
        }
    }
}
