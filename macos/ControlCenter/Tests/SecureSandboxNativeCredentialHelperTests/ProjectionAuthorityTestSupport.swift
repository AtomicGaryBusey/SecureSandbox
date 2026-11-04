import Foundation
@testable import SecureSandboxNativeCredentialHelper

func testProjectionAuthority(
    operationID: UUID,
    sessionID: UUID = UUID(
        uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )!,
    requestSHA256: String,
    stackSHA256: String,
    runtimeAuthoritySHA256: String,
    observedAt: Int64,
    expiresAt: Int64,
    subjectMarker: Character = "7",
    hostReleaseID: String = String(repeating: "1", count: 64),
    consumerExecutablePath: String? = nil
) throws -> NativeCredentialProjectionAuthority {
    let nativeStack = String(repeating: "2", count: 64)
    let harnessBinding = String(repeating: "3", count: 64)
    let generation = String(repeating: "4", count: 64)
    let executable = String(repeating: "5", count: 64)
    let policy = String(repeating: subjectMarker, count: 64)
    let probe = String(repeating: "8", count: 64)
    let research = String(repeating: "9", count: 64)
    let boot = String(repeating: "a", count: 64)
    let evidence = String(repeating: "b", count: 64)
    let launch: [String: Any] = [
        "runtime_authority_sha256": runtimeAuthoritySHA256,
        "session_id": sessionID.uuidString.lowercased(),
        "native_stack_binding_sha256": nativeStack,
        "harness_binding_sha256": harnessBinding,
        "harness_generation_id": generation,
        "harness_executable_sha256": executable,
        "model_id": "gpt-6.1-sol",
        "reasoning_effort": "xhigh",
        "cyber_access_program": "daybreakBlue",
    ]
    let launchDigest = try testCanonicalDigest(launch)
    let subject: [String: Any] = [
        "provider": "codex",
        "harness_generation_id": generation,
        "harness_executable_sha256": executable,
        "model_id": "gpt-6.1-sol",
        "reasoning_effort": "xhigh",
        "cyber_access_program": "daybreakBlue",
        "policy_manifest_sha256": policy,
        "probe_executable_sha256": probe,
        "protocol_version": "codex-app-server-0.166",
    ]
    let subjectDigest = try testCanonicalDigest(subject)
    let readback: [String: Any] = [
        "operation_id": operationID.uuidString.lowercased(),
        "request_sha256": requestSHA256,
        "stack_sha256": stackSHA256,
        "session_id": sessionID.uuidString.lowercased(),
        "runtime_authority_sha256": runtimeAuthoritySHA256,
        "launch_descriptor_sha256": launchDigest,
        "research_release_id": research,
        "boot_id_sha256": boot,
        "qualification_subject_sha256": subjectDigest,
        "qualification_evidence_sha256": evidence,
        "qualification_observed_at": observedAt,
        "qualification_expires_at": expiresAt,
    ]
    return NativeCredentialProjectionAuthority(
        consumerExecutablePath:
            consumerExecutablePath
                ?? ("/usr/local/libexec/secure-sandbox-host/releases/"
                    + hostReleaseID + "/native_projection_consumer"),
        consumerExecutableSHA256: String(repeating: "c", count: 64),
        hostReleaseID: hostReleaseID,
        sessionID: sessionID.uuidString.lowercased(),
        runtimeAuthoritySHA256: runtimeAuthoritySHA256,
        nativeStackBindingSHA256: nativeStack,
        harnessBindingSHA256: harnessBinding,
        harnessGenerationID: generation,
        harnessExecutableSHA256: executable,
        modelID: "gpt-6.1-sol",
        reasoningEffort: "xhigh",
        cyberAccessProgram: "daybreakBlue",
        policyManifestSHA256: policy,
        probeExecutableSHA256: probe,
        protocolVersion: "codex-app-server-0.166",
        launchDescriptorSHA256: launchDigest,
        researchReleaseID: research,
        bootIDSHA256: boot,
        qualificationSubjectSHA256: subjectDigest,
        qualificationEvidenceSHA256: evidence,
        qualificationObservedAt: observedAt,
        qualificationExpiresAt: expiresAt,
        qualificationReadbackSHA256: try testCanonicalDigest(readback)
    )
}

func testProjectionAuthorityJSON(
    _ authority: NativeCredentialProjectionAuthority?
) -> [String: Any] {
    guard let authority else {
        return Dictionary(
            uniqueKeysWithValues: projectionAuthorityWireKeys.map {
                ($0, NSNull())
            }
        )
    }
    return [
        "consumer_executable_path": authority.consumerExecutablePath,
        "consumer_executable_sha256": authority.consumerExecutableSHA256,
        "host_release_id": authority.hostReleaseID,
        "session_id": authority.sessionID,
        "runtime_authority_sha256": authority.runtimeAuthoritySHA256,
        "native_stack_binding_sha256": authority.nativeStackBindingSHA256,
        "harness_binding_sha256": authority.harnessBindingSHA256,
        "harness_generation_id": authority.harnessGenerationID,
        "harness_executable_sha256": authority.harnessExecutableSHA256,
        "model_id": authority.modelID,
        "reasoning_effort": authority.reasoningEffort,
        "cyber_access_program": authority.cyberAccessProgram,
        "policy_manifest_sha256": authority.policyManifestSHA256,
        "probe_executable_sha256": authority.probeExecutableSHA256,
        "protocol_version": authority.protocolVersion,
        "launch_descriptor_sha256": authority.launchDescriptorSHA256,
        "research_release_id": authority.researchReleaseID,
        "boot_id_sha256": authority.bootIDSHA256,
        "qualification_subject_sha256": authority.qualificationSubjectSHA256,
        "qualification_evidence_sha256": authority.qualificationEvidenceSHA256,
        "qualification_observed_at": authority.qualificationObservedAt,
        "qualification_expires_at": authority.qualificationExpiresAt,
        "qualification_readback_sha256": authority.qualificationReadbackSHA256,
    ]
}

let projectionAuthorityWireKeys = [
    "consumer_executable_path", "consumer_executable_sha256",
    "host_release_id", "session_id", "runtime_authority_sha256",
    "native_stack_binding_sha256", "harness_binding_sha256",
    "harness_generation_id", "harness_executable_sha256", "model_id",
    "reasoning_effort", "cyber_access_program", "policy_manifest_sha256",
    "probe_executable_sha256", "protocol_version",
    "launch_descriptor_sha256", "research_release_id", "boot_id_sha256",
    "qualification_subject_sha256", "qualification_evidence_sha256",
    "qualification_observed_at", "qualification_expires_at",
    "qualification_readback_sha256",
]

func testCanonicalData(_ value: Any) throws -> Data {
    let encoded = try JSONSerialization.data(
        withJSONObject: value, options: [.sortedKeys]
    )
    // JSONSerialization still escapes forward slashes on some macOS SDK/runtime
    // combinations. Production and the Python authority codec use unescaped
    // slashes, so normalize the test fixture to those canonical bytes.
    var data = Data()
    data.reserveCapacity(encoded.count + 1)
    var index = encoded.startIndex
    while index < encoded.endIndex {
        let next = encoded.index(after: index)
        if encoded[index] == 0x5c,
           next < encoded.endIndex,
           encoded[next] == 0x2f {
            data.append(0x2f)
            index = encoded.index(after: next)
        } else {
            data.append(encoded[index])
            index = next
        }
    }
    data.append(0x0a)
    return data
}

private func testCanonicalDigest(_ value: [String: Any]) throws -> String {
    let data = try testCanonicalData(value)
    return NativeAuthorizationTicket.sha256(data)
}
