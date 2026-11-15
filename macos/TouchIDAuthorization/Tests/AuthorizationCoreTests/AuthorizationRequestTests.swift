import CryptoKit
import Foundation
import Testing
@testable import AuthorizationCore

private func canonicalRequest() throws -> Data {
    let value: [String: Any] = [
        "created_at": 2_000_000_000,
        "ceremony": "approve",
        "declared_agent": "Codex",
        "declared_session": "touchid-ddd",
        "expires_at": 2_000_000_180,
        "identity_evidence": "operator-declared",
        "invoking_uid": 501,
        "operation": "pki-anchor-begin",
        "parameters": ["generation_id": "12345678-1234-4123-8123-123456789abc"],
        "purpose": "Verify Touch ID binding",
        "request_id": "12345678-1234-4123-8123-123456789abc",
        "resource": "/usr/local/var/lib/secure-sandbox/pki",
        "schema": "secure-sandbox-operator-authorization-v1",
    ]
    return try CanonicalJSON.encode(value) + Data([0x0a])
}

@Test func acceptsPythonCanonicalKeyOrderIndependentOfFoundation() throws {
    let fixture = [
        "{\"ceremony\":\"approve\",\"declared_agent\":\"Codex\"," +
        "\"declared_session\":\"network-order-regression\",",
        "\"expires_at\":2000000180,\"operation\":\"vm-create\"," +
        "\"parameters\":{\"network_config\":{\"control-net\":",
        "{\"dhcp4_enabled\":\"0\",\"dhcp_ip\":\"172.30.10.1\"}}}," +
        "\"purpose\":\"Verify explicit canonical ordering\",",
        "\"request_id\":\"12345678-1234-4123-8123-123456789abc\"," +
        "\"resource\":\"none\"}\n",
    ].joined()
    let encoded = Data(fixture.utf8)
    let digest = SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
    let request = try AuthorizationRequest.parse(encoded, expectedSHA256: digest)
    #expect(String(data: request.parametersCanonical, encoding: .utf8) ==
        "{\"network_config\":{\"control-net\":{\"dhcp4_enabled\":\"0\",\"dhcp_ip\":\"172.30.10.1\"}}}")

    let noncanonical = Data(String(decoding: encoded, as: UTF8.self)
        .replacingOccurrences(
            of: "\"dhcp4_enabled\":\"0\",\"dhcp_ip\":\"172.30.10.1\"",
            with: "\"dhcp_ip\":\"172.30.10.1\",\"dhcp4_enabled\":\"0\""
        ).utf8)
    let noncanonicalDigest = SHA256.hash(data: noncanonical)
        .map { String(format: "%02x", $0) }.joined()
    #expect(throws: AuthorizationDocumentError.notCanonical) {
        try AuthorizationRequest.parse(noncanonical, expectedSHA256: noncanonicalDigest)
    }
}

@Test func canonicalCryptoJSONUsesPythonKeyOrder() throws {
    let encoded = try ExecutionApprovalCrypto.canonicalJSON([
        "dhcp_ip": "172.30.10.1", "dhcp4_enabled": "0",
    ])
    #expect(String(data: encoded, encoding: .utf8) ==
        "{\"dhcp4_enabled\":\"0\",\"dhcp_ip\":\"172.30.10.1\"}")
}

@Test func canonicalJSONMatchesPythonScalarAndStringEncoding() throws {
    let encoded = try CanonicalJSON.encode([
        "values": [true, NSNull(), -1, 8_589_934_592, "\u{7f}\u{80}\u{1f600}"],
    ])
    #expect(String(data: encoded, encoding: .utf8) ==
        "{\"values\":[true,null,-1,8589934592,\"\\u007f\\u0080\\ud83d\\ude00\"]}")
    #expect(throws: CanonicalJSONError.unsupportedValue) {
        try CanonicalJSON.encode(["floating_point": 1.5])
    }
}

@Test func parsesAndDisplaysEverySecurityRelevantField() throws {
    let data = try canonicalRequest()
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let request = try AuthorizationRequest.parse(data, expectedSHA256: digest)
    #expect(request.displayText.contains("Declared agent: Codex"))
    #expect(request.displayText.contains("Declared session: touchid-ddd"))
    #expect(request.displayText.contains("Ceremony: APPROVAL"))
    #expect(request.displayText.contains("Request digest: \(digest)"))
    #expect(request.displayText.contains("One-time nonce: 12345678"))
    #expect(request.displayText.contains("generation_id"))
}

@Test func cancellationCeremonyIsExplicitAndBound() throws {
    let data = try canonicalRequest()
    var object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    object["ceremony"] = "cancel-test"
    let encoded = try CanonicalJSON.encode(object) + Data([0x0a])
    let digest = SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
    let request = try AuthorizationRequest.parse(encoded, expectedSHA256: digest)
    #expect(request.isCancellationTest)
    #expect(request.displayText.contains("Ceremony: CANCEL TEST"))

    object["ceremony"] = "ambiguous"
    let invalid = try CanonicalJSON.encode(object) + Data([0x0a])
    let invalidDigest = SHA256.hash(data: invalid).map { String(format: "%02x", $0) }.joined()
    #expect(throws: AuthorizationDocumentError.invalidField("ceremony")) {
        try AuthorizationRequest.parse(invalid, expectedSHA256: invalidDigest)
    }
}

@Test func rejectsDigestMismatchAndNonCanonicalJSON() throws {
    let data = try canonicalRequest()
    #expect(throws: AuthorizationDocumentError.digestMismatch) {
        try AuthorizationRequest.parse(data, expectedSHA256: String(repeating: "0", count: 64))
    }
    let object = try JSONSerialization.jsonObject(with: data)
    let pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    let digest = SHA256.hash(data: pretty).map { String(format: "%02x", $0) }.joined()
    #expect(throws: AuthorizationDocumentError.notCanonical) {
        try AuthorizationRequest.parse(pretty, expectedSHA256: digest)
    }
}

@Test func executionApprovalRequiresBiometrics() throws {
    let data = try canonicalRequest()
    let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    for operation in [
        "execution-approval-key-init",
        "execution-approval-sign",
        "execution-approval-migration-activate",
        "execution-approval-migration-authorize-acceptance",
        "execution-approval-migration-verify-acceptance",
        "execution-approval-migration-commit",
        "execution-approval-software-retire",
    ] {
        var value = object
        value["operation"] = operation
        let encoded = try CanonicalJSON.encode(value) + Data([0x0a])
        let digest = SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
        let request = try AuthorizationRequest.parse(encoded, expectedSHA256: digest)
        #expect(request.requiresBiometricApproval)
    }
}

@Test func normalizesForcedHighSSignatureAndRejectsNoncanonicalForms() throws {
    let orderMinusOne = Data([
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50,
    ])
    var high = Data([0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00])
    high.append(orderMinusOne)
    let normalized = try ExecutionApprovalCrypto.normalizeP256SignatureDER(high)
    #expect(normalized == Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]))
    try ExecutionApprovalCrypto.validateCanonicalLowSP256SignatureDER(normalized)

    #expect(throws: ExecutionApprovalCryptoError.invalidDER) {
        try ExecutionApprovalCrypto.validateCanonicalLowSP256SignatureDER(high)
    }
    #expect(throws: ExecutionApprovalCryptoError.invalidDER) {
        try ExecutionApprovalCrypto.validateCanonicalLowSP256SignatureDER(normalized + Data([0]))
    }
}

@Test func wrapsP256X963AsDeterministicSPKIAndEnforcesCanonicalBase64() throws {
    let privateKey = P256.Signing.PrivateKey()
    let x963 = privateKey.publicKey.x963Representation
    let spki = try ExecutionApprovalCrypto.spkiDER(fromX963: x963)
    #expect(spki.count == 91)
    #expect(spki.prefix(26) == Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ]))
    #expect(spki.suffix(65) == x963)
    let encoded = ExecutionApprovalCrypto.canonicalBase64(spki)
    #expect(try ExecutionApprovalCrypto.decodeCanonicalBase64(encoded) == spki)
    #expect(throws: ExecutionApprovalCryptoError.invalidBase64) {
        try ExecutionApprovalCrypto.decodeCanonicalBase64(encoded + "\n")
    }
}

private func productionSource(_ relative: String) throws -> String {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    return try String(contentsOf: root.appendingPathComponent(relative), encoding: .utf8)
}

@Test func productionSigningIsFreshContextOneSignatureAndBiometricOnly() throws {
    let main = try productionSource("Sources/SecureSandboxAuthorizationUI/main.swift")
    let start = try #require(main.range(of: "private func signExecutionApproval("))
    let end = try #require(main.range(of: "private func legacyAuthorization(",
                                      range: start.upperBound..<main.endIndex))
    let signing = String(main[start.lowerBound..<end.lowerBound])
    #expect(signing.components(separatedBy: "freshSigningContext()").count - 1 == 1)
    #expect(signing.components(separatedBy: "SecureEnclaveKeyStore.sign(").count - 1 == 1)
    #expect(main.contains(".deviceOwnerAuthenticationWithBiometrics"))
    #expect(!main.contains(".deviceOwnerAuthentication,"))
    #expect(!main.contains("deviceOwnerAuthenticationWithWatch"))
}

@Test func cancellationCeremonyHasNoApprovalOrBiometricPath() throws {
    let main = try productionSource("Sources/SecureSandboxAuthorizationUI/main.swift")
    let submit = try #require(main.range(of: "private func submit("))
    let start = try #require(main.range(
        of: "if request.isCancellationTest {", range: submit.upperBound..<main.endIndex
    ))
    let end = try #require(main.range(
        of: "switch decision.response {", range: start.upperBound..<main.endIndex
    ))
    let cancellation = String(main[start.lowerBound..<end.lowerBound])
    let decision = try #require(main.range(
        of: "let decision = approvalChoice", range: submit.upperBound..<start.lowerBound
    ))
    let beforeCancellation = String(main[decision.lowerBound..<start.lowerBound])
    #expect(beforeCancellation.contains("decision.expired"))
    #expect(beforeCancellation.contains("status: expiredExit"))
    #expect(cancellation.contains(".alertFirstButtonReturn"))
    #expect(cancellation.contains("cancelledAuthorization(request)"))
    #expect(!cancellation.contains("evaluateTouchID"))
    #expect(!cancellation.contains("signExecutionApproval"))
    #expect(!cancellation.contains("prepareSecureEnclaveKey"))
}

@Test func productionKeyStoreIsNonexportableCurrentEnrollmentAndUnambiguous() throws {
    let store = try productionSource(
        "Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift"
    )
    #expect(store.contains("kSecAttrTokenIDSecureEnclave"))
    #expect(store.contains("kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"))
    #expect(store.contains("[.privateKeyUsage, .biometryCurrentSet]"))
    #expect(store.contains("kSecMatchLimitAll"))
    #expect(store.contains("records.count == 1"))
    #expect(store.contains("SecKeyCopyExternalRepresentation(privateKey"))
    #expect(store.contains("throw SecureEnclaveKeyStoreError.privateKeyExportable"))
    #expect(store.contains("defer { context.invalidate() }"))
}

@Test func productionSigningCannotRecreateOrFallBackOnLookupFailure() throws {
    let main = try productionSource("Sources/SecureSandboxAuthorizationUI/main.swift")
    let start = try #require(main.range(of: "private func signExecutionApproval("))
    let end = try #require(main.range(of: "private func legacyAuthorization(",
                                      range: start.upperBound..<main.endIndex))
    let signing = String(main[start.lowerBound..<end.lowerBound])
    #expect(signing.contains("SecureEnclaveKeyStore.lookup("))
    #expect(!signing.contains("SecureEnclaveKeyStore.create("))
    #expect(!signing.contains("errSecItemNotFound"))
    #expect(!signing.contains("legacyAuthorization"))
}

