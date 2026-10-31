import CryptoKit
import Foundation
import Testing
@testable import SecureSandboxUpdateCore

struct UpdateProtocolTests {
    @Test func scheduledChecksCanOnlyFetchMetadata() {
        #expect(UpdateAuthority.capabilities(for: .scheduled) == [.fetchSignedMetadata])
        #expect(!UpdateAuthority.capabilities(for: .scheduled).contains(.fetchArtifact))
        #expect(!UpdateAuthority.capabilities(for: .scheduled).contains(.installVerifiedArtifact))
        #expect(UpdateAuthority.capabilities(for: .manualDownload) == [.fetchArtifact])
        #expect(UpdateAuthority.capabilities(for: .touchIDInstall) == [.installVerifiedArtifact])
    }

    @Test func signedManifestAdvancesMonotonicSequence() throws {
        let fixture = try fixture(sequence: 2)
        let verified = try UpdateVerifier.verifyEnvelope(
            fixture.envelope,
            policy: fixture.policy,
            installed: installed(sequence: 1)
        )
        #expect(verified.manifest.version == "0.2.0")
        #expect(verified.manifest.sequence == 2)
        #expect(verified.envelopeDigest.count == 64)
    }

    @Test func badSignatureIsRejected() throws {
        var fixture = try fixture(sequence: 2)
        fixture.envelope[fixture.envelope.count - 3] ^= 1
        #expect(throws: (any Error).self) {
            try UpdateVerifier.verifyEnvelope(fixture.envelope, policy: fixture.policy, installed: installed(sequence: 1))
        }
    }

    @Test func rollbackAndReplayAreRejected() throws {
        let fixture = try fixture(sequence: 4)
        #expect(throws: UpdateProtocolError.rollback(current: 4, offered: 4)) {
            try UpdateVerifier.verifyEnvelope(fixture.envelope, policy: fixture.policy, installed: installed(sequence: 4))
        }
        #expect(throws: UpdateProtocolError.rollback(current: 5, offered: 4)) {
            try UpdateVerifier.verifyEnvelope(fixture.envelope, policy: fixture.policy, installed: installed(sequence: 5))
        }
    }

    @Test func unknownEnvelopeAndManifestFieldsAreRejected() throws {
        let baseFixture = try fixture(sequence: 2)
        var envelopeObject = try #require(JSONSerialization.jsonObject(with: baseFixture.envelope) as? [String: Any])
        envelopeObject["future_authority"] = true
        let enlargedEnvelope = try JSONSerialization.data(withJSONObject: envelopeObject, options: [.sortedKeys])
        #expect(throws: (any Error).self) {
            try UpdateVerifier.verifyEnvelope(enlargedEnvelope, policy: baseFixture.policy, installed: installed(sequence: 1))
        }

        let altered = try fixture(sequence: 2, extraManifestField: true)
        #expect(throws: (any Error).self) {
            try UpdateVerifier.verifyEnvelope(altered.envelope, policy: altered.policy, installed: installed(sequence: 1))
        }
    }

    @Test func crossOriginArtifactIsRejectedEvenWhenSigned() throws {
        let fixture = try fixture(sequence: 2, artifactURL: "https://attacker.invalid/SecureSandbox.zip")
        #expect(throws: (any Error).self) {
            try UpdateVerifier.verifyEnvelope(fixture.envelope, policy: fixture.policy, installed: installed(sequence: 1))
        }
    }

    @Test func artifactSizeAndDigestAreBothBound() throws {
        let bytes = Data("reviewed artifact".utf8)
        let fixture = try fixture(sequence: 2, artifact: bytes)
        let verified = try UpdateVerifier.verifyEnvelope(fixture.envelope, policy: fixture.policy, installed: installed(sequence: 1))
        try UpdateVerifier.verifyArtifact(bytes, manifest: verified.manifest)
        #expect(throws: UpdateProtocolError.sizeMismatch) {
            try UpdateVerifier.verifyArtifact(bytes + Data([0]), manifest: verified.manifest)
        }
        var changed = bytes
        changed[0] ^= 1
        #expect(throws: UpdateProtocolError.digestMismatch) {
            try UpdateVerifier.verifyArtifact(changed, manifest: verified.manifest)
        }
    }

    @Test func disabledPolicyCannotCheckOrInstall() throws {
        let fixture = try fixture(sequence: 2, enabled: false)
        #expect(throws: (any Error).self) {
            try UpdateVerifier.verifyEnvelope(fixture.envelope, policy: fixture.policy, installed: installed(sequence: 1))
        }
    }

    private func installed(sequence: UInt64) -> InstalledUpdateIdentity {
        InstalledUpdateIdentity(sequence: sequence, version: "0.1.0", build: 1, macOSMajor: 27)
    }

    private func fixture(
        sequence: UInt64,
        artifactURL: String = "https://updates.example.test/artifacts/SecureSandbox.zip",
        artifact: Data = Data("reviewed artifact".utf8),
        enabled: Bool = true,
        extraManifestField: Bool = false
    ) throws -> (policy: UpdatePolicy, envelope: Data) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let policy = UpdatePolicy(
            schema: UpdatePolicy.schema,
            enabled: enabled,
            disabledReason: enabled ? nil : "Developer ID release service not provisioned",
            channel: "stable",
            manifestURL: URL(string: "https://updates.example.test/control-center/stable.json"),
            keyID: "fixture-2026",
            publicKeyBase64: privateKey.publicKey.rawRepresentation.base64EncodedString(),
            artifactOrigin: URL(string: "https://updates.example.test"),
            artifactRedirectHosts: ["updates.example.test"],
            teamIdentifier: ["TEST", "TEAM", "01"].joined(),
            bundleIdentifier: "org.zebeth.SecureSandbox.ControlCenter",
            maximumManifestBytes: 131_072,
            maximumArtifactBytes: 268_435_456
        )
        var manifest: [String: Any] = [
            "schema": UpdateManifest.schema,
            "channel": "stable",
            "sequence": sequence,
            "version": "0.2.0",
            "build": 2,
            "published_at": "2026-10-31T21:00:00Z",
            "minimum_macos": "27.0",
            "minimum_current_sequence": 1,
            "release_commit": String(repeating: "a", count: 40),
            "artifact": [
                "url": artifactURL,
                "size": artifact.count,
                "sha256": UpdateVerifier.sha256(artifact),
            ],
            "security": [
                "classification": "security",
                "summary": "Hardens the reviewed update verifier.",
            ],
            "compatibility": [
                "control_center": "Replaces only the user-local Control Center.",
                "protected_environment": "Host and guests remain unchanged and require separate authorization.",
            ],
        ]
        if extraManifestField { manifest["automatic_install"] = true }
        let payload = try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
        let signature = try privateKey.signature(for: payload)
        let envelope: [String: Any] = [
            "schema": SignedUpdateEnvelope.schema,
            "key_id": "fixture-2026",
            "payload_base64": payload.base64EncodedString(),
            "signature_base64": signature.base64EncodedString(),
        ]
        return (policy, try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]))
    }
}
