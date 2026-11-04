import Darwin
import Foundation
import Security

struct CallerAuditEvidence: Equatable, Sendable {
    static let byteCount = MemoryLayout<audit_token_t>.size
    let data: Data

    init(data: Data) throws {
        guard data.count == Self.byteCount else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        self.data = data
    }

    fileprivate var token: audit_token_t {
        var result = audit_token_t()
        _ = withUnsafeMutableBytes(of: &result) { destination in
            data.copyBytes(to: destination)
        }
        return result
    }
}

protocol NativeCredentialCallerIdentityValidating: Sendable {
    func validate(_ evidence: CallerAuditEvidence) throws
}

struct AuditTokenCodeIdentityValidator: NativeCredentialCallerIdentityValidating, Sendable {
    let expectedBundleIdentifier: String
    let expectedTeamIdentifier: String
    let expectedEffectiveUserID: uid_t

    init(
        expectedBundleIdentifier: String = "org.zebeth.SecureSandbox.ControlCenter",
        expectedTeamIdentifier: String,
        expectedEffectiveUserID: uid_t = getuid()
    ) throws {
        guard expectedBundleIdentifier == "org.zebeth.SecureSandbox.ControlCenter",
              expectedTeamIdentifier.range(
                  of: #"^[A-Z0-9]{10}$"#, options: .regularExpression
              ) != nil,
              expectedEffectiveUserID != 0 else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        self.expectedBundleIdentifier = expectedBundleIdentifier
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.expectedEffectiveUserID = expectedEffectiveUserID
    }

    func validate(_ evidence: CallerAuditEvidence) throws {
        let token = evidence.token
        guard audit_token_to_euid(token) == expectedEffectiveUserID else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        let attributes = [kSecGuestAttributeAudit as String: evidence.data] as CFDictionary
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
              let guest else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        let escapedBundle = Self.requirementLiteral(expectedBundleIdentifier)
        let escapedTeam = Self.requirementLiteral(expectedTeamIdentifier)
        let source = "identifier \"\(escapedBundle)\" and anchor apple generic "
            + "and certificate leaf[subject.OU] = \"\(escapedTeam)\" "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(source as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        var validationError: Unmanaged<CFError>?
        let flags = SecCSFlags(
            rawValue: kSecCSStrictValidate
                | kSecCSCheckAllArchitectures
                | kSecCSCheckNestedCode
                // Public C constant omitted by Swift's importer.
                | (1 << 23)
        )
        guard SecCodeCheckValidityWithErrors(guest, flags, requirement, &validationError)
                == errSecSuccess else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
        var information: CFDictionary?
        let hardenedRuntimeFlag: UInt32 = 0x0001_0000
        // Security.framework documents this API as accepting either a live
        // SecCode or SecStaticCode. Swift imports only the latter CF wrapper;
        // preserve the live object so kSecCSDynamicInformation remains valid.
        let signingInformationCode = unsafeBitCast(
            guest, to: SecStaticCode.self
        )
        guard SecCodeCopySigningInformation(
                  signingInformationCode,
                  SecCSFlags(rawValue:
                      kSecCSSigningInformation | kSecCSDynamicInformation
                  ),
                  &information
              ) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == expectedBundleIdentifier,
              values[kSecCodeInfoTeamIdentifier as String] as? String == expectedTeamIdentifier,
              let dynamicStatus = values[kSecCodeInfoStatus as String] as? NSNumber,
              dynamicStatus.uint32Value & hardenedRuntimeFlag != 0 else {
            throw NativeCredentialXPCError.callerIdentityRejected
        }
    }

    private static func requirementLiteral(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
