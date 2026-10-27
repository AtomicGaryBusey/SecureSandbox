#if canImport(AuthorizationCore)
import AuthorizationCore
#endif
import Foundation
import LocalAuthentication
import Security

enum SecureEnclaveKeyStoreError: Error {
    case accessControl(CFError?)
    case creation(CFError?)
    case lookup(OSStatus)
    case ambiguousLookup
    case invalidAttributes(String)
    case publicKeyUnavailable
    case publicKeyMismatch
    case privateKeyExportable
    case unsupportedAlgorithm
    case signature(CFError?)
}

struct SecureEnclaveKeyIdentity {
    static let accessGroup: String = {
        guard let value = Bundle.main.object(
            forInfoDictionaryKey: "SecureSandboxAccessGroup"
        ) as? String,
        !value.isEmpty,
        !value.contains("$(") else {
            fatalError("SecureSandboxAccessGroup is missing or unresolved")
        }
        return value
    }()

    let applicationTag: String
    let publicKeySPKIDER: Data
    let publicKeySHA256: String
}

enum SecureEnclaveKeyStore {
    static func create(applicationTag: String) throws {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessError
        ) else {
            throw SecureEnclaveKeyStoreError.accessControl(accessError?.takeRetainedValue())
        }
        let privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(applicationTag.utf8),
            kSecAttrAccessGroup as String: SecureEnclaveKeyIdentity.accessGroup,
            kSecAttrAccessControl as String: access,
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        var creationError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &creationError) != nil else {
            throw SecureEnclaveKeyStoreError.creation(creationError?.takeRetainedValue())
        }
    }

    static func lookup(
        applicationTag: String,
        expectedPublicKeySHA256: String?,
        context: LAContext,
        reason: String
    ) throws -> (SecKey, SecureEnclaveKeyIdentity) {
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: Data(applicationTag.utf8),
            kSecAttrAccessGroup as String: SecureEnclaveKeyIdentity.accessGroup,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
        ]
        var raw: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &raw)
        guard status == errSecSuccess else { throw SecureEnclaveKeyStoreError.lookup(status) }
        guard let records = raw as? [[String: Any]], records.count == 1,
              let key = records[0][kSecValueRef as String] as! SecKey? else {
            throw SecureEnclaveKeyStoreError.ambiguousLookup
        }
        let record = records[0]
        guard (record[kSecAttrApplicationTag as String] as? Data) == Data(applicationTag.utf8) else {
            throw SecureEnclaveKeyStoreError.invalidAttributes("application_tag")
        }
        guard (record[kSecAttrAccessGroup as String] as? String)
                == SecureEnclaveKeyIdentity.accessGroup else {
            throw SecureEnclaveKeyStoreError.invalidAttributes("access_group")
        }
        return (key, try identity(
            for: key,
            applicationTag: applicationTag,
            expectedSHA256: expectedPublicKeySHA256
        ))
    }

    static func sign(
        message: Data,
        key: SecKey,
        context: LAContext
    ) throws -> Data {
        defer { context.invalidate() }
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw SecureEnclaveKeyStoreError.unsupportedAlgorithm
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, message as CFData, &error) else {
            throw SecureEnclaveKeyStoreError.signature(error?.takeRetainedValue())
        }
        return try ExecutionApprovalCrypto.normalizeP256SignatureDER(signature as Data)
    }

    private static func identity(
        for privateKey: SecKey,
        applicationTag: String,
        expectedSHA256: String?
    ) throws -> SecureEnclaveKeyIdentity {
        var privateExportError: Unmanaged<CFError>?
        if SecKeyCopyExternalRepresentation(privateKey, &privateExportError) != nil {
            throw SecureEnclaveKeyStoreError.privateKeyExportable
        }
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SecureEnclaveKeyStoreError.unsupportedAlgorithm
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveKeyStoreError.publicKeyUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw SecureEnclaveKeyStoreError.publicKeyUnavailable
        }
        let spki = try ExecutionApprovalCrypto.spkiDER(fromX963: external as Data)
        let digest = ExecutionApprovalCrypto.sha256Hex(spki)
        if let expectedSHA256, digest != expectedSHA256 {
            throw SecureEnclaveKeyStoreError.publicKeyMismatch
        }
        return SecureEnclaveKeyIdentity(
            applicationTag: applicationTag,
            publicKeySPKIDER: spki,
            publicKeySHA256: digest
        )
    }
}
