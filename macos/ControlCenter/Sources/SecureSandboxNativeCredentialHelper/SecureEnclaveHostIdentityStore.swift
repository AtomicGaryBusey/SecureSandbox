import Foundation
import Security
import SecureSandboxNativeAuthCore

protocol NativeHostIdentityProviding: Sendable {
    func hostID() throws -> String
}

final class SecureEnclaveHostIdentityStore: NativeHostIdentityProviding, @unchecked Sendable {
    private let applicationTag: Data

    init(applicationTag: String = "org.zebeth.SecureSandbox.NativeCredentialHelper.host-identity-v1") {
        self.applicationTag = Data(applicationTag.utf8)
    }

    func hostID() throws -> String {
        let privateKey: SecKey
        do { privateKey = try loadOrCreatePrivateKey() }
        catch let error as NativeCredentialHelperError { throw error }
        catch { throw NativeCredentialHelperError.hostIdentityUnavailable }

        guard try isSecureEnclavePrivateKey(privateKey),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NativeCredentialHelperError.hostIdentityUnavailable
        }
        var copyError: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(publicKey, &copyError) as Data?,
              representation.count == 65, representation.first == 0x04 else {
            throw NativeCredentialHelperError.hostIdentityUnavailable
        }
        do { return try NativeHostIdentity.p256JWKThumbprintURI(x963PublicKey: representation) }
        catch { throw NativeCredentialHelperError.hostIdentityUnavailable }
    }

    private func loadOrCreatePrivateKey() throws -> SecKey {
        if let existing = try loadPrivateKey() { return existing }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            throw NativeCredentialHelperError.secureEnclaveUnavailable
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var createError: Unmanaged<CFError>?
        if let created = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) {
            return created
        }
        // Another authorized helper instance may have won creation. Accept only the exact
        // device-bound key that now exists; every other failure remains fail closed.
        if let existing = try loadPrivateKey() { return existing }
        throw NativeCredentialHelperError.secureEnclaveUnavailable
    }

    private func loadPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let key = result,
              CFGetTypeID(key) == SecKeyGetTypeID() else {
            throw NativeCredentialHelperError.hostIdentityUnavailable
        }
        return (key as! SecKey)
    }

    private func isSecureEnclavePrivateKey(_ key: SecKey) throws -> Bool {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == (kSecAttrKeyTypeECSECPrimeRandom as String),
              attributes[kSecAttrKeyClass as String] as? String == (kSecAttrKeyClassPrivate as String),
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              attributes[kSecAttrTokenID as String] as? String == (kSecAttrTokenIDSecureEnclave as String),
              attributes[kSecAttrApplicationTag as String] as? Data == applicationTag else {
            return false
        }
        return true
    }
}
