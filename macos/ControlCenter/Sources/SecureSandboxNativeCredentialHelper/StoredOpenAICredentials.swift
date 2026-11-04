import CryptoKit
import Foundation
import Security
import SecureSandboxNativeAuthCore

struct StoredOpenAICredentials: Codable, Equatable, Sendable {
    static let schema = "secure-sandbox-openai-credential-v1"

    let schema: String
    let clientID: String
    let accessToken: String
    let refreshToken: String
    let idToken: String
    let accountSubjectSHA256: String
    let workspaceSHA256: String
    let scopeSHA256: String
    let accessExpiresAt: Date
    let earliestRefreshAt: Date
    let refreshExpiresAt: Date
    let savedAt: Date

    static func from(
        responseData: Data,
        validated: ValidatedOpenAITokenSet
    ) throws -> StoredOpenAICredentials {
        guard responseData.count <= 131_072,
              let object = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
              Set(object.keys) == Set([
                  "access_token", "refresh_token", "id_token", "token_type",
                  "expires_in", "scope", "earliest_refresh_at",
              ]),
              let accessToken = object["access_token"] as? String,
              let refreshToken = object["refresh_token"] as? String,
              let idToken = object["id_token"] as? String else {
            throw NativeCredentialHelperError.providerResponseRejected
        }
        let status = validated.contentFreeStatus
        let record = StoredOpenAICredentials(
            schema: schema,
            clientID: validated.clientID,
            accessToken: accessToken,
            refreshToken: refreshToken,
            idToken: idToken,
            accountSubjectSHA256: status.accountSubjectSHA256,
            workspaceSHA256: status.workspaceSHA256,
            scopeSHA256: status.scopeSHA256,
            accessExpiresAt: status.accessExpiresAt,
            earliestRefreshAt: status.earliestRefreshAt,
            refreshExpiresAt: status.refreshExpiresAt,
            savedAt: validated.savedAt
        )
        try record.validate()
        return record
    }

    static func decodeExact(_ data: Data) throws -> StoredOpenAICredentials {
        guard data.count <= 196_608,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set([
                  "schema", "clientID", "accessToken", "refreshToken", "idToken",
                  "accountSubjectSHA256", "workspaceSHA256", "scopeSHA256",
                  "accessExpiresAt", "earliestRefreshAt", "refreshExpiresAt", "savedAt",
              ]),
              let decoded = try? JSONDecoder.secureSandbox.decode(Self.self, from: data) else {
            throw NativeCredentialHelperError.credentialStoreFailed
        }
        try decoded.validate()
        return decoded
    }

    var encoded: Data {
        get throws {
            try validate()
            let data = try JSONEncoder.secureSandbox.encode(self)
            guard data.count <= 196_608 else { throw NativeCredentialHelperError.credentialStoreFailed }
            return data
        }
    }

    func status(now: Date) throws -> NativeCredentialStatus {
        let state: NativeCredentialState = if now >= refreshExpiresAt {
            .blocked
        } else if now >= earliestRefreshAt {
            .refreshRequired
        } else {
            .ready
        }
        return try NativeCredentialStatus(
            provider: .openAIChatGPT,
            state: state,
            clientIDHash: Self.sha256(clientID),
            accountSubjectSHA256: accountSubjectSHA256,
            workspaceSHA256: workspaceSHA256,
            scopeSHA256: scopeSHA256,
            accessExpiresAt: accessExpiresAt,
            earliestRefreshAt: earliestRefreshAt,
            refreshExpiresAt: refreshExpiresAt
        )
    }

    func validate() throws {
        guard schema == Self.schema else { throw NativeCredentialHelperError.credentialStoreFailed }
        do { try OpenAISignInPolicy.validateIssuedClientID(clientID) }
        catch { throw NativeCredentialHelperError.credentialStoreFailed }
        guard (16...65_536).contains(accessToken.utf8.count),
              (16...16_384).contains(refreshToken.utf8.count),
              (16...65_536).contains(idToken.utf8.count),
              [accessToken, refreshToken, idToken].allSatisfy({
                  $0.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
              }),
              [accountSubjectSHA256, workspaceSHA256, scopeSHA256].allSatisfy({
                  $0.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
              }),
              accessExpiresAt > savedAt,
              earliestRefreshAt >= savedAt.addingTimeInterval(-120),
              earliestRefreshAt < accessExpiresAt,
              refreshExpiresAt > accessExpiresAt else {
            throw NativeCredentialHelperError.credentialStoreFailed
        }
    }

    private static func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

protocol OpenAICredentialVault: Sendable {
    func load() throws -> StoredOpenAICredentials?
    func replace(with credentials: StoredOpenAICredentials) throws
    func delete() throws
}

final class DataProtectionKeychainOpenAIVault: OpenAICredentialVault, @unchecked Sendable {
    private let service: String
    private let account = "openai-chatgpt-plan"

    init(service: String = "org.zebeth.SecureSandbox.NativeCredentialHelper") {
        self.service = service
    }

    func load() throws -> StoredOpenAICredentials? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw NativeCredentialHelperError.credentialStoreFailed
        }
        return try StoredOpenAICredentials.decodeExact(data)
    }

    func replace(with credentials: StoredOpenAICredentials) throws {
        let data = try credentials.encoded
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        var status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = baseQuery
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw NativeCredentialHelperError.credentialStoreFailed }
        guard try load() == credentials else { throw NativeCredentialHelperError.credentialStoreFailed }
    }

    func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NativeCredentialHelperError.credentialStoreFailed
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
    }
}

private extension JSONEncoder {
    static var secureSandbox: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}

private extension JSONDecoder {
    static var secureSandbox: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}
