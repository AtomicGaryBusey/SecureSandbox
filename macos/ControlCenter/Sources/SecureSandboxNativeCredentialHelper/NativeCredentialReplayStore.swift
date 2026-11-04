import Foundation
import Security

protocol NativeAuthorizationTicketReplayProtecting: Sendable {
    func claim(_ ticket: NativeAuthorizationTicket, now: Date) throws
}

private struct NativeAuthorizationReplayEntry: Codable, Equatable {
    let ticketID: String
    let ticketSHA256: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case ticketID = "ticket_id"
        case ticketSHA256 = "ticket_sha256"
        case expiresAt = "expires_at"
    }
}

private struct NativeAuthorizationReplayRecord: Codable, Equatable {
    static let schemaName = "secure-sandbox-native-credential-ticket-replay-v1"
    let schema: String
    let entries: [NativeAuthorizationReplayEntry]

    func validate() throws {
        guard schema == Self.schemaName, entries.count <= 4_096,
              entries == entries.sorted(by: { $0.ticketID < $1.ticketID }),
              Set(entries.map(\.ticketID)).count == entries.count,
              Set(entries.map(\.ticketSHA256)).count == entries.count,
              entries.allSatisfy({
                  NativeAuthorizationTicket.isUUID4($0.ticketID)
                      && NativeAuthorizationTicket.isSHA256($0.ticketSHA256)
                      && $0.expiresAt > 0
              }) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
    }
}

final class DataProtectionKeychainTicketReplayStore:
    NativeAuthorizationTicketReplayProtecting, @unchecked Sendable
{
    private let service: String
    private let account = "native-credential-authorization-replay"
    private let lock = NSLock()

    init(service: String = "org.zebeth.SecureSandbox.NativeCredentialHelper.replay") {
        self.service = service
    }

    func claim(_ ticket: NativeAuthorizationTicket, now: Date) throws {
        try lock.withLock {
            try ticket.validate(now: now)
            let timestamp = Int64(now.timeIntervalSince1970)
            let previous = try load()
            var entries = previous.entries.filter { $0.expiresAt > timestamp }
            guard !entries.contains(where: {
                $0.ticketID == ticket.ticketID || $0.ticketSHA256 == ticket.ticketSHA256
            }) else {
                throw NativeCredentialXPCError.authorizationTicketReplayed
            }
            guard entries.count < 4_096 else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
            entries.append(NativeAuthorizationReplayEntry(
                ticketID: ticket.ticketID,
                ticketSHA256: ticket.ticketSHA256,
                expiresAt: ticket.expiresAt
            ))
            entries.sort { $0.ticketID < $1.ticketID }
            let replacement = NativeAuthorizationReplayRecord(
                schema: NativeAuthorizationReplayRecord.schemaName,
                entries: entries
            )
            try replacement.validate()
            try replace(replacement)
            guard try load() == replacement else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
        }
    }

    private func load() throws -> NativeAuthorizationReplayRecord {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return NativeAuthorizationReplayRecord(
                schema: NativeAuthorizationReplayRecord.schemaName,
                entries: []
            )
        }
        guard status == errSecSuccess, let data = result as? Data,
              data.count <= 512 * 1024,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["schema", "entries"]),
              let record = try? JSONDecoder().decode(NativeAuthorizationReplayRecord.self,
                                                     from: data) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        try record.validate()
        guard data == (try? Self.canonicalData(record)) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        return record
    }

    private func replace(_ record: NativeAuthorizationReplayRecord) throws {
        let data = try Self.canonicalData(record)
        guard data.count <= 512 * 1024 else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        var status = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var addition = baseQuery
            addition[kSecValueData as String] = data
            addition[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(addition as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
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

    private static func canonicalData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(value)
        data.append(0x0a)
        return data
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
