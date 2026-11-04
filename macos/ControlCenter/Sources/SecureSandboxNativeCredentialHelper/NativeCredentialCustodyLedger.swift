import CryptoKit
import Darwin
import Foundation
import Security

struct NativeCredentialCustodyObservation: Equatable, Sendable {
    let state: NativeCredentialCustodyState
    let tombstoneSHA256: String?
    let projectionCount: Int?
}

protocol NativeCredentialCustodyTracking: Sendable {
    func observe(hasCredential: Bool, now: Date) throws -> NativeCredentialCustodyObservation
    func clear() throws
    func recordDestruction(ticketSHA256: String) throws
    func reserveProjection(operationID: UUID, expiresAt: Date, now: Date) throws
    func commitProjection(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        binding: NativeCredentialProjectionCustodyBinding,
        now: Date
    ) throws
    func cancelProjection(operationID: UUID) throws
    func completeTerminatedProjection(
        operationID: UUID,
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        sessionAuthoritySHA256: String
    ) throws
    func reconcileProjection(
        ticket: NativeProjectionReconciliationTicket,
        now: Date
    ) throws -> NativeProjectionReconciliationCompletion
    func inspectProjectionIdentity(
        ticket: NativeProjectionIdentityRecoveryTicket,
        now: Date
    ) throws -> NativeProjectionIdentityRecoveryCompletion
}

extension NativeCredentialCustodyTracking {
    func inspectProjectionIdentity(
        ticket: NativeProjectionIdentityRecoveryTicket,
        now: Date
    ) throws -> NativeProjectionIdentityRecoveryCompletion {
        _ = ticket
        _ = now
        throw NativeCredentialXPCError.ticketReplayStoreFailed
    }
}

struct UnknownNativeCredentialCustodyLedger: NativeCredentialCustodyTracking {
    func observe(hasCredential: Bool, now: Date) throws -> NativeCredentialCustodyObservation {
        NativeCredentialCustodyObservation(
            state: hasCredential ? .retained : .ambiguous,
            tombstoneSHA256: nil,
            projectionCount: hasCredential ? 0 : nil
        )
    }

    func clear() throws {}
    func recordDestruction(ticketSHA256: String) throws {}
    func reserveProjection(operationID: UUID, expiresAt: Date, now: Date) throws {}
    func commitProjection(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        binding: NativeCredentialProjectionCustodyBinding,
        now: Date
    ) throws {}
    func cancelProjection(operationID: UUID) throws {}
    func completeTerminatedProjection(
        operationID: UUID,
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        sessionAuthoritySHA256: String
    ) throws {}
    func reconcileProjection(
        ticket: NativeProjectionReconciliationTicket,
        now: Date
    ) throws -> NativeProjectionReconciliationCompletion {
        throw NativeCredentialXPCError.ticketReplayStoreFailed
    }
}

enum NativeCredentialProcessIdentityObservation: Equatable, Sendable {
    case exact(UInt64)
    case absent
    case unavailable
}

func nativeCredentialProcessIdentity(
    _ processIdentifier: Int32
) -> NativeCredentialProcessIdentityObservation {
    guard processIdentifier > 0 else { return .unavailable }
    var information = proc_bsdinfo()
    let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
    let count = withUnsafeMutablePointer(to: &information) {
        proc_pidinfo(processIdentifier, PROC_PIDTBSDINFO, 0, $0, expected)
    }
    if count == expected {
        let seconds = UInt64(information.pbi_start_tvsec)
        let microseconds = UInt64(information.pbi_start_tvusec)
        guard microseconds < 1_000_000,
              seconds <= (UInt64.max - microseconds) / 1_000_000 else {
            return .unavailable
        }
        return .exact(seconds * 1_000_000 + microseconds)
    }
    errno = 0
    if kill(processIdentifier, 0) == -1, errno == ESRCH { return .absent }
    return .unavailable
}

struct NativeCredentialProjectionLedgerEntry: Codable, Equatable {
    let operationID: String
    let provider: NativeCredentialProvider?
    let stackSHA256: String?
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64?
    let executableSHA256: String?
    let sessionAuthoritySHA256: String?
    let authorizationTicketSHA256: String?
    let projectionPolicySHA256: String?
    let qualificationSubjectSHA256: String?
    let qualificationEvidenceSHA256: String?
    let researchReleaseID: String?
    let authorizationExpiresAtMilliseconds: Int64

    enum CodingKeys: String, CodingKey {
        case operationID = "operation_id"
        case provider
        case stackSHA256 = "stack_sha256"
        case processIdentifier = "process_identifier"
        case processStartTimeMicroseconds = "process_start_time_us"
        case executableSHA256 = "executable_sha256"
        case sessionAuthoritySHA256 = "session_authority_sha256"
        case authorizationTicketSHA256 = "authorization_ticket_sha256"
        case projectionPolicySHA256 = "projection_policy_sha256"
        case qualificationSubjectSHA256 = "qualification_subject_sha256"
        case qualificationEvidenceSHA256 = "qualification_evidence_sha256"
        case researchReleaseID = "research_release_id"
        case authorizationExpiresAtMilliseconds = "authorization_expires_at_ms"
    }
}

struct NativeCredentialCustodyLedgerRecord: Codable, Equatable {
    static let schemaName = "secure-sandbox-native-credential-custody-ledger-v1"

    let schema: String
    let tombstoneSHA256: String?
    let projections: [NativeCredentialProjectionLedgerEntry]

    enum CodingKeys: String, CodingKey {
        case schema
        case tombstoneSHA256 = "tombstone_sha256"
        case projections
    }

    func validate() throws {
        guard schema == Self.schemaName,
              tombstoneSHA256.map(NativeAuthorizationTicket.isSHA256) ?? true,
              projections.count <= 64,
              projections == projections.sorted(by: { $0.operationID < $1.operationID }),
              Set(projections.map(\.operationID)).count == projections.count,
              projections.allSatisfy({ entry in
                  let pending = entry.processIdentifier == 0
                      && entry.provider == nil
                      && entry.stackSHA256 == nil
                      && entry.processStartTimeMicroseconds == nil
                      && entry.executableSHA256 == nil
                      && entry.sessionAuthoritySHA256 == nil
                      && entry.authorizationTicketSHA256 == nil
                      && entry.projectionPolicySHA256 == nil
                      && entry.qualificationSubjectSHA256 == nil
                      && entry.qualificationEvidenceSHA256 == nil
                      && entry.researchReleaseID == nil
                  let committed = entry.processIdentifier > 0
                      && entry.provider == .openAIChatGPT
                      && entry.stackSHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && (entry.processStartTimeMicroseconds ?? 0) > 0
                      && entry.executableSHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && entry.sessionAuthoritySHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && entry.authorizationTicketSHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && entry.projectionPolicySHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && entry.qualificationSubjectSHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && entry.qualificationEvidenceSHA256.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                      && entry.researchReleaseID.map(
                          NativeAuthorizationTicket.isSHA256
                      ) == true
                  return NativeAuthorizationTicket.isUUID4(entry.operationID)
                      && entry.authorizationExpiresAtMilliseconds > 0
                      && (pending || committed)
              }),
              projections.isEmpty || tombstoneSHA256 == nil else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
    }

    func observation(
        hasCredential: Bool,
        processIdentity: (Int32) -> NativeCredentialProcessIdentityObservation
    ) throws -> NativeCredentialCustodyObservation {
        try validate()
        if !projections.isEmpty {
            guard hasCredential else {
                return NativeCredentialCustodyObservation(
                    state: .ambiguous,
                    tombstoneSHA256: nil,
                    projectionCount: nil
                )
            }
            let exact = projections.allSatisfy { entry in
                guard entry.processIdentifier > 0,
                      let generation = entry.processStartTimeMicroseconds else {
                    return false
                }
                return processIdentity(entry.processIdentifier) == .exact(generation)
            }
            return NativeCredentialCustodyObservation(
                state: exact ? .sessionProjected : .ambiguous,
                tombstoneSHA256: nil,
                projectionCount: exact ? projections.count : nil
            )
        }
        if hasCredential {
            return NativeCredentialCustodyObservation(
                state: .retained,
                tombstoneSHA256: nil,
                projectionCount: 0
            )
        }
        if let tombstoneSHA256 {
            return NativeCredentialCustodyObservation(
                state: .absent,
                tombstoneSHA256: tombstoneSHA256,
                projectionCount: 0
            )
        }
        return NativeCredentialCustodyObservation(
            state: .ambiguous,
            tombstoneSHA256: nil,
            projectionCount: nil
        )
    }

    func completingTerminatedProjection(
        operationID: UUID,
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        sessionAuthoritySHA256: String,
        processIdentity: NativeCredentialProcessIdentityObservation
    ) throws -> Self {
        try validate()
        let identifier = operationID.uuidString.lowercased()
        guard NativeAuthorizationTicket.isSHA256(sessionAuthoritySHA256),
              let entry = projections.first(where: {
                  $0.operationID == identifier
              }),
              entry.processIdentifier == processIdentifier,
              entry.processStartTimeMicroseconds
                == processStartTimeMicroseconds,
              entry.sessionAuthoritySHA256 == sessionAuthoritySHA256 else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        switch processIdentity {
        case .absent:
            break
        case .exact(let observed)
            where observed != processStartTimeMicroseconds:
            break
        case .exact, .unavailable:
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        let replacement = Self(
            schema: Self.schemaName,
            tombstoneSHA256: tombstoneSHA256,
            projections: projections.filter { $0.operationID != identifier }
        )
        guard replacement.projections.count + 1 == projections.count else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        try replacement.validate()
        return replacement
    }

    func reconcilingProjection(
        ticket: NativeProjectionReconciliationTicket,
        now: Date,
        processIdentity: NativeCredentialProcessIdentityObservation
    ) throws -> (record: Self, completion: NativeProjectionReconciliationCompletion) {
        try validate()
        try ticket.validate(now: now)
        guard let entry = projections.first(where: {
            $0.operationID == ticket.originalOperationID
        }),
            entry.provider == ticket.provider,
            entry.stackSHA256 == ticket.stackSHA256,
            entry.processIdentifier == ticket.processIdentifier,
            entry.processStartTimeMicroseconds
                == ticket.processStartTimeMicroseconds,
            entry.executableSHA256 == ticket.consumerExecutableSHA256,
            entry.sessionAuthoritySHA256 == ticket.sessionAuthoritySHA256 else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        let observedState: String
        let observedStartTime: UInt64?
        switch processIdentity {
        case .absent:
            observedState = "absent"
            observedStartTime = nil
        case .exact(let observed)
            where observed != ticket.processStartTimeMicroseconds:
            observedState = "pid-reused"
            observedStartTime = observed
        case .exact, .unavailable:
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        struct EvidenceBody: Encodable {
            let ticketSHA256: String
            let originalOperationID: String
            let processIdentifier: Int32
            let processStartTimeMicroseconds: UInt64
            let consumerExecutableSHA256: String
            let sessionAuthoritySHA256: String
            let guestAbsenceEvidenceSHA256: String
            let egressClosedEvidenceSHA256: String
            let hostReleaseID: String
            let observedProcessState: String
            let observedProcessStartTimeMicroseconds: UInt64?

            enum CodingKeys: String, CodingKey {
                case ticketSHA256 = "ticket_sha256"
                case originalOperationID = "original_operation_id"
                case processIdentifier = "process_identifier"
                case processStartTimeMicroseconds = "process_start_time_us"
                case consumerExecutableSHA256 = "consumer_executable_sha256"
                case sessionAuthoritySHA256 = "session_authority_sha256"
                case guestAbsenceEvidenceSHA256 =
                    "guest_absence_evidence_sha256"
                case egressClosedEvidenceSHA256 =
                    "egress_closed_evidence_sha256"
                case hostReleaseID = "host_release_id"
                case observedProcessState = "observed_process_state"
                case observedProcessStartTimeMicroseconds =
                    "observed_process_start_time_us"
            }
        }
        let evidence = EvidenceBody(
            ticketSHA256: ticket.ticketSHA256,
            originalOperationID: ticket.originalOperationID,
            processIdentifier: ticket.processIdentifier,
            processStartTimeMicroseconds: ticket.processStartTimeMicroseconds,
            consumerExecutableSHA256: ticket.consumerExecutableSHA256,
            sessionAuthoritySHA256: ticket.sessionAuthoritySHA256,
            guestAbsenceEvidenceSHA256: ticket.guestAbsenceEvidenceSHA256,
            egressClosedEvidenceSHA256: ticket.egressClosedEvidenceSHA256,
            hostReleaseID: ticket.hostReleaseID,
            observedProcessState: observedState,
            observedProcessStartTimeMicroseconds: observedStartTime
        )
        let replacement = Self(
            schema: Self.schemaName,
            tombstoneSHA256: tombstoneSHA256,
            projections: projections.filter {
                $0.operationID != ticket.originalOperationID
            }
        )
        guard replacement.projections.count + 1 == projections.count else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        try replacement.validate()
        return (
            replacement,
            NativeProjectionReconciliationCompletion(
                evidenceSHA256: NativeAuthorizationTicket.sha256(
                    try NativeAuthorizationTicket.canonicalData(evidence)
                )
            )
        )
    }

    func inspectingProjectionIdentity(
        ticket: NativeProjectionIdentityRecoveryTicket,
        now: Date
    ) throws -> NativeProjectionIdentityRecoveryCompletion {
        try validate()
        try ticket.validate(now: now)
        guard let entry = projections.first(where: {
            $0.operationID == ticket.originalOperationID
        }),
            entry.provider == ticket.provider,
            entry.stackSHA256 == ticket.stackSHA256,
            entry.processIdentifier > 0,
            let processStartTimeMicroseconds =
                entry.processStartTimeMicroseconds,
            processStartTimeMicroseconds > 0,
            let executableSHA256 = entry.executableSHA256,
            let sessionAuthoritySHA256 = entry.sessionAuthoritySHA256,
            sessionAuthoritySHA256 == ticket.sessionAuthoritySHA256,
            let authorizationTicketSHA256 =
                entry.authorizationTicketSHA256,
            let projectionPolicySHA256 = entry.projectionPolicySHA256,
            let qualificationSubjectSHA256 =
                entry.qualificationSubjectSHA256,
            let qualificationEvidenceSHA256 =
                entry.qualificationEvidenceSHA256,
            let researchReleaseID = entry.researchReleaseID,
            [executableSHA256, sessionAuthoritySHA256,
             authorizationTicketSHA256, projectionPolicySHA256,
             qualificationSubjectSHA256, qualificationEvidenceSHA256,
             researchReleaseID]
                .allSatisfy(NativeAuthorizationTicket.isSHA256) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        struct EvidenceBody: Encodable {
            let recoveryTicketSHA256: String
            let recoveryPlanSHA256: String
            let ledgerEntry: NativeCredentialProjectionLedgerEntry

            enum CodingKeys: String, CodingKey {
                case recoveryTicketSHA256 = "recovery_ticket_sha256"
                case recoveryPlanSHA256 = "recovery_plan_sha256"
                case ledgerEntry = "ledger_entry"
            }
        }
        return NativeProjectionIdentityRecoveryCompletion(
            processIdentifier: entry.processIdentifier,
            processStartTimeMicroseconds: processStartTimeMicroseconds,
            consumerExecutableSHA256: executableSHA256,
            sessionAuthoritySHA256: sessionAuthoritySHA256,
            evidenceSHA256: NativeAuthorizationTicket.sha256(
                try NativeAuthorizationTicket.canonicalData(EvidenceBody(
                    recoveryTicketSHA256: ticket.ticketSHA256,
                    recoveryPlanSHA256: ticket.recoveryPlanSHA256,
                    ledgerEntry: entry
                ))
            )
        )
    }
}

final class DataProtectionKeychainNativeCredentialCustodyLedger:
    NativeCredentialCustodyTracking, @unchecked Sendable
{
    private let service: String
    private let account = "native-credential-custody-ledger"
    private let lock = NSLock()
    private let processIdentity: @Sendable (Int32) -> NativeCredentialProcessIdentityObservation

    init(
        service: String = "org.zebeth.SecureSandbox.NativeCredentialHelper.custody",
        processIdentity: @escaping @Sendable (Int32)
            -> NativeCredentialProcessIdentityObservation = nativeCredentialProcessIdentity
    ) {
        self.service = service
        self.processIdentity = processIdentity
    }

    func observe(hasCredential: Bool, now: Date) throws -> NativeCredentialCustodyObservation {
        try lock.withLock {
            _ = now
            let record = try load()
            return try record.observation(
                hasCredential: hasCredential,
                processIdentity: processIdentity
            )
        }
    }

    func clear() throws {
        try lock.withLock {
            let previous = try load()
            try replace(NativeCredentialCustodyLedgerRecord(
                schema: NativeCredentialCustodyLedgerRecord.schemaName,
                tombstoneSHA256: nil,
                projections: previous.projections
            ))
        }
    }

    func recordDestruction(ticketSHA256: String) throws {
        guard NativeAuthorizationTicket.isSHA256(ticketSHA256) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        let material = Data(
            ("secure-sandbox-native-credential-destroy-tombstone-v1\n" + ticketSHA256 + "\n").utf8
        )
        let tombstone = SHA256.hash(data: material).map {
            String(format: "%02x", $0)
        }.joined()
        try lock.withLock {
            guard try load().projections.isEmpty else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
            try replace(NativeCredentialCustodyLedgerRecord(
                schema: NativeCredentialCustodyLedgerRecord.schemaName,
                tombstoneSHA256: tombstone,
                projections: []
            ))
        }
    }

    func reserveProjection(operationID: UUID, expiresAt: Date, now: Date) throws {
        guard expiresAt > now, expiresAt <= now.addingTimeInterval(120) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        try lock.withLock {
            var projections = try load().projections
            let identifier = operationID.uuidString.lowercased()
            guard !projections.contains(where: { $0.operationID == identifier }),
                  projections.count < 64 else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
            projections.append(NativeCredentialProjectionLedgerEntry(
                operationID: identifier,
                provider: nil,
                stackSHA256: nil,
                processIdentifier: 0,
                processStartTimeMicroseconds: nil,
                executableSHA256: nil,
                sessionAuthoritySHA256: nil,
                authorizationTicketSHA256: nil,
                projectionPolicySHA256: nil,
                qualificationSubjectSHA256: nil,
                qualificationEvidenceSHA256: nil,
                researchReleaseID: nil,
                authorizationExpiresAtMilliseconds: Int64(
                    expiresAt.timeIntervalSince1970 * 1_000
                )
            ))
            projections.sort { $0.operationID < $1.operationID }
            try replace(NativeCredentialCustodyLedgerRecord(
                schema: NativeCredentialCustodyLedgerRecord.schemaName,
                tombstoneSHA256: nil,
                projections: projections
            ))
        }
    }

    func commitProjection(
        operationID: UUID,
        consumer: LaunchedCredentialConsumer,
        binding: NativeCredentialProjectionCustodyBinding,
        now: Date
    ) throws {
        guard consumer.processIdentifier > 0,
              consumer.processStartTimeMicroseconds > 0,
              NativeAuthorizationTicket.isSHA256(consumer.executableSHA256),
              NativeAuthorizationTicket.isSHA256(consumer.sessionAuthoritySHA256)
        else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        try lock.withLock {
            let timestamp = Int64(now.timeIntervalSince1970 * 1_000)
            var projections = try load().projections
            let identifier = operationID.uuidString.lowercased()
            guard let index = projections.firstIndex(where: {
                $0.operationID == identifier && $0.processIdentifier == 0
            }), projections[index].authorizationExpiresAtMilliseconds > timestamp else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
            projections[index] = NativeCredentialProjectionLedgerEntry(
                operationID: identifier,
                provider: binding.provider,
                stackSHA256: binding.stackSHA256,
                processIdentifier: consumer.processIdentifier,
                processStartTimeMicroseconds: consumer.processStartTimeMicroseconds,
                executableSHA256: consumer.executableSHA256,
                sessionAuthoritySHA256: consumer.sessionAuthoritySHA256,
                authorizationTicketSHA256: binding.ticketSHA256,
                projectionPolicySHA256: binding.policySHA256,
                qualificationSubjectSHA256:
                    binding.qualificationSubjectSHA256,
                qualificationEvidenceSHA256:
                    binding.qualificationEvidenceSHA256,
                researchReleaseID: binding.researchReleaseID,
                authorizationExpiresAtMilliseconds:
                    projections[index].authorizationExpiresAtMilliseconds
            )
            let replacement = NativeCredentialCustodyLedgerRecord(
                schema: NativeCredentialCustodyLedgerRecord.schemaName,
                tombstoneSHA256: nil,
                projections: projections
            )
            try replacement.validate()
            try replace(replacement)
        }
    }

    func cancelProjection(operationID: UUID) throws {
        try lock.withLock {
            let identifier = operationID.uuidString.lowercased()
            let previous = try load()
            guard previous.projections.contains(where: {
                $0.operationID == identifier && $0.processIdentifier == 0
            }) else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
            let projections = previous.projections.filter { $0.operationID != identifier }
            guard projections.count + 1 == previous.projections.count else {
                throw NativeCredentialXPCError.ticketReplayStoreFailed
            }
            try replace(NativeCredentialCustodyLedgerRecord(
                schema: NativeCredentialCustodyLedgerRecord.schemaName,
                tombstoneSHA256: previous.tombstoneSHA256,
                projections: projections
            ))
        }
    }

    func completeTerminatedProjection(
        operationID: UUID,
        processIdentifier: Int32,
        processStartTimeMicroseconds: UInt64,
        sessionAuthoritySHA256: String
    ) throws {
        try lock.withLock {
            let previous = try load()
            try replace(try previous.completingTerminatedProjection(
                operationID: operationID,
                processIdentifier: processIdentifier,
                processStartTimeMicroseconds: processStartTimeMicroseconds,
                sessionAuthoritySHA256: sessionAuthoritySHA256,
                processIdentity: processIdentity(processIdentifier)
            ))
        }
    }

    func reconcileProjection(
        ticket: NativeProjectionReconciliationTicket,
        now: Date
    ) throws -> NativeProjectionReconciliationCompletion {
        try lock.withLock {
            let previous = try load()
            let result = try previous.reconcilingProjection(
                ticket: ticket,
                now: now,
                processIdentity: processIdentity(ticket.processIdentifier)
            )
            try replace(result.record)
            return result.completion
        }
    }

    func inspectProjectionIdentity(
        ticket: NativeProjectionIdentityRecoveryTicket,
        now: Date
    ) throws -> NativeProjectionIdentityRecoveryCompletion {
        try lock.withLock {
            try load().inspectingProjectionIdentity(ticket: ticket, now: now)
        }
    }

    private func load() throws -> NativeCredentialCustodyLedgerRecord {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return NativeCredentialCustodyLedgerRecord(
                schema: NativeCredentialCustodyLedgerRecord.schemaName,
                tombstoneSHA256: nil,
                projections: []
            )
        }
        guard status == errSecSuccess, let data = result as? Data,
              data.count <= 64 * 1024,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == Set(["schema", "tombstone_sha256", "projections"]),
              let record = try? JSONDecoder().decode(
                  NativeCredentialCustodyLedgerRecord.self, from: data
              ),
              data == (try? Self.canonicalData(record)) else {
            throw NativeCredentialXPCError.ticketReplayStoreFailed
        }
        try record.validate()
        return record
    }

    private func replace(_ record: NativeCredentialCustodyLedgerRecord) throws {
        try record.validate()
        let data = try Self.canonicalData(record)
        guard data.count <= 64 * 1024 else {
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
