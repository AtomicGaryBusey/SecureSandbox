import CryptoKit
import Darwin
import Foundation
import Security
import SecureSandboxNativeCredentialHelper

private enum BackendFailure: Error {
    case rejected
}

private let maximumBytes = 32 * 1024
private let schema = "secure-sandbox-native-credential-client-handoff-v1"
private let replySchema = "secure-sandbox-native-credential-client-reply-v1"
private let reconciliationSchema =
    "secure-sandbox-native-projection-reconciliation-handoff-v1"
private let reconciliationReplySchema =
    "secure-sandbox-native-projection-reconciliation-reply-v1"
private let requiredIdentifier = "org.zebeth.SecureSandbox.NativeStackBackend"
private let forbiddenNames = [
    "access_token", "refresh_token", "authorization_code", "code_verifier",
    "pkce", "provider_response", "credential_path", "client_secret",
]

private struct Handoff {
    let operationID: UUID
    let operation: NativeCredentialOperation
    let authorizationTicketID: String?
    let planSHA256: String?
    let operatorRequestSHA256: String?
    let stackSHA256: String?
    let sessionAuthoritySHA256: String?
    let authorizationReceiptSHA256: String?
}

private struct ReconciliationHandoff {
    let ticketID: UUID
    let recoveryOperationID: UUID
    let originalOperationID: UUID
    let processIdentifier: Int32
    let processStartTimeMicroseconds: UInt64
    let consumerExecutableSHA256: String
    let sessionAuthoritySHA256: String
    let stackSHA256: String
    let recoveryPlanSHA256: String
    let guestAbsenceEvidenceSHA256: String
    let egressClosedEvidenceSHA256: String
    let hostReleaseID: String
    let recoveryRequestSHA256: String
    let recoveryReceiptSHA256: String
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func canonical(_ value: Any) throws -> Data {
    guard JSONSerialization.isValidJSONObject(value) else { throw BackendFailure.rejected }
    var data = try JSONSerialization.data(
        withJSONObject: value,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
    data.append(0x0a)
    guard data.count <= maximumBytes else { throw BackendFailure.rejected }
    return data
}

private func optionalString(_ value: Any?) throws -> String? {
    if value == nil || value is NSNull { return nil }
    guard let value = value as? String else { throw BackendFailure.rejected }
    return value
}

private func isSHA256(_ value: String?) -> Bool {
    guard let value else { return false }
    return value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
}

private func isUUID4(_ value: String?) -> Bool {
    guard let value else { return false }
    return value.range(
        of: #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#,
        options: .regularExpression
    ) != nil
}

private func exactPositiveInteger<T: FixedWidthInteger>(
    _ value: Any?, as type: T.Type
) throws -> T {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          number.doubleValue.rounded(.towardZero) == number.doubleValue,
          number.doubleValue > 0,
          number.doubleValue <= Double(T.max) else {
        throw BackendFailure.rejected
    }
    return T(number.uint64Value)
}

private func readHandoff(descriptor: Int32) throws -> Data {
    guard descriptor >= 3 else { throw BackendFailure.rejected }
    var before = stat()
    guard fstat(descriptor, &before) == 0,
          before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
          before.st_uid == 0,
          before.st_nlink == 0,
          before.st_mode & mode_t(0o777) == mode_t(0o400),
          (2...maximumBytes).contains(Int(before.st_size)),
          lseek(descriptor, 0, SEEK_CUR) == 0 else {
        throw BackendFailure.rejected
    }
    var output = Data()
    while output.count <= maximumBytes {
        var buffer = [UInt8](repeating: 0, count: min(4096, maximumBytes + 1 - output.count))
        let count = Darwin.read(descriptor, &buffer, buffer.count)
        if count < 0 {
            if errno == EINTR { continue }
            throw BackendFailure.rejected
        }
        if count == 0 { break }
        output.append(buffer, count: count)
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0,
          output.count == before.st_size,
          output.count <= maximumBytes,
          before.st_dev == after.st_dev,
          before.st_ino == after.st_ino,
          before.st_size == after.st_size,
          before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
          before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
          before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
          before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
        throw BackendFailure.rejected
    }
    return output
}

private func decodeHandoff(_ data: Data) throws -> Handoff {
    guard let lowercased = String(data: data, encoding: .ascii)?.lowercased(),
          !lowercased.isEmpty,
          !forbiddenNames.contains(where: { lowercased.contains($0) }),
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == Set([
              "schema", "operation_id", "operation", "authorization_ticket_id",
              "plan_sha256", "operator_request_sha256", "stack_sha256",
              "session_authority_sha256", "authorization_receipt_sha256",
              "handoff_sha256",
          ]),
          object["schema"] as? String == schema,
          data == (try? canonical(object)),
          let operationIDString = object["operation_id"] as? String,
          isUUID4(operationIDString),
          let operationID = UUID(uuidString: operationIDString),
          operationID.uuidString.lowercased() == operationIDString,
          let operationRaw = object["operation"] as? String,
          let operation = NativeCredentialOperation(rawValue: operationRaw),
          let suppliedDigest = object["handoff_sha256"] as? String,
          isSHA256(suppliedDigest) else {
        throw BackendFailure.rejected
    }
    var body = object
    body.removeValue(forKey: "schema")
    body.removeValue(forKey: "handoff_sha256")
    guard suppliedDigest == sha256(try canonical(body)) else {
        throw BackendFailure.rejected
    }
    let ticket = try optionalString(object["authorization_ticket_id"])
    let plan = try optionalString(object["plan_sha256"])
    let operatorRequest = try optionalString(object["operator_request_sha256"])
    let stack = try optionalString(object["stack_sha256"])
    let session = try optionalString(object["session_authority_sha256"])
    let receipt = try optionalString(object["authorization_receipt_sha256"])
    let authorized = ticket != nil || plan != nil || operatorRequest != nil
        || stack != nil || receipt != nil
    if operation == .status {
        guard !authorized, session == nil else { throw BackendFailure.rejected }
    } else {
        guard isUUID4(ticket), isSHA256(plan), isSHA256(operatorRequest),
              isSHA256(stack), isSHA256(receipt) else {
            throw BackendFailure.rejected
        }
        if operation == .projectForSession {
            guard isSHA256(session) else { throw BackendFailure.rejected }
        } else {
            guard session == nil else { throw BackendFailure.rejected }
        }
    }
    return Handoff(
        operationID: operationID,
        operation: operation,
        authorizationTicketID: ticket,
        planSHA256: plan,
        operatorRequestSHA256: operatorRequest,
        stackSHA256: stack,
        sessionAuthoritySHA256: session,
        authorizationReceiptSHA256: receipt
    )
}

private func decodeReconciliationHandoff(
    _ data: Data
) throws -> ReconciliationHandoff {
    let keys = Set([
        "schema", "ticket_id", "recovery_operation_id",
        "original_operation_id", "process_identifier",
        "process_start_time_us", "consumer_executable_sha256",
        "session_authority_sha256", "stack_sha256",
        "recovery_plan_sha256", "guest_absence_evidence_sha256",
        "egress_closed_evidence_sha256", "host_release_id",
        "recovery_request_sha256", "recovery_receipt_sha256",
        "handoff_sha256",
    ])
    guard let lowercased = String(data: data, encoding: .ascii)?.lowercased(),
          !lowercased.isEmpty,
          !forbiddenNames.contains(where: { lowercased.contains($0) }),
          let object = try JSONSerialization.jsonObject(with: data)
            as? [String: Any],
          Set(object.keys) == keys,
          object["schema"] as? String == reconciliationSchema,
          data == (try? canonical(object)),
          let ticketIDString = object["ticket_id"] as? String,
          let recoveryIDString = object["recovery_operation_id"] as? String,
          let originalIDString = object["original_operation_id"] as? String,
          [ticketIDString, recoveryIDString, originalIDString]
            .allSatisfy({ isUUID4($0) }),
          let ticketID = UUID(uuidString: ticketIDString),
          let recoveryID = UUID(uuidString: recoveryIDString),
          let originalID = UUID(uuidString: originalIDString),
          ticketID.uuidString.lowercased() == ticketIDString,
          recoveryID.uuidString.lowercased() == recoveryIDString,
          originalID.uuidString.lowercased() == originalIDString,
          recoveryID != originalID,
          let consumer = object["consumer_executable_sha256"] as? String,
          let authority = object["session_authority_sha256"] as? String,
          let stack = object["stack_sha256"] as? String,
          let plan = object["recovery_plan_sha256"] as? String,
          let guest = object["guest_absence_evidence_sha256"] as? String,
          let egress = object["egress_closed_evidence_sha256"] as? String,
          let release = object["host_release_id"] as? String,
          let request = object["recovery_request_sha256"] as? String,
          let receipt = object["recovery_receipt_sha256"] as? String,
          [consumer, authority, stack, plan, guest, egress, release, request,
           receipt].allSatisfy({ isSHA256($0) }),
          let suppliedDigest = object["handoff_sha256"] as? String,
          isSHA256(suppliedDigest) else {
        throw BackendFailure.rejected
    }
    var body = object
    body.removeValue(forKey: "schema")
    body.removeValue(forKey: "handoff_sha256")
    guard suppliedDigest == sha256(try canonical(body)) else {
        throw BackendFailure.rejected
    }
    return ReconciliationHandoff(
        ticketID: ticketID,
        recoveryOperationID: recoveryID,
        originalOperationID: originalID,
        processIdentifier: try exactPositiveInteger(
            object["process_identifier"], as: Int32.self
        ),
        processStartTimeMicroseconds: try exactPositiveInteger(
            object["process_start_time_us"], as: UInt64.self
        ),
        consumerExecutableSHA256: consumer,
        sessionAuthoritySHA256: authority,
        stackSHA256: stack,
        recoveryPlanSHA256: plan,
        guestAbsenceEvidenceSHA256: guest,
        egressClosedEvidenceSHA256: egress,
        hostReleaseID: release,
        recoveryRequestSHA256: request,
        recoveryReceiptSHA256: receipt
    )
}

private func inputSchema(_ data: Data) throws -> String {
    guard let object = try JSONSerialization.jsonObject(with: data)
            as? [String: Any],
          let inputSchema = object["schema"] as? String else {
        throw BackendFailure.rejected
    }
    return inputSchema
}

private func currentSigningTeam() throws -> String {
    var code: SecCode?
    var information: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess,
          let code,
          SecCodeCopySigningInformation(
              // Security.framework accepts a live SecCode here; Swift imports
              // only the layout-compatible SecStaticCode wrapper.
              unsafeBitCast(code, to: SecStaticCode.self),
              SecCSFlags(rawValue:
                  kSecCSSigningInformation | kSecCSDynamicInformation
              ),
              &information
          ) == errSecSuccess,
          let values = information as? [String: Any],
          values[kSecCodeInfoIdentifier as String] as? String == requiredIdentifier,
          let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
          team.range(of: #"^[A-Z0-9]{10}$"#, options: .regularExpression) != nil,
          let status = values[kSecCodeInfoStatus as String] as? NSNumber,
          status.uint32Value & 0x0001_0000 != 0 else {
        throw BackendFailure.rejected
    }
    let requirementSource = "identifier \"\(requiredIdentifier)\" "
        + "and anchor apple generic "
        + "and certificate leaf[subject.OU] = \"\(team)\" "
        + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(
              requirementSource as CFString, [], &requirement
          ) == errSecSuccess,
          let requirement,
          SecCodeCheckValidityWithErrors(
              code,
              SecCSFlags(rawValue:
                  kSecCSStrictValidate
                      | kSecCSCheckAllArchitectures
                      | kSecCSCheckNestedCode
                      // Public C constant omitted by Swift's importer.
                      | (1 << 23)
              ),
              requirement,
              nil
          ) == errSecSuccess else {
        throw BackendFailure.rejected
    }
    return team
}

private func milliseconds(_ date: Date?) -> Any {
    guard let date else { return NSNull() }
    return Int64(date.timeIntervalSince1970 * 1_000)
}

private func normalizedStatus(_ status: NativeCredentialStatus?) -> Any {
    guard let status else { return NSNull() }
    return [
        "provider": status.provider.rawValue,
        "state": status.state.rawValue,
        "client_id_sha256": status.clientIDHash ?? NSNull(),
        "account_subject_sha256": status.accountSubjectSHA256 ?? NSNull(),
        "workspace_sha256": status.workspaceSHA256 ?? NSNull(),
        "scope_sha256": status.scopeSHA256 ?? NSNull(),
        "access_expires_at_ms": milliseconds(status.accessExpiresAt),
        "earliest_refresh_at_ms": milliseconds(status.earliestRefreshAt),
        "refresh_expires_at_ms": milliseconds(status.refreshExpiresAt),
        "custody_state": status.custodyState.rawValue,
        "custody_tombstone_sha256": status.custodyTombstoneSHA256 ?? NSNull(),
        "custody_projection_count": status.custodyProjectionCount ?? NSNull(),
    ] as [String: Any]
}

private func normalizedProjection(_ projection: NativeCredentialXPCClientProjection?) -> Any {
    guard let projection else { return NSNull() }
    return [
        "process_identifier": projection.processIdentifier,
        "process_start_time_us": projection.processStartTimeMicroseconds,
        "executable_sha256": projection.executableSHA256,
        "session_authority_sha256": projection.sessionAuthoritySHA256,
        "started_at_ms": projection.startedAtMilliseconds,
    ] as [String: Any]
}

private func runLegacy(_ data: Data, descriptor: Int32) throws {
    guard geteuid() == 0,
          [3, 5].contains(CommandLine.arguments.count),
          CommandLine.arguments[1] == "--request-fd",
          Int32(CommandLine.arguments[2]) == descriptor else {
        throw BackendFailure.rejected
    }
    let handoff = try decodeHandoff(data)
    let projectionFD: Int32?
    if CommandLine.arguments.count == 5 {
        guard CommandLine.arguments[3] == "--projection-fd",
              let supplied = Int32(CommandLine.arguments[4]) else {
            throw BackendFailure.rejected
        }
        var information = stat()
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        var socketType: Int32 = 0
        var socketTypeSize = socklen_t(MemoryLayout<Int32>.size)
        var localAddress = sockaddr_storage()
        var localAddressSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        var peerAddress = sockaddr_storage()
        var peerAddressSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        guard handoff.operation == .projectForSession,
              supplied >= 3, supplied != descriptor,
              fstat(supplied, &information) == 0,
              information.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
              isatty(supplied) == 0,
              getsockopt(
                  supplied, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeSize
              ) == 0,
              socketTypeSize == socklen_t(MemoryLayout<Int32>.size),
              socketType == SOCK_STREAM,
              withUnsafeMutablePointer(to: &localAddress, {
                  $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                      getsockname(supplied, $0, &localAddressSize)
                  }
              }) == 0,
              localAddress.ss_family == sa_family_t(AF_UNIX),
              withUnsafeMutablePointer(to: &peerAddress, {
                  $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                      getpeername(supplied, $0, &peerAddressSize)
                  }
              }) == 0,
              peerAddress.ss_family == sa_family_t(AF_UNIX),
              getpeereid(supplied, &peerUID, &peerGID) == 0,
              peerUID == 0, peerGID == 0 else {
            throw BackendFailure.rejected
        }
        projectionFD = supplied
    } else {
        guard handoff.operation != .projectForSession else {
            throw BackendFailure.rejected
        }
        projectionFD = nil
    }
    let team = try currentSigningTeam()
    let request = try NativeCredentialXPCClientContract.encodeRequest(
        operationID: handoff.operationID,
        operation: handoff.operation,
        authorizationTicketID: handoff.authorizationTicketID,
        planSHA256: handoff.planSHA256,
        operatorRequestSHA256: handoff.operatorRequestSHA256,
        stackSHA256: handoff.stackSHA256,
        sessionAuthoritySHA256: handoff.sessionAuthoritySHA256,
        authorizationReceiptSHA256: handoff.authorizationReceiptSHA256
    )
    let reply = try NativeCredentialXPCClientContract.transact(
        request: request,
        teamIdentifier: team,
        projectionFD: projectionFD
    )
    var body: [String: Any] = [
        "operation_id": reply.operationID?.uuidString.lowercased() ?? NSNull(),
        "verified": reply.verified,
        "status": normalizedStatus(reply.status),
        "projection": normalizedProjection(reply.projection),
        "error_code": reply.errorCode ?? NSNull(),
        "response_sha256": reply.responseSHA256,
    ]
    body["reply_sha256"] = sha256(try canonical(body))
    let output = try canonical(["schema": replySchema] .merging(body) { _, replacement in replacement })
    try FileHandle.standardOutput.write(contentsOf: output)
}

private func runReconciliation(_ data: Data, descriptor: Int32) throws {
    guard geteuid() == 0,
          CommandLine.arguments.count == 3,
          CommandLine.arguments[1] == "--request-fd",
          Int32(CommandLine.arguments[2]) == descriptor else {
        throw BackendFailure.rejected
    }
    let handoff = try decodeReconciliationHandoff(data)
    let request = try NativeCredentialXPCClientContract
        .encodeProjectionReconciliationRequest(
            ticketID: handoff.ticketID,
            recoveryOperationID: handoff.recoveryOperationID,
            originalOperationID: handoff.originalOperationID,
            processIdentifier: handoff.processIdentifier,
            processStartTimeMicroseconds:
                handoff.processStartTimeMicroseconds,
            consumerExecutableSHA256: handoff.consumerExecutableSHA256,
            sessionAuthoritySHA256: handoff.sessionAuthoritySHA256,
            stackSHA256: handoff.stackSHA256,
            recoveryPlanSHA256: handoff.recoveryPlanSHA256,
            guestAbsenceEvidenceSHA256:
                handoff.guestAbsenceEvidenceSHA256,
            egressClosedEvidenceSHA256:
                handoff.egressClosedEvidenceSHA256,
            hostReleaseID: handoff.hostReleaseID,
            recoveryRequestSHA256: handoff.recoveryRequestSHA256,
            recoveryReceiptSHA256: handoff.recoveryReceiptSHA256
        )
    let reply = try NativeCredentialXPCClientContract
        .transactProjectionReconciliation(
            request: request, teamIdentifier: try currentSigningTeam()
        )
    guard reply.verified,
          reply.errorCode == nil,
          reply.recoveryOperationID == handoff.recoveryOperationID,
          reply.originalOperationID == handoff.originalOperationID,
          reply.processIdentifier == handoff.processIdentifier,
          reply.processStartTimeMicroseconds
            == handoff.processStartTimeMicroseconds,
          reply.consumerExecutableSHA256
            == handoff.consumerExecutableSHA256,
          reply.sessionAuthoritySHA256 == handoff.sessionAuthoritySHA256,
          let evidence = reply.reconciliationEvidenceSHA256,
          isSHA256(evidence), isSHA256(reply.replySHA256) else {
        throw BackendFailure.rejected
    }
    let output: [String: Any] = [
        "schema": reconciliationReplySchema,
        "outcome": "verified",
        "recovery_operation_id": handoff.recoveryOperationID.uuidString
            .lowercased(),
        "original_operation_id": handoff.originalOperationID.uuidString
            .lowercased(),
        "process_identifier": handoff.processIdentifier,
        "process_start_time_us": handoff.processStartTimeMicroseconds,
        "consumer_executable_sha256": handoff.consumerExecutableSHA256,
        "session_authority_sha256": handoff.sessionAuthoritySHA256,
        "reconciliation_evidence_sha256": evidence,
        "reply_sha256": reply.replySHA256,
    ]
    try FileHandle.standardOutput.write(contentsOf: try canonical(output))
}

private func run() throws {
    guard [3, 5].contains(CommandLine.arguments.count),
          CommandLine.arguments[1] == "--request-fd",
          let descriptor = Int32(CommandLine.arguments[2]) else {
        throw BackendFailure.rejected
    }
    let data = try readHandoff(descriptor: descriptor)
    switch try inputSchema(data) {
    case schema:
        try runLegacy(data, descriptor: descriptor)
    case reconciliationSchema:
        try runReconciliation(data, descriptor: descriptor)
    default:
        throw BackendFailure.rejected
    }
}

do {
    try run()
    exit(0)
} catch {
    FileHandle.standardError.write(Data("native_stack_backend_rejected\n".utf8))
    exit(1)
}
