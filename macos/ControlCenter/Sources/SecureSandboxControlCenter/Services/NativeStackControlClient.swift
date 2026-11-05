import CryptoKit
import Darwin
import Foundation

enum NativeStackControlError: LocalizedError {
    case rejected(String)

    var errorDescription: String? {
        switch self {
        case .rejected(let code):
            return "Native stack control rejected the request (\(code))."
        }
    }
}

struct NativeStackInspection: Sendable {
    let status: NativeStackOperationalStatus
    let canonicalStatus: Data
}

struct NativeStackControlClient: Sendable {
    private static let socketPath = "/var/run/secure-sandbox-authorization.sock"
    private static let publicStatusPath =
        "/usr/local/var/lib/secure-sandbox/native-stack-public/status.json"
    private static let maximumBytes = 1024 * 1024

    func publicCatalogStatus() throws -> NativeStackPublicCatalogStatus {
        let raw = try Self.trustedPublicFile(Self.publicStatusPath)
        let object = try Self.canonicalObject(raw)
        try Self.requireKeys(
            object,
            [
                "schema", "catalog_sha256", "host_release_id", "promotion_id",
                "promotion_receipt_sha256", "published_at", "stacks", "status_sha256",
            ],
            "native_stack_public_status_fields_invalid"
        )
        guard object["schema"] as? String
                == "secure-sandbox-native-stack-catalog-public-status-v1",
              let supplied = object["status_sha256"] as? String,
              Self.isSHA256(supplied)
        else {
            throw NativeStackControlError.rejected("native_stack_public_status_invalid")
        }
        var body = object
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "status_sha256")
        guard supplied == Self.digest(try Self.canonical(body)) else {
            throw NativeStackControlError.rejected("native_stack_public_status_digest_mismatch")
        }
        let value = try JSONDecoder().decode(NativeStackPublicCatalogStatus.self, from: raw)
        try value.validate()
        // A public catalog status is immutable promotion provenance. It may
        // legitimately outlive the Host release that published it.
        return value
    }

    func inspect(
        stackID: String,
        stackSHA256: String,
        catalogSHA256: String
    ) throws -> NativeStackInspection {
        guard Self.isIdentifier(stackID), Self.isSHA256(stackSHA256),
              Self.isSHA256(catalogSHA256)
        else {
            throw NativeStackControlError.rejected("native_stack_inspect_identity_invalid")
        }
        let operationID = UUID().uuidString.lowercased()
        let body: [String: Any] = [
            "catalog_sha256": catalogSHA256,
            "operation_id": operationID,
            "stack_id": stackID,
            "stack_sha256": stackSHA256,
        ]
        let requestSHA256 = Self.digest(try Self.canonical(body))
        let request: [String: Any] = [
            "schema": "secure-sandbox-native-stack-inspect-request-v1",
            "catalog_sha256": catalogSHA256,
            "operation_id": operationID,
            "request_sha256": requestSHA256,
            "stack_id": stackID,
            "stack_sha256": stackSHA256,
        ]
        let response = try Self.exchange(try Self.canonical(request))
        let object = try Self.canonicalObject(response)
        if object["schema"] as? String
            == "secure-sandbox-native-stack-inspect-query-error-v1"
        {
            try Self.requireKeys(
                object, ["schema", "status", "error"],
                "native_stack_inspect_error_invalid"
            )
            let code = object["error"] as? String ?? "native_stack_inspect_rejected"
            throw NativeStackControlError.rejected(Self.safeCode(code))
        }
        try Self.requireKeys(
            object,
            ["schema", "operation_id", "request_sha256", "status", "reply_sha256"],
            "native_stack_inspect_reply_fields_invalid"
        )
        guard object["schema"] as? String
                == "secure-sandbox-native-stack-inspect-query-reply-v1",
              object["operation_id"] as? String == operationID,
              object["request_sha256"] as? String == requestSHA256,
              let statusObject = object["status"] as? [String: Any],
              let replySHA256 = object["reply_sha256"] as? String,
              Self.isSHA256(replySHA256)
        else {
            throw NativeStackControlError.rejected("native_stack_inspect_reply_invalid")
        }
        let replyBody: [String: Any] = [
            "operation_id": operationID,
            "request_sha256": requestSHA256,
            "status": statusObject,
        ]
        guard replySHA256 == Self.digest(try Self.canonical(replyBody)) else {
            throw NativeStackControlError.rejected("native_stack_inspect_reply_digest_mismatch")
        }
        let canonicalStatus = try Self.canonical(statusObject)
        try Self.validateOperationalStatusObject(statusObject)
        let status = try JSONDecoder().decode(
            NativeStackOperationalStatus.self, from: canonicalStatus
        )
        try status.validate()
        guard status.stackID == stackID, status.stackSHA256 == stackSHA256 else {
            throw NativeStackControlError.rejected("native_stack_inspect_status_mismatch")
        }
        return NativeStackInspection(status: status, canonicalStatus: canonicalStatus)
    }

    private static func validateOperationalStatusObject(_ value: [String: Any]) throws {
        try requireKeys(
            value,
            [
                "schema", "stack_id", "stack_sha256", "harness", "authentication",
                "credential_custody", "account_binding", "program_entitlement",
                "model_entitlement", "network", "activation", "live_run_count",
                "fence_reason", "status_sha256",
            ],
            "native_stack_operational_status_fields_invalid"
        )
        guard value["schema"] as? String
                == "secure-sandbox-native-stack-operational-status-v2",
              let supplied = value["status_sha256"] as? String,
              isSHA256(supplied)
        else {
            throw NativeStackControlError.rejected("native_stack_operational_status_invalid")
        }
        var body = value
        body.removeValue(forKey: "schema")
        body.removeValue(forKey: "status_sha256")
        guard supplied == digest(try canonical(body)) else {
            throw NativeStackControlError.rejected(
                "native_stack_operational_status_digest_mismatch"
            )
        }
    }

    private static func trustedPublicFile(_ path: String) throws -> Data {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        var parentInfo = stat()
        var before = stat()
        guard lstat(parent, &parentInfo) == 0,
              parentInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              parentInfo.st_uid == 0, parentInfo.st_gid == 0,
              parentInfo.st_mode & 0o777 == 0o755,
              lstat(path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_uid == 0, before.st_gid == 0,
              before.st_mode & 0o777 == 0o644, before.st_nlink == 1,
              (2...maximumBytes).contains(Int(before.st_size))
        else {
            throw NativeStackControlError.rejected("native_stack_public_status_untrusted")
        }
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw NativeStackControlError.rejected("native_stack_public_status_unavailable")
        }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0 else {
            throw NativeStackControlError.rejected("native_stack_public_status_untrusted")
        }
        var data = Data()
        while data.count <= maximumBytes {
            var buffer = [UInt8](repeating: 0, count: min(65536, maximumBytes + 1 - data.count))
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw NativeStackControlError.rejected("native_stack_public_status_read_failed")
            }
            if count == 0 { break }
            data.append(buffer, count: count)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              opened.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              opened.st_uid == 0, opened.st_gid == 0,
              opened.st_mode & 0o777 == 0o644, opened.st_nlink == 1,
              before.st_dev == opened.st_dev, before.st_ino == opened.st_ino,
              before.st_size == opened.st_size,
              before.st_mtimespec.tv_sec == opened.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == opened.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == opened.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == opened.st_ctimespec.tv_nsec,
              opened.st_size == after.st_size,
              opened.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              opened.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              opened.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              opened.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              data.count == Int(opened.st_size), data.count <= maximumBytes
        else {
            throw NativeStackControlError.rejected("native_stack_public_status_changed")
        }
        return data
    }

    private static func exchange(_ request: Data) throws -> Data {
        guard request.count <= 65536 else {
            throw NativeStackControlError.rejected("native_stack_inspect_request_oversized")
        }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw NativeStackControlError.rejected("native_stack_inspect_socket_unavailable")
        }
        defer { close(descriptor) }
        var noSignal: Int32 = 1
        let noSignalSize = socklen_t(MemoryLayout.size(ofValue: noSignal))
        _ = withUnsafePointer(to: &noSignal) {
            setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, noSignalSize)
        }
        var receiveTimeout = timeval(tv_sec: 190, tv_usec: 0)
        var sendTimeout = timeval(tv_sec: 10, tv_usec: 0)
        let receiveTimeoutSize = socklen_t(MemoryLayout.size(ofValue: receiveTimeout))
        let sendTimeoutSize = socklen_t(MemoryLayout.size(ofValue: sendTimeout))
        _ = withUnsafePointer(to: &receiveTimeout) {
            setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, $0, receiveTimeoutSize)
        }
        _ = withUnsafePointer(to: &sendTimeout) {
            setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, $0, sendTimeoutSize)
        }
        var address = sockaddr_un()
        let path = Array(socketPath.utf8CString)
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw NativeStackControlError.rejected("native_stack_inspect_socket_path_invalid")
        }
        address.sun_family = sa_family_t(AF_UNIX)
        let addressLength = socklen_t(MemoryLayout<sockaddr_un>.size)
        address.sun_len = UInt8(addressLength)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: path.count) { destination in
                for index in path.indices { destination[index] = path[index] }
            }
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, addressLength)
            }
        }
        guard connected == 0 else {
            throw NativeStackControlError.rejected("native_stack_inspect_socket_connect_failed")
        }
        var offset = 0
        try request.withUnsafeBytes { bytes in
            while offset < request.count {
                let count = Darwin.write(
                    descriptor, bytes.baseAddress!.advanced(by: offset), request.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw NativeStackControlError.rejected("native_stack_inspect_socket_write_failed")
                }
                offset += count
            }
        }
        guard shutdown(descriptor, SHUT_WR) == 0 else {
            throw NativeStackControlError.rejected("native_stack_inspect_socket_shutdown_failed")
        }
        var response = Data()
        while response.count <= maximumBytes {
            var buffer = [UInt8](repeating: 0, count: min(65536, maximumBytes + 1 - response.count))
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw NativeStackControlError.rejected("native_stack_inspect_socket_read_failed")
            }
            if count == 0 { break }
            response.append(buffer, count: count)
        }
        guard (2...maximumBytes).contains(response.count) else {
            throw NativeStackControlError.rejected("native_stack_inspect_response_size_invalid")
        }
        return response
    }

    private static func canonicalObject(_ data: Data) throws -> [String: Any] {
        guard data.count <= maximumBytes, data.last == 0x0a,
              data.dropLast().allSatisfy({ $0 < 0x80 }),
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              data == (try? canonical(value))
        else {
            throw NativeStackControlError.rejected("native_stack_response_not_canonical")
        }
        return value
    }

    private static func canonical(_ value: Any) throws -> Data {
        guard JSONSerialization.isValidJSONObject(value) else {
            throw NativeStackControlError.rejected("native_stack_value_invalid")
        }
        var data = try JSONSerialization.data(
            withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard data.allSatisfy({ $0 < 0x80 }) else {
            throw NativeStackControlError.rejected("native_stack_value_non_ascii")
        }
        data.append(0x0a)
        guard data.count <= maximumBytes else {
            throw NativeStackControlError.rejected("native_stack_value_oversized")
        }
        return data
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func requireKeys(
        _ value: [String: Any], _ expected: Set<String>, _ code: String
    ) throws {
        guard Set(value.keys) == expected else {
            throw NativeStackControlError.rejected(code)
        }
    }

    static func isSHA256(_ value: String?) -> Bool {
        value?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }

    static func isIdentifier(_ value: String?) -> Bool {
        value?.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }

    private static func safeCode(_ value: String) -> String {
        guard value.range(of: "^[a-z0-9_]{1,100}$", options: .regularExpression) != nil else {
            return "native_stack_inspect_rejected"
        }
        return value
    }
}
