import Foundation

/// Strict decoder for a broker rejection emitted before a signed Control
/// Center request can be classified as an NDJSON query.
///
/// A successful Touch ID response is deliberately not a valid direct-broker
/// reply.  Only the exact content-free rejected form is admitted so binary
/// framing can improve diagnostics without becoming an alternate success
/// protocol.
public enum NativeBrokerRejectionFrame {
    private static let magic = Data([0x53, 0x53, 0x41, 0x52]) // SSAR
    private static let headerBytes = 16
    private static let rejectedStatus: UInt32 = 1
    private static let schema = "secure-sandbox-touchid-approval-v1"

    public static func hasMagic(_ data: Data) -> Bool {
        data.count >= magic.count && data.prefix(magic.count) == magic
    }

    public static func decodeRejectedError(
        _ data: Data,
        maximumErrorBytes: Int = 65_536
    ) throws -> String {
        guard maximumErrorBytes >= 2,
              data.count >= headerBytes,
              hasMagic(data),
              uint32(data, offset: 4) == rejectedStatus,
              uint32(data, offset: 8) == 0,
              let errorSize = Int(exactly: uint32(data, offset: 12)),
              (2...maximumErrorBytes).contains(errorSize),
              data.count == headerBytes + errorSize
        else { throw invalid() }

        let errorData = data.subdata(in: headerBytes..<data.count)
        let value: [String: Any]
        do {
            value = try CanonicalNativeJSON.parseLine(
                errorData, maximumBytes: maximumErrorBytes
            )
        } catch {
            throw invalid()
        }
        guard Set(value.keys) == ["schema", "status", "error"],
              value["schema"] as? String == schema,
              value["status"] as? String == "rejected",
              let error = value["error"] as? String,
              isSafeErrorCode(error)
        else { throw invalid() }
        return error
    }

    private static func isSafeErrorCode(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...128).contains(bytes.count),
              (0x61...0x7a).contains(bytes[0])
        else { return false }
        return bytes.dropFirst().allSatisfy {
            (0x61...0x7a).contains($0)
                || (0x30...0x39).contains($0)
                || $0 == 0x5f
        }
    }

    private static func uint32(_ data: Data, offset: Int) -> UInt32 {
        data[offset..<(offset + 4)].reduce(UInt32(0)) {
            ($0 << 8) | UInt32($1)
        }
    }

    private static func invalid() -> NativeSessionProtocolError {
        .rejected("native_broker_rejection_frame_invalid")
    }
}
