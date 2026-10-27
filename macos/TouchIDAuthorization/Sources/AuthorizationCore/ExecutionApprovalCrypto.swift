import CryptoKit
import Foundation

public enum ExecutionApprovalCryptoError: Error, Equatable {
    case invalidDER
    case invalidScalar
    case invalidX963
    case invalidBase64
    case invalidJSON
}

public enum ExecutionApprovalCrypto {
    public static let signatureAlgorithm = "ecdsa-p256-sha256-x962-low-s"
    public static let envelopeSchema = "secure-sandbox-execution-approval-envelope-v2"
    public static let attestationSchema = "secure-sandbox-execution-approval-attestation-v2"

    // SEC 2, section 2.4.2: order of the NIST P-256 base point.
    private static let order: [UInt8] = hex(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    )
    private static let halfOrder: [UInt8] = hex(
        "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8"
    )
    private static let p256SPKIPrefix: [UInt8] = hex(
        "3059301306072A8648CE3D020106082A8648CE3D030107034200"
    )

    public static func canonicalJSON(_ value: Any) throws -> Data {
        guard JSONSerialization.isValidJSONObject(value) else {
            throw ExecutionApprovalCryptoError.invalidJSON
        }
        let data = try JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard !data.contains(0x0a), !data.contains(0x0d) else {
            throw ExecutionApprovalCryptoError.invalidJSON
        }
        return data
    }

    public static func spkiDER(fromX963 x963: Data) throws -> Data {
        guard x963.count == 65, x963.first == 0x04 else {
            throw ExecutionApprovalCryptoError.invalidX963
        }
        return Data(p256SPKIPrefix) + x963
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func canonicalBase64(_ data: Data) -> String {
        data.base64EncodedString()
    }

    public static func decodeCanonicalBase64(_ value: String) throws -> Data {
        guard !value.isEmpty,
              value.unicodeScalars.allSatisfy({ $0.isASCII }),
              let decoded = Data(base64Encoded: value, options: []),
              decoded.base64EncodedString() == value else {
            throw ExecutionApprovalCryptoError.invalidBase64
        }
        return decoded
    }

    public static func normalizeP256SignatureDER(_ der: Data) throws -> Data {
        let (r, originalS) = try parseP256SignatureDER(der)
        let s = compare(originalS, halfOrder) == .orderedDescending
            ? subtract(order, originalS)
            : originalS
        return encodeP256SignatureDER(r: r, s: s)
    }

    public static func validateCanonicalLowSP256SignatureDER(_ der: Data) throws {
        let (r, s) = try parseP256SignatureDER(der)
        guard compare(s, halfOrder) != .orderedDescending,
              encodeP256SignatureDER(r: r, s: s) == der else {
            throw ExecutionApprovalCryptoError.invalidDER
        }
    }

    private static func parseP256SignatureDER(_ data: Data) throws -> ([UInt8], [UInt8]) {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, bytes[0] == 0x30,
              Int(bytes[1]) == bytes.count - 2,
              bytes[1] < 0x80 else {
            throw ExecutionApprovalCryptoError.invalidDER
        }
        var offset = 2
        let r = try parseInteger(bytes, offset: &offset)
        let s = try parseInteger(bytes, offset: &offset)
        guard offset == bytes.count else { throw ExecutionApprovalCryptoError.invalidDER }
        return (r, s)
    }

    private static func parseInteger(_ bytes: [UInt8], offset: inout Int) throws -> [UInt8] {
        guard offset + 2 <= bytes.count, bytes[offset] == 0x02 else {
            throw ExecutionApprovalCryptoError.invalidDER
        }
        let length = Int(bytes[offset + 1])
        offset += 2
        guard length > 0, length <= 33, offset + length <= bytes.count else {
            throw ExecutionApprovalCryptoError.invalidDER
        }
        var value = Array(bytes[offset..<(offset + length)])
        offset += length
        guard value[0] & 0x80 == 0 else { throw ExecutionApprovalCryptoError.invalidDER }
        if value.count > 1, value[0] == 0 {
            guard value[1] & 0x80 != 0 else { throw ExecutionApprovalCryptoError.invalidDER }
            value.removeFirst()
        }
        guard value.count <= 32 else { throw ExecutionApprovalCryptoError.invalidScalar }
        value = Array(repeating: 0, count: 32 - value.count) + value
        guard value.contains(where: { $0 != 0 }), compare(value, order) == .orderedAscending else {
            throw ExecutionApprovalCryptoError.invalidScalar
        }
        return value
    }

    private static func encodeP256SignatureDER(r: [UInt8], s: [UInt8]) -> Data {
        let rEncoded = encodeInteger(r)
        let sEncoded = encodeInteger(s)
        let body = [UInt8(0x02), UInt8(rEncoded.count)] + rEncoded
            + [UInt8(0x02), UInt8(sEncoded.count)] + sEncoded
        return Data([0x30, UInt8(body.count)] + body)
    }

    private static func encodeInteger(_ scalar: [UInt8]) -> [UInt8] {
        var value = Array(scalar.drop(while: { $0 == 0 }))
        if value.isEmpty { value = [0] }
        if value[0] & 0x80 != 0 { value.insert(0, at: 0) }
        return value
    }

    private static func compare(_ lhs: [UInt8], _ rhs: [UInt8]) -> ComparisonResult {
        precondition(lhs.count == rhs.count)
        for (left, right) in zip(lhs, rhs) {
            if left < right { return .orderedAscending }
            if left > right { return .orderedDescending }
        }
        return .orderedSame
    }

    private static func subtract(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
        precondition(lhs.count == rhs.count && compare(lhs, rhs) != .orderedAscending)
        var result = Array(repeating: UInt8(0), count: lhs.count)
        var borrow = 0
        for index in stride(from: lhs.count - 1, through: 0, by: -1) {
            var value = Int(lhs[index]) - Int(rhs[index]) - borrow
            if value < 0 {
                value += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(value)
        }
        precondition(borrow == 0)
        return result
    }

    private static func hex(_ value: String) -> [UInt8] {
        stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        }
    }
}
