import CoreFoundation
import CryptoKit
import Foundation

public enum NativeSessionProtocolError: Error, Equatable, LocalizedError {
    case rejected(String)

    public var errorDescription: String? {
        switch self {
        case .rejected(let code):
            return "Native session protocol rejected the message (\(code))."
        }
    }
}

public enum CanonicalNativeJSON {
    public static let sha256Pattern = #"^[0-9a-f]{64}$"#
    public static let uuid4Pattern =
        #"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"#

    public static func parseLine(_ data: Data, maximumBytes: Int) throws -> [String: Any] {
        guard (2...maximumBytes).contains(data.count), data.last == 0x0a,
              data.dropLast().allSatisfy({ $0 != 0x0a && $0 != 0 }) else {
            throw NativeSessionProtocolError.rejected("native_json_framing_invalid")
        }
        let payload = data.dropLast()
        guard let object = try JSONSerialization.jsonObject(with: Data(payload)) as? [String: Any],
              try encodeLine(object) == data else {
            throw NativeSessionProtocolError.rejected("native_json_not_canonical")
        }
        return object
    }

    public static func encodeLine(_ value: Any) throws -> Data {
        var result = Data()
        try append(value, to: &result)
        result.append(0x0a)
        return result
    }

    public static func digest(_ value: Any) throws -> String {
        SHA256.hash(data: try encodeLine(value)).map { String(format: "%02x", $0) }.joined()
    }

    public static func isSHA256(_ value: Any?) -> Bool {
        (value as? String)?.range(of: sha256Pattern, options: .regularExpression) != nil
    }

    public static func isUUID4(_ value: Any?) -> Bool {
        (value as? String)?.range(of: uuid4Pattern, options: .regularExpression) != nil
    }

    public static func requireKeys(
        _ value: [String: Any], _ expected: Set<String>, _ code: String
    ) throws {
        guard Set(value.keys) == expected else {
            throw NativeSessionProtocolError.rejected(code)
        }
    }

    static func exactInteger(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite,
              number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= Double(Int.min),
              number.doubleValue <= Double(Int.max) else { return nil }
        return number.intValue
    }

    private static func append(_ value: Any, to result: inout Data) throws {
        switch value {
        case is NSNull:
            result.append(contentsOf: "null".utf8)
        case let value as String:
            appendJSONString(value, to: &result)
        case let value as [Any]:
            result.append(0x5b)
            for (index, item) in value.enumerated() {
                if index > 0 { result.append(0x2c) }
                try append(item, to: &result)
            }
            result.append(0x5d)
        case let value as [String: Any]:
            result.append(0x7b)
            for (index, key) in value.keys.sorted().enumerated() {
                if index > 0 { result.append(0x2c) }
                appendJSONString(key, to: &result)
                result.append(0x3a)
                try append(value[key]!, to: &result)
            }
            result.append(0x7d)
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() {
                result.append(contentsOf: (value.boolValue ? "true" : "false").utf8)
            } else {
                let number = value.doubleValue
                guard number.isFinite, number.rounded() == number,
                      number >= Double(Int.min), number <= Double(Int.max) else {
                    throw NativeSessionProtocolError.rejected("native_json_number_invalid")
                }
                result.append(contentsOf: String(value.intValue).utf8)
            }
        case let value as Int:
            result.append(contentsOf: String(value).utf8)
        default:
            throw NativeSessionProtocolError.rejected("native_json_value_invalid")
        }
    }

    private static func appendJSONString(_ value: String, to result: inout Data) {
        result.append(0x22)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: result.append(contentsOf: #"\""#.utf8)
            case 0x5c: result.append(contentsOf: #"\\"#.utf8)
            case 0x08: result.append(contentsOf: #"\b"#.utf8)
            case 0x0c: result.append(contentsOf: #"\f"#.utf8)
            case 0x0a: result.append(contentsOf: #"\n"#.utf8)
            case 0x0d: result.append(contentsOf: #"\r"#.utf8)
            case 0x09: result.append(contentsOf: #"\t"#.utf8)
            case 0x20...0x7e:
                result.append(UInt8(scalar.value))
            case 0...0xffff:
                appendUnicodeEscape(UInt16(scalar.value), to: &result)
            default:
                let adjusted = scalar.value - 0x1_0000
                appendUnicodeEscape(UInt16(0xd800 + (adjusted >> 10)), to: &result)
                appendUnicodeEscape(UInt16(0xdc00 + (adjusted & 0x3ff)), to: &result)
            }
        }
        result.append(0x22)
    }

    private static func appendUnicodeEscape(_ value: UInt16, to result: inout Data) {
        result.append(contentsOf: String(format: "\\u%04x", value).utf8)
    }
}
