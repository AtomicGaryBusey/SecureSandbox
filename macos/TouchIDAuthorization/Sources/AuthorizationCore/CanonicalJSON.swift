import CoreFoundation
import Foundation

enum CanonicalJSONError: Error {
    case unsupportedValue
}

/// Encode the JSON subset shared with Python's compact, `sort_keys=True`,
/// `ensure_ascii=True` encoder. Foundation's `.sortedKeys` ordering is not a
/// wire contract: on macOS 27 it orders `dhcp_ip` before `dhcp4_enabled`, while
/// Python (and Unicode code-point order) does the reverse.
enum CanonicalJSON {
    static func encode(_ value: Any) throws -> Data {
        var result = Data()
        try append(value, to: &result)
        return result
    }

    private static func append(_ value: Any, to result: inout Data) throws {
        switch value {
        case is NSNull:
            result.append(contentsOf: "null".utf8)
        case let value as String:
            appendString(value, to: &result)
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() {
                result.append(contentsOf: (value.boolValue ? "true" : "false").utf8)
            } else {
                let type = Character(UnicodeScalar(UInt8(value.objCType.pointee)))
                guard "cCsSiIlLqQ".contains(type) else {
                    throw CanonicalJSONError.unsupportedValue
                }
                result.append(contentsOf: value.stringValue.utf8)
            }
        case let value as [Any]:
            result.append(UInt8(ascii: "["))
            for (index, element) in value.enumerated() {
                if index > 0 { result.append(UInt8(ascii: ",")) }
                try append(element, to: &result)
            }
            result.append(UInt8(ascii: "]"))
        case let value as [String: Any]:
            result.append(UInt8(ascii: "{"))
            let entries = value.sorted { left, right in
                left.key.utf8.lexicographicallyPrecedes(right.key.utf8)
            }
            for (index, entry) in entries.enumerated() {
                if index > 0 { result.append(UInt8(ascii: ",")) }
                appendString(entry.key, to: &result)
                result.append(UInt8(ascii: ":"))
                try append(entry.value, to: &result)
            }
            result.append(UInt8(ascii: "}"))
        default:
            throw CanonicalJSONError.unsupportedValue
        }
    }

    private static func appendString(_ value: String, to result: inout Data) {
        result.append(UInt8(ascii: "\""))
        for unit in value.utf16 {
            switch unit {
            case 0x08: result.append(contentsOf: "\\b".utf8)
            case 0x09: result.append(contentsOf: "\\t".utf8)
            case 0x0a: result.append(contentsOf: "\\n".utf8)
            case 0x0c: result.append(contentsOf: "\\f".utf8)
            case 0x0d: result.append(contentsOf: "\\r".utf8)
            case 0x22: result.append(contentsOf: "\\\"".utf8)
            case 0x5c: result.append(contentsOf: "\\\\".utf8)
            case 0x00...0x1f, 0x7f...0xffff:
                result.append(contentsOf: String(format: "\\u%04x", unit).utf8)
            default:
                result.append(UInt8(unit))
            }
        }
        result.append(UInt8(ascii: "\""))
    }
}
