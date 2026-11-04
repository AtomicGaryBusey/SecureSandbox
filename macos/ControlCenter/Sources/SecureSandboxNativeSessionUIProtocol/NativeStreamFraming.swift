import Foundation

public struct NativeStreamHeaderGate: Sendable {
    private let expected: Data
    private var received = Data()
    public private(set) var isOpen = false

    public init(expectedASCII: String) throws {
        guard let data = expectedASCII.data(using: .ascii),
              (2...32).contains(data.count), data.last == 0x0a,
              data.dropLast().allSatisfy({ 0x21...0x7e ~= $0 }) else {
            throw NativeSessionProtocolError.rejected("native_stream_header_invalid")
        }
        expected = data
    }

    public mutating func receive(_ data: Data) throws -> Data {
        guard !data.isEmpty else { return Data() }
        if isOpen { return data }
        let remaining = expected.count - received.count
        let headerBytes = data.prefix(remaining)
        received.append(headerBytes)
        guard expected.starts(with: received) else {
            throw NativeSessionProtocolError.rejected("native_stream_header_mismatch")
        }
        guard received.count == expected.count else { return Data() }
        isOpen = true
        return Data(data.dropFirst(headerBytes.count))
    }

    public func requireOpenAtEOF() throws {
        guard isOpen else {
            throw NativeSessionProtocolError.rejected("native_stream_header_truncated")
        }
    }
}

public struct NativeCanonicalLineFramer: Sendable {
    private let maximumBytes: Int
    private var buffered = Data()

    public init(maximumBytes: Int) throws {
        guard (2...1_048_576).contains(maximumBytes) else {
            throw NativeSessionProtocolError.rejected("native_line_limit_invalid")
        }
        self.maximumBytes = maximumBytes
    }

    public mutating func receive(_ data: Data) throws -> [Data] {
        guard !data.contains(0) else {
            throw NativeSessionProtocolError.rejected("native_line_contains_nul")
        }
        buffered.append(data)
        var lines: [Data] = []
        while let newline = buffered.firstIndex(of: 0x0a) {
            let length = buffered.distance(from: buffered.startIndex, to: newline) + 1
            guard (2...maximumBytes).contains(length) else {
                throw NativeSessionProtocolError.rejected("native_line_size_invalid")
            }
            lines.append(Data(buffered.prefix(length)))
            buffered.removeFirst(length)
        }
        guard buffered.count <= maximumBytes else {
            throw NativeSessionProtocolError.rejected("native_line_oversized")
        }
        return lines
    }

    public func requireEmptyAtEOF() throws {
        guard buffered.isEmpty else {
            throw NativeSessionProtocolError.rejected("native_line_truncated")
        }
    }
}
