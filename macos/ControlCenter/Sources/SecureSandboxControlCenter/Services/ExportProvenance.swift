import CryptoKit
import Darwin
import Foundation

enum ExportProvenance {
    static func digest(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func writeBeside(_ destination: URL, fields: [String: String]) throws {
        guard destination.isFileURL, !fields.isEmpty else { throw ExportError.invalidDestination }
        let sidecar = destination.path + ".provenance.json"
        var data = try JSONSerialization.data(withJSONObject: fields,
                                              options: [.prettyPrinted, .sortedKeys])
        data.append(0x0a)
        guard data.count <= 16 * 1024 else { throw ExportError.oversized }
        let descriptor = Darwin.open(sidecar, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw ExportError.sidecarUnavailable }
        var complete = false
        defer {
            Darwin.close(descriptor)
            if !complete { Darwin.unlink(sidecar) }
        }
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { throw ExportError.writeFailed }
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
                guard written > 0 else { throw ExportError.writeFailed }
                offset += written
            }
        }
        guard Darwin.fsync(descriptor) == 0 else { throw ExportError.writeFailed }
        complete = true
    }

    enum ExportError: LocalizedError {
        case invalidDestination, oversized, sidecarUnavailable, writeFailed

        var errorDescription: String? {
            switch self {
            case .invalidDestination: "The selected export destination is invalid."
            case .oversized: "The provenance record exceeds its size limit."
            case .sidecarUnavailable: "The provenance sidecar could not be created. An existing sidecar is never replaced."
            case .writeFailed: "The provenance sidecar could not be completed."
            }
        }
    }
}
