import CryptoKit
import Darwin
import Foundation

enum ExportProvenance {
    static func digest(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func protectExport(_ destination: URL) throws {
        guard destination.isFileURL else { throw ExportError.invalidDestination }
        let descriptor = Darwin.open(destination.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ExportError.permissionsUnavailable }
        defer { Darwin.close(descriptor) }
        var details = stat()
        guard Darwin.fstat(descriptor, &details) == 0,
              details.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              details.st_uid == Darwin.geteuid(),
              Darwin.fchmod(descriptor, 0o600) == 0,
              Darwin.fsync(descriptor) == 0 else {
            throw ExportError.permissionsUnavailable
        }
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
        case invalidDestination, oversized, sidecarUnavailable, writeFailed, permissionsUnavailable

        var errorDescription: String? {
            switch self {
            case .invalidDestination: "The selected export destination is invalid."
            case .oversized: "The provenance record exceeds its size limit."
            case .sidecarUnavailable: "The provenance sidecar could not be created. An existing sidecar is never replaced."
            case .writeFailed: "The provenance sidecar could not be completed."
            case .permissionsUnavailable: "The exported file could not be secured to owner-only access."
            }
        }
    }
}
