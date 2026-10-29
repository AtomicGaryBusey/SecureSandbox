import Foundation

struct CatalogClient: Sendable {
    let repositoryPath: String

    func load<T: Decodable>(_ catalog: String, as type: T.Type) throws -> T {
        guard ["overview", "sessions", "sources", "findings"].contains(catalog) else {
            throw CatalogError.invalidCatalog
        }
        let script = URL(fileURLWithPath: repositoryPath)
            .appending(path: "scripts/control-center-api.py")
        guard FileManager.default.isReadableFile(atPath: script.path) else {
            throw CatalogError.missingBridge
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [script.path, catalog]
        process.currentDirectoryURL = URL(fileURLWithPath: repositoryPath)
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard data.count <= 8 * 1024 * 1024 else { throw CatalogError.oversized }
        if process.terminationStatus != 0 {
            if let failure = try? JSONDecoder().decode(Failure.self, from: data) {
                throw CatalogError.bridge(failure.error)
            }
            throw CatalogError.bridge("The host catalog could not be loaded.")
        }
        let envelope = try JSONDecoder().decode(Envelope<T>.self, from: data)
        guard envelope.schema == "secure-sandbox-control-center-v1", envelope.catalog == catalog else {
            throw CatalogError.invalidSchema
        }
        return envelope.data
    }

    private struct Failure: Decodable { let error: String }
}

enum CatalogError: LocalizedError {
    case invalidCatalog, missingBridge, oversized, invalidSchema, bridge(String)

    var errorDescription: String? {
        switch self {
        case .invalidCatalog: "Unknown catalog."
        case .missingBridge: "The SecureSandbox repository was not found. Set its location in Settings."
        case .oversized: "The catalog exceeded its size limit."
        case .invalidSchema: "The host returned an unsupported catalog version."
        case .bridge(let detail): detail
        }
    }
}
