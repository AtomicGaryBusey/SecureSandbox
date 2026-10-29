import Foundation

struct CatalogClient: Sendable {
    let repositoryPath: String

    func load<T: Decodable>(_ catalog: String, as type: T.Type) throws -> T {
        guard ["overview", "sessions", "sources", "findings", "artifacts", "activity", "maintenance"].contains(catalog) else {
            throw CatalogError.invalidCatalog
        }
        return try execute(catalog: catalog, arguments: ["catalog", catalog], as: type)
    }

    func planSource(url: String, ref: String) throws -> SourcePlan {
        try execute(catalog: "source-plan", arguments: ["plan-source", url, ref], as: SourcePlan.self)
    }

    func sourceStatus(planID: String) throws -> SourcePlanStatus {
        let value = try execute(catalog: "source-status", arguments: ["source-status", planID], as: SourcePlanStatus.self)
        guard value.schema == "secure-sandbox-source-plan-status-v1", value.planID == planID else {
            throw CatalogError.invalidSchema
        }
        return value
    }

    func applySource(planID: String) throws -> SourceImportResult {
        try execute(catalog: "source-import", arguments: ["apply-source", planID], as: SourceImportResult.self)
    }

    func labelSession(id: String, label: String) throws -> SessionLabelResult {
        try execute(catalog: "session-label", arguments: ["label-session", id, label], as: SessionLabelResult.self)
    }

    func unlabelSession(id: String) throws -> SessionLabelResult {
        try execute(catalog: "session-label", arguments: ["unlabel-session", id], as: SessionLabelResult.self)
    }

    func findingDetail(id: String) throws -> FindingDetail {
        try execute(catalog: "finding-detail", arguments: ["finding-detail", id], as: FindingDetail.self)
    }

    func artifactDetail(id: String) throws -> ArtifactDetail {
        try execute(catalog: "artifact-detail", arguments: ["artifact-detail", id], as: ArtifactDetail.self)
    }

    func verifyBoundaries() throws -> BoundaryVerificationResult {
        try execute(catalog: "boundary-verification", arguments: ["verify-boundaries"], as: BoundaryVerificationResult.self)
    }

    func lifecycle(_ operation: String) throws -> LifecycleResult {
        guard ["start", "stop"].contains(operation) else { throw CatalogError.invalidCatalog }
        return try execute(catalog: "lifecycle", arguments: ["lifecycle", operation], as: LifecycleResult.self)
    }

    private func execute<T: Decodable>(catalog: String, arguments: [String], as type: T.Type) throws -> T {
        let script = URL(fileURLWithPath: repositoryPath)
            .appending(path: "scripts/control-center-api.py")
        guard FileManager.default.isReadableFile(atPath: script.path) else {
            throw CatalogError.missingBridge
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [script.path] + arguments
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
