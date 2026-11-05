import Foundation

struct NativeDeploymentTerminalRecord: Decodable, Sendable {
    let schema: String
    let deploymentID: String
    let sequence: Int
    let phase: String
    let plan: PlanIdentity
    let applyAuthorizationSHA256: String
    let authorizationSHA256: String
    let hostReleaseID: String
    let payloadContainerSHA256: String
    let event: String
    let evidence: Evidence
    let transport: String?
    let priorRecordSHA256: String
    let updatedAt: Int
    let recordSHA256: String

    struct PlanIdentity: Decodable, Sendable {
        let deploymentID: String
        let hostReleaseID: String
        let planSHA256: String

        enum CodingKeys: String, CodingKey {
            case deploymentID = "deployment_id"
            case hostReleaseID = "host_release_id"
            case planSHA256 = "plan_sha256"
        }
    }

    struct Evidence: Decodable, Sendable {
        let gatewayStatusSHA256: String
        let researchStatusSHA256: String
        let terminalSHA256: String
        let outcome: String

        enum CodingKeys: String, CodingKey {
            case gatewayStatusSHA256 = "gateway_status_sha256"
            case researchStatusSHA256 = "research_status_sha256"
            case terminalSHA256 = "terminal_sha256"
            case outcome
        }
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case deploymentID = "deployment_id"
        case sequence
        case phase
        case plan
        case applyAuthorizationSHA256 = "apply_authorization_sha256"
        case authorizationSHA256 = "authorization_sha256"
        case hostReleaseID = "host_release_id"
        case payloadContainerSHA256 = "payload_container_sha256"
        case event
        case evidence
        case transport
        case priorRecordSHA256 = "prior_record_sha256"
        case updatedAt = "updated_at"
        case recordSHA256 = "record_sha256"
    }
}
