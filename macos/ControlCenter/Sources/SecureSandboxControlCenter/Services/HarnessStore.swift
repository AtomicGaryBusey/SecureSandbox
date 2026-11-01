import Foundation
import Observation
import UserNotifications

enum HarnessOperationState: Equatable {
    case idle
    case loading
    case running(String)
    case completed(String)
    case rejected(String)
}

@MainActor
@Observable
final class HarnessStore {
    private(set) var state: HarnessOperationState = .idle
    private(set) var status: HarnessControlCenterStatus?
    private(set) var releases: HarnessReleaseCatalog?
    private(set) var lastReceipt: HarnessLifecycleReceipt?
    private(set) var qualification: HarnessQualificationReport?
    private(set) var acceptance: HarnessAcceptanceAvailability?
    private(set) var lastGenerationResult: HarnessGenerationResult?
    private(set) var lastCheckedAt: Date?

    private let client = CatalogClient(repositoryPath: ControlCenterPaths.repository)

    var automaticOperationInvariant: String {
        "Automatic download, qualification, staging, activation, rollback, retirement, and revocation do not exist."
    }

    func load() async {
        state = .loading
        do {
            status = try await Task.detached { [client] in try client.harnessStatus() }.value
            if status?.lifecycle.floor != nil {
                releases = try await Task.detached { [client] in try client.harnessReleases() }.value
            } else {
                releases = nil
            }
            acceptance = try await Task.detached { [client] in
                try client.harnessAcceptanceStatus()
            }.value
            state = .idle
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func refreshAcceptanceStatus() async {
        state = .running("Verifying the read-only disposable-Mac campaign status…")
        do {
            acceptance = try await Task.detached { [client] in
                try client.harnessAcceptanceStatus()
            }.value
            state = .completed("Disposable-Mac campaign status verified. No evidence or authority changed.")
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func automaticCheckIfDue() async {
        guard UserDefaults.standard.bool(forKey: "automaticHarnessMetadataChecks") else { return }
        let previous = UserDefaults.standard.object(forKey: "lastAutomaticHarnessMetadataCheck") as? Date
        guard previous == nil || Date().timeIntervalSince(previous!) >= 86_400 else { return }
        let oldSequence = status?.lifecycle.floor?.sequence
        await checkMetadata()
        UserDefaults.standard.set(Date(), forKey: "lastAutomaticHarnessMetadataCheck")
        if case .completed = state,
           let sequence = lastReceipt?.sequence,
           oldSequence == nil || sequence > oldSequence! {
            await notifyVerifiedMetadata(sequence: sequence)
        }
    }

    func requestNotificationPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge])
    }

    func checkMetadata() async {
        state = .running("Verifying signed metadata…")
        do {
            let receipt = try await Task.detached { [client] in try client.checkHarnessMetadata() }.value
            lastReceipt = receipt
            lastCheckedAt = Date()
            status = try await Task.detached { [client] in try client.harnessStatus() }.value
            releases = try await Task.detached { [client] in try client.harnessReleases() }.value
            state = .completed("Signed metadata verified. No artifact was downloaded.")
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func acquire(generationID: String) async {
        state = .running("Downloading exact candidate into inert quarantine…")
        do {
            lastReceipt = try await Task.detached { [client] in
                try client.acquireHarness(generationID: generationID)
            }.value
            status = try await Task.detached { [client] in try client.harnessStatus() }.value
            state = .completed("Candidate quarantined. It is not admitted or executable.")
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func verify(generationID: String) async {
        state = .running("Reverifying quarantined bytes and evidence…")
        do {
            lastReceipt = try await Task.detached { [client] in
                try client.verifyHarness(generationID: generationID)
            }.value
            state = .completed("Artifact and evidence bindings verified; still not admitted or executable.")
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func runQualificationSelfTest() async {
        state = .running("Running the synthetic malicious-harness fixture…")
        do {
            qualification = try await Task.detached { [client] in
                try client.runHarnessQualificationSelfTest()
            }.value
            state = .completed("Synthetic containment self-test passed. It grants no admission authority.")
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    func prepareGenerationPlan(operation: String, generationID: String? = nil,
                               reason: String? = nil) async -> HarnessGenerationPlan? {
        state = .running("Creating an exact expiring Research plan…")
        do {
            let plan = try await Task.detached { [client] in
                try client.planHarnessGeneration(operation: operation,
                                                 generationID: generationID, reason: reason)
            }.value
            state = .completed("Exact plan created for review. No protected state changed.")
            return plan
        } catch {
            state = .rejected(error.localizedDescription)
            return nil
        }
    }

    func authorizeGenerationPlan(_ plan: HarnessGenerationPlan) async {
        state = .running("Waiting for Touch ID and applying the exact reviewed plan…")
        do {
            lastGenerationResult = try await Task.detached { [client] in
                try client.authorizeHarnessGeneration(plan)
            }.value
            status = try await Task.detached { [client] in try client.harnessStatus() }.value
            state = .completed("Protected harness \(plan.operation) completed and the boundary was verified.")
        } catch {
            state = .rejected(error.localizedDescription)
        }
    }

    private func notifyVerifiedMetadata(sequence: Int) async {
        let content = UNMutableNotificationContent()
        content.title = "Harness release metadata verified"
        content.body = "Signed metadata sequence \(sequence) is ready for review. SecureSandbox did not download or install anything."
        let request = UNNotificationRequest(
            identifier: "secure-sandbox-harness-metadata-\(sequence)", content: content, trigger: nil
        )
        try? await UNUserNotificationCenter.current().add(request)
    }
}
