import Observation

@MainActor @Observable
final class RecoveryWorkflowState {
    var preflight: BackupPreflight?
    var preflightError: String?
    var checking = false

    var snapshotDetail: SnapshotPolicyResult?
    var snapshotError: String?
    var checkingSnapshots = false
    var snapshotPreview: SnapshotPreview?
    var snapshotPreviewError: String?
    var checkingSnapshotPreview = false
    var applyingSnapshots = false
    var snapshotApplyResult: SnapshotApplyResult?

    var backupPlan: BackupPlan?
    var backupStatus: BackupOperationStatus?
    var backupError: String?
    var planningBackup = false
    var submittingBackup = false
    var monitorVersion = 0

    var backupInventory: BackupInventory?
    var restorePreview: RestorePreview?
    var restoreError: String?
    var readingBackups = false
    var verifyingBackup = false
    var restorePlan: RestorePlan?
    var restoreStatus: RestoreOperationStatus?
    var planningRestore = false
    var submittingRestore = false
    var recoveringRestore = false
    var restoreMonitorVersion = 0

    var retirement: RestoreRetirement?
    var checkingRetirement = false
    var submittingRetirement = false
    var retirementError: String?
}
