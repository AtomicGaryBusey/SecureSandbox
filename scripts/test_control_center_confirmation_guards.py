#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VIEWS = ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Views"


class ControlCenterConfirmationGuardTests(unittest.TestCase):
    def view(self, name: str) -> str:
        return (VIEWS / name).read_text(encoding="utf-8")

    def test_model_profile_removal_is_confirmed_and_identity_bound(self):
        source = self.view("ModelProfilesSettingsView.swift")
        self.assertIn('Button(role: .destructive) { requestProfileDeletion() }', source)
        self.assertIn('.alert("Remove Model Profile?"', source)
        self.assertIn('deleteProfile(profile.profileID)', source)
        self.assertIn('Button("Cancel", role: .cancel)', source)
        self.assertNotIn('Button { deleteSelected() }', source)

    def test_model_reload_confirms_only_when_draft_changed(self):
        source = self.view("ModelProfilesSettingsView.swift")
        self.assertIn('private var hasUnsavedChanges: Bool', source)
        self.assertIn('catalog != persistedCatalog', source)
        self.assertIn('.alert("Discard Unsaved Model Changes?"', source)
        self.assertIn('Button("Discard and Reload", role: .destructive)', source)

    def test_persisted_label_removal_is_confirmed(self):
        source = self.view("SessionLabelSheet.swift")
        self.assertIn('Button("Remove Label", role: .destructive) { confirmingRemoval = true }', source)
        self.assertIn('.alert("Remove Session Label?"', source)
        self.assertIn('Button("Remove Label", role: .destructive) { Task { await remove() } }', source)

    def test_unsubmitted_plan_handles_are_not_forgotten_directly(self):
        source = self.view("SourcePlanSheet.swift")
        recovery = self.view("RecoveryView.swift")
        self.assertIn('.alert("Forget Unsubmitted Source Plan?"', source)
        self.assertIn('Button("Forget Plan", role: .destructive) { forgetPlan() }', source)
        self.assertIn('confirmForgetBackup = true', recovery)
        self.assertIn('confirmForgetRestore = true', recovery)
        self.assertIn('Button("Forget Backup Plan", role: .destructive) { forgetBackupPlan() }', recovery)
        self.assertIn('Button("Forget Restore Plan", role: .destructive) { forgetRestorePlan() }', recovery)


if __name__ == "__main__":
    unittest.main()
