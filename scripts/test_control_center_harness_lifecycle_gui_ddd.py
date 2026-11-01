#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ControlCenterHarnessLifecycleGUIDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.design = (ROOT / "docs/CONTROL_CENTER_HARNESS_LIFECYCLE_GUI_DESIGN.md").read_text()
        cls.todo = (ROOT / "docs/TODO.md").read_text()
        cls.view = (ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Views/HarnessSettingsView.swift").read_text()
        cls.store = (ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Services/HarnessStore.swift").read_text()
        cls.client = (ROOT / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Services/CatalogClient.swift").read_text()
        cls.bridge = (ROOT / "scripts/control-center-api.py").read_text()

    def test_automatic_path_is_metadata_only(self) -> None:
        self.assertIn("fetches the same bounded metadata as the manual", self.design)
        self.assertIn('bool(forKey: "automaticHarnessMetadataChecks")', self.store)
        automatic = self.store[self.store.index("func automaticCheckIfDue"):self.store.index("func requestNotificationPermission")]
        self.assertIn("checkMetadata()", automatic)
        for forbidden in ("acquire(", "verify(", "runQualification", "activate", "install"):
            self.assertNotIn(forbidden, automatic)

    def test_manual_candidate_actions_are_confirmed_and_non_admitting(self) -> None:
        self.assertIn("Download exact candidate?", self.view)
        self.assertIn("Reverify quarantined candidate?", self.view)
        self.assertIn("Run synthetic containment self-test?", self.view)
        self.assertIn("not_admitted_not_executable", self.client)
        self.assertIn('value.get("authority") != "none"', self.bridge)

    def test_protected_mutations_are_not_faked(self) -> None:
        self.assertIn(".disabled(true)", self.view)
        self.assertIn("no password fallback", self.view)
        self.assertIn('"activate": False', self.bridge)
        self.assertIn('"requires_touch_id": True, "password_fallback": False', self.bridge)
        self.assertIn("Protected Harness Lifecycle Authorization Consumer DDD", self.todo)

    def test_release_review_keeps_claims_separate_from_authority(self) -> None:
        self.assertIn("Review Evidence and Compatibility", self.view)
        self.assertIn("authenticated release claims, not SecureSandbox admission", self.view)
        self.assertIn("signed-metadata-only", self.bridge)
        self.assertIn("cannot qualify vendor bytes", self.view)


if __name__ == "__main__":
    unittest.main()
