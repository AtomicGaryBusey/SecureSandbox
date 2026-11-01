#!/usr/bin/env python3
"""Source-level acceptance for protected harness generations."""

from __future__ import annotations

import unittest
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parent.parent


class HarnessGenerationStoreDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = (ROOT / "docs/PROTECTED_HARNESS_GENERATION_STORE_DESIGN.md").read_text()
        cls.store = (ROOT / "shared/harness_generation_store.py").read_text()
        cls.cli = (ROOT / "scripts/harness-generation.py").read_text()
        cls.watchdog = (ROOT / "research/run_lease_watchdog.py").read_text()

    def test_design_preserves_non_admission_and_separate_future_work(self):
        for phrase in (
            "fixture_qualified_not_admitted", "No vendor generation is admitted",
            "Harness-Bound Sessions, Leases, and Runtime Migration",
            "Control Center Harness Lifecycle GUI",
        ):
            self.assertIn(phrase, self.design)

    def test_store_has_exact_touchid_and_transaction_bindings(self):
        for phrase in (
            "secure-sandbox-harness-touchid-authorization-v1",
            '"method"] != "touch-id"', '"password_fallback"] is not False',
            "WorkflowStore", "authorization_sha256", "plan_sha256",
        ):
            self.assertIn(phrase, self.store)

    def test_store_has_immutable_catalog_floor_and_recovery(self):
        for phrase in (
            "secure-sandbox-harness-catalog-v1",
            "secure-sandbox-harness-admission-floor-v1",
            "highest_release_sequence", "restored_predecessor",
            "release_catalog_mismatch", 'os.chmod(temporary, 0o555)',
        ):
            self.assertIn(phrase, self.store)

    def test_synthetic_fixture_cannot_be_admission_evidence(self):
        self.assertIn('value["synthetic"] is not False', self.store)
        self.assertIn('value["authority"] != "qualification-evidence-only"', self.store)
        self.assertIn("synthetic fixture report is categorically rejected", self.design)

    def test_read_only_cli_has_no_mutation_command(self):
        help_text = __import__("subprocess").run(
            ["python3", str(ROOT / "scripts/harness-generation.py"), "--help"],
            text=True, capture_output=True, check=True,
        ).stdout
        self.assertIn("status", help_text)
        self.assertIn("verify-boundary", help_text)
        for forbidden in ("activate", "rollback", "retire", "revoke", "stage", "install"):
            self.assertNotIn(forbidden, help_text)
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            state = Path(directory) / "state"
            result = __import__("subprocess").run(
                ["python3", str(ROOT / "scripts/harness-generation.py"),
                 "--release-root", str(release), "--state-root", str(state), "status"],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(release.exists())
            self.assertFalse(state.exists())

    def test_run_admission_observes_activation_fence(self):
        self.assertIn("HARNESS_ACTIVATION_FENCE", self.watchdog)
        self.assertIn("or HARNESS_ACTIVATION_FENCE.exists()", self.watchdog)


if __name__ == "__main__":
    unittest.main()
