#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DisposableMacHarnessLifecycleAcceptanceDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = (ROOT / "docs/DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_DESIGN.md").read_text()
        cls.evidence = (ROOT / "docs/DISPOSABLE_MAC_HARNESS_LIFECYCLE_ACCEPTANCE_EVIDENCE.md").read_text()
        cls.contract = (ROOT / "shared/harness_lifecycle_acceptance.py").read_text()
        cls.store = (ROOT / "shared/harness_generation_store.py").read_text()
        cls.cli = (ROOT / "scripts/harness-lifecycle-acceptance.py").read_text()
        cls.enrollment = (ROOT / "scripts/enroll-disposable-mac-harness-lifecycle.py").read_text()

    def test_status_is_honest_about_pending_physical_acceptance(self):
        for phrase in (
            "physical\ndisposable-Mac execution pending",
            "no\nacceptance verdict has been issued",
            "must not be relabeled as physical",
        ):
            self.assertIn(phrase, self.design + self.evidence)

    def test_campaign_has_no_admission_or_candidate_authority(self):
        for phrase in (
            '"authority": "acceptance-evidence-only"',
            '"candidate_authority": "none"',
            '"production_material_used": False',
            '"candidate_statement_used"] is not False',
        ):
            self.assertIn(phrase, self.contract)

    def test_cli_has_only_evidence_operations(self):
        for command in ("catalog", "initialize", "verify-campaign", "assemble", "verify-export"):
            self.assertIn(f'"{command}"', self.cli)
        for forbidden in ('add_parser("activate")', 'add_parser("rollback")',
                          'add_parser("revoke")', 'add_parser("poweroff")'):
            self.assertNotIn(forbidden, self.cli)

    def test_enrollment_does_not_read_or_export_secret_values(self):
        self.assertIn("PROVIDER_ENVIRONMENT", self.enrollment)
        self.assertIn("op-service-account-agents", self.enrollment)
        self.assertNotIn("op-agents read", self.enrollment)
        self.assertIn("hashlib.sha256(material).hexdigest()", self.enrollment)

    def test_journal_precedes_fence_and_checkpoints_are_not_runtime_inputs(self):
        journal = self.store.index('journal["phase"] = "fenced"')
        fence = self.store.index('self._write_fence(plan)', journal - 1200)
        prepared = self.store.rindex('atomic_write(journal_path, canonical_bytes(journal))',
                                     journal - 1200, fence)
        self.assertLess(prepared, fence)
        self.assertNotIn("--checkpoint", self.store)
        self.assertNotIn("os.environ", self.store)
        for checkpoint in (
            "journal-prepared", "fenced", "workflow-authorized", "release-published",
            "catalog-written", "floor-written", "selector-written", "health-passed",
            "workflow-activated", "workflow-verified", "workflow-committed",
            "fence-removed", "journal-removed",
        ):
            self.assertIn(f'self.checkpoint("{checkpoint}")', self.store)


if __name__ == "__main__":
    unittest.main()
