#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HarnessLifecycleFoundationSurfaceTests(unittest.TestCase):
    def test_labctl_exposes_only_non_mutating_lifecycle_actions(self) -> None:
        source = (ROOT / "scripts/labctl").read_text(encoding="utf-8")
        self.assertIn("harness {status|check|releases|acquire GENERATION_SHA256|verify GENERATION_SHA256|protected-status|protected-verify|qualify-self-test}", source)
        harness_case = source[source.index("  harness)\n"):source.index("  sources)\n")]
        for forbidden in ("activate", "install", "stage", "rollback", "revoke", "retire"):
            self.assertNotIn(forbidden, harness_case)

    def test_foundation_never_executes_candidate_or_enables_automatic_download(self) -> None:
        source = (ROOT / "shared/harness_lifecycle.py").read_text(encoding="utf-8")
        self.assertIn('"authority": "none"', source)
        self.assertIn('"automatic_download": False', source)
        self.assertNotIn("subprocess.Popen", source)
        self.assertNotIn("os.exec", source)
        self.assertNotIn("chmod(0o755", source)

    def test_all_seven_discrete_implementation_ddds_are_backlogged(self) -> None:
        roadmap = " ".join((ROOT / "docs/TODO.md").read_text(encoding="utf-8").split())
        for title in (
            "Harness Lifecycle Foundation and Host Quarantine",
            "Harness Conformance and Disposable Qualification",
            "Protected Harness Generation Store and Transactional Activation",
            "Harness-Bound Sessions, Leases, and Runtime Migration",
            "Control Center Harness Lifecycle GUI",
            "Protected Harness Lifecycle Authorization Consumer",
            "Disposable-Mac Harness Lifecycle Acceptance",
            "First Exact Claude Generation Admission",
        ):
            self.assertIn(title, roadmap)


if __name__ == "__main__":
    unittest.main()
