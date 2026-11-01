#!/usr/bin/env python3
"""Source-level regression contract for the harness lifecycle DDD."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/HARNESS_LIFECYCLE_VERIFIED_UPGRADE_DESIGN.md"


class HarnessLifecycleDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.design = DESIGN.read_text(encoding="utf-8")
        cls.todo = (ROOT / "docs/TODO.md").read_text(encoding="utf-8")
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.multi = (
            ROOT / "docs/MULTI_HARNESS_ADMISSION_PLUGIN_ECOSYSTEM_ISOLATION_DESIGN.md"
        ).read_text(encoding="utf-8")
        cls.first_party = (
            ROOT / "docs/FIRST_PARTY_RESEARCH_HARNESS_FEASIBILITY_DESIGN.md"
        ).read_text(encoding="utf-8")

    def test_status_and_scope_are_explicit(self) -> None:
        self.assertIn(
            "Status: research and design complete; implementation and live admission not authorized",
            self.design,
        )
        self.assertIn("does not admit a new Claude", self.design)
        self.assertIn("legacy bootstrap", self.design)

    def test_automatic_behavior_is_metadata_only(self) -> None:
        self.assertIn("There is no automatic harness update", self.design)
        self.assertIn("can invoke only `Check`", self.design)
        self.assertIn("There is deliberately no auto-download or", self.design)
        self.assertIn("no `Update`, `Update All`, `Automatically download`", self.design)

    def test_fail_closed_provenance_has_no_bypass(self) -> None:
        self.assertIn("carrier, not the final", self.design)
        self.assertIn("fails closed with no bypass", self.design)
        self.assertIn("No GUI, CLI,", self.design)
        self.assertIn("Updating can remain bricked", self.design)
        self.assertIn("secure-sandbox-harness-release-manifest-v1", self.design)

    def test_activation_and_session_generation_are_exact(self) -> None:
        self.assertIn("five-minute activation plan", self.design)
        self.assertIn("password fallback is forbidden", self.design)
        self.assertIn("`harness_generation_id`", self.design)
        self.assertIn("resumed session", self.design)
        self.assertIn("never inherits the current selector", self.design)
        self.assertIn("cannot invoke", self.design)

    def test_rollback_revocation_and_recovery_are_bounded(self) -> None:
        self.assertIn("explicit rollback is a new exact Touch ID transaction", self.design)
        self.assertIn("remote notice", self.design)
        self.assertIn("cannot remotely kill", self.design)
        self.assertIn("Revocation is monotonic and fail closed", self.design)
        self.assertIn("only three valid outcomes", self.design)
        self.assertIn("Repeated exact recovery is idempotent", self.design)
        self.assertIn("generic transaction is still `authorized`", self.design)

    def test_roadmap_and_adjacent_designs_are_reconciled(self) -> None:
        self.assertIn("Harness lifecycle and verified upgrade", self.readme)
        self.assertIn("Preserve the completed Harness Lifecycle", self.todo)
        self.assertNotIn("Complete a Harness Lifecycle and Verified Upgrade DDD", self.todo)
        self.assertIn("completed research/design DDD", self.multi)
        self.assertIn("completed research/design DDD", self.first_party)


if __name__ == "__main__":
    unittest.main()
