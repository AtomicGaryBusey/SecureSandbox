#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/HARNESS_CONFORMANCE_DISPOSABLE_QUALIFICATION_DESIGN.md"


class HarnessConformanceQualificationDDDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.design = DESIGN.read_text(encoding="utf-8")
        cls.todo = (ROOT / "docs/TODO.md").read_text(encoding="utf-8")
        cls.labctl = (ROOT / "scripts/labctl").read_text(encoding="utf-8")
        cls.runner = (ROOT / "shared/harness_qualification.py").read_text(encoding="utf-8")
        cls.adapter = (ROOT / "shared/claude_core_adapter.py").read_text(encoding="utf-8")

    def test_status_and_authority_ceiling_are_explicit(self) -> None:
        self.assertIn("implemented and source-verified for the synthetic fixture", self.design)
        self.assertIn("no vendor\ngeneration qualified or admitted", self.design)
        self.assertIn("`authority: none`", self.design)
        self.assertIn("fixture_qualified_not_admitted", self.design)
        self.assertIn("accepts no\nexecutable path", self.design)

    def test_outer_observation_and_complete_matrix_are_retained(self) -> None:
        self.assertIn("candidate-authored claim has no authority", self.design)
        self.assertIn("thirty ordered cases", self.design)
        self.assertIn("Denial cases must be both exercised", self.design)
        self.assertIn("secure-sandbox-disposable-supervisor-v1", self.runner)
        self.assertIn('"authority": "none"', self.runner)

    def test_claude_adapter_is_narrow_and_non_executing(self) -> None:
        for required in (
            '"/usr/local/bin/claude"',
            '"--restricted"',
            '"DISABLE_UPDATES": "1"',
            '"ANTHROPIC_API_KEY"',
            'raise ClaudeAdapterError("event_unknown")',
        ):
            self.assertIn(required, self.adapter)
        self.assertNotIn("subprocess", self.adapter)

    def test_roadmap_advances_without_expanding_labctl_authority(self) -> None:
        self.assertIn(
            "Preserve and extend the completed Harness Conformance and Disposable",
            self.todo,
        )
        self.assertNotIn("Complete the Harness Conformance and Disposable Qualification DDD", self.todo)
        harness_case = self.labctl[
            self.labctl.index("  harness)\n"):self.labctl.index("  sources)\n")
        ]
        self.assertNotIn("qualify", harness_case)
        self.assertNotIn("activate", harness_case)


if __name__ == "__main__":
    unittest.main()
