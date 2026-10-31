#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DESIGN = ROOT / "docs/FIRST_PARTY_RESEARCH_HARNESS_FEASIBILITY_DESIGN.md"


class FirstPartyHarnessFeasibilityDDDTests(unittest.TestCase):
    def test_research_decision_is_complete_but_does_not_authorize_implementation(self):
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn(
            "research complete; hybrid decision accepted; implementation not\n"
            "authorized",
            design,
        )
        self.assertIn("should **not forsake all existing harnesses", design)
        self.assertIn("This DDD does not authorize development", design)

    def test_decision_has_measured_reconsideration_and_build_gates(self):
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn("## 12. Prototype trigger and acceptance thresholds", design)
        self.assertIn("100% pass on the Harness Admission Contract conformance suite", design)
        self.assertIn("blinded corpus of at least\n  30 representative research tasks", design)
        self.assertIn("## 17. Reconsideration conditions", design)

    def test_contract_keeps_sensitive_authority_outside_the_harness(self):
        design = DESIGN.read_text(encoding="utf-8")
        for heading in (
            "### 10.1 Immutable identity",
            "### 10.2 Launch authority",
            "### 10.3 Model boundary",
            "### 10.4 Tool boundary",
            "### 10.5 Session and context boundary",
            "### 10.6 Terminal boundary",
            "### 10.7 Shutdown and recovery",
        ):
            self.assertIn(heading, design)
        self.assertIn("The harness may reach only the Research loopback relay", design)
        self.assertIn("A model request is never approval", design)

    def test_roadmap_records_completed_hybrid_decision(self):
        roadmap = (ROOT / "docs/TODO.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("completed First-Party Research Harness Feasibility DDD", roadmap)
        self.assertNotIn("Complete a First-Party Research Harness Feasibility DDD", roadmap)
        self.assertIn(
            "docs/FIRST_PARTY_RESEARCH_HARNESS_FEASIBILITY_DESIGN.md",
            readme,
        )


if __name__ == "__main__":
    unittest.main()
