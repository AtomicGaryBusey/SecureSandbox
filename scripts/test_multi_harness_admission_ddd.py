#!/usr/bin/env python3
"""Regression checks for the multi-harness admission design decision."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "MULTI_HARNESS_ADMISSION_PLUGIN_ECOSYSTEM_ISOLATION_DESIGN.md"
ROADMAP = ROOT / "docs" / "TODO.md"
README = ROOT / "README.md"
FIRST_PARTY = ROOT / "docs" / "FIRST_PARTY_RESEARCH_HARNESS_FEASIBILITY_DESIGN.md"


class MultiHarnessAdmissionDDDTests(unittest.TestCase):
    def test_design_is_complete_without_authorizing_admission(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn("research and design complete", design)
        self.assertIn("implementation and admission not authorized", design)
        self.assertIn("small, deliberately selected set", design)
        self.assertIn("Every harness begins in **core-only mode**", design)

    def test_marketplaces_and_in_process_extensions_are_not_authority(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn("No marketplaces in Research", design)
        self.assertIn("In-process extension, mod, native library, or dynamic module", design)
        self.assertIn("Native executable hooks are prohibited", design)
        self.assertIn("Vendor approval modes are UX signals only", design)

    def test_cross_harness_profile_and_session_isolation_is_explicit(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn("A session is permanently bound to one harness generation", design)
        self.assertIn("may never expose “call Claude,”", design)
        self.assertIn("Cross-harness migration is not resume", design)
        self.assertIn("There is no wildcard harness, model profile, provider", design)

    def test_admission_has_measurable_fail_closed_gates(self) -> None:
        design = DESIGN.read_text(encoding="utf-8")
        self.assertIn("100% pass on the Harness Admission Contract", design)
        self.assertIn("zero unresolved Critical or High findings", design)
        self.assertIn("complete rejection of every known ambient plugin", design)
        self.assertIn("or operator bypass", design)

    def test_roadmap_and_readme_record_completed_decision(self) -> None:
        roadmap = ROADMAP.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        first_party = FIRST_PARTY.read_text(encoding="utf-8")
        self.assertIn("completed Multi-Harness Admission", roadmap)
        self.assertNotIn("Complete a Multi-Harness Admission", roadmap)
        self.assertIn("MULTI_HARNESS_ADMISSION_PLUGIN_ECOSYSTEM_ISOLATION_DESIGN.md", readme)
        self.assertIn("completed multi-harness DDD's neutral framework", first_party)


if __name__ == "__main__":
    unittest.main()
