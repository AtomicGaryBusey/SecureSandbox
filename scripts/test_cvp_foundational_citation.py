import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = (
    "https://support.claude.com/en/articles/"
    "17317514-agent-containment-best-practices-for-cvp-participants"
)


class CVPFoundationalCitationTests(unittest.TestCase):
    def test_foundation_records_source_and_normative_controls(self):
        text = (ROOT / "docs/ANTHROPIC_CVP_DEFENSE_CONTAINMENT_FOUNDATION.md").read_text()
        self.assertIn(SOURCE_URL, text)
        for control in (
            "Default-deny networking",
            "real API credential outside",
            "at least 30 days",
            "human actively supervising",
            "high-consequence production targets",
        ):
            self.assertIn(control, text)

    def test_foundation_is_cited_by_architecture_and_harness_designs(self):
        for relative in (
            "README.md",
            "docs/DESIGN.md",
            "docs/EXTERNAL_CONTAINMENT_AUDIT_DESIGN.md",
            "docs/HARNESS_LIFECYCLE_VERIFIED_UPGRADE_DESIGN.md",
            "docs/HARNESS_LIFECYCLE_FOUNDATION_HOST_QUARANTINE_DESIGN.md",
            "docs/MULTI_HARNESS_ADMISSION_PLUGIN_ECOSYSTEM_ISOLATION_DESIGN.md",
            "docs/FIRST_PARTY_RESEARCH_HARNESS_FEASIBILITY_DESIGN.md",
            "docs/IMPLEMENTATION.md",
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("ANTHROPIC_CVP_DEFENSE_CONTAINMENT_FOUNDATION.md", text)


if __name__ == "__main__":
    unittest.main()
