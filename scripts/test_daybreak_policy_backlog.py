import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DaybreakPolicyBacklogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.roadmap = (ROOT / "docs/TODO.md").read_text()

    def test_daybreak_account_and_tier_hierarchy_is_explicit(self):
        for required in (
            "OpenAI Daybreak Blue Account Policy and Conformance DDD",
            "`daybreak-disabled`",
            "`daybreak-enabled`",
            "select exactly `blue` or `red`",
            "must never imply enrollment or tier",
            "access_programs.cyber=daybreak_blue",
            "OpenAI Daybreak Red Compatibility DDD",
            "access_programs.cyber=daybreak_red",
        ):
            self.assertIn(required, self.roadmap)

    def test_primary_sources_and_physical_key_ddd_are_retained(self):
        for required in (
            "expanding-daybreak-as-the-cyber-defense-window-narrows",
            "20001258-openai-daybreak-trusted-access-for-cyber-overview",
            "Physical FIDO2 Security Key and Human-Origin Authorization DDD",
            "YubiKey",
            "Vendor enrollment evidence must",
            "canonical operation digest",
            "Touch ID plus key composition",
        ):
            self.assertIn(required, self.roadmap)


if __name__ == "__main__":
    unittest.main()
