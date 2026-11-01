import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FairwindPolicyBacklogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.roadmap = (ROOT / "docs/TODO.md").read_text()

    def test_fairwind_hierarchy_and_grants_are_explicit(self):
        for required in (
            "Google Fairwind Account Policy and Conformance DDD",
            "`fairwind-disabled`",
            "`fairwind-enabled`",
            "Do not invent subtiers",
            "separate versioned grant set",
            "must never imply enrollment",
            "deepmind.google/fairwind-program/",
        ):
            self.assertIn(required, self.roadmap)

    def test_governance_and_provider_isolation_are_retained(self):
        for required in (
            "phishing-resistant MFA",
            "access-and-use tracking",
            "no sharing, redistribution, resale, or",
            "zero data retention",
            "do not infer that Fairwind requires a YubiKey specifically",
            "Fairwind-disabled Google profiles or any other provider",
        ):
            self.assertIn(required, self.roadmap)


if __name__ == "__main__":
    unittest.main()
