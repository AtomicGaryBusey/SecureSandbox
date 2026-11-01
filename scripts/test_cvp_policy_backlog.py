import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CVPPolicyBacklogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.roadmap = (ROOT / "docs/TODO.md").read_text()

    def test_cvp_is_account_scoped_not_provider_inferred(self):
        for required in (
            "`cvp-disabled`",
            "`cvp-enabled`",
            "`defense`",
            "`red-team`",
            "`specialized`",
            "must not activate CVP policy",
        ):
            self.assertIn(required, self.roadmap)

    def test_wif_source_and_fail_closed_controls_are_retained(self):
        for required in (
            "workload-identity-federation",
            "service-account, federation-issuer, and",
            "fresh single-use `jti`",
            "`ANTHROPIC_API_KEY`",
            "precedence-shadowing",
            "prohibit rollback to it after",
        ):
            self.assertIn(required, self.roadmap)


if __name__ == "__main__":
    unittest.main()
