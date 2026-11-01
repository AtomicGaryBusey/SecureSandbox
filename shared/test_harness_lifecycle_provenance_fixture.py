#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness_lifecycle_provenance_fixture import (
    EXPECTED_ERRORS,
    PROVENANCE_CASES,
    ProvenanceFixture,
    ProvenanceFixtureError,
)


class ProvenanceFixtureTests(unittest.TestCase):
    def test_all_fixed_provenance_cases_have_real_expected_results(self) -> None:
        self.assertEqual(len(PROVENANCE_CASES), 16)
        for case_id in sorted(PROVENANCE_CASES):
            with self.subTest(case_id=case_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                root.chmod(0o700)
                result = ProvenanceFixture(root, now=2_000_000_000).run(case_id)
                if case_id.startswith("reject-"):
                    self.assertEqual(result["status"], "rejected")
                    self.assertEqual(result["observed_error"], EXPECTED_ERRORS[case_id])
                    self.assertEqual(
                        result["protected_state_before_sha256"],
                        result["protected_state_after_sha256"],
                    )
                else:
                    self.assertEqual(result["status"], "verified")
                    self.assertIsInstance(result["result"], dict)
                self.assertEqual(result["candidate_authority"], "none")
                self.assertFalse(result["production_material_used"])

    def test_unknown_case_rejects_without_creating_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            fixture = ProvenanceFixture(root, now=2_000_000_000)
            with self.assertRaisesRegex(ProvenanceFixtureError, "case_invalid"):
                fixture.run("not-a-case")


if __name__ == "__main__":
    unittest.main()
