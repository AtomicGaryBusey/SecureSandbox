#!/usr/bin/env python3
from __future__ import annotations

import unittest

from harness_archive_preflight import ArchivePreflightError, validate_ustar
from harness_lifecycle_archive_fixture import (
    ARCHIVE_CASES,
    EXPECTED_ERRORS,
    ArchiveFixtureError,
    archive,
    member,
    run,
)


class HarnessArchivePreflightTests(unittest.TestCase):
    def test_safe_ustar_is_verified_without_extraction_or_execution(self) -> None:
        result = validate_ustar(archive(member("bin/harness", value=b"inert\n")))
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["entry_count"], 1)
        self.assertFalse(result["extracted"])
        self.assertFalse(result["executed"])
        self.assertEqual(result["authority"], "none")

    def test_all_fixed_archive_attacks_reject_without_state_change(self) -> None:
        self.assertEqual(len(ARCHIVE_CASES), 12)
        for case_id in sorted(ARCHIVE_CASES):
            with self.subTest(case_id=case_id):
                result = run(case_id)
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["observed_error"], EXPECTED_ERRORS[case_id])
                self.assertEqual(
                    result["protected_state_before_sha256"],
                    result["protected_state_after_sha256"],
                )
                self.assertFalse(result["extracted"])
                self.assertFalse(result["executed"])
                self.assertEqual(result["candidate_authority"], "none")

    def test_unknown_case_and_malformed_header_fail_closed(self) -> None:
        with self.assertRaisesRegex(ArchiveFixtureError, "case_invalid"):
            run("not-a-case")
        malformed = bytearray(archive(member("safe")))
        malformed[0] ^= 1
        with self.assertRaisesRegex(ArchivePreflightError, "checksum_invalid"):
            validate_ustar(bytes(malformed))


if __name__ == "__main__":
    unittest.main()
