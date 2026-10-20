#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-public-identifiers.py")
SPEC = importlib.util.spec_from_file_location("check_public_identifiers", SCRIPT)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class PublicIdentifierCheckerTests(unittest.TestCase):
    def test_random_uuid_is_rejected_in_python(self):
        findings = checker.inspect_text(
            "example.py",
            'session_id = "' + "0f2c1a09" + "-adce-46fd-b91b-6eb297320dba" + '"\n',
            [],
        )
        self.assertTrue(any("concrete operational UUID" in item for item in findings))

    def test_explicit_synthetic_uuid_is_allowed(self):
        findings = checker.inspect_text(
            "example.py",
            'session_id = "11111111-1111-4111-8111-111111111111"\n',
            [],
        )
        self.assertEqual(findings, [])

    def test_unsupported_blob_classes_fail_closed(self):
        self.assertTrue(checker.inspect_raw("binary.dat", b"a\0b", []))
        self.assertTrue(checker.inspect_raw("legacy.txt", b"\xff", []))
        self.assertTrue(checker.inspect_raw("large.txt", b"a" * (8 * 1024 * 1024 + 1), []))

    def test_invalid_json_and_key_variants_fail_closed(self):
        self.assertTrue(checker.inspect_text("broken.json", "{", []))
        findings = checker.inspect_text(
            "config.json",
            '{"tenantId":"11111111-1111-1111-1111-111111111111"}',
            [],
        )
        self.assertTrue(any("deployment-specific value" in item for item in findings))


if __name__ == "__main__":
    unittest.main()
