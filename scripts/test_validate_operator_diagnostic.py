#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-operator-diagnostic.py")
SPEC = importlib.util.spec_from_file_location("validate_operator_diagnostic", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class OperatorDiagnosticValidationTests(unittest.TestCase):
    def record(self):
        return {
            "action":"start_new_request_when_ready",
            "code":"operator_cancelled",
            "operation":"authorization-probe",
            "outcome":"cancelled",
            "phase":"ceremony",
            "request_id":"12345678-1234-4123-8123-123456789abc",
            "retry":"new-request",
            "schema":VALIDATOR.SCHEMA,
        }

    def validate(self, path):
        return VALIDATOR.validate(
            path, "operator_cancelled", "authorization-probe", "cancelled",
            "new-request", "start_new_request_when_ready",
        )

    def test_accepts_one_terminal_record_after_human_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr"
            path.write_text(
                "SecureSandbox cancellation test\n\n"
                + json.dumps(self.record(), separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(self.validate(path)["code"], "operator_cancelled")

    def test_rejects_duplicates_extra_fields_and_nonterminal_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr"
            encoded = json.dumps(self.record(), separators=(",", ":"), sort_keys=True)
            for content in (
                encoded + "\n" + encoded + "\n",
                json.dumps({**self.record(), "purpose":"secret"}) + "\n",
                encoded + "\ntrailing\n",
            ):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(VALIDATOR.DiagnosticError):
                    self.validate(path)


if __name__ == "__main__":
    unittest.main()
