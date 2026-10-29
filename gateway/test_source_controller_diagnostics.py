import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "source_controller", Path(__file__).with_name("source_controller.py")
)
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


class FetcherDiagnosticsTests(unittest.TestCase):
    def test_stable_error_code_survives(self):
        result = SimpleNamespace(returncode=1, stdout=b"", stderr=b"traceback\nRuntimeError: github_status_403\n")
        with patch.object(CONTROLLER.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "^github_status_403$"):
                CONTROLLER.run_fetcher(["resolve", "owner/repo", "main"])

    def test_untrusted_error_details_are_suppressed(self):
        result = SimpleNamespace(returncode=1, stdout=b"", stderr=b"ValueError: private path /secret\n")
        with patch.object(CONTROLLER.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "^fetcher_failed$"):
                CONTROLLER.run_fetcher(["resolve", "owner/repo", "main"])

    def test_status_returns_bounded_completed_identity(self):
        plan_id = "11111111-1111-4111-8111-111111111111"
        value = {"schema": "secure-sandbox-source-plan-v1", "plan_id": plan_id,
                 "repository": "owner/repo", "requested_ref": "main",
                 "resolved_commit": "a" * 40, "expires_at": "2026-10-28T02:00:00Z",
                 "state": "completed", "source_id": "22222222-2222-4222-8222-222222222222",
                 "private_path": "/secret"}
        stream = io.StringIO()
        with patch.object(CONTROLLER, "load_plan", return_value=value), redirect_stdout(stream):
            CONTROLLER.status_plan(plan_id)
        result = json.loads(stream.getvalue())
        self.assertEqual(result["source_id"], value["source_id"])
        self.assertNotIn("private_path", result)


if __name__ == "__main__":
    unittest.main()
