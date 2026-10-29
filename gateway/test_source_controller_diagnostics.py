import importlib.util
import unittest
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


if __name__ == "__main__":
    unittest.main()
