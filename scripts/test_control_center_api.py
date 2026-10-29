import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "control_center_api", Path(__file__).with_name("control-center-api.py")
)
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


class CatalogTests(unittest.TestCase):
    def test_session_catalog_preserves_content_free_fields(self):
        raw = (
            "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL\n"
            "11111111-1111-1111-1111-111111111111\t2026-10-28T01:00:00Z\t"
            "2026-10-28T02:00:00Z\t2\t0\t1\tExample\n"
        )
        with patch.object(API, "run_labctl", return_value=raw):
            result = API.catalog("sessions")
        self.assertEqual(result[0]["label"], "Example")
        self.assertEqual(result[0]["id"], "11111111-1111-1111-1111-111111111111")

    def test_session_catalog_rejects_extra_fields(self):
        raw = "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL\n" + "x\t" * 7
        with patch.object(API, "run_labctl", return_value=raw):
            with self.assertRaises(ValueError):
                API.catalog("sessions")

    def test_source_catalog_rejects_invalid_commit(self):
        raw = "2026-10-28T01:00:00Z\t11111111-1111-1111-1111-111111111111\towner/repo\tbad\tpath\n"
        with patch.object(API, "run_labctl", return_value=raw):
            with self.assertRaises(ValueError):
                API.catalog("sources")

    def test_status_requires_versioned_record(self):
        with patch.object(API, "run_labctl", return_value='{"schema":"wrong"}'):
            with self.assertRaises(ValueError):
                API.catalog("overview")

    def test_github_url_rejects_credentials_query_and_subpaths(self):
        for url in (
            "https://github.com/owner/repo?x=1",
            "https://github.com/owner/repo/tree/main",
            "http://github.com/owner/repo",
            "https://github.com:443/owner/repo",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                API.normalize_github_url(url)
        self.assertEqual(API.normalize_github_url("https://github.com/owner/repo"), "owner/repo")

    def test_plan_binds_exact_repository_and_ref(self):
        raw = (
            "Plan:       11111111-1111-4111-8111-111111111111\n"
            "Repository: owner/repo\nRequested:  main\n"
            "Commit:     " + "a" * 40 + "\nExpires:    2026-10-28T02:00:00Z\n"
        )
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.plan_source("https://github.com/owner/repo", "main")
        command.assert_called_once_with("source", "plan", "owner/repo", "main")
        self.assertEqual(plan["resolved_commit"], "a" * 40)

    def test_label_is_bounded_and_identity_checked(self):
        session_id = "11111111-1111-1111-1111-111111111111"
        with patch.object(API, "run_labctl", return_value=f"labeled\t{session_id}\tResearch\n") as command:
            result = API.label_session(session_id, "Research")
        self.assertEqual(result, {"session_id": session_id, "label": "Research"})
        command.assert_called_once_with("session", "label", session_id, "Research")
        for bad in ("", " leading", "x" * 121, "has\nnewline"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                API.label_session(session_id, bad)


if __name__ == "__main__":
    unittest.main()
