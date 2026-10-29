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


if __name__ == "__main__":
    unittest.main()
