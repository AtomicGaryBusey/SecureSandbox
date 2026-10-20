import importlib.util
import os
import pwd
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "artifact_collector", os.path.join(os.path.dirname(__file__), "artifact_collector.py")
)
collector = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(collector)


class ArtifactCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        collector.REPORT_DIR = os.path.join(self.temp.name, "reports")
        collector.OUTBOX = os.path.join(self.temp.name, "outbox")
        collector.STATE = os.path.join(self.temp.name, "state", "state.json")
        os.makedirs(collector.REPORT_DIR)
        os.makedirs(collector.OUTBOX)
        os.makedirs(os.path.dirname(collector.STATE))

    def tearDown(self):
        self.temp.cleanup()

    def test_reads_safe_agent_owned_report(self):
        path = os.path.join(collector.REPORT_DIR, "report.md")
        with open(path, "wb") as handle:
            handle.write(b"# Evidence\n")
        with mock.patch.object(pwd, "getpwnam", return_value=mock.Mock(pw_uid=os.getuid())):
            content, signature = collector.read_report("report.md")
        self.assertEqual(content, b"# Evidence\n")
        self.assertEqual(signature[2], len(content))

    def test_rejects_symlink(self):
        target = os.path.join(self.temp.name, "target.md")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("secret")
        os.symlink(target, os.path.join(collector.REPORT_DIR, "report.md"))
        with self.assertRaises(OSError):
            collector.read_report("report.md")

    def test_rejects_non_utf8(self):
        path = os.path.join(collector.REPORT_DIR, "report.md")
        with open(path, "wb") as handle:
            handle.write(b"\xff\xfe")
        with mock.patch.object(pwd, "getpwnam", return_value=mock.Mock(pw_uid=os.getuid())):
            with self.assertRaisesRegex(ValueError, "not_utf8"):
                collector.read_report("report.md")

    def test_name_allowlist(self):
        self.assertRegex("2026-10-15-report.md", collector.NAME_RE)
        self.assertNotRegex("../escape.md", collector.NAME_RE)
        self.assertNotRegex("payload.bin", collector.NAME_RE)


if __name__ == "__main__":
    unittest.main()
