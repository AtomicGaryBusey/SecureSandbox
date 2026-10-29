#!/usr/bin/env python3

import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "session_catalog", Path(__file__).with_name("session-catalog.py")
)
catalog = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(catalog)


class SessionCatalogTests(unittest.TestCase):
    session_id = "11111111-1111-4111-8111-111111111111"

    def test_parse_registry_accepts_enriched_transitional_and_legacy_rows(self):
        enriched = (
            f"{self.session_id}\t2000-01-01T00:00:00Z\t2000-01-02T00:00:00Z"
            "\t7\t2\n"
        ).encode()
        self.assertEqual(
            catalog.parse_registry(enriched)[0],
            (self.session_id, "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z", "7", "2"),
        )
        transitional = enriched.rstrip(b"\n") + b"\t176\n"
        self.assertEqual(catalog.parse_registry(transitional), catalog.parse_registry(enriched))
        legacy = f"{self.session_id}\t2000-01-01T00:00:00Z\n".encode()
        self.assertEqual(catalog.parse_registry(legacy)[0][2:], ("unknown",) * 3)

    def test_rejects_untrusted_fields(self):
        with self.assertRaisesRegex(ValueError, "field count"):
            catalog.parse_registry(f"{self.session_id}\tone\ttwo\n".encode())
        with self.assertRaisesRegex(ValueError, "counter"):
            catalog.parse_registry(
                f"{self.session_id}\tunknown\tunknown\t-1\t0\n".encode()
            )

    def test_labels_are_private_atomic_and_do_not_contain_prompt_text_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "labels.json"
            catalog.save_labels(path, {self.session_id: "Bug finding"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(catalog.load_labels(path), {self.session_id: "Bug finding"})
            value = json.loads(path.read_text())
            self.assertEqual(value["schema"], catalog.SCHEMA)

    def test_render_combines_only_explicit_operator_label(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "labels.json"
            run_path = Path(directory) / "runs.json"
            catalog.save_labels(path, {self.session_id: "Bug finding"})
            run_path.write_text(json.dumps({
                "schema": catalog.LEGACY_RUN_SCHEMA,
                "sessions": {self.session_id: {"last_started_at": 1, "runs": 4}},
            }) + "\n", encoding="ascii")
            os.chmod(run_path, 0o600)
            raw = (
                f"{self.session_id}\t2000-01-01T00:00:00Z\t2000-01-02T00:00:00Z"
                "\t7\t2\n"
            ).encode()
            output = io.StringIO()
            with mock.patch.object(catalog.sys, "stdin", mock.Mock(buffer=io.BytesIO(raw))), \
                 redirect_stdout(output):
                self.assertEqual(catalog.render(path, run_path), 0)
            self.assertIn("\t7\t2\t4\tBug finding\n", output.getvalue())

    def test_render_marks_historical_run_count_unknown(self):
        raw = f"{self.session_id}\tunknown\tunknown\t1\t0\n".encode()
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(catalog.sys, "stdin", mock.Mock(buffer=io.BytesIO(raw))), \
             redirect_stdout(output):
            self.assertEqual(catalog.render(
                Path(directory) / "labels.json", Path(directory) / "runs.json"
            ), 0)
        self.assertIn("\t1\t0\tunknown\t-\n", output.getvalue())

    def test_run_catalog_rejects_untrusted_or_malformed_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.json"
            path.write_text(json.dumps({
                "schema": catalog.LEGACY_RUN_SCHEMA,
                "sessions": {self.session_id: {"last_started_at": 1, "runs": 2}},
            }) + "\n", encoding="ascii")
            os.chmod(path, 0o600)
            self.assertEqual(catalog.load_run_counts(path), {self.session_id: 2})
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                catalog.load_run_counts(path)

    def test_host_controller_records_concurrent_runs_atomically(self):
        controller = Path(__file__).with_name("claude-run-controller.sh").read_text()
        marker = "/usr/bin/python3 -I - \"$state_root/session-runs.json\" \"$session_binding_id\" \"$run_id\" <<'PY'\n"
        embedded = controller.split(marker, 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "controller-state"
            parent.mkdir(mode=0o700)
            path = parent / "session-runs.json"
            processes = [
                subprocess.Popen(
                    ["/usr/bin/python3", "-I", "-", str(path), self.session_id,
                     f"{index + 1:08x}-1111-4111-8111-111111111111"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for index in range(8)
            ]
            for process in processes:
                _, stderr = process.communicate(embedded, timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(catalog.load_run_counts(path), {self.session_id: 8})
            self.assertEqual(len(catalog.session_runs(path, self.session_id)["run_ids"]), 8)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_session_runs_preserve_legacy_count_without_invented_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.json"
            path.write_text(json.dumps({"schema": catalog.LEGACY_RUN_SCHEMA,
                                        "sessions": {self.session_id: {"runs": 3, "last_started_at": 1}}}))
            os.chmod(path, 0o600)
            result = catalog.session_runs(path, self.session_id)
            self.assertEqual(result["total_runs"], 3)
            self.assertEqual(result["run_ids"], [])

    def test_session_runs_read_mixed_v2_catalog_without_invented_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.json"
            path.write_text(json.dumps({"schema": catalog.RUN_SCHEMA,
                                        "sessions": {self.session_id: {"runs": 3, "last_started_at": 1}}}))
            os.chmod(path, 0o600)
            result = catalog.session_runs(path, self.session_id)
            self.assertEqual(result["total_runs"], 3)
            self.assertEqual(result["run_ids"], [])

    def test_new_run_migrates_legacy_count_and_links_only_new_run(self):
        controller = Path(__file__).with_name("claude-run-controller.sh").read_text()
        marker = "/usr/bin/python3 -I - \"$state_root/session-runs.json\" \"$session_binding_id\" \"$run_id\" <<'PY'\n"
        embedded = controller.split(marker, 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "state"
            parent.mkdir(mode=0o700)
            path = parent / "session-runs.json"
            path.write_text(json.dumps({"schema": catalog.LEGACY_RUN_SCHEMA,
                                        "sessions": {self.session_id: {"runs": 4, "last_started_at": 1}}}))
            os.chmod(path, 0o600)
            run_id = "22222222-2222-4222-8222-222222222222"
            process = subprocess.run(["/usr/bin/python3", "-I", "-", str(path), self.session_id, run_id],
                                     input=embedded, text=True, capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(catalog.session_runs(path, self.session_id)["total_runs"], 5)
            self.assertEqual(catalog.session_runs(path, self.session_id)["run_ids"], [run_id])

    def test_new_run_normalizes_older_records_in_v2_catalog(self):
        controller = Path(__file__).with_name("claude-run-controller.sh").read_text()
        marker = "/usr/bin/python3 -I - \"$state_root/session-runs.json\" \"$session_binding_id\" \"$run_id\" <<'PY'\n"
        embedded = controller.split(marker, 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "state"
            parent.mkdir(mode=0o700)
            path = parent / "session-runs.json"
            path.write_text(json.dumps({"schema": catalog.RUN_SCHEMA,
                                        "sessions": {self.session_id: {"runs": 4, "last_started_at": 1}}}))
            os.chmod(path, 0o600)
            run_id = "22222222-2222-4222-8222-222222222222"
            process = subprocess.run(["/usr/bin/python3", "-I", "-", str(path), self.session_id, run_id],
                                     input=embedded, text=True, capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(catalog.session_runs(path, self.session_id)["total_runs"], 5)
            self.assertEqual(catalog.session_runs(path, self.session_id)["run_ids"], [run_id])

    def test_label_validation_blocks_control_characters_and_oversize_values(self):
        with self.assertRaises(ValueError):
            catalog.validate_label(" bad")
        with self.assertRaises(ValueError):
            catalog.validate_label("bad\tlabel")
        with self.assertRaises(ValueError):
            catalog.validate_label("x" * (catalog.MAX_LABEL_BYTES + 1))

    def test_load_rejects_world_readable_or_linked_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.json"
            path.write_text('{"labels":{},"schema":"secure-sandbox-session-labels-v1"}\n')
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                catalog.load_labels(path)
            path.unlink()
            target = Path(directory) / "target"
            target.write_text("{}")
            path.symlink_to(target)
            with self.assertRaises(PermissionError):
                catalog.load_labels(path)

    def test_catalog_count_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "too many"):
                catalog.save_labels(
                    Path(directory) / "labels.json",
                    {f"00000000-0000-4000-8000-{index:012d}": "x" for index in range(10_001)},
                )


if __name__ == "__main__":
    unittest.main()
