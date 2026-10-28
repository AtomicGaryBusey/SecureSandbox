#!/usr/bin/env python3

import importlib.util
import io
import json
import os
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

    def test_parse_registry_accepts_enriched_and_legacy_rows(self):
        enriched = (
            f"{self.session_id}\t2000-01-01T00:00:00Z\t2000-01-02T00:00:00Z"
            "\t7\t2\t3\n"
        ).encode()
        self.assertEqual(
            catalog.parse_registry(enriched)[0],
            (self.session_id, "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z", "7", "2", "3"),
        )
        legacy = f"{self.session_id}\t2000-01-01T00:00:00Z\n".encode()
        self.assertEqual(catalog.parse_registry(legacy)[0][2:], ("unknown",) * 4)

    def test_rejects_untrusted_fields(self):
        with self.assertRaisesRegex(ValueError, "field count"):
            catalog.parse_registry(f"{self.session_id}\tone\ttwo\n".encode())
        with self.assertRaisesRegex(ValueError, "counter"):
            catalog.parse_registry(
                f"{self.session_id}\tunknown\tunknown\t-1\t0\t0\n".encode()
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
            catalog.save_labels(path, {self.session_id: "Bug finding"})
            raw = (
                f"{self.session_id}\t2000-01-01T00:00:00Z\t2000-01-02T00:00:00Z"
                "\t7\t2\t3\n"
            ).encode()
            output = io.StringIO()
            with mock.patch.object(catalog.sys, "stdin", mock.Mock(buffer=io.BytesIO(raw))), \
                 redirect_stdout(output):
                self.assertEqual(catalog.render(path), 0)
            self.assertIn("\t7\t2\t3\tBug finding\n", output.getvalue())

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
