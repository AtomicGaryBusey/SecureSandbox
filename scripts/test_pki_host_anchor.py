#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


path = Path(__file__).with_name("pki-host-anchor.py")
spec = importlib.util.spec_from_file_location("pki_host_anchor", path)
pki_host_anchor = importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys
sys.modules["pki_host_anchor"] = pki_host_anchor
spec.loader.exec_module(pki_host_anchor)


class HostAnchorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "anchor"

    def tearDown(self):
        self.temporary.cleanup()

    def commit(self, generation, digest, expected=""):
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "pending-generation.json").write_text("pending")
        def lock(_root):
            return os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        with mock.patch("pki_host_anchor.prepare_root", side_effect=lock), \
             mock.patch("pki_host_anchor.os.fchown"), \
             mock.patch("pki_host_anchor.read_pending", return_value=pki_host_anchor.pending_value(generation)):
            return pki_host_anchor.commit(self.root, generation, digest, expected)

    def test_anchor_advances_only_from_expected_generation(self):
        first = str(uuid.uuid4())
        second = str(uuid.uuid4())
        value = self.commit(first, "a" * 64)
        self.assertEqual(value["generation_id"], first)
        with mock.patch("pki_host_anchor.prepare_root", side_effect=lambda _root: os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o600)), \
             mock.patch("pki_host_anchor.read_anchor", return_value=value), \
             mock.patch("pki_host_anchor.read_pending", return_value=pki_host_anchor.pending_value(second)), \
             mock.patch("pki_host_anchor.os.fchown"):
            with self.assertRaisesRegex(pki_host_anchor.AnchorError, "anchor_expected_current_mismatch"):
                pki_host_anchor.commit(self.root, second, "b" * 64, "")
        # The filesystem test cannot emulate root ownership, so validate the
        # sealed successor record directly.
        successor = pki_host_anchor.seal({
            "schema": 2, "generation_id": second, "manifest_sha256": "b" * 64,
            "committed_at": 1, "previous_generation_id": first,
            "previous_manifest_sha256": "a" * 64,
        })
        self.assertEqual(pki_host_anchor.validate(successor)["previous_generation_id"], first)

    def test_record_tamper_is_detected(self):
        value = pki_host_anchor.seal({
            "schema": 2, "generation_id": str(uuid.uuid4()), "manifest_sha256": "a" * 64,
            "committed_at": 1, "previous_generation_id": "", "previous_manifest_sha256": "",
        })
        value["manifest_sha256"] = "b" * 64
        with self.assertRaisesRegex(pki_host_anchor.AnchorError, "anchor_record_mismatch"):
            pki_host_anchor.validate(value)

    def test_idempotent_commit_clears_crash_left_pending_record(self):
        generation = str(uuid.uuid4())
        self.root.mkdir(parents=True)
        pending = self.root / "pending-generation.json"
        pending.write_text("pending")
        active = pki_host_anchor.seal({
            "schema": 2, "generation_id": generation, "manifest_sha256": "a" * 64,
            "committed_at": 1, "previous_generation_id": "", "previous_manifest_sha256": "",
        })
        (self.root / "active-generation.json").write_text("active")
        with mock.patch("pki_host_anchor.prepare_root", side_effect=lambda _root: os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o600)), \
             mock.patch("pki_host_anchor.read_pending", return_value=pki_host_anchor.pending_value(generation)), \
             mock.patch("pki_host_anchor.read_anchor", return_value=active), \
             mock.patch("pki_host_anchor.os.fchown"):
            result = pki_host_anchor.commit(self.root, generation, "a" * 64, "")
        self.assertEqual(result, active)
        self.assertFalse(pending.exists())


if __name__ == "__main__":
    unittest.main()
