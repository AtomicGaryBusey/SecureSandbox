#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import update_client_fingerprints as updater


class UpdateClientFingerprintsTests(unittest.TestCase):
    def test_update_preserves_metadata_and_fsyncs_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.json"
            path.write_text(json.dumps({"allowed_client_sha256": ["a" * 64]}), encoding="utf-8")
            path.chmod(0o640)
            with mock.patch.object(updater.os, "fsync", wraps=os.fsync) as synced:
                updater.update(str(path), "b" * 64, True)
            self.assertEqual(json.loads(path.read_text())["allowed_client_sha256"], ["a" * 64, "b" * 64])
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertGreaterEqual(synced.call_count, 2)


if __name__ == "__main__":
    unittest.main()
