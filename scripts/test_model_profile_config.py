#!/usr/bin/env python3

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("model-profile-config.py")
SPEC = importlib.util.spec_from_file_location("model_profile_config", SCRIPT)
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)


class ModelProfileConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.catalog = self.root / "catalog.json"
        self.example = self.root / "example.json"
        source = CONFIG.ROOT / "config/model-profiles.example.json"
        self.example.write_bytes(source.read_bytes())
        os.chmod(self.example, 0o644)
        self.catalog_patch = mock.patch.object(CONFIG, "CATALOG", self.catalog)
        self.example_patch = mock.patch.object(CONFIG, "EXAMPLE", self.example)
        self.catalog_patch.start(); self.example_patch.start()

    def tearDown(self):
        mock.patch.stopall()
        self.temporary.cleanup()

    def test_missing_live_catalog_returns_inert_example(self):
        result = CONFIG.status()
        self.assertEqual(result["source"], "example")
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["profiles"][0]["revision_sha256"]), 64)
        self.assertFalse(self.catalog.exists())

    def test_stage_writes_private_canonical_catalog_and_reads_it_back(self):
        value = json.loads(self.example.read_text())
        result = CONFIG.stage(json.dumps(value).encode())
        self.assertEqual(result["source"], "staged")
        self.assertEqual(self.catalog.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.catalog.read_bytes(), CONFIG.model_profiles.canonical_json(value))

    def test_stage_rejects_unknown_fields_without_changing_existing_catalog(self):
        value = json.loads(self.example.read_text())
        CONFIG.stage(json.dumps(value).encode())
        before = self.catalog.read_bytes()
        value["profiles"][0]["credential"]["value"] = "secret"
        with self.assertRaises(CONFIG.model_profiles.ProfileError):
            CONFIG.stage(json.dumps(value).encode())
        self.assertEqual(self.catalog.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
