#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "scripts/native-vendor-stack-config.py"
SPEC = importlib.util.spec_from_file_location("native_vendor_stack_config", PATH)
assert SPEC is not None and SPEC.loader is not None
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)


class NativeVendorStackConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.catalog = self.root / "native-vendor-stacks.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def example(self) -> dict:
        return json.loads(CONFIG.EXAMPLE.read_bytes())

    def test_missing_operator_catalog_returns_non_authorizing_example(self) -> None:
        result = CONFIG.status(self.catalog, CONFIG.EXAMPLE)
        self.assertEqual(result["source"], "example")
        self.assertEqual(
            {item["readiness"]["status"] for item in result["stacks"]},
            {"configuration-required"},
        )

    def test_stage_round_trips_canonical_private_catalog(self) -> None:
        raw = CONFIG.stacks.canonical_bytes(self.example())
        result = CONFIG.stage(raw, self.catalog, CONFIG.EXAMPLE)
        self.assertEqual(result["source"], "staged")
        self.assertEqual(self.catalog.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.catalog.read_bytes(), raw)

    def test_stage_rejects_cross_vendor_pairing_without_replacing_catalog(self) -> None:
        CONFIG.stage(CONFIG.stacks.canonical_bytes(self.example()), self.catalog, CONFIG.EXAMPLE)
        before = self.catalog.read_bytes()
        hostile = self.example()
        hostile["stacks"][0]["harness"]["harness_id"] = "codex"
        with self.assertRaisesRegex(
            CONFIG.stacks.NativeVendorStackError,
            "pairing_not_admitted",
        ):
            CONFIG.stage(CONFIG.stacks.canonical_bytes(hostile), self.catalog, CONFIG.EXAMPLE)
        self.assertEqual(self.catalog.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
