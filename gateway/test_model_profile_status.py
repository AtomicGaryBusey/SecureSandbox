#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
from pathlib import Path

import model_profile_status


class ModelProfileStatusTests(unittest.TestCase):
    def test_emits_only_bounded_nonsecret_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.json"
            path.write_text(json.dumps({
                "adapter": "anthropic-messages-v1", "mode": "mock",
                "allowed_models": ["model"], "profile_id": "test-profile",
                "profile_sha256": "a" * 64, "upstream_origin": "https://example.test",
                "vendor_id": "test-vendor", "secret": "do-not-emit",
            }))
            path.chmod(0o640)
            result = model_profile_status.status(path, os.getuid())
            self.assertNotIn("secret", result)
            self.assertEqual(result["profile_id"], "test-profile")

    def test_rejects_world_readable_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.json"
            path.write_text("{}")
            path.chmod(0o644)
            with self.assertRaises(PermissionError):
                model_profile_status.status(path, os.getuid())


if __name__ == "__main__":
    unittest.main()
