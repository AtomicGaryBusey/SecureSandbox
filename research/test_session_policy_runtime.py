#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from research import session_policy_runtime as policy


class SessionPolicyRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.persona = self.root / "persona.md"
        self.settings = self.root / "settings.json"
        self.mcp = self.root / "mcp.json"
        self.extensions = self.root / "plugins"
        self.persona.write_bytes(b"fixed persona\n")
        self.settings.write_text(
            json.dumps(policy.REQUIRED_EXTENSION_FENCES), encoding="ascii"
        )
        self.mcp.write_text(
            json.dumps({"mcpServers": {"outer": {"command": "/fixed"}}}),
            encoding="ascii",
        )
        for path, mode in ((self.persona, 0o444), (self.settings, 0o644), (self.mcp, 0o644)):
            os.chmod(path, mode)
        self.paths = mock.patch.multiple(
            policy,
            PERSONA=self.persona,
            MANAGED_SETTINGS=self.settings,
            MANAGED_MCP=self.mcp,
            EMPTY_EXTENSION_PATHS=(self.extensions,),
            TRUSTED_UID=os.getuid(),
        )
        self.paths.start()

    def tearDown(self) -> None:
        self.paths.stop()
        self.temporary.cleanup()

    def test_content_free_measurement_is_deterministic(self) -> None:
        first = policy.measure("none")
        second = policy.measure("none")
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], policy.SCHEMA)
        self.assertIsNone(first["source_id"])
        self.assertNotIn("fixed persona", json.dumps(first))

    def test_extension_fence_or_ambient_extension_fails_closed(self) -> None:
        value = dict(policy.REQUIRED_EXTENSION_FENCES)
        value["disableSideloadFlags"] = False
        self.settings.write_text(json.dumps(value), encoding="ascii")
        with self.assertRaisesRegex(policy.SessionPolicyRuntimeError, "extension_fence"):
            policy.measure("none")
        self.settings.write_text(json.dumps(policy.REQUIRED_EXTENSION_FENCES), encoding="ascii")
        self.extensions.mkdir()
        (self.extensions / "untrusted").write_text("x", encoding="ascii")
        with self.assertRaisesRegex(policy.SessionPolicyRuntimeError, "not_empty"):
            policy.measure("none")

    def test_symlink_or_wrong_mode_is_rejected(self) -> None:
        os.chmod(self.persona, 0o644)
        with self.assertRaisesRegex(policy.SessionPolicyRuntimeError, "untrusted"):
            policy.measure("none")

    def test_source_requires_independent_verified_manifest(self) -> None:
        source_id = "11111111-1111-4111-8111-111111111111"
        with mock.patch.dict(
            "sys.modules",
            {
                "source_integrity": mock.Mock(
                    registered_source=lambda _value: {"tree_manifest_sha256": "a" * 64},
                    verify_source=lambda _value, scope: {
                        "overall_status": "match",
                        "registered_tree_manifest_sha256": "a" * 64,
                    },
                )
            },
        ):
            result = policy.measure(source_id)
        self.assertEqual(result["source_id"], source_id)
        self.assertEqual(result["source_manifest_sha256"], "a" * 64)

    def test_changed_source_is_rejected(self) -> None:
        source_id = "11111111-1111-4111-8111-111111111111"
        with mock.patch.dict(
            "sys.modules",
            {
                "source_integrity": mock.Mock(
                    registered_source=lambda _value: {"tree_manifest_sha256": "a" * 64},
                    verify_source=lambda _value, scope: {
                        "overall_status": "changed_or_unverified",
                        "registered_tree_manifest_sha256": "a" * 64,
                    },
                )
            },
        ), self.assertRaisesRegex(policy.SessionPolicyRuntimeError, "source_unverified"):
            policy.measure(source_id)


if __name__ == "__main__":
    unittest.main()
