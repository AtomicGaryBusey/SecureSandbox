#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from research import native_claude_login_channel as channel


OPERATION_ID = "11111111-1111-4111-8111-111111111111"
ROOT = Path(__file__).resolve().parent.parent


class NativeClaudeLoginChannelTests(unittest.TestCase):
    def test_handle_is_exact_root_equivalent_durable_and_one_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            arguments = dict(
                operation_id=OPERATION_ID, plan_sha256="1" * 64,
                authorization_sha256="2" * 64, stack_sha256="3" * 64,
                catalog_sha256="4" * 64, root=root,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid())
            channel._claim_handle(**arguments)
            path = root / f"{OPERATION_ID}.json"
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            raw = path.read_bytes().lower()
            for forbidden in (b"token", b"email", b"url", b"code"):
                self.assertNotIn(forbidden, raw)
            with self.assertRaises(FileExistsError):
                channel._claim_handle(**arguments)

    def test_channel_contract_is_unmodified_no_capture_and_scope_bound(self) -> None:
        source = (ROOT / "research/native_claude_login_channel.py").read_text(
            encoding="utf-8")
        self.assertIn("native_claude_adapter.login_command(executable)", source)
        self.assertIn("relay_opaque_pty", source)
        self.assertIn("start_transient_scope", source)
        self.assertIn("SIGSTOP before any vendor exec", source)
        self.assertIn("scope/UID readback", source)
        self.assertIn("native-harness-supervisor.service", (
            ROOT / "research/native_codex_session_controller.py").read_text(
                encoding="utf-8"))
        self.assertNotIn("logging.", source)
        self.assertNotIn("print(", source)
        self.assertNotIn("auth login --claudeai", source)
        self.assertIn("observe_status", source)
        self.assertIn("write_login_proof", source)


if __name__ == "__main__":
    unittest.main()
