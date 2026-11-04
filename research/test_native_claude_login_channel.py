#!/usr/bin/env python3

from __future__ import annotations

import fcntl
import os
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

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
        self.assertIn("expected_runtime_max_usec=runtime_max_usec", source)
        self.assertIn("deadline=deadline", source)
        self.assertIn("native-harness-supervisor.service", (
            ROOT / "research/native_codex_session_controller.py").read_text(
                encoding="utf-8"))
        self.assertNotIn("logging.", source)
        self.assertNotIn("print(", source)
        self.assertNotIn("auth login --claudeai", source)
        self.assertIn("observe_status", source)
        self.assertIn("write_login_proof", source)

    def test_handle_evidence_retention_is_bounded_and_never_evicted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            for index in range(channel.MAX_RETAINED_HANDLES):
                operation_id = str(uuid.UUID(int=index + 1, version=4))
                channel._claim_handle(
                    operation_id=operation_id, plan_sha256="1" * 64,
                    authorization_sha256="2" * 64,
                    stack_sha256="3" * 64, catalog_sha256="4" * 64,
                    root=root, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid())
            retained = sorted(root.glob("*.json"))
            self.assertEqual(len(retained), channel.MAX_RETAINED_HANDLES)
            with self.assertRaisesRegex(
                channel.NativeClaudeLoginError, "handle_retention_limit"):
                channel._claim_handle(
                    operation_id=str(uuid.UUID(
                        int=channel.MAX_RETAINED_HANDLES + 1, version=4)),
                    plan_sha256="1" * 64, authorization_sha256="2" * 64,
                    stack_sha256="3" * 64, catalog_sha256="4" * 64,
                    root=root, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid())
            self.assertEqual(sorted(root.glob("*.json")), retained)

    def test_scope_setup_delay_cannot_extend_login_deadline(self) -> None:
        values = iter((50.0, 351.0))
        deadline = next(values) + channel.MAXIMUM_SECONDS
        with self.assertRaisesRegex(
            channel.NativeClaudeLoginError, "login_timeout"
        ):
            channel._remaining_runtime_usec(
                deadline, monotonic=lambda: next(values)
            )

    def test_full_output_buffer_cannot_block_past_login_deadline(self) -> None:
        reader, writer = os.pipe()
        try:
            flags = fcntl.fcntl(writer, fcntl.F_GETFL)
            fcntl.fcntl(writer, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            while True:
                try:
                    os.write(writer, b"x" * 4096)
                except BlockingIOError:
                    break
            with self.assertRaisesRegex(
                channel.NativeClaudeLoginError, "login_timeout"
            ):
                channel._write_before_deadline(
                    writer, b"blocked", time.monotonic() + 0.02
                )
        finally:
            os.close(reader)
            os.close(writer)

    def test_scope_absence_rejects_same_process_generation(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 4, b"", b""
        )
        with mock.patch.object(
            channel.native_codex_session_controller.run_journal,
            "process_start_time", return_value=55,
        ):
            with self.assertRaisesRegex(
                channel.NativeClaudeLoginError, "process_live"
            ):
                channel._prove_scope_absent(
                    "secure-sandbox-native-run-"
                    + OPERATION_ID.replace("-", "") + ".scope",
                    process_id=123, process_start_time=55,
                    systemctl=Path("/bin/systemctl"),
                    cgroup_root=Path("/sys/fs/cgroup"),
                    runner=lambda *args, **kwargs: completed,
                )

    def test_reaped_login_child_pid_is_never_signalled(self) -> None:
        kill = mock.Mock()
        channel._terminate_direct_child(
            1234,
            waitpid=mock.Mock(side_effect=ChildProcessError),
            kill=kill,
        )
        kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
