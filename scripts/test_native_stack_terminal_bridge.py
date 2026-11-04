#!/usr/bin/env python3

from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path

from scripts import native_stack_terminal_bridge as bridge
from shared import native_terminal_handle as handle


class NativeStackTerminalBridgeTests(unittest.TestCase):
    def claimed_handle(self, root: Path, *, expires_at: int = 1_120) -> int:
        operation_id = "11111111-1111-4111-8111-111111111111"
        record = handle.make_record(
            handle_id="22222222-2222-4222-8222-222222222222",
            kind="claude-login", operation_id=operation_id,
            plan_sha256="3" * 64, authorization_sha256="4" * 64,
            stack_sha256="5" * 64, catalog_sha256="6" * 64,
            session_id=operation_id,
            remote_arguments=[
                operation_id, "3" * 64, "4" * 64, "5" * 64, "6" * 64,
            ],
            issued_at=1_000, expires_at=expires_at,
        )
        public = handle.publish(
            record, root=root, trusted_uid=os.geteuid(),
            trusted_gid=os.getegid(),
        )
        body = {
            "handle_id": public["handle_id"],
            "handle_sha256": public["handle_sha256"],
        }
        claim = {
            "schema": handle.CLAIM_SCHEMA, **body,
            "request_sha256": handle.sha256(body),
        }
        descriptor, _ = handle.claim_unlinked_fd(
            claim, root=root, now=1_001, trusted_uid=os.geteuid(),
            trusted_gid=os.getegid(),
        )
        return descriptor

    def test_exact_duplicate_unix_stream_and_fd_authority_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = self.claimed_handle(root)
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            output = os.dup(left.fileno())
            try:
                command, record = bridge.validated_command(
                    handle_fd=descriptor, input_fd=left.fileno(),
                    output_fd=output, now=1_001,
                    trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                    control_client=Path("/fixed/control_client"),
                    ssh_config=Path("/fixed/ssh_config"),
                )
            finally:
                os.close(descriptor); os.close(output)
                left.close(); right.close()
            self.assertEqual(record["kind"], "claude-login")
            self.assertEqual(command[-6], "native-claude-login")
            self.assertNotIn(record["handle_id"], command)

    def test_substituted_socket_and_pty_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = self.claimed_handle(root)
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            other_left, other_right = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            try:
                with self.assertRaisesRegex(
                    bridge.NativeStackTerminalBridgeError, "stream_substituted"
                ):
                    bridge.validated_command(
                        handle_fd=descriptor, input_fd=left.fileno(),
                        output_fd=other_left.fileno(), now=1_001,
                        trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                    )
                master, slave = os.openpty()
                try:
                    with self.assertRaisesRegex(
                        bridge.NativeStackTerminalBridgeError, "stream_invalid"
                    ):
                        bridge.validated_command(
                            handle_fd=descriptor, input_fd=master,
                            output_fd=slave, now=1_001,
                            trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                        )
                finally:
                    os.close(master); os.close(slave)
            finally:
                os.close(descriptor)
                left.close(); right.close(); other_left.close(); other_right.close()


if __name__ == "__main__":
    unittest.main()
