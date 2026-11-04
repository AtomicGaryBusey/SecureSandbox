#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from shared import native_terminal_handle as handle


class NativeTerminalHandleTests(unittest.TestCase):
    def record(self, *, kind: str = "claude-login") -> dict:
        operation_id = "11111111-1111-4111-8111-111111111111"
        session_id = (
            operation_id if kind == "claude-login"
            else "22222222-2222-4222-8222-222222222222"
        )
        arguments = (
            [operation_id, "2" * 64, "3" * 64, "4" * 64, "5" * 64]
            if kind == "claude-login"
            else [operation_id, "6" * 64]
        )
        return handle.make_record(
            handle_id="77777777-7777-4777-8777-777777777777",
            kind=kind, operation_id=operation_id, plan_sha256="2" * 64,
            authorization_sha256="3" * 64, stack_sha256="4" * 64,
            catalog_sha256="5" * 64, session_id=session_id,
            remote_arguments=arguments, issued_at=1_000, expires_at=1_120,
        )

    def test_publish_claim_and_unlinked_fd_are_exact_and_one_shot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.record()
            public = handle.publish(
                record, root=root, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            self.assertEqual(handle.validate_public(public), public)
            claim_body = {
                "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            claim = {
                "schema": handle.CLAIM_SCHEMA, **claim_body,
                "request_sha256": handle.sha256(claim_body),
            }
            descriptor, observed = handle.claim_unlinked_fd(
                claim, root=root, now=1_001, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            try:
                self.assertEqual(observed, record)
                self.assertEqual(
                    handle.read_unlinked_fd(
                        descriptor, now=1_001, trusted_uid=os.geteuid(),
                        trusted_gid=os.getegid(),
                    ),
                    record,
                )
            finally:
                os.close(descriptor)
            self.assertTrue(
                (root / f"{record['handle_id']}.consumed.json").is_file()
            )
            consumed, consumption = handle.read_consumed(
                root=root, handle_id=public["handle_id"],
                handle_sha256=public["handle_sha256"],
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )
            self.assertEqual(consumed, record)
            self.assertEqual(consumption["claimed_at"], 1_001)
            self.assertEqual(
                handle.read_consumed_by_id(
                    root=root, handle_id=public["handle_id"],
                    trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                ),
                (record, consumption),
            )
            with self.assertRaisesRegex(
                handle.NativeTerminalHandleError, "replay_denied"
            ):
                handle.claim_unlinked_fd(
                    claim, root=root, now=1_001, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                )

    def test_session_handle_keeps_action_and_session_id_distinct(self) -> None:
        record = self.record(kind="claude-session")
        self.assertNotEqual(record["operation_id"], record["session_id"])
        self.assertEqual(handle.validate_record(record), record)

    def test_expired_claim_is_consumed_and_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = handle.publish(
                self.record(), root=root, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            body = {
                "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            claim = {"schema": handle.CLAIM_SCHEMA, **body,
                     "request_sha256": handle.sha256(body)}
            with self.assertRaisesRegex(
                handle.NativeTerminalHandleError, "expired"
            ):
                handle.claim_unlinked_fd(
                    claim, root=root, now=1_121, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                )
            with self.assertRaisesRegex(
                handle.NativeTerminalHandleError, "replay_denied"
            ):
                handle.claim_unlinked_fd(
                    claim, root=root, now=1_001, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                )
            self.assertFalse(
                (root / f"{public['handle_id']}.claim.json").exists()
            )

    def test_hostile_symlink_and_linked_fd_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(handle.canonical_bytes(self.record()))
            target.chmod(0o600)
            link = root / "77777777-7777-4777-8777-777777777777.json"
            link.symlink_to(target)
            body = {"handle_id": link.stem, "handle_sha256": "8" * 64}
            claim = {"schema": handle.CLAIM_SCHEMA, **body,
                     "request_sha256": handle.sha256(body)}
            with self.assertRaises((OSError, handle.NativeTerminalHandleError)):
                handle.claim_unlinked_fd(
                    claim, root=root, now=1_001, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid(),
                )
            descriptor = os.open(target, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    handle.NativeTerminalHandleError, "fd_untrusted"
                ):
                    handle.read_unlinked_fd(
                        descriptor, now=1_001, trusted_uid=os.geteuid(),
                        trusted_gid=os.getegid(),
                    )
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
