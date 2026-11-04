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
                "kind": public["kind"],
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
            handle.retire_handle(
                root=root, handle_id=public["handle_id"],
                handle_sha256=public["handle_sha256"], now=1_002,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )
            self.assertTrue(
                (root / f"{public['handle_id']}.retired.json").is_file()
            )
            handle.retire_handle(
                root=root, handle_id=public["handle_id"],
                handle_sha256=public["handle_sha256"], now=1_002,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )
            handle.finalize_retirement(
                root=root, handle_id=public["handle_id"],
                handle_sha256=public["handle_sha256"], now=1_003,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
            )
            self.assertEqual(os.listdir(root), [handle.LOCK_NAME])

    def test_session_handle_keeps_action_and_session_id_distinct(self) -> None:
        record = self.record(kind="claude-session")
        self.assertNotEqual(record["operation_id"], record["session_id"])
        self.assertEqual(handle.validate_record(record), record)

    def test_wrong_kind_rejects_before_consuming_one_shot_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = handle.publish(
                self.record(), root=root, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            wrong_body = {
                "kind": "claude-session", "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            wrong = {
                "schema": handle.CLAIM_SCHEMA, **wrong_body,
                "request_sha256": handle.sha256(wrong_body),
            }
            with self.assertRaisesRegex(
                handle.NativeTerminalHandleError, "claim_mismatch"
            ):
                handle.claim_unlinked_fd(
                    wrong, root=root, now=1_001,
                    trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                )
            self.assertTrue((root / f"{public['handle_id']}.json").is_file())
            correct_body = {
                "kind": public["kind"], "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            descriptor, _record = handle.claim_unlinked_fd(
                {
                    "schema": handle.CLAIM_SCHEMA, **correct_body,
                    "request_sha256": handle.sha256(correct_body),
                },
                root=root, now=1_001, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            os.close(descriptor)

    def test_expired_claim_is_consumed_and_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = handle.publish(
                self.record(), root=root, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid(),
            )
            body = {
                "kind": public["kind"],
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
            body = {"kind": "claude-login", "handle_id": link.stem,
                    "handle_sha256": "8" * 64}
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

    def test_inventory_reaps_only_stale_owned_fd_and_expired_source(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.record()
            handle.publish(
                record, root=root, trusted_uid=uid, trusted_gid=gid
            )
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            name = f".fd-{record['handle_id']}"
            try:
                handle._write_new_at(
                    directory, name, record, mode=0o400,
                    trusted_uid=uid, trusted_gid=gid,
                )
                os.utime(
                    name, (1_000, 1_000), dir_fd=directory,
                    follow_symlinks=False,
                )
                lock = handle._lock(directory, uid, gid)
                try:
                    handle._inventory(
                        directory, now=1_500, uid=uid, gid=gid
                    )
                finally:
                    os.close(lock)
            finally:
                os.close(directory)
            self.assertEqual(os.listdir(root), [handle.LOCK_NAME])

    def test_expired_partial_claim_is_reaped_only_after_stale_window(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.record()
            public = handle.publish(
                record, root=root, trusted_uid=uid, trusted_gid=gid
            )
            body = {
                "kind": public["kind"], "handle_id": public["handle_id"],
                "handle_sha256": public["handle_sha256"],
            }
            with self.assertRaisesRegex(
                handle.NativeTerminalHandleError, "expired"
            ):
                handle.claim_unlinked_fd(
                    {"schema": handle.CLAIM_SCHEMA, **body,
                     "request_sha256": handle.sha256(body)},
                    root=root, now=1_121, trusted_uid=uid, trusted_gid=gid,
                )
            consumed = root / f"{record['handle_id']}.consumed.json"
            self.assertTrue(consumed.is_file())
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                lock = handle._lock(directory, uid, gid)
                try:
                    handle._inventory(
                        directory, now=1_421, uid=uid, gid=gid
                    )
                finally:
                    os.close(lock)
            finally:
                os.close(directory)
            self.assertFalse(consumed.exists())
            self.assertEqual(os.listdir(root), [handle.LOCK_NAME])


if __name__ == "__main__":
    unittest.main()
