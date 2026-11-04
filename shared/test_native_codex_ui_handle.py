#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shared import native_codex_ui_handle as handle
from shared import native_stack_session


NOW = 2_000_000_000


def record(identifier: str, operation: str, session: str) -> dict:
    lease = native_stack_session.make_session_lease(
        lease_profile_id="interactive", session_id=session,
        runtime_authority_sha256="a" * 64,
        grant_id="33333333-3333-4333-8333-333333333333",
        grant_sha256="b" * 64, issued_at=NOW, expires_at=NOW + 3600,
    )
    return handle.make_record(
        handle_id=identifier, operation_id=operation,
        plan_sha256="c" * 64, authorization_sha256="d" * 64,
        stack_sha256="e" * 64, catalog_sha256="f" * 64,
        session_id=session, runtime_authority_sha256="a" * 64,
        harness_generation_id="1" * 64,
        harness_executable_sha256="2" * 64,
        session_lease=lease, issued_at=NOW, expires_at=NOW + 120,
    )


class NativeCodexUIHandleTests(unittest.TestCase):
    def test_claim_is_unlinked_one_shot_and_terminal_retirement_is_exact(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        value = record(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "44444444-4444-4444-8444-444444444444",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            public = handle.publish(
                value, root=root, trusted_uid=uid, trusted_gid=gid
            )
            claim_body = {
                "handle_id": value["handle_id"],
                "handle_sha256": value["record_sha256"],
            }
            claim = {
                "schema": handle.CLAIM_SCHEMA, **claim_body,
                "request_sha256": handle.sha256(claim_body),
            }
            descriptor, claimed = handle.claim_unlinked_fd(
                claim, root=root, now=NOW + 1,
                trusted_uid=uid, trusted_gid=gid,
            )
            try:
                self.assertEqual(
                    handle.read_unlinked_fd(
                        descriptor, now=NOW + 1,
                        trusted_uid=uid, trusted_gid=gid,
                    ),
                    claimed,
                )
            finally:
                os.close(descriptor)
            with self.assertRaisesRegex(
                handle.NativeCodexUIHandleError, "replay_denied"
            ):
                handle.claim_unlinked_fd(
                    claim, root=root, now=NOW + 1,
                    trusted_uid=uid, trusted_gid=gid,
                )
            self.assertEqual(
                handle.read_consumed_by_id(
                    root=root, handle_id=value["handle_id"],
                    trusted_uid=uid, trusted_gid=gid,
                )[0],
                value,
            )
            handle.retire_handle(
                root=root, handle_id=value["handle_id"],
                handle_sha256=public["handle_sha256"], now=NOW + 2,
                trusted_uid=uid, trusted_gid=gid,
            )
            self.assertTrue(
                (root / f"{value['handle_id']}.retired.json").is_file()
            )
            handle.finalize_retirement(
                root=root, handle_id=value["handle_id"],
                handle_sha256=public["handle_sha256"], now=NOW + 3,
                trusted_uid=uid, trusted_gid=gid,
            )
            self.assertEqual(os.listdir(root), [handle.LOCK_NAME])

    def test_inventory_reaps_expired_source_and_stale_fd_but_not_unknowns(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        first = record(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "44444444-4444-4444-8444-444444444444",
        )
        second = record(
            "55555555-5555-4555-8555-555555555555",
            "66666666-6666-4666-8666-666666666666",
            "77777777-7777-4777-8777-777777777777",
        )
        second["issued_at"] = NOW + 121
        second["expires_at"] = NOW + 241
        second_body = {
            key: second[key]
            for key in second if key not in {"schema", "record_sha256"}
        }
        second["record_sha256"] = handle.sha256(second_body)
        second = handle.validate_record(second)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            handle.publish(first, root=root, trusted_uid=uid, trusted_gid=gid)
            stale_name = f".fd-{first['handle_id']}"
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                handle._write_at(
                    directory, stale_name, first, uid, gid, 0o400
                )
                os.utime(
                    stale_name, (NOW - 1000, NOW - 1000),
                    dir_fd=directory, follow_symlinks=False,
                )
            finally:
                os.close(directory)
            handle.publish(second, root=root, trusted_uid=uid, trusted_gid=gid)
            self.assertFalse((root / stale_name).exists())
            self.assertFalse((root / f"{first['handle_id']}.json").exists())

            (root / "unknown").write_bytes(b"x")
            third = dict(second)
            with self.assertRaisesRegex(
                handle.NativeCodexUIHandleError, "inventory_untrusted"
            ):
                handle.publish(
                    third, root=root, trusted_uid=uid, trusted_gid=gid
                )

    def test_capacity_is_hard_and_does_not_replace_live_authority(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        first = record(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "44444444-4444-4444-8444-444444444444",
        )
        second = record(
            "55555555-5555-4555-8555-555555555555",
            "66666666-6666-4666-8666-666666666666",
            "77777777-7777-4777-8777-777777777777",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            with mock.patch.object(handle, "MAXIMUM_RECORDS", 1):
                handle.publish(first, root=root, trusted_uid=uid, trusted_gid=gid)
                with self.assertRaisesRegex(
                    handle.NativeCodexUIHandleError, "capacity_exceeded"
                ):
                    handle.publish(
                        second, root=root, trusted_uid=uid, trusted_gid=gid
                    )
            self.assertTrue((root / f"{first['handle_id']}.json").is_file())

    def test_incomplete_retirement_reconciles_before_terminal_finalize(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        value = record(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "44444444-4444-4444-8444-444444444444",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            public = handle.publish(
                value, root=root, trusted_uid=uid, trusted_gid=gid
            )
            body = {
                "handle_id": value["handle_id"],
                "handle_sha256": value["record_sha256"],
            }
            descriptor, _ = handle.claim_unlinked_fd(
                {"schema": handle.CLAIM_SCHEMA, **body,
                 "request_sha256": handle.sha256(body)},
                root=root, now=NOW + 1, trusted_uid=uid, trusted_gid=gid,
            )
            os.close(descriptor)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                handle._write_at(
                    directory, f"{value['handle_id']}.retired.json",
                    handle._retirement(
                        value["handle_id"], value["record_sha256"], NOW + 2
                    ),
                    uid, gid, 0o600,
                )
                os.unlink(
                    f"{value['handle_id']}.consumed.json", dir_fd=directory
                )
                os.fsync(directory)
            finally:
                os.close(directory)
            handle.retire_handle(
                root=root, handle_id=value["handle_id"],
                handle_sha256=public["handle_sha256"], now=NOW + 3,
                trusted_uid=uid, trusted_gid=gid,
            )
            self.assertFalse(
                (root / f"{value['handle_id']}.claim.json").exists()
            )
            handle.finalize_retirement(
                root=root, handle_id=value["handle_id"],
                handle_sha256=public["handle_sha256"], now=NOW + 4,
                trusted_uid=uid, trusted_gid=gid,
            )
            self.assertEqual(os.listdir(root), [handle.LOCK_NAME])


if __name__ == "__main__":
    unittest.main()
