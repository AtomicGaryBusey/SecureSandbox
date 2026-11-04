#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shared import native_install_transaction as transaction


class NativeInstallTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.pending_root = self.root / "state"
        self.backup_root = self.root / "backups"
        self.destination_root = self.root / "destinations"
        for path in (self.pending_root, self.backup_root, self.destination_root):
            path.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def begin(self, destinations: list[Path]) -> tuple[Path, Path, dict]:
        pending = self.pending_root / "pending.json"
        backup = self.backup_root / "backup-1"
        record = transaction.begin(
            pending,
            backup,
            destinations,
            expected_uid=self.uid,
            expected_gid=self.gid,
            now=2_000_000_000,
        )
        return pending, backup, record

    def test_exact_modes_content_and_absence_survive_recovery(self) -> None:
        executable = self.destination_root / "controller"
        module = self.destination_root / "module.py"
        absent = self.destination_root / "new-file"
        executable.write_bytes(b"#!/bin/sh\n")
        module.write_bytes(b"value = 1\n")
        executable.chmod(0o755)
        module.chmod(0o644)
        pending, _, record = self.begin([executable, module, absent])
        self.assertTrue(pending.exists())
        self.assertEqual(
            [entry["path"] for entry in record["destinations"]],
            sorted([str(executable), str(module), str(absent)]),
        )

        executable.write_bytes(b"changed\n")
        executable.chmod(0o600)
        module.unlink()
        absent.write_bytes(b"created\n")
        restored = transaction.recover(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(restored["status"], "restored")
        self.assertTrue(pending.exists())
        transaction.finalize_recovery(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )

        self.assertEqual(executable.read_bytes(), b"#!/bin/sh\n")
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
        self.assertEqual(module.read_bytes(), b"value = 1\n")
        self.assertEqual(stat.S_IMODE(module.stat().st_mode), 0o644)
        self.assertFalse(absent.exists())
        self.assertFalse(pending.exists())

    def test_recovery_is_idempotent_after_partial_restore(self) -> None:
        first = self.destination_root / "first"
        second = self.destination_root / "second"
        first.write_bytes(b"one")
        second.write_bytes(b"two")
        first.chmod(0o600)
        second.chmod(0o640)
        pending, backup, record = self.begin([first, second])
        first.write_bytes(b"bad-one")
        second.write_bytes(b"bad-two")

        original = transaction._atomic_file
        failures = {str(first): 1}

        def injected(path: Path, raw: bytes, **kwargs: object) -> None:
            if str(path) in failures:
                failures.pop(str(path))
                raise OSError("injected crash")
            original(path, raw, **kwargs)

        with mock.patch.object(transaction, "_atomic_file", side_effect=injected):
            with self.assertRaises(OSError):
                transaction.recover(
                    pending, expected_uid=self.uid, expected_gid=self.gid
                )
        self.assertTrue(pending.exists())
        self.assertTrue(backup.exists())
        result = transaction.recover(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(result["status"], "restored")
        self.assertEqual(first.read_bytes(), b"one")
        self.assertEqual(second.read_bytes(), b"two")
        transaction.finalize_recovery(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )

    def test_backup_tamper_fails_closed_and_retains_pending(self) -> None:
        destination = self.destination_root / "policy"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, backup, record = self.begin([destination])
        backup_name = record["destinations"][0]["backup_name"]
        (backup / backup_name).write_bytes(b"tampered")
        destination.write_bytes(b"new")
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError,
            "native_install_backup_mismatch",
        ):
            transaction.recover(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        self.assertTrue(pending.exists())
        self.assertEqual(destination.read_bytes(), b"new")

    def test_existing_symlink_destination_is_rejected_without_mutating_target(self) -> None:
        target = self.destination_root / "target"
        target.write_bytes(b"unchanged")
        target.chmod(0o644)
        link = self.destination_root / "link"
        link.symlink_to(target)
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError,
            "native_install_file_untrusted",
        ):
            self.begin([link])
        self.assertEqual(target.read_bytes(), b"unchanged")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_canonical_pending_record_rejects_extension_and_commit_is_durable(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, _ = self.begin([destination])
        result = transaction.commit(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(result["status"], "committed")
        self.assertFalse(pending.exists())
        archive = next(self.pending_root.glob("*.committed.json"))
        archived = json.loads(archive.read_bytes())
        self.assertEqual(archived["status"], "committed")
        self.assertEqual(
            archived["transaction"]["transaction_sha256"],
            result["transaction_sha256"],
        )
        self.assertEqual(
            archived["transaction"]["destinations"][0]["path"],
            str(destination),
        )

    def test_commit_decision_can_only_finish_commit_after_crash(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, _ = self.begin([destination])
        transaction.decide(
            pending,
            "commit",
            expected_uid=self.uid,
            expected_gid=self.gid,
            now=2_000_000_001,
        )
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError, "decision_conflict"
        ):
            transaction.recover(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        result = transaction.commit(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(result["status"], "committed")

    def test_archive_publication_crash_reconciles_without_opposite_outcome(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, _ = self.begin([destination])
        original_unlink = os.unlink
        failed = False

        def injected(path: object, *args: object, **kwargs: object) -> None:
            nonlocal failed
            if path == pending.name and kwargs.get("dir_fd") is not None and not failed:
                failed = True
                raise OSError("injected finalization crash")
            original_unlink(path, *args, **kwargs)

        with mock.patch.object(os, "unlink", injected), self.assertRaises(OSError):
            transaction.commit(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        self.assertTrue(pending.exists())
        self.assertEqual(
            transaction.read_record(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )["decision"],
            "commit",
        )
        result = transaction.commit(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual(len(list(self.pending_root.glob("*.committed.json"))), 1)
        self.assertEqual(len(list(self.pending_root.glob("*.recovered.json"))), 0)

    def test_helper_tamper_does_not_choose_recovery(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        helper = self.root / "helper.py"
        helper.write_bytes(b"original helper\n")
        helper.chmod(0o555)
        pending = self.pending_root / "pending.json"
        transaction.begin(
            pending,
            self.backup_root / "backup-1",
            [destination],
            expected_uid=self.uid,
            expected_gid=self.gid,
            now=2_000_000_000,
            metadata={"source_manifest": [{"sha256": "a" * 64}]},
            recovery_helper=helper,
        )
        helper.chmod(0o755)
        helper.write_bytes(b"tampered helper\n")
        destination.write_bytes(b"new")
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError,
            "native_install_recovery_helper_mismatch",
        ):
            transaction.recover(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        record = transaction.read_record(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertIsNone(record["decision"])
        self.assertEqual(destination.read_bytes(), b"new")

    def test_commit_decision_survives_crash_before_archive_publication(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, _ = self.begin([destination])
        original = transaction._atomic_file
        failed = False

        def injected(path: Path, raw: bytes, **kwargs: object) -> None:
            nonlocal failed
            if path.name.endswith(".committed.json") and not failed:
                failed = True
                raise OSError("injected archive crash")
            original(path, raw, **kwargs)

        with mock.patch.object(transaction, "_atomic_file", side_effect=injected):
            with self.assertRaises(OSError):
                transaction.commit(
                    pending, expected_uid=self.uid, expected_gid=self.gid
                )
        record = transaction.read_record(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(record["decision"], "commit")
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError, "decision_conflict"
        ):
            transaction.recover(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        self.assertEqual(
            transaction.commit(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )["status"],
            "committed",
        )

    def test_archive_collision_fails_closed_and_retains_decided_pending(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, record = self.begin([destination])
        transaction.decide(
            pending,
            "commit",
            expected_uid=self.uid,
            expected_gid=self.gid,
            now=2_000_000_001,
        )
        archive = pending.with_name(
            f"{pending.stem}.{record['transaction_id']}.committed.json"
        )
        archive.write_bytes(b"{}\n")
        archive.chmod(0o600)
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError,
            "native_install_archive_collision",
        ):
            transaction.commit(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        self.assertTrue(pending.exists())
        self.assertEqual(
            transaction.read_record(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )["decision"],
            "commit",
        )

    def test_retention_limit_blocks_growth_before_backup_creation(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, _ = self.begin([destination])
        transaction.commit(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        next_backup = self.backup_root / "backup-2"
        with mock.patch.object(transaction, "MAX_RETAINED_ARCHIVES", 1):
            with self.assertRaisesRegex(
                transaction.NativeInstallTransactionError,
                "native_install_retention_limit",
            ):
                transaction.begin(
                    pending,
                    next_backup,
                    [destination],
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                    now=2_000_000_002,
                )
        self.assertFalse(next_backup.exists())

    def test_aggregate_backup_bound_fails_before_pending_publication(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"oversized")
        destination.chmod(0o600)
        pending = self.pending_root / "pending.json"
        backup = self.backup_root / "backup-1"
        with mock.patch.object(transaction, "MAX_BACKUP_BYTES", 1):
            with self.assertRaisesRegex(
                transaction.NativeInstallTransactionError,
                "native_install_backup_set_oversized",
            ):
                transaction.begin(
                    pending,
                    backup,
                    [destination],
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                    now=2_000_000_000,
                )
        self.assertFalse(pending.exists())
        self.assertFalse(backup.exists())

    def test_recovery_cannot_finalize_before_exact_file_readback(self) -> None:
        destination = self.destination_root / "file"
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        pending, _, _ = self.begin([destination])
        transaction.decide(
            pending,
            "recover",
            expected_uid=self.uid,
            expected_gid=self.gid,
            now=2_000_000_001,
        )
        destination.write_bytes(b"not-restored")
        with self.assertRaisesRegex(
            transaction.NativeInstallTransactionError,
            "native_install_recovery_readback_failed",
        ):
            transaction.finalize_recovery(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )
        self.assertTrue(pending.exists())
        transaction.recover(
            pending, expected_uid=self.uid, expected_gid=self.gid
        )
        self.assertEqual(
            transaction.finalize_recovery(
                pending, expected_uid=self.uid, expected_gid=self.gid
            )["status"],
            "recovered",
        )


if __name__ == "__main__":
    unittest.main()
