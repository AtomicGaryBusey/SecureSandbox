from __future__ import annotations

import datetime
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import control_center_backup as backup
from scripts import control_center_restore_operation as operation


class RestoreOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "scripts/control_center_restore_operation.py").write_text("worker")
        (self.repo / "vms").mkdir()
        (self.repo / ".private").mkdir(mode=0o700)
        self.root = Path(self.temporary.name) / "operations"
        self.source = Path(self.temporary.name) / "backups"
        self.source.mkdir()
        self.restore_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.generation_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        self.volume = "11111111-1111-4111-8111-111111111111"
        self.key = b"k" * 32
        self.identities = {name: {"uuid": f"{index:08x}-1111-4111-8111-111111111111",
                                  "device": 1, "inode": index}
                           for index, name in enumerate(backup.NAMES, 1)}

    def tearDown(self):
        self.temporary.cleanup()

    def plan(self):
        return operation.create_plan(self.root, self.source, self.generation_id,
                                     self.volume, "a" * 64, self.identities, 10,
                                     1000, self.key, restore_id=self.restore_id)

    def test_plan_authentication_expiry_and_single_claim(self):
        self.plan()
        self.assertEqual(operation.plan_detail(self.root, self.restore_id, self.key)["source"], str(self.source))
        with self.assertRaisesRegex(operation.RestoreOperationError, "authentication_failed"):
            operation.load_plan(self.root, self.restore_id, b"x" * 32)
        with patch.object(operation.time, "time", return_value=10**10):
            with self.assertRaisesRegex(operation.RestoreOperationError, "expired"):
                operation.load_plan(self.root, self.restore_id, self.key)
        with patch.object(operation.subprocess, "Popen") as launched:
            self.assertEqual(operation.submit(self.root, self.repo, self.restore_id, self.key)["state"], "submitted")
        self.assertNotIn(self.key.decode(), str(launched.call_args))
        with self.assertRaisesRegex(operation.RestoreOperationError, "already_claimed"):
            operation.submit(self.root, self.repo, self.restore_id, self.key)

    def test_worker_rechecks_plan_then_calls_staging_and_swap_under_one_lock(self):
        self.plan()
        with patch.object(operation.subprocess, "Popen"):
            operation.submit(self.root, self.repo, self.restore_id, self.key)
        descriptor = os.open(Path(self.temporary.name) / "lifecycle.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fake_lifecycle = SimpleNamespace(ensure_mutation_preconditions=lambda _: descriptor)
        fake_api = SimpleNamespace(restore_preview=lambda *_: {
            "ready": True, "volume_uuid": self.volume, "manifest_hmac_sha256": "a" * 64,
            "file_count": 10, "logical_bytes": 1000})
        fake_maintenance = SimpleNamespace(pending_transaction=lambda *_: None)
        with (patch.object(operation.backup, "read_backup_key", return_value=self.key),
              patch.object(operation, "verify_host_release_precondition") as release_check,
              patch.object(operation.restore, "load_repo_module", side_effect=[
                  fake_lifecycle, fake_api, fake_maintenance]),
              patch.object(operation.base, "vm_identities", return_value=self.identities),
              patch.object(operation.restore, "stage_candidate", return_value={"stage": str(self.repo / "candidate")}) as staged,
              patch.object(operation.restore, "ParallelsRestoreAdapter") as adapter,
              patch.object(operation.restore, "swap_candidate") as swapped):
            self.assertEqual(operation.worker(self.root, self.repo, self.restore_id), 0)
        self.assertEqual(staged.call_count, 1)
        self.assertEqual(release_check.call_count, 1)
        self.assertEqual(swapped.call_count, 1)
        self.assertEqual(adapter.call_args.args[1], descriptor)

    def test_worker_rejects_changed_preflight_without_staging(self):
        self.plan()
        with patch.object(operation.subprocess, "Popen"):
            operation.submit(self.root, self.repo, self.restore_id, self.key)
        descriptor = os.open(Path(self.temporary.name) / "lifecycle.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fake_lifecycle = SimpleNamespace(ensure_mutation_preconditions=lambda _: descriptor)
        fake_api = SimpleNamespace(restore_preview=lambda *_: {"ready": False})
        with (patch.object(operation.backup, "read_backup_key", return_value=self.key),
              patch.object(operation, "verify_host_release_precondition"),
              patch.object(operation.restore, "load_repo_module", side_effect=[fake_lifecycle, fake_api]),
              patch.object(operation.restore, "stage_candidate") as staged):
            self.assertEqual(operation.worker(self.root, self.repo, self.restore_id), 1)
        staged.assert_not_called()

    def test_worker_rejects_unverified_host_release_before_archive_read(self):
        self.plan()
        with patch.object(operation.subprocess, "Popen"):
            operation.submit(self.root, self.repo, self.restore_id, self.key)
        descriptor = os.open(Path(self.temporary.name) / "lifecycle.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fake_lifecycle = SimpleNamespace(ensure_mutation_preconditions=lambda _: descriptor)
        with (patch.object(operation.backup, "read_backup_key", return_value=self.key),
              patch.object(operation, "verify_host_release_precondition",
                           side_effect=operation.RestoreOperationError("restore_host_release_unverified")),
              patch.object(operation.restore, "load_repo_module", return_value=fake_lifecycle) as loader,
              patch.object(operation.restore, "stage_candidate") as staged):
            self.assertEqual(operation.worker(self.root, self.repo, self.restore_id), 1)
        self.assertEqual(loader.call_count, 1)
        staged.assert_not_called()
        self.assertEqual(operation.read_status(self.root, self.restore_id, self.key)["error"],
                         "restore_host_release_unverified")

    def test_restore_profile_requires_transaction_headroom(self):
        now = datetime.datetime(2026, 10, 30, tzinfo=datetime.timezone.utc)
        profile = plistlib.dumps({
            "ExpirationDate": now + datetime.timedelta(hours=51, minutes=59),
        })
        completed = SimpleNamespace(returncode=0, stdout=profile)
        with patch.object(operation.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                    operation.RestoreOperationError,
                    "restore_authorization_profile_headroom_insufficient"):
                operation.verify_restore_profile_headroom(self.repo, now=now)
        profile = plistlib.dumps({
            "ExpirationDate": now + datetime.timedelta(hours=52, minutes=1),
        })
        completed = SimpleNamespace(returncode=0, stdout=profile)
        with patch.object(operation.subprocess, "run", return_value=completed):
            operation.verify_restore_profile_headroom(self.repo, now=now)

    def test_partial_journal_is_recoverable_once_under_lifecycle_lock(self):
        self.plan()
        with patch.object(operation.subprocess, "Popen"):
            operation.submit(self.root, self.repo, self.restore_id, self.key)
        journal_path = (self.repo / ".private/control-center-restores"
                        / f"restore-{self.restore_id}.journal.json")
        journal_path.parent.mkdir(mode=0o700)
        journal_path.write_text("fixture")
        operation.write_status(self.root, self.restore_id, "failed", "execution", self.key,
                               error="restore_worker_failed")
        journal = {"restore_id": self.restore_id, "phase": "installed"}
        with patch.object(operation.restore, "read_journal", return_value=journal):
            self.assertTrue(operation.operation_status(self.root, self.repo,
                                                       self.restore_id, self.key)["recoverable"])
            with patch.object(operation.subprocess, "Popen"):
                self.assertEqual(operation.submit_recovery(self.root, self.repo,
                                                           self.restore_id, self.key)["state"], "submitted")
            pending = operation.operation_status(self.root, self.repo, self.restore_id, self.key)
            self.assertEqual(pending["state"], "running")
            self.assertFalse(pending["recoverable"])
            claim = self.root / f"{self.restore_id}.recovery.claimed"
            with patch.object(operation.time, "time", return_value=claim.stat().st_mtime + 31):
                stalled = operation.operation_status(self.root, self.repo, self.restore_id, self.key)
            self.assertEqual(stalled["state"], "incomplete")
            self.assertFalse(stalled["recoverable"])
            operation.write_status(self.root, self.restore_id, "failed", "recovery", self.key,
                                   error="restore_recovery_failed")
            failed = operation.operation_status(self.root, self.repo, self.restore_id, self.key)
            self.assertEqual(failed["state"], "failed")
            self.assertFalse(failed["recoverable"])
            with self.assertRaisesRegex(operation.RestoreOperationError, "already_claimed"):
                operation.submit_recovery(self.root, self.repo, self.restore_id, self.key)
        descriptor = os.open(Path(self.temporary.name) / "recovery.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fake_lifecycle = SimpleNamespace(ensure_mutation_preconditions=lambda _: descriptor)
        with (patch.object(operation.backup, "read_backup_key", return_value=self.key),
              patch.object(operation.restore, "load_repo_module", return_value=fake_lifecycle),
              patch.object(operation.restore, "read_journal", return_value=journal),
              patch.object(operation.restore, "ParallelsRestoreAdapter") as adapter,
              patch.object(operation.restore, "rollback_swap") as rollback):
            self.assertEqual(operation.recover(self.root, self.repo, self.restore_id), 0)
        self.assertEqual(adapter.call_args.args[1], descriptor)
        self.assertEqual(rollback.call_count, 1)

    def test_rolled_back_status_exposes_authenticated_failure_code(self):
        self.plan()
        journal_path = (self.repo / ".private/control-center-restores"
                        / f"restore-{self.restore_id}.journal.json")
        journal_path.parent.mkdir(mode=0o700)
        journal_path.write_text("fixture")
        operation.write_status(self.root, self.restore_id, "failed", "execution", self.key,
                               error="restore_failed_rolled_back_restore_cold_acceptance_failed")
        with patch.object(operation.restore, "read_journal", return_value={
                "restore_id": self.restore_id, "phase": "rolled_back"}):
            result = operation.operation_status(self.root, self.repo, self.restore_id, self.key)
        self.assertEqual(result["state"], "rolled_back")
        self.assertEqual(result["error"],
                         "restore_failed_rolled_back_restore_cold_acceptance_failed")


if __name__ == "__main__":
    unittest.main()
