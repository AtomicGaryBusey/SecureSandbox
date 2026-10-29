import tempfile
import os
import shutil
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import control_center_backup as backup
from scripts import control_center_backup_operation as operation


class BackupOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "operations"
        self.destination = Path(self.temporary.name) / "destination"
        self.destination.mkdir()
        self.key = b"k" * 32
        self.identities = {name: {"uuid": f"{index:08x}-1111-4111-8111-111111111111",
                                  "device": 1, "inode": index}
                           for index, name in enumerate(backup.NAMES, 1)}
        self.plan_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.volume = "11111111-1111-4111-8111-111111111111"

    def tearDown(self):
        self.temporary.cleanup()

    def test_plan_authenticates_identity_expires_and_claims_once(self):
        value = operation.create_plan(self.root, self.destination, self.volume,
                                      self.identities, self.key, now=100,
                                      plan_id=self.plan_id)
        self.assertEqual(value["plan_id"], self.plan_id)
        self.assertEqual(operation.load_plan(self.root, self.plan_id, self.key, now=101)["destination"],
                         str(self.destination))
        with self.assertRaisesRegex(operation.OperationError, "authentication_failed"):
            operation.load_plan(self.root, self.plan_id, b"x" * 32, now=101)
        with self.assertRaisesRegex(operation.OperationError, "expired"):
            operation.load_plan(self.root, self.plan_id, self.key, now=1000 + operation.PLAN_LIFETIME_SECONDS)
        operation.claim_plan(self.root, self.plan_id, self.key, now=101)
        with self.assertRaisesRegex(operation.OperationError, "already_claimed"):
            operation.claim_plan(self.root, self.plan_id, self.key, now=101)

    def test_plan_file_change_is_rejected(self):
        operation.create_plan(self.root, self.destination, self.volume,
                              self.identities, self.key, plan_id=self.plan_id)
        path = self.root / f"{self.plan_id}.json"
        payload = path.read_text().replace(str(self.destination), "/tmp/attacker")
        path.write_text(payload)
        with self.assertRaisesRegex(operation.OperationError, "authentication_failed"):
            operation.load_plan(self.root, self.plan_id, self.key, now=101)

    def test_plan_detail_and_status_survive_reopen_without_replaying_claim(self):
        operation.create_plan(self.root, self.destination, self.volume,
                              self.identities, self.key, logical_bytes=1234,
                              plan_id=self.plan_id)
        detail = operation.plan_detail(self.root, self.plan_id, self.key)
        self.assertEqual(detail["logical_bytes"], 1234)
        self.assertEqual(operation.operation_status(self.root, self.plan_id, self.key)["state"], "planned")
        operation.claim_plan(self.root, self.plan_id, self.key)
        self.assertEqual(operation.operation_status(self.root, self.plan_id, self.key)["phase"], "starting")
        with patch.object(operation.time, "time", return_value=operation.time.time() + 60):
            self.assertEqual(operation.operation_status(self.root, self.plan_id, self.key)["state"], "incomplete")

    def test_published_generation_is_not_rehashed_while_worker_is_verifying(self):
        operation.create_plan(self.root, self.destination, self.volume,
                              self.identities, self.key, plan_id=self.plan_id)
        (self.destination / f"secure-sandbox-backup-{self.plan_id}").mkdir()
        with (patch.object(operation, "worker_active", return_value=True),
              patch.object(operation.backup, "verify_backup") as verify):
            self.assertEqual(operation.operation_status(self.root, self.plan_id, self.key), {
                "plan_id": self.plan_id, "state": "running", "phase": "verifying"})
            verify.assert_not_called()

    def test_claimed_plan_runs_once_and_readback_verifies_published_copy(self):
        repo = Path(self.temporary.name) / "repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "scripts/control_center_backup_operation.py").write_text("worker")
        (repo / "vms").mkdir()
        (repo / "config").mkdir()
        for name in operation.backup.HOST_CONFIG_FILES:
            (repo / "config" / name).write_text(name)
        for name in backup.NAMES:
            bundle = repo / "vms" / f"{name}.pvm"
            bundle.mkdir()
            (bundle / "config.pvs").write_text(name)
        operation.create_plan(self.root, self.destination, self.volume,
                              self.identities, self.key, plan_id=self.plan_id)
        with patch.object(operation.subprocess, "Popen") as launched:
            submitted = operation.submit_backup(self.root, repo, self.plan_id, self.key)
        self.assertEqual(submitted["state"], "submitted")
        self.assertNotIn(self.key.decode(), str(launched.call_args))
        with self.assertRaisesRegex(operation.OperationError, "already_claimed"):
            operation.submit_backup(self.root, repo, self.plan_id, self.key)

        original_create = operation.backup.create_backup
        def fake_create(*args, **kwargs):
            return original_create(*args, **kwargs,
                                   copier=lambda source, destination: shutil.copytree(source, destination))
        lifecycle_fd = os.open(Path(self.temporary.name) / "lifecycle.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fake_lifecycle = SimpleNamespace(ensure_mutation_preconditions=lambda _operation: lifecycle_fd)
        fake_api = SimpleNamespace(backup_preflight=lambda _destination: {
            "ready": True, "destination": str(self.destination), "volume_uuid": self.volume})
        with (patch.object(operation.backup, "read_backup_key", return_value=self.key),
              patch.object(operation, "load_repo_module", side_effect=[fake_lifecycle, fake_api]),
              patch.object(operation, "vm_identities", return_value=self.identities),
              patch.object(operation.backup, "create_backup", side_effect=fake_create)):
            self.assertEqual(operation.worker(self.root, repo, self.plan_id), 0)
        with patch.object(operation.backup, "verify_backup") as full_verify:
            self.assertEqual(operation.operation_status(self.root, self.plan_id, self.key)["state"], "verified")
            full_verify.assert_not_called()
        published = self.destination / f"secure-sandbox-backup-{self.plan_id}"
        (published / "vms" / "SecureSandbox-Gateway.pvm" / "config.pvs").write_text("tampered")
        self.assertEqual(operation.operation_status(self.root, self.plan_id, self.key)["state"], "verified")
        with self.assertRaisesRegex(backup.BackupError, "content_changed"):
            backup.verify_backup(published, self.key)


if __name__ == "__main__":
    unittest.main()
