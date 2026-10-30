import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import control_center_backup as backup


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir()
        self.destination.mkdir()
        self.config = self.root / "config"
        self.config.mkdir()
        for name in backup.HOST_CONFIG_FILES:
            (self.config / name).write_text(name, encoding="utf-8")
        for name in backup.NAMES:
            bundle = self.source / f"{name}.pvm"
            bundle.mkdir()
            (bundle / "config.pvs").write_text(name, encoding="utf-8")
        self.identities = {name: f"{index:08x}-1111-4111-8111-111111111111"
                           for index, name in enumerate(backup.NAMES, 1)}
        self.key = b"k" * 32
        self.volume = "11111111-1111-4111-8111-111111111111"

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def copier(source: Path, destination: Path) -> None:
        shutil.copytree(source, destination, copy_function=shutil.copy2)

    def test_backup_publishes_only_after_authenticated_readback(self):
        generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        result = backup.create_backup(self.source, self.config, self.destination, self.identities,
                                      self.volume, self.key, copier=self.copier,
                                      generation=generation)
        published = Path(result["path"])
        self.assertTrue(published.is_dir())
        self.assertEqual(backup.verify_backup(published, self.key)["file_count"], 3 + len(backup.HOST_CONFIG_FILES))
        self.assertEqual(len(list(self.destination.iterdir())), 1)
        self.assertEqual(backup.backup_status(self.destination, generation, self.key)["state"], "verified")
        with self.assertRaisesRegex(backup.BackupError, "authentication_failed"):
            backup.verify_backup(published, b"x" * 32)
        (published / "vms" / "SecureSandbox-Gateway.pvm" / "config.pvs").write_text("tampered")
        self.assertEqual(backup.verify_backup_metadata(published, self.key)["generation_id"], generation)
        with self.assertRaisesRegex(backup.BackupError, "content_changed"):
            backup.verify_backup(published, self.key)

    def test_backup_rejects_changed_host_configuration(self):
        result = backup.create_backup(self.source, self.config, self.destination, self.identities,
                                      self.volume, self.key, copier=self.copier)
        published = Path(result["path"])
        (published / "host-config" / backup.HOST_CONFIG_FILES[0]).write_text("tampered")
        with self.assertRaisesRegex(backup.BackupError, "content_changed"):
            backup.verify_backup(published, self.key)

    def test_finder_metadata_does_not_change_exact_vm_bundle_inventory(self):
        baseline = backup.inventory(self.source)
        (self.source / ".DS_Store").write_bytes(b"Finder metadata")
        self.assertEqual(backup.inventory(self.source), baseline)
        result = backup.create_backup(self.source, self.config, self.destination, self.identities,
                                      self.volume, self.key, copier=self.copier)
        self.assertTrue(Path(result["path"]).is_dir())
        self.assertEqual(backup.inventory(self.source), backup.inventory(Path(result["path"]) / "vms"))

    def test_finder_metadata_beside_published_generation_is_bounded(self):
        result = backup.create_backup(self.source, self.config, self.destination, self.identities,
                                      self.volume, self.key, copier=self.copier)
        published = Path(result["path"])
        metadata = published / ".DS_Store"
        metadata.write_bytes(b"Finder metadata")
        self.assertEqual(backup.verify_backup_metadata(published, self.key)["generation_id"], result["generation_id"])
        self.assertEqual(backup.verify_backup(published, self.key)["generation_id"], result["generation_id"])
        metadata.unlink()
        metadata.symlink_to(self.config / backup.HOST_CONFIG_FILES[0])
        with self.assertRaisesRegex(backup.BackupError, "generation_incomplete"):
            backup.verify_backup_metadata(published, self.key)
        metadata.unlink()
        metadata.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(backup.BackupError, "generation_incomplete"):
            backup.verify_backup_metadata(published, self.key)

    def test_unexpected_or_untrusted_vm_root_entries_still_fail(self):
        unexpected = self.source / "unexpected"
        unexpected.write_text("not a VM", encoding="utf-8")
        with self.assertRaisesRegex(backup.BackupError, "bundle_set_invalid"):
            backup.inventory(self.source)
        unexpected.unlink()
        metadata = self.source / ".DS_Store"
        metadata.symlink_to(self.config / backup.HOST_CONFIG_FILES[0])
        with self.assertRaisesRegex(backup.BackupError, "bundle_set_invalid"):
            backup.inventory(self.source)

    def test_failed_copy_remains_incomplete_and_unpublished(self):
        def fail_copy(_source: Path, _destination: Path) -> None:
            raise RuntimeError("copy interrupted")
        generation = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        with self.assertRaisesRegex(RuntimeError, "copy interrupted"):
            backup.create_backup(self.source, self.config, self.destination, self.identities,
                                 self.volume, self.key, copier=fail_copy,
                                 generation=generation)
        names = [entry.name for entry in self.destination.iterdir()]
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].endswith(".incomplete"))
        self.assertFalse((self.destination / names[0] / "COMPLETE").exists())
        self.assertEqual(backup.backup_status(self.destination, generation, self.key)["state"], "incomplete")
        with self.assertRaisesRegex(backup.BackupError, "collision"):
            backup.create_backup(self.source, self.config, self.destination, self.identities,
                                 self.volume, self.key, copier=self.copier,
                                 generation=generation)

    def test_key_reader_accepts_bounded_vault_value_without_exposing_it(self):
        with patch.object(backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"k" * 64 + b"\n", b"")):
            self.assertEqual(len(backup.read_backup_key()), 64)
        with (patch.object(backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"private diagnostic")) as run,
              patch.object(backup.time, "sleep")):
            with self.assertRaisesRegex(backup.BackupError, "key_unavailable"):
                backup.read_backup_key()
            self.assertEqual(run.call_count, backup.BACKUP_KEY_ATTEMPTS)

    def test_key_reader_recovers_from_transient_cli_failure(self):
        failed = subprocess.CompletedProcess([], 1, b"", b"private diagnostic")
        succeeded = subprocess.CompletedProcess([], 0, b"k" * 64 + b"\n", b"")
        with (patch.object(backup.subprocess, "run", side_effect=[failed, succeeded]) as run,
              patch.object(backup.time, "sleep") as sleep):
            self.assertEqual(backup.read_backup_key(), b"k" * 64)
            self.assertEqual(run.call_count, 2)
            sleep.assert_called_once_with(backup.BACKUP_KEY_RETRY_DELAYS[0])

    def test_key_reader_recovers_from_transient_timeout(self):
        timed_out = subprocess.TimeoutExpired(["op-agents", "read"], 5)
        succeeded = subprocess.CompletedProcess([], 0, b"k" * 64 + b"\n", b"")
        with (patch.object(backup.subprocess, "run", side_effect=[timed_out, succeeded]),
              patch.object(backup.time, "sleep")):
            self.assertEqual(backup.read_backup_key(), b"k" * 64)


if __name__ == "__main__":
    unittest.main()
