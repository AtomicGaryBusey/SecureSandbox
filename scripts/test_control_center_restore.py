import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import control_center_backup as backup
from scripts import control_center_restore as restore


class RestoreStageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.live = self.root / "live-vms"
        self.config = self.root / "config"
        self.backups = self.root / "backups"
        self.stage_root = self.root / "restore-stages"
        for directory in (self.live, self.config, self.backups):
            directory.mkdir()
        for name in backup.NAMES:
            bundle = self.live / f"{name}.pvm"
            bundle.mkdir()
            (bundle / "config.pvs").write_text(name)
        for name in backup.HOST_CONFIG_FILES:
            (self.config / name).write_text(name)
        self.key = b"k" * 32
        identities = {name: f"{index:08x}-1111-4111-8111-111111111111"
                      for index, name in enumerate(backup.NAMES, 1)}
        self.generation = Path(backup.create_backup(
            self.live, self.config, self.backups, identities,
            "11111111-1111-4111-8111-111111111111", self.key,
            copier=shutil.copytree)["path"])
        self.restore_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    def tearDown(self):
        self.temporary.cleanup()

    def test_staging_preserves_live_vms_and_verifies_both_payload_sets(self):
        original = backup.inventory(self.live)
        result = restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                         restore_id=self.restore_id, bundle_copier=shutil.copytree)
        ready = Path(result["stage"])
        self.assertTrue(ready.is_dir())
        self.assertEqual(backup.inventory(self.live), original)
        self.assertEqual(restore.verify_candidate(ready, self.generation, self.key)["file_count"],
                         3 + len(backup.HOST_CONFIG_FILES))
        with self.assertRaisesRegex(restore.RestoreError, "collision"):
            restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                    restore_id=self.restore_id, bundle_copier=shutil.copytree)
        (ready / "host-config" / backup.HOST_CONFIG_FILES[0]).write_text("tampered")
        with self.assertRaisesRegex(restore.RestoreError, "content_changed"):
            restore.verify_candidate(ready, self.generation, self.key)

    def test_interrupted_stage_remains_incomplete_and_never_replaces_live_vms(self):
        def fail_copy(_source, _destination):
            raise RuntimeError("copy interrupted")
        with self.assertRaisesRegex(RuntimeError, "copy interrupted"):
            restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                    restore_id=self.restore_id, bundle_copier=fail_copy)
        self.assertTrue((self.stage_root / f".restore-{self.restore_id}.incomplete").is_dir())
        self.assertFalse((self.stage_root / f"restore-{self.restore_id}.ready").exists())
        self.assertEqual(len(list(self.live.iterdir())), 3)


if __name__ == "__main__":
    unittest.main()
