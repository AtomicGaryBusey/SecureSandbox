from __future__ import annotations

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
        self.archived_ids = identities
        for name, identifier in identities.items():
            (self.live / f"{name}.pvm" / "uuid.txt").write_text(identifier)
        self.generation = Path(backup.create_backup(
            self.live, self.config, self.backups, identities,
            "11111111-1111-4111-8111-111111111111", self.key,
            copier=shutil.copytree)["path"])
        self.restore_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.current_ids = {name: f"{index:08x}-2222-4222-8222-222222222222"
                            for index, name in enumerate(backup.NAMES, 1)}
        for name, identifier in self.current_ids.items():
            (self.live / f"{name}.pvm" / "uuid.txt").write_text(identifier)

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
                         6 + len(backup.HOST_CONFIG_FILES))
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

    def test_swap_keeps_prior_generation_and_accepts_archived_registration(self):
        staged = restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                         restore_id=self.restore_id, bundle_copier=shutil.copytree)
        adapter = FakeAdapter(self.live)
        journal = restore.swap_candidate(Path(staged["stage"]), self.generation, self.live,
                                         self.key, adapter)
        self.assertEqual(journal["phase"], "accepted")
        self.assertEqual(adapter.registrations, self.archived_ids)
        self.assertTrue(Path(journal["old_vms"]).is_dir())
        self.assertEqual(restore.read_journal(self.stage_root / f"restore-{self.restore_id}.journal.json",
                                              self.key)["phase"], "accepted")

    def test_failed_acceptance_restores_original_bundles_and_registration(self):
        staged = restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                         restore_id=self.restore_id, bundle_copier=shutil.copytree)
        adapter = FakeAdapter(self.live, fail_accept=True)
        with self.assertRaisesRegex(restore.RestoreError, "rolled_back"):
            restore.swap_candidate(Path(staged["stage"]), self.generation, self.live,
                                   self.key, adapter)
        self.assertEqual(adapter.registrations, self.current_ids)
        self.assertTrue((self.stage_root / f"restore-{self.restore_id}.failed").is_dir())
        self.assertEqual(restore.read_journal(self.stage_root / f"restore-{self.restore_id}.journal.json",
                                              self.key)["phase"], "rolled_back")

    def test_rollback_resumes_after_candidate_was_moved_to_failed_quarantine(self):
        staged = restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                         restore_id=self.restore_id, bundle_copier=shutil.copytree)
        adapter = FakeAdapter(self.live)
        journal = restore.swap_candidate(Path(staged["stage"]), self.generation, self.live,
                                         self.key, adapter)
        adapter.stop()
        for identifier in list(adapter.registrations.values()):
            adapter.unregister(identifier)
        self.live.rename(Path(journal["failed_vms"]))
        recovered = restore.rollback_swap(self.stage_root / f"restore-{self.restore_id}.journal.json",
                                          self.key, adapter)
        self.assertEqual(recovered["phase"], "rolled_back")
        self.assertEqual(adapter.registrations, self.current_ids)

    def test_journal_tamper_is_rejected_before_recovery(self):
        staged = restore.stage_candidate(self.generation, self.stage_root, self.live, self.key,
                                         restore_id=self.restore_id, bundle_copier=shutil.copytree)
        adapter = FakeAdapter(self.live)
        restore.swap_candidate(Path(staged["stage"]), self.generation, self.live, self.key, adapter)
        path = self.stage_root / f"restore-{self.restore_id}.journal.json"
        path.write_text(path.read_text().replace('"accepted"', '"prepared"'))
        with self.assertRaisesRegex(restore.RestoreError, "authentication_failed"):
            restore.rollback_swap(path, self.key, adapter)


class FakeAdapter:
    def __init__(self, live: Path, *, fail_accept: bool = False):
        self.live = live
        self.registrations = {name: (live / f"{name}.pvm" / "uuid.txt").read_text()
                              for name in backup.NAMES}
        self.fail_accept = fail_accept
        self.stopped = True

    def identity(self, name: str, home: Path) -> str | None:
        if not home.exists() or name not in self.registrations:
            return None
        if home.parent != self.live or not self.stopped:
            raise restore.RestoreError("fake_vm_not_stopped_at_expected_home")
        return self.registrations[name]

    def unregister(self, identifier: str) -> None:
        name = next(name for name, value in self.registrations.items() if value == identifier)
        del self.registrations[name]

    def register(self, home: Path) -> None:
        name = home.name.removesuffix(".pvm")
        if name in self.registrations:
            raise restore.RestoreError("fake_vm_name_collision")
        self.registrations[name] = (home / "uuid.txt").read_text()

    def accept(self) -> None:
        if self.fail_accept:
            self.stopped = False
            raise restore.RestoreError("fake_acceptance_failed")
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


if __name__ == "__main__":
    unittest.main()
