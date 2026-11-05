#!/usr/bin/env python3
"""Focused tests for whole-generation native Host artifact publication."""

from __future__ import annotations

import importlib.util
import os
import pwd
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parent.parent
HELPER_PATH = REPO / "scripts/native_host_generation_publication.py"
SPEC = importlib.util.spec_from_file_location(
    "native_host_generation_publication", HELPER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
PUBLICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLICATION)


class SimulatedCrash(BaseException):
    pass


class NativeHostGenerationPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidates = self.root / "candidates"
        self.private = self.root / "private"
        self.public = self.root / "public"
        self.candidates.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        self.public.mkdir(mode=0o755)
        self.state = self.private / "publication"
        PUBLICATION._existing_private_state_root(self.state)
        self.target = self.public / "host"

    def tearDown(self) -> None:
        for directory, _children, _files in os.walk(
            self.root, topdown=True, followlinks=False,
        ):
            os.chmod(directory, 0o700)
        self.temporary.cleanup()

    def generation(self, name: str, content: bytes) -> Path:
        root = self.candidates / name
        root.mkdir(mode=0o755)
        nested = root / "SignedProduct.app"
        nested.mkdir(mode=0o755)
        executable = nested / "executable"
        executable.write_bytes(content)
        executable.chmod(0o555)
        nested.chmod(0o555)
        receipt = root / "receipt.json"
        receipt.write_bytes(b"{}\n")
        receipt.chmod(0o444)
        return root

    def test_initial_publication_is_exact_whole_tree(self) -> None:
        candidate = self.generation("candidate", b"new")
        expected = PUBLICATION.tree_digest(candidate)
        result = PUBLICATION.publish_generation(
            candidate, self.target, self.state,
        )
        self.assertEqual(result, {"status": "verified", "tree_sha256": expected})
        self.assertEqual(PUBLICATION.tree_digest(self.target), expected)
        self.assertFalse((self.state / PUBLICATION.JOURNAL_NAME).exists())
        self.assertFalse(list(self.state.glob("stage.*")))
        self.assertTrue(list(self.state.glob("completed.*.json")))

    def test_state_authority_binds_persistent_private_lock(self) -> None:
        lock = self.state / PUBLICATION.LOCK_NAME
        info = lock.lstat()
        self.assertEqual(PUBLICATION.stat.S_IMODE(info.st_mode), 0o600)
        lock_value = PUBLICATION.json.loads(lock.read_bytes())
        self.assertEqual(lock_value["schema"], PUBLICATION.LOCK_SCHEMA)
        self.assertEqual(lock_value["inode"], self.state.lstat().st_ino)
        authority = PUBLICATION.json.loads(
            (self.state / PUBLICATION.AUTHORITY_NAME).read_bytes(),
        )
        self.assertEqual(
            authority["lock_identity"], PUBLICATION._inode_record(info),
        )
        self.assertEqual(
            authority["lock_sha256"],
            PUBLICATION.hashlib.sha256(lock.read_bytes()).hexdigest(),
        )

    def test_every_bootstrap_crash_boundary_retries_without_deletion(self) -> None:
        events = (
            "bootstrap-directory-created",
            "bootstrap-lock-created",
            "bootstrap-lock-durable",
            "bootstrap-authority-created",
            "bootstrap-authority-durable",
            "bootstrap-state-durable",
            "bootstrap-validated",
            "bootstrap-published",
            "bootstrap-parent-durable",
        )
        for index, event in enumerate(events):
            with self.subTest(event=event):
                requested = self.private / f"bootstrap-{index}"

                def crash(name: str) -> None:
                    if name == event:
                        raise SimulatedCrash()

                with self.assertRaises(SimulatedCrash):
                    PUBLICATION._existing_private_state_root(
                        requested, checkpoint=crash,
                    )
                orphans = list(self.private.glob(
                    f".{requested.name}.bootstrap.*",
                ))
                orphan_identities = {
                    path.name: (path.lstat().st_dev, path.lstat().st_ino)
                    for path in orphans
                }
                PUBLICATION._existing_private_state_root(requested)
                state, _state_info = PUBLICATION._open_state_root(requested)
                os.close(state)
                for path in orphans:
                    self.assertTrue(path.exists())
                    self.assertEqual(
                        (path.lstat().st_dev, path.lstat().st_ino),
                        orphan_identities[path.name],
                    )

    def test_concurrent_publishers_are_serialized_before_reconciliation(self) -> None:
        first = self.generation("first", b"first")
        second = self.generation("second", b"second")
        first_digest = PUBLICATION.tree_digest(first)
        second_digest = PUBLICATION.tree_digest(second)
        first_paused = threading.Event()
        release_first = threading.Event()
        second_attempted_lock = threading.Event()
        second_finished = threading.Event()
        results: dict[str, object] = {}
        failures: list[BaseException] = []
        real_flock = PUBLICATION.fcntl.flock

        def observed_flock(descriptor: int, operation: int):
            if (threading.current_thread().name == "publisher-2"
                    and operation & PUBLICATION.fcntl.LOCK_EX):
                second_attempted_lock.set()
            return real_flock(descriptor, operation)

        def first_checkpoint(name: str) -> None:
            if name == "journal-committed":
                first_paused.set()
                if not release_first.wait(5):
                    raise RuntimeError("concurrent-publication-test-timeout")

        def run_first() -> None:
            try:
                results["first"] = PUBLICATION.publish_generation(
                    first, self.target, self.state,
                    checkpoint=first_checkpoint,
                )
            except BaseException as error:
                failures.append(error)

        def run_second() -> None:
            try:
                results["second"] = PUBLICATION.publish_generation(
                    second, self.target, self.state,
                )
            except BaseException as error:
                failures.append(error)
            finally:
                second_finished.set()

        with mock.patch.object(
            PUBLICATION.fcntl, "flock", side_effect=observed_flock,
        ):
            publisher_one = threading.Thread(
                target=run_first, name="publisher-1",
            )
            publisher_two = threading.Thread(
                target=run_second, name="publisher-2",
            )
            publisher_one.start()
            self.assertTrue(first_paused.wait(5))
            publisher_two.start()
            self.assertTrue(second_attempted_lock.wait(5))
            self.assertFalse(second_finished.is_set())
            release_first.set()
            publisher_one.join(5)
            publisher_two.join(5)
        self.assertFalse(publisher_one.is_alive())
        self.assertFalse(publisher_two.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(PUBLICATION.tree_digest(self.target), second_digest)
        completed = list(self.state.glob("completed.*.json"))
        self.assertEqual(len(completed), 2)
        second_journal = next(
            PUBLICATION.json.loads(path.read_bytes())
            for path in completed
            if PUBLICATION.json.loads(path.read_bytes())[
                "candidate_tree_sha256"
            ] == second_digest
        )
        self.assertEqual(
            second_journal["predecessor_tree_sha256"], first_digest,
        )
        self.assertIsNotNone(second_journal["predecessor_identity"])
        self.assertEqual(len(list(self.state.glob("retained.*.predecessor"))), 1)

    def test_pre_swap_crash_reconciles_forward_without_split_tree(self) -> None:
        old = self.generation("old", b"old")
        PUBLICATION.publish_generation(old, self.target, self.state)
        old_digest = PUBLICATION.tree_digest(self.target)
        candidate = self.generation("candidate", b"new")
        expected = PUBLICATION.tree_digest(candidate)

        def crash(name: str) -> None:
            if name == "journal-committed":
                raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state, checkpoint=crash,
            )
        self.assertEqual(PUBLICATION.tree_digest(self.target), old_digest)
        result = PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(result, {"status": "verified", "tree_sha256": expected})
        self.assertEqual(PUBLICATION.tree_digest(self.target), expected)

    def test_post_swap_crash_keeps_complete_candidate_and_finishes(self) -> None:
        old = self.generation("old", b"old")
        PUBLICATION.publish_generation(old, self.target, self.state)
        candidate = self.generation("candidate", b"new")
        expected = PUBLICATION.tree_digest(candidate)

        def crash(name: str) -> None:
            if name == "generation-swapped":
                raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state, checkpoint=crash,
            )
        self.assertEqual(PUBLICATION.tree_digest(self.target), expected)
        result = PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(result, {"status": "verified", "tree_sha256": expected})
        self.assertFalse(list(self.state.glob("stage.*")))
        self.assertTrue(list(self.state.glob("retained.*.predecessor")))

    def test_damaged_post_swap_candidate_rolls_back_exact_predecessor(self) -> None:
        old = self.generation("old", b"old")
        PUBLICATION.publish_generation(old, self.target, self.state)
        predecessor = PUBLICATION.tree_digest(self.target)
        candidate = self.generation("candidate", b"new")

        def crash(name: str) -> None:
            if name == "generation-swapped":
                raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state, checkpoint=crash,
            )
        executable = self.target / "SignedProduct.app/executable"
        executable.chmod(0o755)
        executable.write_bytes(b"tampered")
        executable.chmod(0o555)
        with self.assertRaisesRegex(
            PUBLICATION.PublicationRolledBack,
            "publication_candidate_failed_readback",
        ):
            PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(PUBLICATION.tree_digest(self.target), predecessor)
        self.assertFalse((self.state / PUBLICATION.JOURNAL_NAME).exists())

    def test_damaged_initial_candidate_is_quarantined_without_deletion(self) -> None:
        candidate = self.generation("candidate", b"new")

        def crash(name: str) -> None:
            if name == "generation-swapped":
                raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state, checkpoint=crash,
            )
        executable = self.target / "SignedProduct.app/executable"
        executable.chmod(0o755)
        executable.write_bytes(b"tampered")
        executable.chmod(0o555)
        with self.assertRaisesRegex(
            PUBLICATION.PublicationRolledBack,
            "publication_candidate_failed_readback",
        ):
            PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertFalse(self.target.exists())
        rejected = list(self.state.glob("retained.*.rejected"))
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            (rejected[0] / "SignedProduct.app/executable").read_bytes(),
            b"tampered",
        )

    def test_link_in_candidate_is_rejected_before_journal(self) -> None:
        candidate = self.generation("candidate", b"new")
        (candidate / "link").symlink_to(candidate / "receipt.json")
        with self.assertRaisesRegex(
            PUBLICATION.PublicationError, "publication_tree_symlink",
        ):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        self.assertFalse((self.state / PUBLICATION.JOURNAL_NAME).exists())
        self.assertFalse(self.target.exists())

    def test_stage_is_durably_synced_before_journal_authority(self) -> None:
        candidate = self.generation("candidate", b"new")
        events: list[str] = []
        original_sync = PUBLICATION._durably_sync_tree
        original_write = PUBLICATION._write_journal

        def sync(path: Path) -> None:
            events.append("durable-tree")
            original_sync(path)

        def write(path: Path, value: dict[str, object]) -> None:
            events.append("journal")
            original_write(path, value)

        with mock.patch.object(
            PUBLICATION, "_durably_sync_tree", side_effect=sync,
        ), mock.patch.object(
            PUBLICATION, "_write_journal", side_effect=write,
        ):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        self.assertLess(events.index("durable-tree"), events.index("journal"))

    def test_durable_sync_reaches_files_and_directories(self) -> None:
        candidate = self.generation("candidate", b"new")
        kinds: set[str] = set()
        original_fsync = PUBLICATION.os.fsync

        def fsync(descriptor: int) -> None:
            info = os.fstat(descriptor)
            if PUBLICATION.stat.S_ISREG(info.st_mode):
                kinds.add("file")
            elif PUBLICATION.stat.S_ISDIR(info.st_mode):
                kinds.add("directory")
            original_fsync(descriptor)

        with mock.patch.object(PUBLICATION.os, "fsync", side_effect=fsync):
            PUBLICATION._durably_sync_tree(candidate)
        self.assertEqual(kinds, {"file", "directory"})

    def test_journal_mode_is_applied_before_file_fsync(self) -> None:
        calls: list[str] = []
        original_fchmod = PUBLICATION.os.fchmod
        original_fsync = PUBLICATION.os.fsync

        def fchmod(descriptor: int, mode: int) -> None:
            calls.append(f"chmod:{mode:o}")
            original_fchmod(descriptor, mode)

        def fsync(descriptor: int) -> None:
            calls.append("fsync")
            original_fsync(descriptor)

        value = PUBLICATION._journal_value(
            target=self.target, publication_id="1" * 32,
            stage_name="stage." + ("1" * 32),
            candidate_digest="a" * 64,
            candidate_identity={"device": 1, "inode": 1},
            predecessor_digest=None, predecessor_identity=None,
        )
        with mock.patch.object(PUBLICATION.os, "fchmod", side_effect=fchmod), \
                mock.patch.object(PUBLICATION.os, "fsync", side_effect=fsync):
            PUBLICATION._write_journal(self.state, value)
        self.assertLess(calls.index("chmod:600"), calls.index("fsync"))

    def test_terminal_publication_retains_evidence_without_path_deletion(self) -> None:
        old = self.generation("old", b"old")
        candidate = self.generation("candidate", b"candidate")
        PUBLICATION.publish_generation(old, self.target, self.state)
        with mock.patch.object(
            PUBLICATION.os, "unlink",
            side_effect=AssertionError("publication must not unlink evidence"),
        ), mock.patch.object(
            PUBLICATION.os, "rmdir",
            side_effect=AssertionError("publication must not rmdir evidence"),
        ):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state,
            )
        self.assertTrue(list(self.state.glob("retained.*.predecessor")))
        self.assertTrue(list(self.state.glob("completed.*.json")))

    def test_swap_rejects_substituted_stage_before_public_exposure(self) -> None:
        old = self.generation("old", b"old")
        candidate = self.generation("candidate", b"candidate")
        substitute = self.generation("substitute", b"malicious")
        PUBLICATION.publish_generation(old, self.target, self.state)
        predecessor = PUBLICATION.tree_digest(self.target)
        parked = self.state / "parked-authentic-stage"

        def substitute_operand(name: str) -> None:
            if name != "swap-operands-opened":
                return
            stage = next(self.state.glob("stage.*"))
            stage.rename(parked)
            substitute.rename(stage)

        with self.assertRaisesRegex(
            PUBLICATION.PublicationError, "publication_swap_operand_changed",
        ):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state,
                checkpoint=substitute_operand,
            )
        self.assertEqual(PUBLICATION.tree_digest(self.target), predecessor)
        self.assertNotEqual(
            PUBLICATION.tree_digest(self.target),
            PUBLICATION.tree_digest(self.state / next(
                path.name for path in self.state.glob("stage.*")
            )),
        )

    def test_initial_rename_rejects_substituted_stage_before_publication(self) -> None:
        candidate = self.generation("candidate", b"candidate")
        substitute = self.generation("substitute", b"malicious")
        parked = self.state / "parked-authentic-stage"

        def substitute_operand(name: str) -> None:
            if name != "rename-operands-opened":
                return
            stage = next(self.state.glob("stage.*"))
            stage.rename(parked)
            substitute.rename(stage)

        with self.assertRaisesRegex(
            PUBLICATION.PublicationError, "publication_rename_source_changed",
        ):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state,
                checkpoint=substitute_operand,
            )
        self.assertFalse(self.target.exists())

    def test_syscall_lookup_substitution_is_compensated_before_failure(self) -> None:
        candidate = self.generation("candidate", b"candidate")
        substitute = self.generation("substitute", b"malicious")
        parked = self.state / "parked-authentic-stage"
        original = PUBLICATION._renameatx
        attacked = False

        def attack_at_syscall(source_parent, source_name,
                              destination_parent, destination_name, flags):
            nonlocal attacked
            if (not attacked and flags & PUBLICATION.RENAME_EXCL
                    and destination_name == self.target.name):
                attacked = True
                stage = self.state / source_name
                stage.rename(parked)
                substitute.rename(stage)
            return original(
                source_parent, source_name,
                destination_parent, destination_name, flags,
            )

        with mock.patch.object(
            PUBLICATION, "_renameatx", side_effect=attack_at_syscall,
        ), self.assertRaisesRegex(
            PUBLICATION.PublicationError,
            "publication_rename_identity_mismatch",
        ):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        self.assertTrue(attacked)
        self.assertFalse(self.target.exists())
        quarantined = list(self.state.glob("quarantine.*"))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(
            (quarantined[0] / "SignedProduct.app/executable").read_bytes(),
            b"malicious",
        )

    def test_syscall_swap_substitution_restores_public_predecessor(self) -> None:
        old = self.generation("old", b"old")
        candidate = self.generation("candidate", b"candidate")
        substitute = self.generation("substitute", b"malicious")
        PUBLICATION.publish_generation(old, self.target, self.state)
        predecessor = PUBLICATION.tree_digest(self.target)
        parked = self.state / "parked-authentic-stage"
        original = PUBLICATION._renameatx
        attacked = False

        def attack_at_syscall(source_parent, source_name,
                              destination_parent, destination_name, flags):
            nonlocal attacked
            if not attacked and flags & PUBLICATION.RENAME_SWAP:
                attacked = True
                stage = self.state / source_name
                stage.rename(parked)
                substitute.rename(stage)
            return original(
                source_parent, source_name,
                destination_parent, destination_name, flags,
            )

        with mock.patch.object(
            PUBLICATION, "_renameatx", side_effect=attack_at_syscall,
        ), self.assertRaisesRegex(
            PUBLICATION.PublicationError,
            "publication_swap_identity_mismatch",
        ):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        self.assertTrue(attacked)
        self.assertEqual(PUBLICATION.tree_digest(self.target), predecessor)
        self.assertEqual(
            (self.target / "SignedProduct.app/executable").read_bytes(),
            b"old",
        )

    def test_post_syscall_displacement_quarantines_public_mismatch(self) -> None:
        old = self.generation("old", b"old")
        candidate = self.generation("candidate", b"candidate")
        public_substitute = self.generation(
            "public-substitute", b"public-malicious",
        )
        stage_substitute = self.generation(
            "stage-substitute", b"stage-malicious",
        )
        PUBLICATION.publish_generation(old, self.target, self.state)
        original = PUBLICATION._renameatx
        attacked = False
        parked_candidate = self.state / "parked-published-candidate"
        parked_predecessor = self.state / "parked-exact-predecessor"

        def displace_after_syscall(source_parent, source_name,
                                   destination_parent, destination_name, flags):
            nonlocal attacked
            result = original(
                source_parent, source_name,
                destination_parent, destination_name, flags,
            )
            if not attacked and flags & PUBLICATION.RENAME_SWAP:
                attacked = True
                self.target.rename(parked_candidate)
                public_substitute.rename(self.target)
                stage = self.state / source_name
                stage.rename(parked_predecessor)
                stage_substitute.rename(stage)
            return result

        with mock.patch.object(
            PUBLICATION, "_renameatx", side_effect=displace_after_syscall,
        ), self.assertRaisesRegex(
            PUBLICATION.PublicationError,
            "publication_swap_identity_mismatch",
        ):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        self.assertTrue(attacked)
        self.assertFalse(self.target.exists())
        quarantined = list(self.state.glob("quarantine.*"))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(
            (quarantined[0] / "SignedProduct.app/executable").read_bytes(),
            b"public-malicious",
        )
        self.assertEqual(
            (parked_predecessor / "SignedProduct.app/executable").read_bytes(),
            b"old",
        )

    def test_crash_after_predecessor_retention_resumes_idempotently(self) -> None:
        old = self.generation("old", b"old")
        candidate = self.generation("candidate", b"candidate")
        PUBLICATION.publish_generation(old, self.target, self.state)
        expected = PUBLICATION.tree_digest(candidate)
        original = PUBLICATION._rename_generation_bound

        def crash_after_retention(source, destination, state_root, identity, **options):
            original(source, destination, state_root, identity, **options)
            if destination.name.endswith(".predecessor"):
                raise SimulatedCrash()

        with mock.patch.object(
            PUBLICATION, "_rename_generation_bound",
            side_effect=crash_after_retention,
        ), self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        result = PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(result, {"status": "verified", "tree_sha256": expected})

    def test_crash_after_rollback_swap_resumes_without_cleanup(self) -> None:
        old = self.generation("old", b"old")
        PUBLICATION.publish_generation(old, self.target, self.state)
        predecessor = PUBLICATION.tree_digest(self.target)
        candidate = self.generation("candidate", b"candidate")

        def crash(name: str) -> None:
            if name == "generation-swapped":
                raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state, checkpoint=crash,
            )
        executable = self.target / "SignedProduct.app/executable"
        executable.chmod(0o755)
        executable.write_bytes(b"tampered")
        executable.chmod(0o555)
        with mock.patch.object(
            PUBLICATION, "_retain_generation", side_effect=SimulatedCrash(),
        ), self.assertRaises(SimulatedCrash):
            PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(PUBLICATION.tree_digest(self.target), predecessor)
        with self.assertRaises(PUBLICATION.PublicationRolledBack):
            PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(PUBLICATION.tree_digest(self.target), predecessor)

    def test_rejected_child_tamper_blocks_terminal_archive(self) -> None:
        old = self.generation("old", b"old")
        PUBLICATION.publish_generation(old, self.target, self.state)
        predecessor = PUBLICATION.tree_digest(self.target)
        candidate = self.generation("candidate", b"candidate")

        def crash_after_swap(name: str) -> None:
            if name == "generation-swapped":
                raise SimulatedCrash()

        with self.assertRaises(SimulatedCrash):
            PUBLICATION.publish_generation(
                candidate, self.target, self.state,
                checkpoint=crash_after_swap,
            )
        executable = self.target / "SignedProduct.app/executable"
        executable.chmod(0o755)
        executable.write_bytes(b"first-tamper")
        executable.chmod(0o555)
        original_retain = PUBLICATION._retain_generation

        def retain_then_crash(*arguments, **keywords):
            original_retain(*arguments, **keywords)
            raise SimulatedCrash()

        with mock.patch.object(
            PUBLICATION, "_retain_generation",
            side_effect=retain_then_crash,
        ), self.assertRaises(SimulatedCrash):
            PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertEqual(PUBLICATION.tree_digest(self.target), predecessor)
        rejected = next(self.state.glob("retained.*.rejected"))
        record = list(self.state.glob("rejected.*.json"))
        self.assertEqual(len(record), 1)
        rejected_child = rejected / "SignedProduct.app/executable"
        rejected_child.chmod(0o755)
        rejected_child.write_bytes(b"second-tamper")
        rejected_child.chmod(0o555)
        with self.assertRaisesRegex(
            PUBLICATION.PublicationError,
            "publication_rejected_generation_changed",
        ):
            PUBLICATION.reconcile_publication(self.target, self.state)
        self.assertTrue((self.state / PUBLICATION.JOURNAL_NAME).exists())
        self.assertFalse(list(self.state.glob("rolledback.*.json")))

    def test_state_root_creation_refuses_substituted_partial_evidence(self) -> None:
        requested = self.private / "raced-publication"
        substitute = self.root / "partial-state"
        substitute.mkdir(mode=0o700)
        evidence = substitute / "stage.old"
        evidence.mkdir(mode=0o700)
        sentinel = evidence / "retained"
        sentinel.write_text("evidence", encoding="utf-8")
        sentinel.chmod(0o600)
        parked = self.private / "parked-new-state"
        original = PUBLICATION._open_directory_entry
        raced = False
        substituted_path: Path | None = None

        def substitute_after_mkdir(parent, name, **options):
            nonlocal raced, substituted_path
            if (name.startswith(f".{requested.name}.bootstrap.")
                    and not raced):
                raced = True
                substituted_path = requested.parent / name
                substituted_path.rename(parked)
                substitute.rename(substituted_path)
            return original(parent, name, **options)

        with mock.patch.object(
            PUBLICATION, "_open_directory_entry",
            side_effect=substitute_after_mkdir,
        ), self.assertRaisesRegex(
            PUBLICATION.PublicationError,
            "publication_state_root_creation_raced",
        ):
            PUBLICATION._existing_private_state_root(requested)
        self.assertIsNotNone(substituted_path)
        assert substituted_path is not None
        self.assertFalse(requested.exists())
        self.assertEqual(
            (substituted_path / "stage.old/retained").read_text(
                encoding="utf-8",
            ),
            "evidence",
        )

    def test_cross_device_descendant_rejects_before_publication(self) -> None:
        candidate = self.generation("candidate", b"new")
        original = PUBLICATION._open_directory_entry

        def reject_descendant(parent, name, **options):
            if name == "SignedProduct.app":
                raise PUBLICATION.PublicationError(
                    "publication_cross_device_forbidden"
                )
            return original(parent, name, **options)

        with mock.patch.object(
            PUBLICATION, "_open_directory_entry",
            side_effect=reject_descendant,
        ), self.assertRaisesRegex(
            PUBLICATION.PublicationError,
            "publication_cross_device_forbidden",
        ):
            PUBLICATION.publish_generation(candidate, self.target, self.state)
        self.assertFalse(self.target.exists())

    def test_extended_acl_is_rejected(self) -> None:
        candidate = self.generation("candidate", b"new")
        receipt = candidate / "receipt.json"
        principal = pwd.getpwuid(os.geteuid()).pw_name
        subprocess.run(
            ["/bin/chmod", "+a", f"{principal} allow write", str(receipt)],
            check=True, capture_output=True,
        )
        try:
            with self.assertRaisesRegex(
                PUBLICATION.PublicationError, "publication_tree_entry_acl",
            ):
                PUBLICATION.publish_generation(
                    candidate, self.target, self.state,
                )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(receipt)],
                check=True, capture_output=True,
            )


class NativeHostBuilderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (
            REPO / "scripts/build-native-host-products.sh"
        ).read_text(encoding="utf-8")

    def test_builder_is_privileged_exact_archive_driver(self) -> None:
        for required in (
            "#!/bin/bash -p",
            "native_host_release_requires_public_release_branch",
            "status --porcelain=v1 --untracked-files=all",
            "native_host_release_source.py",
            "GIT_NO_REPLACE_OBJECTS=1",
            "verify-repo",
            "source_archive_sha256",
            "require_unchanged_release_source",
            "SECURE_SANDBOX_NATIVE_HOST_CANDIDATE_ONLY=1",
            "SECURE_SANDBOX_SWIFT_HERMETIC=1",
            "SECURE_SANDBOX_RELEASE_OUTPUT_ROOT",
        ):
            self.assertIn(required, self.script)

    def test_builder_binds_exact_identity_config_and_notary_job(self) -> None:
        team_setting = "SECURE_SANDBOX_DEVELOPMENT_TEAM = "
        team_setting += "389K3H8Y32"
        for required in (
            "SECURE_SANDBOX_DEVELOPER_ID_requires_SHA1_pin",
            "fixed_team=389K3H8Y32",
            "native_host_product_certificate_SHA1_mismatch",
            team_setting,
            'str(value.get("jobId","")).lower()!=sys.argv[2].lower()',
            'str(value["sha256"]).lower()!=sys.argv[3].lower()',
            "notary_submission_sha256",
        ):
            self.assertIn(required, self.script)

    def test_v3_receipt_has_closed_agreed_top_level_fields(self) -> None:
        for field in (
            "build_custody", "container_cdhash", "container_identifier",
            "container_manifest_sha256", "container_sha256",
            "container_size", "developer_id_certificate_sha1",
            "gatekeeper_assessed", "host_release_preimage_sha256",
            "notary_log_sha256", "notary_status",
            "notary_submission_id", "notary_submission_sha256", "products",
            "release_commit", "schema", "signing_config_sha256",
            "source_archive_sha256", "source_tree_sha256",
            "stapler_validated", "team_id",
        ):
            self.assertIn(f'"{field}"', self.script)
        self.assertIn(
            "secure-sandbox-native-host-products-notarization-v3",
            self.script,
        )
        self.assertIn(
            "SecureSandboxNativeHostProducts.source.tar", self.script,
        )
        self.assertIn("trusted-login-principal-v1", self.script)


if __name__ == "__main__":
    unittest.main()
