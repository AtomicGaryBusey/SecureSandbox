import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


restore = load("restore_fresh_vms", ROOT / "scripts/restore-fresh-vms.py")
pki = load("pki_operation", ROOT / "scripts/pki-operation.py")


class FreshVmRestorationTests(unittest.TestCase):
    def test_phase_child_does_not_inherit_blocked_termination_signals(self):
        result = restore.run_phase(
            (restore.sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)"),
            restore.DeferredSignals(),
        )
        self.assertEqual(result, -restore.signal.SIGTERM)

    def test_dependency_order_keeps_run_leases_last_before_acceptance(self):
        names = [name for name, _ in restore.PHASES]
        self.assertLess(names.index("pki_generation"), names.index("source_acquisition"))
        self.assertLess(names.index("disposable_execution"), names.index("evidence_receipts"))
        self.assertLess(names.index("evidence_receipts"), names.index("findings"))
        self.assertEqual(
            names[-4:],
            ["run_leases", "hot_acceptance", "cold_boot_acceptance", "publication_safety"],
        )

    def test_bounded_provisioning_receives_preflight_bound_vm_uuids(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            inventory = {
                "SecureSandbox-Gateway": {"uuid": "11111111-1111-4111-8111-111111111111", "home": "/g"},
                "SecureSandbox-Research": {"uuid": "22222222-2222-4222-8222-222222222222", "home": "/r"},
                "SecureSandbox-Target": {"uuid": "33333333-3333-4333-8333-333333333333", "home": "/t"},
            }
            observed = []
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", (("bounded_package_provisioning", ("scripts/provision-fresh-vm-dependencies.sh", "--apply")),)),
                  mock.patch.object(restore, "preflight", return_value=(inventory, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "input_digest", return_value="a" * 64),
                  mock.patch.object(restore, "run_phase", side_effect=lambda parts, _deferred: observed.append(parts) or 0)):
                self.assertEqual(restore.apply(), 0)
            self.assertEqual(observed, [(
                "scripts/provision-fresh-vm-dependencies.sh", "--apply",
                "--gateway-uuid", inventory["SecureSandbox-Gateway"]["uuid"],
                "--research-uuid", inventory["SecureSandbox-Research"]["uuid"],
                "--target-uuid", inventory["SecureSandbox-Target"]["uuid"],
            )])

    def test_failed_phase_is_not_journaled_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            phases = (("one", ("/bin/true",)), ("two", ("/bin/false",)))
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", phases),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "input_digest", return_value="a" * 64),
                  mock.patch.object(restore, "run_phase", side_effect=[0, 1])):
                with self.assertRaises(restore.subprocess.CalledProcessError):
                    restore.apply()
            value = json.loads(journal.read_text())
            self.assertEqual(value["status"], "pending")
            self.assertEqual(value["completed"], ["one"])

    def test_resume_rejects_changed_vm_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "a" * 64,
                "vms": {"old": {}}, "completed": [],
            })
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "preflight", return_value=({"new": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller")):
                with self.assertRaisesRegex(restore.RestoreFailure, "identity_changed"):
                    restore.apply()

    def test_explicit_restart_archives_incomplete_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            journal = private / "current.json"
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "old", "vms": {}, "completed": [],
            })
            with (mock.patch.object(restore, "PRIVATE", private),
                  mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", ()),
                  mock.patch.object(restore, "preflight", return_value=({"new": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=private / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "input_digest", return_value="a" * 64)):
                self.assertEqual(restore.apply(restart=True), 0)
            self.assertEqual(json.loads(journal.read_text())["status"], "complete")
            self.assertEqual(len(list(private.glob("abandoned-*.json"))), 1)

    def test_archive_is_no_replace_and_directory_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            journal = private / "current.json"
            journal.write_text("new evidence\n", encoding="utf-8")
            fixed = datetime(2026, 10, 21, 12, 34, 56, 123456, tzinfo=timezone.utc)
            class FixedDateTime:
                @classmethod
                def now(cls, _timezone):
                    return fixed
            collision = private / f"abandoned-{fixed.strftime('%Y%m%dT%H%M%S.%fZ')}-{'a' * 32}.json"
            collision.write_text("old evidence\n", encoding="utf-8")
            with (mock.patch.object(restore, "PRIVATE", private),
                  mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "datetime", FixedDateTime),
                  mock.patch.object(
                      restore.uuid, "uuid4",
                      side_effect=(SimpleNamespace(hex="a" * 32), SimpleNamespace(hex="b" * 32)),
                  ),
                  mock.patch.object(restore, "fsync_directory", wraps=restore.fsync_directory) as fsync):
                archived = restore.archive_incomplete_journal()
            self.assertEqual(collision.read_text(encoding="utf-8"), "old evidence\n")
            self.assertEqual(archived.read_text(encoding="utf-8"), "new evidence\n")
            self.assertFalse(journal.exists())
            self.assertEqual(fsync.call_count, 2)
            self.assertEqual(os.stat(archived).st_nlink, 1)

    def test_source_change_during_phase_prevents_journal_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            phases = (("one", ("/bin/true",)),)
            digest = "a" * 64
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", phases),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, digest)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "input_digest", side_effect=[digest, "b" * 64]),
                  mock.patch.object(restore, "run_phase", return_value=0)):
                with self.assertRaisesRegex(restore.RestoreFailure, "identity_changed:after:one"):
                    restore.apply()
            value = json.loads(journal.read_text())
            self.assertEqual(value["status"], "pending")
            self.assertEqual(value["completed"], [])

    def test_pki_recovery_replays_exact_generation_only_at_pki_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            generation = "11111111-1111-4111-8111-111111111111"
            phases = (
                ("pki_lifecycle", ("/bin/true",)),
                ("pki_generation", ("/bin/false",)),
            )
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "a" * 64,
                "vms": {"vm": {}}, "completed": ["pki_lifecycle"],
            })
            observed = []
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", phases),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "pki_recovery_candidate", return_value=generation),
                  mock.patch.object(restore, "anchor_value", return_value={"generation_id": generation}),
                  mock.patch.object(restore, "input_digest", return_value="a" * 64),
                  mock.patch.object(restore, "run_phase", side_effect=lambda parts, _deferred: observed.append(parts) or 0)):
                self.assertEqual(restore.apply(recover_pki_generation=generation), 0)
            self.assertEqual(
                observed,
                [(restore.sys.executable, "scripts/pki-operation.py", "rotate", generation,
                  "--recover", "--inherited-lock")],
            )

    def test_pki_recovery_rejects_already_completed_pki_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            generation = "11111111-1111-4111-8111-111111111111"
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "a" * 64,
                "vms": {"vm": {}}, "completed": ["foundation", "pki_generation"],
            })
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", (
                      ("foundation", ("/bin/true",)),
                      ("pki_generation", ("/bin/true",)),
                  )),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller")):
                with self.assertRaisesRegex(restore.RestoreFailure, "pki_recovery_phase_invalid"):
                    restore.apply(recover_pki_generation=generation)

    def test_restart_can_replay_prior_phases_then_recover_exact_pki_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            journal = private / "current.json"
            generation = "11111111-1111-4111-8111-111111111111"
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "old", "vms": {}, "completed": [],
            })
            observed = []
            with (mock.patch.object(restore, "PRIVATE", private),
                  mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", (
                      ("foundation", ("/bin/true",)),
                      ("pki_generation", ("/bin/false",)),
                  )),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=private / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "anchor_value", return_value=None),
                  mock.patch.object(restore, "input_digest", return_value="a" * 64),
                  mock.patch.object(restore, "run_phase", side_effect=lambda parts, _deferred: observed.append(parts) or 0)):
                self.assertEqual(
                    restore.apply(restart=True, recover_pki_generation=generation), 0,
                )
            self.assertEqual(observed[0], ("/bin/true",))
            self.assertEqual(
                observed[1],
                (restore.sys.executable, "scripts/pki-operation.py", "rotate", generation,
                 "--recover", "--inherited-lock"),
            )
            self.assertEqual(len(list(private.glob("abandoned-*.json"))), 1)

    def test_resume_requires_detected_exact_pki_recovery_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            generation = "11111111-1111-4111-8111-111111111111"
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "a" * 64,
                "vms": {"vm": {}}, "completed": ["pki_lifecycle"],
            })
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", (
                      ("pki_lifecycle", ("/bin/true",)),
                      ("pki_generation", ("/bin/true",)),
                  )),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "pki_recovery_candidate", return_value=generation)):
                with self.assertRaisesRegex(restore.RestoreFailure, f"pki_recovery_required:{generation}"):
                    restore.apply()

    def test_mismatched_detected_pki_recovery_generation_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "current.json"
            detected = "11111111-1111-4111-8111-111111111111"
            supplied = "22222222-2222-4222-8222-222222222222"
            restore.atomic_json(journal, {
                "schema": "secure-sandbox-fresh-vm-restoration-v1",
                "status": "pending", "source_digest": "a" * 64,
                "vms": {"vm": {}}, "completed": ["pki_lifecycle"],
            })
            with (mock.patch.object(restore, "JOURNAL", journal),
                  mock.patch.object(restore, "PHASES", (
                      ("pki_lifecycle", ("/bin/true",)),
                      ("pki_generation", ("/bin/true",)),
                  )),
                  mock.patch.object(restore, "preflight", return_value=({"vm": {}}, "a" * 64)),
                  mock.patch.object(restore.LAUNCHER, "acquire_lock", return_value=Path(temporary) / "lock"),
                  mock.patch.object(restore.LAUNCHER, "release_lock"),
                  mock.patch.object(restore, "require_no_active_controller"),
                  mock.patch.object(restore, "pki_recovery_candidate", return_value=detected)):
                with self.assertRaisesRegex(restore.RestoreFailure, "pki_recovery_generation_mismatch"):
                    restore.apply(recover_pki_generation=supplied)

    def test_legacy_same_second_anchor_commit_requires_recovery(self):
        generation = "11111111-1111-4111-8111-111111111111"
        journal = {
            "created_at": "2026-10-21T18:24:09.900000Z",
            "completed": ["pki_lifecycle"],
        }
        with mock.patch.object(
            restore,
            "anchor_value",
            side_effect=(None, {"generation_id": generation, "committed_at": 1792607049}),
        ):
            self.assertEqual(restore.pki_recovery_candidate(journal), generation)

    def test_exact_anchor_snapshot_detects_post_phase_change(self):
        old = {
            "generation_id": "11111111-1111-4111-8111-111111111111",
            "manifest_sha256": "a" * 64,
            "record_sha256": "b" * 64,
        }
        new = {
            "generation_id": "22222222-2222-4222-8222-222222222222",
            "manifest_sha256": "c" * 64,
            "record_sha256": "d" * 64,
        }
        journal = {
            "completed": ["pki_lifecycle"],
            "pki_anchor_before_generation": old,
        }
        with mock.patch.object(restore, "anchor_value", side_effect=(None, new)):
            self.assertEqual(
                restore.pki_recovery_candidate(journal), new["generation_id"],
            )

    def test_source_identity_includes_control_and_acceptance_inputs(self):
        source = (ROOT / "scripts" / "restore-fresh-vms.py").read_text(encoding="utf-8")
        for required in (
            'ROOT / "config" / "privileged-control.sudoers"',
            'ROOT / "config" / "ssh_config"',
            'ROOT / "config" / "sshd-control.conf"',
            'ROOT / "runs" / "control_key.pub"',
            'ROOT / ".gitignore"',
            'ROOT / ".private" / "public-deny-patterns.txt"',
            'paths.extend(public_worktree_paths())',
            'publication_identity()',
        ):
            self.assertIn(required, source)

    def test_publication_identity_binds_exact_head_and_tag_refs(self):
        head = b"a" * 40 + b"\n"
        tags = b"refs/tags/v1\0" + b"b" * 40 + b"\0tag\n"
        with mock.patch.object(
            restore.subprocess,
            "check_output",
            side_effect=(head, tags),
        ) as check_output:
            identity = restore.publication_identity()
        self.assertEqual(identity, b"HEAD\0" + head.strip() + b"\0TAGS\0" + tags)
        self.assertEqual(check_output.call_count, 2)

    def test_public_worktree_paths_reject_parent_traversal(self):
        with mock.patch.object(
            restore.subprocess,
            "check_output",
            return_value=b"../outside\0",
        ):
            with self.assertRaisesRegex(restore.RestoreFailure, "publication_worktree_path_invalid"):
                restore.public_worktree_paths()

    def test_hash_regular_file_rejects_ancestor_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "file").write_text("safe\n", encoding="utf-8")
            os.symlink(outside, root / "dir")
            with mock.patch.object(restore, "ROOT", root):
                with self.assertRaisesRegex(restore.RestoreFailure, "prerequisite_invalid"):
                    restore.hash_regular_file(root / "dir" / "file")

    def test_hash_regular_file_rejects_external_ancestor_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "file").write_text("safe\n", encoding="utf-8")
            os.symlink(outside, base / "external-link")
            with mock.patch.object(restore, "ROOT", root):
                with self.assertRaisesRegex(restore.RestoreFailure, "prerequisite_invalid"):
                    restore.hash_regular_file(base / "external-link" / "file")


class PkiOperationTests(unittest.TestCase):
    def test_pki_child_does_not_inherit_blocked_termination_signals(self):
        result = pki.run_child(
            [pki.sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)"],
            pki.os.environ.copy(),
            pki.DeferredSignals(),
        )
        self.assertEqual(result, -pki.signal.SIGTERM)

    def test_wrapper_holds_lock_through_child_and_passes_parent_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "active").mkdir()
            lock = state / "coordination.lock"
            lock.mkdir()
            (lock / "pid").write_text("1\n")
            observed = {}

            def child(_command, environment, _deferred):
                observed.update(environment)
                return 0

            with (mock.patch.object(pki.LAUNCHER, "STATE_ROOT", state),
                  mock.patch.object(pki.LAUNCHER, "acquire_lock", return_value=lock),
                  mock.patch.object(pki.LAUNCHER, "release_lock") as release,
                  mock.patch.object(pki, "protected_regular_file", return_value=True),
                  mock.patch.object(pki.subprocess, "run", return_value=mock.Mock(returncode=0)),
                  mock.patch.object(pki, "run_child", side_effect=child),
                  mock.patch.object(pki.sys, "argv", ["pki-operation.py", "deploy"])):
                self.assertEqual(pki.main(), 0)
            self.assertEqual(observed["SECURE_SANDBOX_STATE_ROOT"], str(state))
            self.assertEqual(observed["SECURE_SANDBOX_COORDINATION_PARENT_PID"], str(pki.os.getpid()))
            self.assertEqual(observed["SECURE_SANDBOX_COORDINATION_HOLDER_PID"], str(pki.os.getpid()))
            release.assert_called_once_with(lock)

    def test_inherited_lock_is_validated_and_not_released_by_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "active").mkdir()
            lock = state / "coordination.lock"
            lock.mkdir()
            (lock / "pid").write_text(f"{pki.os.getppid()}\n")
            environment = {
                "SECURE_SANDBOX_STATE_ROOT": str(state),
                "SECURE_SANDBOX_COORDINATION_HOLDER_PID": str(pki.os.getppid()),
            }
            with (mock.patch.object(pki.LAUNCHER, "STATE_ROOT", state),
                  mock.patch.object(pki.LAUNCHER, "acquire_lock") as acquire,
                  mock.patch.object(pki.LAUNCHER, "release_lock") as release,
                  mock.patch.object(pki, "protected_regular_file", return_value=True),
                  mock.patch.object(pki.subprocess, "run", return_value=mock.Mock(returncode=0)),
                  mock.patch.object(pki, "run_child", return_value=0),
                  mock.patch.dict(pki.os.environ, environment, clear=False),
                  mock.patch.object(pki.sys, "argv", ["pki-operation.py", "deploy", "--inherited-lock"])):
                self.assertEqual(pki.main(), 0)
            acquire.assert_not_called()
            release.assert_not_called()

    def test_recovery_mode_passes_exact_generation_and_explicit_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "active").mkdir()
            lock = state / "coordination.lock"
            lock.mkdir()
            (lock / "pid").write_text("1\n")
            observed = {}

            def child(command, environment, _deferred):
                observed["command"] = command
                observed["environment"] = environment
                return 0

            generation = "11111111-1111-4111-8111-111111111111"
            with (mock.patch.object(pki.LAUNCHER, "STATE_ROOT", state),
                  mock.patch.object(pki.LAUNCHER, "acquire_lock", return_value=lock),
                  mock.patch.object(pki.LAUNCHER, "release_lock"),
                  mock.patch.object(pki, "protected_regular_file", return_value=True),
                  mock.patch.object(pki.subprocess, "run", return_value=mock.Mock(returncode=0)),
                  mock.patch.object(pki, "run_child", side_effect=child),
                  mock.patch.object(
                      pki.sys, "argv",
                      ["pki-operation.py", "rotate", generation, "--recover",
                       "--requesting-agent", "Codex", "--requesting-session", "thread-7"],
                  )):
                self.assertEqual(pki.main(), 0)
            self.assertEqual(observed["command"][-1], generation)
            self.assertEqual(observed["environment"]["SECURE_SANDBOX_PKI_RECOVERY"], "1")
            self.assertEqual(observed["environment"]["SECURE_SANDBOX_REQUESTING_AGENT"], "Codex")
            self.assertEqual(observed["environment"]["SECURE_SANDBOX_REQUESTING_SESSION"], "thread-7")

    def test_explicit_generation_without_recovery_is_rejected(self):
        generation = "11111111-1111-4111-8111-111111111111"
        with mock.patch.object(pki.sys, "argv", ["pki-operation.py", "rotate", generation]):
            with self.assertRaises(SystemExit) as rejected:
                pki.main()
        self.assertEqual(rejected.exception.code, 2)

    def test_shell_entrypoints_require_pid_bound_parent_and_lifecycle_probe(self):
        for name in ("deploy-pki-lifecycle.sh", "rotate-pki-generation.sh"):
            source = (ROOT / "scripts" / name).read_text()
            self.assertNotIn("SECURE_SANDBOX_COORDINATION_LOCK_HELD", source)
            self.assertIn("SECURE_SANDBOX_COORDINATION_PARENT_PID", source)
            self.assertIn("SECURE_SANDBOX_COORDINATION_HOLDER_PID", source)
            self.assertIn('"$(< "$pid_file")" = "$coordination_holder"', source)
            self.assertIn("run lifecycle-idle", source)


if __name__ == "__main__":
    unittest.main()
