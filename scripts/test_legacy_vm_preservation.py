import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXECUTOR = load("legacy_vm_preservation", ROOT / "scripts/legacy-vm-preservation.py")
PLANNER = load("legacy_vm_preservation_planner_test", ROOT / "scripts/plan-legacy-vm-preservation.py")


class LegacyVmPreservationTests(unittest.TestCase):
    def test_research_capacity_reserves_archive_and_import(self):
        bound = EXECUTOR.ARCHIVE_FIXED_OVERHEAD + 100
        inventory = {
            "paths": 0,
            "regular_bytes": 100,
            "research_destination_free_bytes": bound * 2 + EXECUTOR.MIN_RESERVE - 1,
        }
        filesystem = mock.Mock(f_bavail=bound * 3 + EXECUTOR.MIN_RESERVE, f_frsize=1)
        with mock.patch.object(EXECUTOR.os, "statvfs", return_value=filesystem):
            with self.assertRaisesRegex(
                    EXECUTOR.PreservationError, "insufficient_research_archive_storage"):
                EXECUTOR.require_archive_capacity("research", inventory, Path("/archives"))

    def test_research_capacity_accepts_exact_two_copy_bound(self):
        bound = EXECUTOR.ARCHIVE_FIXED_OVERHEAD + 100
        inventory = {
            "paths": 0,
            "regular_bytes": 100,
            "research_destination_free_bytes": bound * 2 + EXECUTOR.MIN_RESERVE,
        }
        filesystem = mock.Mock(f_bavail=bound * 2 + EXECUTOR.MIN_RESERVE, f_frsize=1)
        with mock.patch.object(EXECUTOR.os, "statvfs", return_value=filesystem):
            self.assertEqual(
                EXECUTOR.require_archive_capacity("research", inventory, Path("/archives")),
                bound,
            )

    def test_clone_uses_cow_command_and_revalidates_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.hdd"
            destination = root / "clone.hdd"
            source.mkdir(mode=0o700)
            (source / "DiskDescriptor.xml").write_text("descriptor")
            expected = PLANNER.disk_inventory(source, os.geteuid())["tree_metadata_sha256"]
            commands = []

            def copy(command, **_kwargs):
                commands.append(command)
                shutil.copytree(source, destination, copy_function=shutil.copy2)
                return mock.Mock(returncode=0)

            with mock.patch.object(EXECUTOR, "run", side_effect=copy):
                identity = EXECUTOR.clone_disk(
                    source, destination, PLANNER, os.geteuid(), expected
                )
            self.assertEqual(commands[0][:2], ["/bin/cp", "-cRp"])
            self.assertEqual(identity, (destination.lstat().st_dev, destination.lstat().st_ino))

    def test_clone_command_preserves_root_directory_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.hdd"
            destination = root / "clone.hdd"
            source.mkdir(mode=0o700)
            (source / "DiskDescriptor.xml").write_text("descriptor")
            source_mtime = source.lstat().st_mtime_ns

            EXECUTOR.run(
                ["/bin/cp", "-cRp", str(source), str(destination)], timeout=1800
            )

            self.assertEqual(destination.lstat().st_mtime_ns, source_mtime)
            self.assertEqual(
                PLANNER.disk_inventory(destination, os.geteuid())["tree_metadata_sha256"],
                PLANNER.disk_inventory(source, os.geteuid())["tree_metadata_sha256"],
            )

    def test_clone_rejects_changed_bytes_even_when_entry_count_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.hdd"
            destination = root / "clone.hdd"
            source.mkdir(mode=0o700)
            (source / "DiskDescriptor.xml").write_text("authorized")
            expected = PLANNER.disk_inventory(source, os.geteuid())["tree_metadata_sha256"]

            def corrupt_copy(_command, **_kwargs):
                shutil.copytree(source, destination, copy_function=shutil.copy2)
                (destination / "DiskDescriptor.xml").write_text("unauthorized")
                return mock.Mock(returncode=0)

            with mock.patch.object(EXECUTOR, "run", side_effect=corrupt_copy):
                with self.assertRaisesRegex(
                        EXECUTOR.PreservationError, "clone_inventory_mismatch"):
                    EXECUTOR.clone_disk(
                        source, destination, PLANNER, os.geteuid(), expected
                    )

    def test_attach_binds_exact_new_device_and_clone_path(self):
        clone = Path("/private/clone.hdd")
        inventories = [
            {"hdd0": "/current.hdd"},
            {"hdd0": "/current.hdd", "hdd1": str(clone)},
        ]
        with mock.patch.object(EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
             mock.patch.object(EXECUTOR, "hdd_inventory", side_effect=inventories), \
             mock.patch.object(EXECUTOR, "run"), \
             mock.patch.object(EXECUTOR.Path, "resolve", side_effect=lambda strict=True: clone):
            self.assertEqual(EXECUTOR.attach_clone("{uuid}", clone), "hdd1")

    def test_attach_rejects_running_transport_before_prlctl(self):
        with mock.patch.object(EXECUTOR, "vm_value", return_value={"State": "running"}), \
             mock.patch.object(EXECUTOR, "run") as run:
            with self.assertRaisesRegex(
                    EXECUTOR.PreservationError, "clone_attachment_requires_stopped_vm"):
                EXECUTOR.attach_clone("{uuid}", Path("/private/clone.hdd"))
        run.assert_not_called()

    def test_cold_attachment_binds_boot_disk_and_secondary_clone(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "clone.hdd"
            system = Path(directory) / "system.hdd"
            clone.mkdir()
            system.mkdir()
            plan = {"transport_vms": {"SecureSandbox-Research": {
                "uuid": "{uuid}", "system_disk": str(system),
            }}}
            with mock.patch.object(
                    EXECUTOR, "vm_value",
                    return_value={"State": "stopped", "Boot order": "hdd0 "}), \
                 mock.patch.object(
                     EXECUTOR, "hdd_inventory",
                     return_value={"hdd0": str(system), "hdd1": str(clone)}):
                EXECUTOR.assert_cold_attachment(plan, "hdd1", clone)

    def test_cold_attachment_rejects_secondary_boot_entry(self):
        clone = Path("/private/clone.hdd")
        plan = {"transport_vms": {"SecureSandbox-Research": {
            "uuid": "{uuid}", "system_disk": "/private/system.hdd",
        }}}
        with mock.patch.object(
                EXECUTOR, "vm_value",
                return_value={"State": "stopped", "Boot order": "hdd0 hdd1"}), \
             mock.patch.object(
                 EXECUTOR, "hdd_inventory",
                 return_value={"hdd0": "/private/system.hdd", "hdd1": str(clone)}):
            with self.assertRaisesRegex(
                    EXECUTOR.PreservationError,
                    "cold_attachment_invariant_failed:boot_order"):
                EXECUTOR.assert_cold_attachment(plan, "hdd1", clone)

    def test_attach_clone_reasserts_system_disk_as_sole_boot_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "clone.hdd"
            system = Path(directory) / "system.hdd"
            clone.mkdir()
            system.mkdir()
            inventories = iter([
                {"hdd0": str(system)},
                {"hdd0": str(system), "hdd1": str(clone)},
            ])
            with mock.patch.object(
                    EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
                 mock.patch.object(
                     EXECUTOR, "hdd_inventory", side_effect=lambda _uuid: next(inventories)), \
                 mock.patch.object(EXECUTOR, "run") as run:
                self.assertEqual(EXECUTOR.attach_clone("{uuid}", clone), "hdd1")
        self.assertEqual(run.call_args_list[-2], mock.call([
            str(EXECUTOR.PRLCTL), "set", "{uuid}",
            "--device-bootorder", "hdd0",
        ], timeout=180))
        self.assertEqual(run.call_args_list[-1], mock.call([
            str(EXECUTOR.PRLCTL), "set", "{uuid}",
            "--auto-share-gamepad", "off",
        ], timeout=180))

    def test_attach_clone_detaches_if_boot_order_cannot_be_reasserted(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "clone.hdd"
            system = Path(directory) / "system.hdd"
            clone.mkdir()
            system.mkdir()
            inventories = iter([
                {"hdd0": str(system)},
                {"hdd0": str(system), "hdd1": str(clone)},
            ])
            with mock.patch.object(
                    EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
                 mock.patch.object(
                     EXECUTOR, "hdd_inventory", side_effect=lambda _uuid: next(inventories)), \
                 mock.patch.object(
                     EXECUTOR, "run", side_effect=[
                         None, EXECUTOR.PreservationError("boot_order_failed"), None,
                     ]) as run:
                with self.assertRaisesRegex(
                        EXECUTOR.PreservationError, "boot_order_failed"):
                    EXECUTOR.attach_clone("{uuid}", clone)
        self.assertEqual(run.call_args_list[-1], mock.call([
            str(EXECUTOR.PRLCTL), "set", "{uuid}",
            "--device-del", "hdd1",
        ], timeout=180))

    def test_stop_research_waits_through_parallels_stopping_state(self):
        plan = {"transport_vms": {
            "SecureSandbox-Research": {"uuid": "{research}"},
        }}
        with mock.patch.object(EXECUTOR, "client_command"), \
             mock.patch.object(EXECUTOR, "wait_stopped", return_value=True) as wait, \
             mock.patch.object(EXECUTOR, "wait_vm_state") as wait_state, \
             mock.patch.object(EXECUTOR, "run") as run:
            EXECUTOR.stop_research(plan)

        wait.assert_called_once_with("{research}", timeout=180)
        wait_state.assert_called_once_with("{research}", "stopped")
        run.assert_not_called()

    def test_detach_reasserts_gamepad_sharing_boundary(self):
        clone = Path("/private/clone.hdd")
        with mock.patch.object(EXECUTOR, "run") as run, \
             mock.patch.object(EXECUTOR, "hdd_inventory", return_value={}):
            EXECUTOR.detach_clone("{research}", "hdd1", clone)

        self.assertEqual(run.call_args_list, [
            mock.call([
                str(EXECUTOR.PRLCTL), "set", "{research}",
                "--device-del", "hdd1",
            ], timeout=180),
            mock.call([
                str(EXECUTOR.PRLCTL), "set", "{research}",
                "--auto-share-gamepad", "off",
            ], timeout=180),
        ])

    def test_guest_deployment_binds_every_uploaded_file_to_plan_hash(self):
        planner = mock.Mock()
        planner.TOOL_PATHS = PLANNER.TOOL_PATHS
        plan = {"tools": {name: f"{index:064x}" for index, name in enumerate(
            PLANNER.TOOL_PATHS, start=1)}}
        planner.sha256_regular.side_effect = lambda path: next(
            plan["tools"][name] for name, candidate in PLANNER.TOOL_PATHS.items()
            if candidate == path
        )
        with mock.patch.object(EXECUTOR, "run") as run:
            EXECUTOR.deploy_tools(plan, planner)
        command = run.call_args.args[0]
        self.assertEqual(command.count("--file"), 9)
        for name in (
            "deployment", "control_policy", "exporter", "guest_preserver",
            "archive_verifier", "continuity_planner", "continuity_importer",
            "continuity_control", "session_registry",
        ):
            self.assertIn(plan["tools"][name], command)

    def test_remove_clone_requires_recorded_identity_and_exact_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone_root = root / "clones"
            clone = clone_root / "research.hdd"
            clone.mkdir(parents=True)
            identity = (clone.lstat().st_dev, clone.lstat().st_ino)
            EXECUTOR.remove_clone(clone, identity, clone_root)
            self.assertFalse(clone.exists())

    def test_plan_change_rejects_before_any_vm_start(self):
        planner = mock.Mock()
        planner.build_plan.return_value = {"plan_sha256": "a" * 64}
        with mock.patch.object(EXECUTOR, "load_module", return_value=planner), \
             mock.patch.object(EXECUTOR, "start_transport") as start:
            with self.assertRaisesRegex(EXECUTOR.PreservationError, "preservation_plan_changed"):
                EXECUTOR.execute(Path("/repo"), "20261021T040946Z", 501, "b" * 64)
        start.assert_not_called()

    def test_recovery_detaches_exact_recorded_clone_before_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {name: base / name for name in ("archives", "clones", "receipts")}
            for path in roots.values():
                path.mkdir(mode=0o700)
            clone = roots["clones"] / "research.hdd"
            clone.mkdir()
            clone_info = clone.lstat()
            root_info = roots["clones"].lstat()
            transaction = {
                "schema": EXECUTOR.TRANSACTION_SCHEMA, "plan_sha256": "a" * 64,
                "role": "research", "clone": str(clone),
                "clone_device": clone_info.st_dev, "clone_inode": clone_info.st_ino,
                "clone_root_device": root_info.st_dev, "clone_root_inode": root_info.st_ino,
                "attached_device": "hdd1", "phase": "attached",
                "temporary_archive": None, "temporary_device": None, "temporary_inode": None,
            }
            transaction_path = base / "transaction.json"
            transaction_path.write_bytes(EXECUTOR.canonical(transaction))
            transaction_path.chmod(0o600)
            digest = hashlib.sha256(transaction_path.read_bytes()).hexdigest()
            plan = {
                "generation": "20261021T040946Z", "plan_sha256": "b" * 64,
                "recovery_transaction_sha256": digest,
                "transport_vms": {
                    "SecureSandbox-Research": {"uuid": "{research}"},
                    "SecureSandbox-Gateway": {"uuid": "{gateway}"},
                },
            }
            with mock.patch.object(EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
                 mock.patch.object(EXECUTOR, "hdd_inventory", return_value={"hdd1": str(clone)}), \
                 mock.patch.object(EXECUTOR, "detach_clone") as detach:
                result = EXECUTOR.recover_transaction(
                    plan, roots, os.geteuid(), transaction_path
                )
            detach.assert_called_once_with("{research}", "hdd1", clone)
            self.assertEqual(result["status"], "recovered")
            self.assertFalse(clone.exists())
            self.assertFalse(transaction_path.exists())

    def test_recovery_accepts_transport_started_after_cleanup_already_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {name: base / name for name in ("archives", "clones", "receipts")}
            for path in roots.values():
                path.mkdir(mode=0o700)
            clone = roots["clones"] / "research.hdd"
            root_info = roots["clones"].lstat()
            transaction = {
                "schema": EXECUTOR.TRANSACTION_SCHEMA, "plan_sha256": "a" * 64,
                "role": "research", "clone": str(clone),
                "clone_device": root_info.st_dev, "clone_inode": 123456789,
                "clone_root_device": root_info.st_dev, "clone_root_inode": root_info.st_ino,
                "attached_device": "hdd1", "phase": "transport_started",
                "temporary_archive": None, "temporary_device": None, "temporary_inode": None,
            }
            transaction_path = base / "transaction.json"
            transaction_path.write_bytes(EXECUTOR.canonical(transaction))
            transaction_path.chmod(0o600)
            digest = hashlib.sha256(transaction_path.read_bytes()).hexdigest()
            plan = {
                "generation": "20261021T040946Z", "plan_sha256": "b" * 64,
                "recovery_transaction_sha256": digest,
                "transport_vms": {
                    "SecureSandbox-Research": {"uuid": "{research}"},
                    "SecureSandbox-Gateway": {"uuid": "{gateway}"},
                },
            }
            with mock.patch.object(EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
                 mock.patch.object(EXECUTOR, "hdd_inventory", return_value={}):
                result = EXECUTOR.recover_transaction(
                    plan, roots, os.geteuid(), transaction_path
                )
            self.assertEqual(result["status"], "recovered")
            self.assertFalse(transaction_path.exists())

    def test_recovery_never_removes_replacement_at_recorded_clone_path(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {name: base / name for name in ("archives", "clones", "receipts")}
            for path in roots.values():
                path.mkdir(mode=0o700)
            clone = roots["clones"] / "research.hdd"
            clone.mkdir()
            root_info = roots["clones"].lstat()
            transaction = {
                "schema": EXECUTOR.TRANSACTION_SCHEMA, "plan_sha256": "a" * 64,
                "role": "research", "clone": str(clone),
                "clone_device": clone.lstat().st_dev, "clone_inode": clone.lstat().st_ino + 1,
                "clone_root_device": root_info.st_dev, "clone_root_inode": root_info.st_ino,
                "attached_device": None, "phase": "transport_started",
                "temporary_archive": None, "temporary_device": None, "temporary_inode": None,
            }
            transaction_path = base / "transaction.json"
            transaction_path.write_bytes(EXECUTOR.canonical(transaction))
            transaction_path.chmod(0o600)
            digest = hashlib.sha256(transaction_path.read_bytes()).hexdigest()
            plan = {
                "generation": "20261021T040946Z", "plan_sha256": "b" * 64,
                "recovery_transaction_sha256": digest,
                "transport_vms": {
                    "SecureSandbox-Research": {"uuid": "{research}"},
                    "SecureSandbox-Gateway": {"uuid": "{gateway}"},
                },
            }
            with mock.patch.object(EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
                 mock.patch.object(EXECUTOR, "hdd_inventory", return_value={}):
                with self.assertRaisesRegex(
                        EXECUTOR.PreservationError, "clone_cleanup_identity_mismatch"):
                    EXECUTOR.recover_transaction(
                        plan, roots, os.geteuid(), transaction_path
                    )
            self.assertTrue(clone.is_dir())
            self.assertTrue(transaction_path.is_file())

    def test_recovery_discards_unreceipted_derivative_for_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {name: base / name for name in ("archives", "clones", "receipts")}
            for path in roots.values():
                path.mkdir(mode=0o700)
            clone = roots["clones"] / "research.hdd"
            clone.mkdir()
            clone_info = clone.lstat()
            root_info = roots["clones"].lstat()
            archive = roots["archives"] / "research.tar.gz"
            archive.write_bytes(b"verified-but-not-yet-receipted")
            archive.chmod(0o600)
            transaction = {
                "schema": EXECUTOR.TRANSACTION_SCHEMA, "plan_sha256": "a" * 64,
                "role": "research", "clone": str(clone),
                "clone_device": clone_info.st_dev, "clone_inode": clone_info.st_ino,
                "clone_root_device": root_info.st_dev, "clone_root_inode": root_info.st_ino,
                "attached_device": None, "phase": "attached",
                "temporary_archive": str(archive.with_name(".research.tar.gz.new-old")),
                "temporary_device": None, "temporary_inode": None,
            }
            transaction_path = base / "transaction.json"
            transaction_path.write_bytes(EXECUTOR.canonical(transaction))
            transaction_path.chmod(0o600)
            digest = hashlib.sha256(transaction_path.read_bytes()).hexdigest()
            plan = {
                "generation": "20261021T040946Z", "plan_sha256": "b" * 64,
                "recovery_transaction_sha256": digest,
                "transport_vms": {
                    "SecureSandbox-Research": {"uuid": "{research}"},
                    "SecureSandbox-Gateway": {"uuid": "{gateway}"},
                },
            }
            with mock.patch.object(EXECUTOR, "vm_value", return_value={"State": "stopped"}), \
                 mock.patch.object(EXECUTOR, "hdd_inventory", return_value={}):
                EXECUTOR.recover_transaction(plan, roots, os.geteuid(), transaction_path)
            self.assertFalse(archive.exists())

    def test_normal_run_never_binds_an_unreceipted_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {name: base / name for name in ("archives", "clones", "receipts")}
            for path in roots.values():
                path.mkdir(mode=0o700)
            (roots["archives"] / "gateway.tar.gz").write_bytes(b"preseeded")
            with self.assertRaisesRegex(
                    EXECUTOR.PreservationError,
                    "unreceipted_preservation_requires_recovery:gateway"):
                EXECUTOR.preserve_role(
                    "gateway", {}, roots, mock.Mock(), mock.Mock(), mock.Mock(),
                    os.geteuid(), base / "transaction.json",
                )

    def test_existing_receipt_retains_creating_plan_across_authorized_resume(self):
        verification = {
            "archive_sha256": "1" * 64,
            "manifest_sha256": "2" * 64,
            "omitted_special_files": 0,
            "paths": 3,
            "regular_bytes": 4,
            "role": "research",
            "schema": "secure-sandbox-legacy-preservation-verification-v1",
            "status": "verified",
        }
        plan = {
            "generation": "20261021T040946Z",
            "plan_sha256": "b" * 64,
            "sources": {"research": {
                "legacy_vm_uuid": "{legacy}",
                "config_sha256": "3" * 64,
                "disk_descriptor_sha256": "4" * 64,
                "disk": {"tree_metadata_sha256": "5" * 64},
            }},
            "transport_vms": {
                "SecureSandbox-Research": {"uuid": "{research}"},
            },
        }
        receipt = EXECUTOR.bind_receipt("research", verification, plan)
        receipt["plan_sha256"] = "a" * 64
        verifier = mock.Mock()
        verifier.verify.return_value = verification

        verified = EXECUTOR.verify_bound_receipt(
            "research", Path("/archive"), receipt, plan, verifier
        )

        self.assertEqual(verified, receipt)
        self.assertEqual(verified["plan_sha256"], "a" * 64)

    def test_existing_receipt_rejects_invalid_creating_plan_hash(self):
        verification = {
            "archive_sha256": "1" * 64,
            "manifest_sha256": "2" * 64,
            "omitted_special_files": 0,
            "paths": 3,
            "regular_bytes": 4,
            "role": "research",
            "schema": "secure-sandbox-legacy-preservation-verification-v1",
            "status": "verified",
        }
        plan = {
            "generation": "20261021T040946Z",
            "plan_sha256": "b" * 64,
            "sources": {"research": {
                "legacy_vm_uuid": "{legacy}",
                "config_sha256": "3" * 64,
                "disk_descriptor_sha256": "4" * 64,
                "disk": {"tree_metadata_sha256": "5" * 64},
            }},
            "transport_vms": {
                "SecureSandbox-Research": {"uuid": "{research}"},
            },
        }
        receipt = EXECUTOR.bind_receipt("research", verification, plan)
        receipt["plan_sha256"] = "not-a-digest"
        verifier = mock.Mock()
        verifier.verify.return_value = verification

        with self.assertRaisesRegex(
                EXECUTOR.PreservationError,
                "existing_preservation_conflict:research"):
            EXECUTOR.verify_bound_receipt(
                "research", Path("/archive"), receipt, plan, verifier
            )

    def test_preservation_set_binds_current_and_creating_plans(self):
        plan = {
            "generation": "20261021T040946Z",
            "plan_sha256": "9" * 64,
            "sources": {
                role: {"disk": {"tree_metadata_sha256": str(index) * 64}}
                for index, role in enumerate(EXECUTOR.ROLES, start=1)
            },
            "transport_vms": {
                "SecureSandbox-Research": {"uuid": "{research}"},
            },
        }
        receipts = {
            role: {
                "archive_sha256": chr(ord("a") + index) * 64,
                "plan_sha256": chr(ord("d") + index) * 64,
            }
            for index, role in enumerate(EXECUTOR.ROLES)
        }

        result = EXECUTOR.preservation_set_receipt(plan, receipts)

        self.assertEqual(result["plan_sha256"], "9" * 64)
        self.assertEqual(
            result["creating_plan_sha256"],
            {role: receipts[role]["plan_sha256"] for role in EXECUTOR.ROLES},
        )
        self.assertEqual(
            result["archive_sha256"],
            {role: receipts[role]["archive_sha256"] for role in EXECUTOR.ROLES},
        )

    def test_recovery_rejects_clone_root_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {name: base / name for name in ("archives", "clones", "receipts")}
            for path in roots.values():
                path.mkdir(mode=0o700)
            clone = roots["clones"] / "gateway.hdd"
            transaction = {
                "schema": EXECUTOR.TRANSACTION_SCHEMA, "plan_sha256": "a" * 64,
                "role": "gateway", "clone": str(clone),
                "clone_device": None, "clone_inode": None,
                "clone_root_device": 1, "clone_root_inode": 2,
                "attached_device": None, "phase": "cloning",
                "temporary_archive": None, "temporary_device": None, "temporary_inode": None,
            }
            path = base / "transaction.json"
            path.write_bytes(EXECUTOR.canonical(transaction))
            path.chmod(0o600)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(EXECUTOR.PreservationError, "transaction_invalid"):
                EXECUTOR.read_transaction(path, digest, roots, os.geteuid())


if __name__ == "__main__":
    unittest.main()
