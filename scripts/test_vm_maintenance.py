#!/usr/bin/env python3

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("vm-maintenance.py")
SPEC = importlib.util.spec_from_file_location("vm_maintenance", SCRIPT)
VM = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VM)


class VmMaintenanceTests(unittest.TestCase):
    def test_parallels_json_uuid_is_normalized_to_transaction_form(self):
        bare = "-".join(("1" * 8, "2" * 4, "4" + "3" * 3, "8" + "4" * 3, "5" * 12))
        canonical = "{" + bare.lower() + "}"
        self.assertEqual(
            VM.normalize_vm_uuid(bare),
            canonical,
        )
        self.assertEqual(
            VM.normalize_vm_uuid("{" + bare + "}"),
            canonical,
        )
        for invalid in (None, "", "3967a31d-cea2-4cbf-8d7e", "../Gateway"):
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_uuid_invalid"):
                VM.normalize_vm_uuid(invalid)

    def test_vm_identity_accepts_actual_parallels_bare_json_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "SecureSandbox-Gateway.pvm"
            home.mkdir()
            bare = "-".join(("1" * 8, "2" * 4, "4" + "3" * 3, "8" + "4" * 3, "5" * 12))
            response = json.dumps([{
                "ID": bare,
                "Name": VM.NAMES[0], "State": "stopped", "Home": str(home) + "/",
            }])
            with mock.patch.object(VM, "run", return_value=response):
                identity = VM.vm_identity(VM.NAMES[0], home)
            self.assertEqual(identity["uuid"], "{" + bare + "}")

    def test_trusted_directory_validates_link_count_and_binds_stable_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            identity = VM.trusted_directory(path, os.geteuid())
            self.assertEqual(identity, (path.lstat().st_dev, path.lstat().st_ino))
            self.assertGreaterEqual(path.lstat().st_nlink, 1)

    def test_plan_digest_binds_all_security_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            with (mock.patch.object(VM, "trusted_repo", return_value=repo),
                  mock.patch.object(VM, "installer_path", return_value=Path("/protected/installer.iso")),
                  mock.patch.object(VM, "seed_hashes", return_value={role: role[0] * 64 for role in VM.ROLES}),
                  mock.patch.object(VM, "vm_inventory", return_value=[]),
                  mock.patch.object(VM, "prlctl_hash", return_value="a" * 64)):
                first = VM.build_plan(str(repo), "create", 501)
                second = VM.build_plan(str(repo), "create", 501)
            self.assertEqual(first, second)
            unsigned = dict(first)
            claimed = unsigned.pop("plan_sha256")
            self.assertEqual(claimed, hashlib.sha256(VM.canonical(unsigned)).hexdigest())
            unsigned["prlctl_sha256"] = "b" * 64
            self.assertNotEqual(claimed, hashlib.sha256(VM.canonical(unsigned)).hexdigest())

    def test_execution_requires_root_broker_before_privilege_drop(self):
        with mock.patch.object(VM.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(VM.MaintenanceError, "root_broker_required"):
                VM.drop_privileges(501)

    def test_each_operator_displayed_component_is_revalidated(self):
        plan = {
            "plan_sha256": "a" * 64, "prlctl_sha256": "b" * 64,
            "installer_sha256": "c" * 64,
            "seed_sha256": {role: str(index) * 64 for index, role in enumerate(VM.ROLES, start=1)},
        }
        expected = {key: plan[key] for key in ("prlctl_sha256", "installer_sha256", "seed_sha256")}
        VM.validate_plan_bindings(plan, plan["plan_sha256"], expected)
        for key in ("prlctl_sha256", "installer_sha256", "seed_sha256"):
            forged = dict(expected)
            forged[key] = ({role: "f" * 64 for role in VM.ROLES}
                           if key == "seed_sha256" else "f" * 64)
            with self.assertRaisesRegex(VM.MaintenanceError, "maintenance_component_binding_changed"):
                VM.validate_plan_bindings(plan, plan["plan_sha256"], forged)

    def test_same_name_substitution_is_never_deleted(self):
        original = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/original.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        substituted = {**original, "uuid": "{22222222-2222-4222-8222-222222222222}"}
        def fail_after_recording(*args):
            created = args[-2]
            created.append(original)
            raise VM.MaintenanceError("configure_failed")

        with (tempfile.TemporaryDirectory() as temporary,
              mock.patch.object(VM, "create_one", side_effect=fail_after_recording),
              mock.patch.object(VM, "vm_identity", return_value=substituted),
              mock.patch.object(VM.subprocess, "run") as cleanup):
            original["expected_home"] = str(Path(temporary) / f"vms/{VM.NAMES[0]}.pvm")
            substituted["expected_home"] = original["expected_home"]
            with self.assertRaisesRegex(VM.MaintenanceError, "configure_failed"):
                VM.create_all(Path(temporary), Path("/installer"))
        cleanup.assert_not_called()

    def test_privilege_drop_must_be_irreversible(self):
        account = mock.Mock(pw_name="operator", pw_gid=20, pw_dir="/Users/operator")
        with (mock.patch.object(VM.os, "geteuid", side_effect=[0, 501]),
              mock.patch.object(VM.os, "getuid", return_value=501),
              mock.patch.object(VM.pwd, "getpwuid", return_value=account),
              mock.patch.object(VM.os, "initgroups"), mock.patch.object(VM.os, "setgid"),
              mock.patch.object(VM.os, "setuid", side_effect=[None, OSError("denied")])):
            VM.drop_privileges(501)

    def test_partial_creation_deletes_only_vms_created_by_this_attempt(self):
        calls = []
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "", "state": "stopped", "bundle_device": 1, "bundle_inode": 2,
        }

        def fake_run(command, **_kwargs):
            calls.append(command)
            if len(command) > 1 and command[1] == "set":
                raise VM.MaintenanceError("simulated_failure")
            return ""

        with (tempfile.TemporaryDirectory() as temporary,
              mock.patch.object(VM, "run", side_effect=fake_run),
              mock.patch.object(VM.subprocess, "run") as cleanup):
            identity["expected_home"] = str(Path(temporary) / f"vms/{VM.NAMES[0]}.pvm")
            with mock.patch.object(VM, "vm_identity", return_value=identity):
                with self.assertRaisesRegex(VM.MaintenanceError, "simulated_failure"):
                    VM.create_all(Path(temporary), Path("/protected/installer.iso"))
        cleanup_commands = [call.args[0] for call in cleanup.call_args_list]
        self.assertTrue(any(command[1:3] == ["delete", identity["uuid"]] for command in cleanup_commands))
        self.assertFalse(any(len(command) > 2 and command[1] == "delete" and command[2] != identity["uuid"]
                             for command in cleanup_commands))

    def test_new_vm_is_journaled_before_every_configuration_step(self):
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/new.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        events = []

        def fake_run(command, **_kwargs):
            events.append(("run", command[1]))
            return ""

        def record(created):
            events.append(("journal", created["uuid"]))

        with (mock.patch.object(VM, "run", side_effect=fake_run),
              mock.patch.object(VM, "vm_identity", return_value=identity)):
            VM.create_one(Path("/repo"), VM.NAMES[0], 1, 2048, 12288,
                          Path("/seed"), Path("/installer"), [], record)
        self.assertEqual(events[0], ("run", "create"))
        self.assertEqual(events[1], ("journal", identity["uuid"]))
        self.assertTrue(all(event[0] == "run" for event in events[2:]))

    def test_crash_after_each_configuration_step_has_persisted_created_identity(self):
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/new.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        # There are currently 31 fixed configuration calls. Every simulated
        # abrupt stop after creation must observe the same already-persisted
        # identity before the failing call.
        for fail_at in range(1, 32):
            journal = []
            set_calls = 0

            def fake_run(command, **_kwargs):
                nonlocal set_calls
                if command[1] == "set":
                    set_calls += 1
                    if set_calls == fail_at:
                        raise KeyboardInterrupt("simulated abrupt stop")
                return ""

            with (mock.patch.object(VM, "run", side_effect=fake_run),
                  mock.patch.object(VM, "vm_identity", return_value=identity)):
                with self.assertRaises(KeyboardInterrupt):
                    VM.create_one(Path("/repo"), VM.NAMES[0], 1, 2048, 12288,
                                  Path("/seed"), Path("/installer"), [], journal.append)
            self.assertEqual(journal, [identity], f"configuration step {fail_at}")

    def test_bundle_is_revalidated_after_unregister_before_quarantine_move(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".private").mkdir(mode=0o700)
            source = repo / f"vms/{VM.NAMES[0]}.pvm"
            source.mkdir(parents=True)
            info = source.lstat()
            expected = [{
                "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
                "expected_home": str(source), "state": "stopped",
                "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
            }]

            def substitute_after_unregister(command, **_kwargs):
                if command[1] == "unregister":
                    source.rename(source.with_name("original-away.pvm"))
                    source.mkdir()
                return ""

            with (mock.patch.object(VM, "run", side_effect=substitute_after_unregister),
                  mock.patch.object(VM, "vm_identity", return_value=expected[0]),
                  mock.patch.object(VM, "recover_transaction", return_value=repo / "quarantine"),
                  mock.patch.object(VM, "create_all") as create_all):
                with self.assertRaisesRegex(VM.MaintenanceError, "vm_bundle_identity_changed"):
                    VM.reprovision(repo, Path("/installer"), expected, "a" * 64, os.geteuid())
            create_all.assert_not_called()
            self.assertTrue(source.is_dir())

    def test_reprovision_rollback_never_deletes_unowned_same_named_vms(self):
        source_by_name = {}
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for name in VM.NAMES:
                source = repo / f"vms/{name}.pvm"
                source.mkdir(parents=True)
                source_by_name[name] = source
            commands = []
            expected = []
            for index, name in enumerate(VM.NAMES, start=1):
                info = source_by_name[name].lstat()
                expected.append({
                    "name": name, "uuid": f"{{00000000-0000-4000-8000-{index:012d}}}",
                    "expected_home": str(source_by_name[name]), "state": "stopped",
                    "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
                })

            def fake_run(command, **_kwargs):
                commands.append(command)
                return ""

            identity_by_uuid = {item["uuid"]: item for item in expected}
            identity_by_uuid.update({item["name"]: item for item in expected})
            with (mock.patch.object(VM, "run", side_effect=fake_run),
                  mock.patch.object(VM, "vm_identity", side_effect=lambda selector, _home: identity_by_uuid[selector]),
                  mock.patch.object(VM, "create_all", side_effect=VM.MaintenanceError("fail")),
                  mock.patch.object(VM.subprocess, "run") as fallback):
                with self.assertRaisesRegex(VM.MaintenanceError, "fail"):
                    VM.reprovision(repo, Path("/protected/installer.iso"), expected, "a" * 64, os.geteuid())
            self.assertFalse(any(len(command) > 1 and command[1] == "delete" for command in commands))
            fallback.assert_not_called()
            for source in source_by_name.values():
                self.assertTrue(source.is_dir())

    def test_crash_left_transaction_restores_and_reregisters_original_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "vms").mkdir()
            (repo / ".private").mkdir(mode=0o700)
            directories = VM.maintenance_directories(repo, os.geteuid())
            quarantine = directories["quarantine"][0] / "20261021T000000Z-11111111-1111-4111-8111-111111111111"
            quarantine.mkdir(mode=0o700)
            directories["quarantine"] = (
                directories["quarantine"][0],
                VM.trusted_directory(directories["quarantine"][0], os.geteuid()),
            )
            originals = []
            for index, name in enumerate(VM.NAMES, start=1):
                bundle = quarantine / f"{name}.pvm"
                bundle.mkdir()
                info = bundle.lstat()
                originals.append({
                    "name": name, "uuid": f"{{00000000-0000-4000-8000-{index:012d}}}",
                    "expected_home": str(repo / f"vms/{name}.pvm"), "state": "stopped",
                    "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
                })
            transaction = {
                "schema": VM.TRANSACTION_SCHEMA, "repo": str(repo), "plan_sha256": "a" * 64,
                "quarantine": str(quarantine), "originals": originals,
                "unregistered": [item["uuid"] for item in originals],
                "displaced": list(VM.NAMES), "created": [],
            }
            VM.atomic_json(VM.transaction_path(repo), transaction)
            registered = set()
            commands = []

            def fake_run(command, capture=False):
                commands.append(command)
                if command[1] == "register":
                    name = Path(command[2]).stem
                    registered.add(next(item["uuid"] for item in originals if item["name"] == name))
                if command[1:5] == ["list", "--all", "--no-header", "--output"]:
                    return ""
                return ""

            def fake_identity(selector, _home):
                if selector not in registered:
                    raise VM.MaintenanceError("command_failed:prlctl:not found")
                return next(item for item in originals if item["uuid"] == selector)

            with (mock.patch.object(VM, "run", side_effect=fake_run),
                  mock.patch.object(VM, "vm_identity", side_effect=fake_identity)):
                VM.recover_transaction(repo, transaction, os.geteuid(), directories)
            self.assertFalse(VM.transaction_path(repo).exists())
            self.assertEqual(len([command for command in commands if command[1] == "register"]), 3)
            for name in VM.NAMES:
                self.assertTrue((repo / f"vms/{name}.pvm").is_dir())

    def test_recovery_preserves_substituted_created_identity(self):
        created = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/created.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        substituted = {**created, "uuid": "{22222222-2222-4222-8222-222222222222}"}
        with mock.patch.object(VM, "vm_identity", return_value=substituted), \
             mock.patch.object(VM, "run") as run:
            with self.assertRaisesRegex(VM.MaintenanceError, "recovery_created_identity_changed"):
                # The path checks precede original restoration, so only a minimal valid directory set is needed.
                with tempfile.TemporaryDirectory() as temporary:
                    repo = Path(temporary)
                    (repo / ".private").mkdir(mode=0o700)
                    directories = VM.maintenance_directories(repo, os.geteuid())
                    quarantine = directories["quarantine"][0] / "q"
                    quarantine.mkdir(mode=0o700)
                    directories["quarantine"] = (
                        directories["quarantine"][0],
                        VM.trusted_directory(directories["quarantine"][0], os.geteuid()),
                    )
                    transaction = {"quarantine": str(quarantine), "created": [created], "originals": []}
                    VM.recover_transaction(repo, transaction, os.geteuid(), directories)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
