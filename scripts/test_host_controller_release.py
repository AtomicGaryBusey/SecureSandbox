#!/usr/bin/env python3

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
REPO = SCRIPT_DIR.parent
MANAGER_PATH = SCRIPT_DIR / "host-controller-release.py"
SPEC = importlib.util.spec_from_file_location("host_controller_release", MANAGER_PATH)
MANAGER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MANAGER)
LAUNCHER_PATH = SCRIPT_DIR / "secure-sandbox-claude-launcher.py"
LAUNCHER_SPEC = importlib.util.spec_from_file_location("secure_sandbox_launcher_test", LAUNCHER_PATH)
LAUNCHER = importlib.util.module_from_spec(LAUNCHER_SPEC)
assert LAUNCHER_SPEC.loader is not None
LAUNCHER_SPEC.loader.exec_module(LAUNCHER)


class HostControllerReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "config").mkdir()
        (self.repo / "seeds").mkdir()
        (self.repo / ".private").mkdir()
        (self.repo / ".private/secure-enclave-ddd.json").write_text(json.dumps({
            "schema":"secure-sandbox-secure-enclave-ddd-local-config-v1",
            "acceptance_source_id":"11111111-1111-4111-8111-111111111111",
            "legacy_launchservices_ui_bundle_sha256":"f" * 64,
        }) + "\n", encoding="ascii")
        (self.repo / ".private/secure-enclave-ddd.json").chmod(0o600)
        touchid_sources = [
            Path("macos/TouchIDAuthorization/Package.swift"),
            Path("macos/TouchIDAuthorization/AuthorizationUI.entitlements"),
            Path("macos/TouchIDAuthorization/Info.plist"),
            Path("macos/TouchIDAuthorization/Signing.example.xcconfig"),
            Path("macos/TouchIDAuthorization/SecureSandboxAuthorizationUI.xcodeproj/project.pbxproj"),
            Path("macos/TouchIDAuthorization/Sources/AuthorizationCore/AuthorizationRequest.swift"),
            Path("macos/TouchIDAuthorization/Sources/AuthorizationCore/ExecutionApprovalCrypto.swift"),
            Path("macos/TouchIDAuthorization/Sources/SecureSandboxAuthorizationUI/SecureEnclaveKeyStore.swift"),
            Path("macos/TouchIDAuthorization/Sources/SecureSandboxAuthorizationUI/main.swift"),
        ]
        for relative in [*MANAGER.PAYLOAD_SOURCES.values(), MANAGER.LAUNCHER_SOURCE,
                         *touchid_sources]:
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, self.repo / relative)
        shutil.copytree(
            REPO / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            self.repo / MANAGER.AUTHORIZATION_UI_APP_SOURCE,
            copy_function=shutil.copy2,
        )
        self.install_root = self.root / "installed"
        self.launcher = self.root / "bin/secure-sandbox-claude"
        self.state = self.root / "state"
        self.uid = os.geteuid()
        self.op_binary = self.root / "op"
        self.op_binary.write_bytes(b"test-op-binary\n")
        self.op_binary.chmod(0o755)
        self.gpgv_binary = self.root / "gpgv"
        self.gpgv_binary.write_bytes(b"test-gpgv-binary\n")
        self.gpgv_binary.chmod(0o755)
        # A live protocol-v2 installation deliberately makes the host floor
        # root-only. Unit tests must never inherit that machine-global state.
        self.execution_approval_floor = mock.patch.object(
            MANAGER, "EXECUTION_APPROVAL_FLOOR", self.root / "minimum-floor.json"
        )
        self.execution_approval_floor.start()

    def tearDown(self):
        self.execution_approval_floor.stop()
        self.temporary.cleanup()

    def install(self):
        return MANAGER.install(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            self.op_binary, self.gpgv_binary,
        )

    def test_install_and_verify_are_content_bound(self):
        deployed = self.install()
        verified = MANAGER.verify(
            self.repo, self.install_root, self.launcher, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        loaded_path, loaded_id = LAUNCHER.load_release(self.install_root, self.uid)
        self.assertEqual(deployed["release_id"], verified["release_id"])
        self.assertEqual((loaded_path.name, loaded_id), (verified["release_id"], verified["release_id"]))
        self.assertEqual(os.readlink(self.install_root / "current"), f"releases/{verified['release_id']}")
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# changed\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_release_source_mismatch"):
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )

    def test_execution_approval_floor_blocks_v1_release_rollback(self):
        floor = self.root / "minimum-floor.json"
        floor.write_text(json.dumps({
            "schema":"secure-sandbox-execution-approval-floor-v1",
            "minimum_protocol":2, "minimum_epoch":4, "updated_at":100,
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        floor.chmod(0o600)
        with mock.patch.object(MANAGER, "EXECUTION_APPROVAL_FLOOR", floor):
            MANAGER.enforce_execution_approval_floor(
                b"contains secure-sandbox-execution-approval-floor-enforcement-v2", self.uid
            )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "release_below_execution_approval_floor"
            ):
                MANAGER.enforce_execution_approval_floor(
                    b"has envelopes but not the monotonic floor gate: secure-sandbox-execution-approval-envelope-v2",
                    self.uid,
                )
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "release_below_execution_approval_floor"
            ):
                MANAGER.enforce_execution_approval_floor(b"v1 only", self.uid)

    def test_install_rejects_source_drift_from_authorized_release_identity(self):
        _values, _hashes, expected = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# changed after authorization\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "source_release_id_unexpected"):
            MANAGER.install(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                self.op_binary, self.gpgv_binary, expected,
            )

    def test_local_secure_enclave_config_is_bound_to_repo_owner_under_sudo(self):
        with mock.patch.object(MANAGER.os, "geteuid", return_value=0):
            _values, hashes, release_id = MANAGER.source_payload(
                self.repo, self.op_binary, self.gpgv_binary,
            )
        self.assertEqual(release_id, MANAGER.release_identity(hashes))

    def test_capacity_recovery_archives_inactive_releases_without_deleting_history(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 3):
            first = self.install()["release_id"]
            for suffix in ("second", "third"):
                with (self.repo / "scripts/claude-run-controller.sh").open(
                    "a", encoding="utf-8"
                ) as handle:
                    handle.write(f"# {suffix}\n")
                latest = self.install()["release_id"]
            self.assertNotEqual(first, latest)
            # A power loss in the narrow chmod-before-rename window leaves an
            # inactive source writable only by root; recovery must resume.
            (self.install_root / "releases" / first).chmod(0o755)
            plan = MANAGER.release_archive_plan(self.install_root, self.uid)
            self.assertEqual(plan["archive_release_ids"], [first])
            with mock.patch.object(
                MANAGER, "enforce_execution_approval_floor",
                wraps=MANAGER.enforce_execution_approval_floor,
            ) as floor:
                result = MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"], plan["previous_release_id"],
                    plan["plan_sha256"],
                )
            # Current and rollback remain activation-floor checked.  The
            # inactive target is integrity-verified but deliberately exempt
            # because archival makes it non-selectable.
            self.assertEqual(floor.call_count, 2)
            self.assertEqual(result["archived"], 1)
            self.assertFalse((self.install_root / "releases" / first).exists())
            self.assertTrue((self.install_root / "release-archive" / first).is_dir())
            self.assertEqual((self.install_root / "current").resolve().name,
                             plan["current_release_id"])
            self.assertEqual((self.install_root / "previous").resolve().name,
                             plan["previous_release_id"])
            with (self.repo / "scripts/claude-run-controller.sh").open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write("# fourth\n")
            self.assertEqual(self.install()["status"], "deployed")

    def test_capacity_recovery_rejects_changed_plan_before_moving_releases(self):
        with mock.patch.object(MANAGER, "MAX_RELEASES", 3):
            first = self.install()["release_id"]
            for suffix in ("second", "third"):
                with (self.repo / "scripts/claude-run-controller.sh").open(
                    "a", encoding="utf-8"
                ) as handle:
                    handle.write(f"# {suffix}\n")
                self.install()
            plan = MANAGER.release_archive_plan(self.install_root, self.uid)
            with self.assertRaisesRegex(MANAGER.ReleaseFailure,
                                        "release_archive_plan_changed"):
                MANAGER.archive_inactive_releases(
                    self.install_root, self.state, self.uid,
                    plan["current_release_id"], plan["previous_release_id"],
                    "0" * 64,
                )
            self.assertTrue((self.install_root / "releases" / first).is_dir())
            self.assertFalse((self.install_root / "release-archive").exists())

    def test_launcher_rejects_payload_tampering(self):
        self.install()
        controller = (self.install_root / "current").resolve() / "controller"
        controller.chmod(0o755)
        with controller.open("a", encoding="utf-8") as handle:
            handle.write("# tampered\n")
        controller.chmod(0o555)
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "payload_hash_mismatch"):
            LAUNCHER.load_release(self.install_root, self.uid)

    def test_failed_syntax_check_does_not_change_current(self):
        original = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("if then\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "controller_syntax_invalid"):
            self.install()
        self.assertEqual((self.install_root / "current").resolve().name, original)

    def test_service_bootstrap_failure_restores_previous_current_release(self):
        original = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        with (mock.patch.object(MANAGER, "manages_live_touchid_service", return_value=True),
              mock.patch.object(MANAGER, "install_touchid_service",
                                side_effect=MANAGER.ReleaseFailure("service failed")),
              mock.patch.object(MANAGER, "stop_touchid_service")):
            with self.assertRaisesRegex(MANAGER.ReleaseFailure, "service failed"):
                self.install()
        self.assertEqual((self.install_root / "current").resolve().name, original)

    def test_touchid_service_plist_is_atomically_installed_with_root_style_mode(self):
        release = self.root / "release"
        release.mkdir()
        source = release / "authorization_service"
        source.write_bytes((REPO / MANAGER.PAYLOAD_SOURCES["authorization_service"]).read_bytes())
        plist = self.root / "LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
        plist.parent.mkdir()
        absent = subprocess.CompletedProcess([], 113, "", "")
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(MANAGER.subprocess, "run", side_effect=[absent, completed, completed]) as run:
            MANAGER.install_touchid_service(release, plist)
        self.assertEqual(plist.read_bytes(), source.read_bytes())
        self.assertEqual(plist.stat().st_mode & 0o777, 0o644)
        self.assertEqual(run.call_args_list[-1].args[0][0:3],
                         ["/bin/launchctl", "bootstrap", "system"])

    def test_touchid_service_update_does_not_kill_authorizing_broker(self):
        release = self.root / "release"
        release.mkdir()
        source = release / "authorization_service"
        source.write_bytes((REPO / MANAGER.PAYLOAD_SOURCES["authorization_service"]).read_bytes())
        plist = self.root / "LaunchDaemons/org.zebeth.securesandbox.authorization.plist"
        plist.parent.mkdir()
        loaded = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(MANAGER.subprocess, "run", return_value=loaded) as run:
            MANAGER.install_touchid_service(release, plist)
        self.assertEqual(len(run.call_args_list), 1)
        self.assertEqual(run.call_args_list[0].args[0][0:3],
                         ["/bin/launchctl", "print", "system/org.zebeth.securesandbox.authorization"])

    def test_terminal_bootstrap_restart_reexecs_loaded_touchid_service(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
            MANAGER.subprocess, "run", side_effect=[completed, completed]
        ) as run:
            MANAGER.restart_touchid_service()
        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "/bin/launchctl", "kickstart", "-k",
                "system/org.zebeth.securesandbox.authorization",
            ],
        )
        self.assertEqual(
            run.call_args_list[1].args[0][0:3],
            ["/bin/launchctl", "print", "system/org.zebeth.securesandbox.authorization"],
        )

    def test_terminal_bootstrap_restart_fails_closed(self):
        failed = subprocess.CompletedProcess([], 5, "", "kickstart denied")
        with mock.patch.object(MANAGER.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(
                MANAGER.ReleaseFailure, "authorization_service_restart_failed"
            ):
                MANAGER.restart_touchid_service()

    def test_exact_successor_recovery_retries_failed_service_restart(self):
        release_id = "a" * 64
        current = self.root / "releases" / release_id
        verified = {
            "schema":MANAGER.SCHEMA,
            "status":"verified",
            "release_id":release_id,
        }
        with (mock.patch.object(MANAGER, "verify", return_value=verified) as verify,
              mock.patch.object(MANAGER, "manages_live_touchid_service", return_value=True),
              mock.patch.object(
                  MANAGER, "restart_touchid_service",
                  side_effect=[MANAGER.ReleaseFailure("restart failed"), None],
              ) as restart):
            with self.assertRaisesRegex(MANAGER.ReleaseFailure, "restart failed"):
                MANAGER.recover_terminal_schema_service(
                    self.repo, current, self.install_root, self.launcher, 0,
                    release_id, self.op_binary, self.gpgv_binary,
                )
            recovered = MANAGER.recover_terminal_schema_service(
                self.repo, current, self.install_root, self.launcher, 0,
                release_id, self.op_binary, self.gpgv_binary,
            )
        self.assertTrue(recovered["recovered_existing_release"])
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(verify.call_count, 2)

        with mock.patch.object(MANAGER, "verify") as verify_mismatch:
            self.assertIsNone(MANAGER.recover_terminal_schema_service(
                self.repo, self.root / "releases" / ("b" * 64),
                self.install_root, self.launcher, 0, release_id,
                self.op_binary, self.gpgv_binary,
            ))
        verify_mismatch.assert_not_called()

    def test_touchid_binary_tampering_invalidates_source_release(self):
        binary = (self.repo / MANAGER.AUTHORIZATION_UI_APP_SOURCE
                  / MANAGER.AUTHORIZATION_UI_EXECUTABLE)
        binary.chmod(0o755)
        with binary.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "authorization_ui_bundle_member_invalid"):
            MANAGER.source_payload(self.repo, self.op_binary, self.gpgv_binary)

    def test_deploy_refuses_live_marker_and_prunes_stale_marker(self):
        self.install()
        active = self.state / "active"
        active.mkdir(parents=True)
        live = active / "live.json"
        live.write_text(json.dumps({"pid": os.getpid(), "release_id": "a" * 64}), encoding="ascii")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "active_controller_invocations"):
            self.install()
        live.write_text(json.dumps({"pid": 2147483647, "release_id": "a" * 64}), encoding="ascii")
        self.install()
        self.assertFalse(live.exists())

    def test_second_release_can_roll_back(self):
        first = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        second = self.install()["release_id"]
        self.assertNotEqual(first, second)
        result = MANAGER.rollback(
            self.repo, self.install_root, self.state, None, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["release_id"], first)
        self.assertFalse(result["repo_match"])
        self.assertEqual((self.install_root / "previous").resolve().name, second)

    def test_first_v1_install_does_not_advertise_legacy_rollback(self):
        values, hashes, _ = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        legacy_hashes = {
            name: hashes[name]
            for name in MANAGER.PRE_CONTROL_PAYLOAD_NAMES
            if name in hashes
        }
        legacy_hashes["op_agents"] = hashlib.sha256(b"legacy bridge\n").hexdigest()
        legacy_id = MANAGER.release_identity(legacy_hashes)
        release = self.install_root / "releases" / legacy_id
        release.mkdir(parents=True)
        for name, digest in legacy_hashes.items():
            data = b"legacy bridge\n" if name == "op_agents" else values[name]
            path = release / name
            path.write_bytes(data)
            path.chmod(MANAGER.EXPECTED_MODES[name])
        manifest = {"schema": MANAGER.SCHEMA, "release_id": legacy_id, "payloads": legacy_hashes}
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (release / "manifest.json").chmod(0o444)
        release.chmod(0o555)
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")
        loaded_path, loaded_id = LAUNCHER.load_release(self.install_root, self.uid)
        self.assertEqual((loaded_path.name, loaded_id), (legacy_id, legacy_id))
        self.install()
        self.assertFalse((self.install_root / "previous").exists())

    def test_migration_rejects_unrecognized_near_legacy_payload_set(self):
        values, hashes, _ = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        legacy_hashes = {
            name: hashes[name]
            for name in MANAGER.PRE_CONTROL_PAYLOAD_NAMES
            if name in hashes
        }
        legacy_hashes["op_agents"] = hashlib.sha256(b"legacy bridge\n").hexdigest()
        legacy_hashes["unexpected"] = hashlib.sha256(b"unexpected\n").hexdigest()
        legacy_id = MANAGER.release_identity(legacy_hashes)
        release = self.install_root / "releases" / legacy_id
        release.mkdir(parents=True)
        for name in legacy_hashes:
            data = (
                b"legacy bridge\n" if name == "op_agents"
                else b"unexpected\n" if name == "unexpected"
                else values[name]
            )
            path = release / name
            path.write_bytes(data)
            path.chmod(MANAGER.EXPECTED_MODES.get(name, 0o444))
        manifest = {"schema": MANAGER.SCHEMA, "release_id": legacy_id, "payloads": legacy_hashes}
        (release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (release / "manifest.json").chmod(0o444)
        release.chmod(0o555)
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "release_manifest_payloads_invalid"):
            self.install()

    def test_stable_launcher_change_requires_explicit_migration(self):
        self.install()
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# incompatible launcher change\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "stable_launcher_change_requires_migration"):
            self.install()

    def test_launcher_migration_is_old_hash_gated_and_backed_up(self):
        self.install()
        old_bytes = self.launcher.read_bytes()
        old_hash = MANAGER.sha256_bytes(old_bytes)
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# reviewed migration\n")
        replacement_hash = MANAGER.sha256_bytes((self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes())
        result = MANAGER.migrate_launcher(
            self.repo, self.install_root, self.launcher, self.state, self.uid, old_hash, replacement_hash
        )
        self.assertEqual(result["previous_launcher_sha256"], old_hash)
        self.assertEqual(Path(result["backup"]).read_bytes(), old_bytes)
        self.assertEqual(MANAGER.sha256_bytes(self.launcher.read_bytes()), result["launcher_sha256"])
        deployed = self.install()
        self.assertEqual(
            MANAGER.verify(
                self.repo, self.install_root, self.launcher, self.uid,
                self.op_binary, self.gpgv_binary,
            )["release_id"],
            deployed["release_id"],
        )

    def test_authorization_bootstrap_binds_launcher_transition_and_is_restart_safe(self):
        old_release = self.install()["release_id"]
        old_launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# authorization bootstrap launcher\n")
        with (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_broker"]).open(
            "a", encoding="utf-8"
        ) as handle:
            handle.write("# authorization bootstrap broker\n")
        replacement_sha256 = MANAGER.sha256_bytes(
            (self.repo / MANAGER.LAUNCHER_SOURCE).read_bytes()
        )
        _values, _hashes, release_id = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        current_manifest = json.loads(
            ((self.install_root / "current").resolve() / "manifest.json").read_text()
        )
        current_manifest["payloads"] = {
            name: digest for name, digest in current_manifest["payloads"].items()
            if name in MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        legacy_id = MANAGER.release_identity(current_manifest["payloads"])
        legacy = self.install_root / "releases" / legacy_id
        legacy.mkdir()
        for name in current_manifest["payloads"]:
            shutil.copyfile((self.install_root / "releases" / old_release / name), legacy / name)
            (legacy / name).chmod(MANAGER.EXPECTED_MODES[name])
        current_manifest["release_id"] = legacy_id
        (legacy / "manifest.json").write_text(json.dumps(current_manifest), encoding="utf-8")
        (legacy / "manifest.json").chmod(0o444)
        legacy.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{legacy_id}")

        with mock.patch.object(
            MANAGER, "install", side_effect=MANAGER.ReleaseFailure("simulated_post_migration_crash")
        ):
            with self.assertRaisesRegex(MANAGER.ReleaseFailure, "simulated_post_migration_crash"):
                MANAGER.bootstrap_authorization(
                    self.repo, self.install_root, self.launcher, self.state, self.uid,
                    release_id, old_launcher_sha256, replacement_sha256,
                    self.op_binary, self.gpgv_binary,
                )
        self.assertEqual(MANAGER.sha256_bytes(self.launcher.read_bytes()), replacement_sha256)
        self.assertEqual((self.install_root / "current").resolve().name, legacy_id)

        result = MANAGER.bootstrap_authorization(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            release_id, replacement_sha256, replacement_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "authorization_bootstrapped")
        self.assertFalse(result["launcher_migrated"])
        self.assertEqual(result["previous_release_id"], legacy_id)
        self.assertEqual((self.install_root / "current").resolve().name, release_id)

    def test_maintenance_schema_bootstrap_accepts_exact_predecessor_once(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        old_payloads = {
            name: source_manifest["payloads"][name]
            for name in MANAGER.PRE_MAINTENANCE_PAYLOAD_NAMES
        }
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release, "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        result = MANAGER.bootstrap_maintenance_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "maintenance_schema_bootstrapped")
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_maintenance_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_touchid_schema_bootstrap_accepts_exact_predecessor_once(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        old_payloads = {
            name: source_manifest["payloads"][name]
            for name in MANAGER.PRE_TOUCHID_PAYLOAD_NAMES
        }
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release, "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        result = MANAGER.bootstrap_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "touchid_schema_bootstrapped")
        self.assertEqual(result["previous_release_id"], old_release)
        recovered = MANAGER.bootstrap_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    @unittest.skip("superseded by the deployed Secure Enclave source-schema bootstrap")
    def test_secure_enclave_schema_bootstrap_is_exactly_current_and_one_time(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        installed_sources = json.loads(
            (source_path / "authorization_ui_sources").read_text(encoding="utf-8")
        )
        old_sources = {
            "schema": installed_sources["schema"],
            "sources": {
                name: digest for name, digest in installed_sources["sources"].items()
                if name in MANAGER.PRE_SECURE_ENCLAVE_TOUCHID_SOURCE_NAMES
            },
        }
        old_sources_bytes = json.dumps(
            old_sources, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        old_payloads = dict(source_manifest["payloads"])
        old_payloads["authorization_ui_sources"] = MANAGER.sha256_bytes(old_sources_bytes)
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            if name == "authorization_ui_sources":
                (old_path / name).write_bytes(old_sources_bytes)
            else:
                shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release,
            "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_secure_enclave_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )

    def test_profiled_touchid_schema_bootstrap_is_exactly_current_and_one_time(self):
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        source_manifest = json.loads((source_path / "manifest.json").read_text())
        binary = (source_path / MANAGER.AUTHORIZATION_UI_APP_NAME
                  / MANAGER.AUTHORIZATION_UI_EXECUTABLE).read_bytes()
        old_payloads = dict(source_manifest["payloads"])
        old_payloads.pop("authorization_ui_bundle")
        old_payloads["authorization_ui"] = MANAGER.sha256_bytes(binary)
        old_release = MANAGER.release_identity(old_payloads)
        old_path = self.install_root / "releases" / old_release
        old_path.mkdir()
        for name in old_payloads:
            if name == "authorization_ui":
                (old_path / name).write_bytes(binary)
            else:
                shutil.copyfile(source_path / name, old_path / name)
            (old_path / name).chmod(MANAGER.EXPECTED_MODES[name])
        (old_path / "manifest.json").write_text(json.dumps({
            "schema": MANAGER.SCHEMA, "release_id": old_release,
            "payloads": old_payloads,
        }), encoding="utf-8")
        (old_path / "manifest.json").chmod(0o444)
        old_path.chmod(0o555)
        (self.install_root / "current").unlink()
        (self.install_root / "current").symlink_to(f"releases/{old_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_profiled_touchid_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.bootstrap_profiled_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, old_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "profiled_touchid_schema_bootstrapped")
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_profiled_touchid_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])
        rolled_back = MANAGER.rollback(
            self.repo, self.install_root, self.state, old_release, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(rolled_back["release_id"], old_release)
        self.assertEqual((self.install_root / "current").resolve().name, old_release)

    def test_touchid_bundle_v2_schema_bootstrap_is_exactly_current_and_one_time(self):
        bundle_path = self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui_bundle"]
        bundle_v2 = json.loads(bundle_path.read_text(encoding="utf-8"))
        self.assertEqual(bundle_v2["schema"], "secure-sandbox-touchid-ui-bundle-v2")
        bundle_v1 = {
            "bundle":bundle_v2["bundle"],
            "files":bundle_v2["files"],
            "schema":"secure-sandbox-touchid-ui-bundle-v1",
        }
        bundle_path.write_text(
            json.dumps(bundle_v1, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        predecessor = self.install()["release_id"]
        bundle_path.write_text(
            json.dumps(bundle_v2, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _values, _hashes, source_release = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())

        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "current_release_id_unexpected"):
            MANAGER.bootstrap_touchid_bundle_v2_schema(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                source_release, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.bootstrap_touchid_bundle_v2_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, predecessor, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "touchid_bundle_v2_schema_bootstrapped")
        self.assertEqual(result["previous_release_id"], predecessor)
        self.assertEqual((self.install_root / "current").resolve().name, source_release)
        recovered = MANAGER.bootstrap_touchid_bundle_v2_schema(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            source_release, source_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertTrue(recovered["recovered_existing_release"])

    def test_operator_ceremony_broker_recovery_accepts_only_exact_predecessor(self):
        predecessor = self.install()["release_id"]
        current = (self.install_root / "current").resolve()
        predecessor_broker = MANAGER.sha256_bytes(
            (current / "authorization_broker").read_bytes()
        )
        original_release = MANAGER.BROKEN_CEREMONY_BROKER_RELEASE_ID
        original_broker = MANAGER.BROKEN_CEREMONY_BROKER_SHA256
        self.addCleanup(
            setattr, MANAGER, "BROKEN_CEREMONY_BROKER_RELEASE_ID", original_release
        )
        self.addCleanup(
            setattr, MANAGER, "BROKEN_CEREMONY_BROKER_SHA256", original_broker
        )
        MANAGER.BROKEN_CEREMONY_BROKER_RELEASE_ID = predecessor
        MANAGER.BROKEN_CEREMONY_BROKER_SHA256 = predecessor_broker
        broker_path = self.repo / MANAGER.PAYLOAD_SOURCES["authorization_broker"]
        broker_path.write_bytes(broker_path.read_bytes() + b"\n# bounded recovery\n")
        _values, _hashes, successor = MANAGER.source_payload(
            self.repo, self.op_binary, self.gpgv_binary,
        )
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "operator_ceremony_broker_recovery_predecessor_invalid",
        ):
            MANAGER.recover_operator_ceremony_broker(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                successor, "0" * 64, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
        result = MANAGER.recover_operator_ceremony_broker(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            successor, predecessor, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "operator_ceremony_broker_recovered")
        self.assertEqual(result["previous_release_id"], predecessor)
        self.assertEqual((self.install_root / "current").resolve().name, successor)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure,
            "operator_ceremony_broker_recovery_predecessor_invalid",
        ):
            MANAGER.recover_operator_ceremony_broker(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                successor, successor, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )
    @unittest.skip("superseded by the provisioned app-bundle schema bootstrap")
    def test_touchid_ui_recovery_accepts_only_known_vulnerable_source_once(self):
        original_recovery_main_sha256 = MANAGER.RECOVERED_TOUCHID_MAIN_SOURCE_SHA256
        original_recovery_ui_sha256 = MANAGER.RECOVERED_TOUCHID_UI_SHA256
        original_recovery_sources_sha256 = MANAGER.RECOVERED_TOUCHID_SOURCES_SHA256
        self.addCleanup(
            setattr, MANAGER, "RECOVERED_TOUCHID_MAIN_SOURCE_SHA256",
            original_recovery_main_sha256,
        )
        self.addCleanup(
            setattr, MANAGER, "RECOVERED_TOUCHID_UI_SHA256",
            original_recovery_ui_sha256,
        )
        self.addCleanup(
            setattr, MANAGER, "RECOVERED_TOUCHID_SOURCES_SHA256",
            original_recovery_sources_sha256,
        )
        # Standard deployments legitimately rebuild and re-sign the UI. This
        # isolated recovery test pins the exact signed fixture copied into its
        # temporary repository, just as the live one-time recovery pinned its
        # independently reviewed artifact.
        MANAGER.RECOVERED_TOUCHID_UI_SHA256 = MANAGER.sha256_bytes(
            (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui"]).read_bytes()
        )
        MANAGER.RECOVERED_TOUCHID_SOURCES_SHA256 = MANAGER.sha256_bytes(
            (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui_sources"]).read_bytes()
        )
        current_sources = json.loads(
            (self.repo / MANAGER.PAYLOAD_SOURCES["authorization_ui_sources"]).read_text(
                encoding="utf-8"
            )
        )
        MANAGER.RECOVERED_TOUCHID_MAIN_SOURCE_SHA256 = current_sources["sources"][
            "Sources/SecureSandboxAuthorizationUI/main.swift"
        ]
        source_release = self.install()["release_id"]
        source_path = self.install_root / "releases" / source_release
        manifest_path = source_path / "manifest.json"
        sources_path = source_path / "authorization_ui_sources"
        source_path.chmod(0o755)
        manifest_path.chmod(0o644)
        sources_path.chmod(0o644)
        sources = json.loads(sources_path.read_text(encoding="utf-8"))
        sources["sources"]["Sources/SecureSandboxAuthorizationUI/main.swift"] = next(
            iter(MANAGER.VULNERABLE_TOUCHID_MAIN_SOURCE_SHA256)
        )
        vulnerable_bytes = (json.dumps(sources, indent=2, sort_keys=True) + "\n").encode()
        sources_path.write_bytes(vulnerable_bytes)
        sources_path.chmod(0o444)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["payloads"]["authorization_ui_sources"] = hashlib.sha256(
            vulnerable_bytes
        ).hexdigest()
        vulnerable_release = MANAGER.release_identity(manifest["payloads"])
        manifest["release_id"] = vulnerable_release
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        manifest_path.chmod(0o444)
        vulnerable_path = source_path.with_name(vulnerable_release)
        source_path.rename(vulnerable_path)
        vulnerable_path.chmod(0o555)
        current = self.install_root / "current"
        current.unlink()
        current.symlink_to(f"releases/{vulnerable_release}")
        launcher_sha256 = MANAGER.sha256_bytes(self.launcher.read_bytes())
        recovery_values, recovery_hashes, recovery_release = (
            MANAGER.touchid_ui_recovery_payload(
                self.repo, self.install_root, self.uid,
                self.op_binary, self.gpgv_binary,
            )
        )

        result = MANAGER.recover_touchid_ui(
            self.repo, self.install_root, self.launcher, self.state, self.uid,
            recovery_release, launcher_sha256, launcher_sha256,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "touchid_ui_recovered")
        self.assertEqual(result["previous_release_id"], vulnerable_release)
        recovered_manifest = json.loads(
            ((self.install_root / "current").resolve() / "manifest.json").read_text()
        )
        self.assertEqual(recovered_manifest["payloads"], recovery_hashes)
        self.assertEqual(
            {name: digest for name, digest in recovered_manifest["payloads"].items()
             if name not in {"authorization_ui", "authorization_ui_sources"}},
            {name: digest for name, digest in manifest["payloads"].items()
             if name not in {"authorization_ui", "authorization_ui_sources"}},
        )
        self.assertEqual(
            recovery_values["authorization_ui"],
            (self.install_root / "current" / "authorization_ui").read_bytes(),
        )
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "touchid_ui_recovery_not_required"):
            MANAGER.recover_touchid_ui(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                recovery_release, launcher_sha256, launcher_sha256,
                self.op_binary, self.gpgv_binary,
            )

    def test_launcher_migration_rejects_unexpected_replacement_hash(self):
        self.install()
        old_hash = MANAGER.sha256_bytes(self.launcher.read_bytes())
        with (self.repo / MANAGER.LAUNCHER_SOURCE).open("a", encoding="utf-8") as handle:
            handle.write("# reviewed migration\n")
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "replacement_launcher_hash_unexpected"):
            MANAGER.migrate_launcher(
                self.repo, self.install_root, self.launcher, self.state, self.uid,
                old_hash, "0" * 64,
            )

    def test_rollback_status_survives_unavailable_repository(self):
        first = self.install()["release_id"]
        with (self.repo / "scripts/claude-run-controller.sh").open("a", encoding="utf-8") as handle:
            handle.write("# second release\n")
        self.install()
        (self.repo / "scripts/pki-host-anchor.py").unlink()
        result = MANAGER.rollback(
            self.repo, self.install_root, self.state, first, self.uid,
            self.op_binary, self.gpgv_binary,
        )
        self.assertEqual(result["status"], "rolled_back")
        self.assertIsNone(result["repo_match"])

    def test_restrictive_umask_cannot_change_installed_modes(self):
        previous = os.umask(0o077)
        try:
            self.install()
        finally:
            os.umask(previous)
        release = (self.install_root / "current").resolve()
        self.assertEqual(self.launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "authorization_broker").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "controller").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "control_client").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "gpgv").stat().st_mode & 0o777, 0o555)
        self.assertEqual((release / "installer_verifier").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "pki_anchor").stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "release_manager").stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.install_root / "current").lstat().st_mode & 0o777, 0o755)
        for name in ("seed_gateway", "seed_research", "seed_target"):
            self.assertEqual((release / name).stat().st_mode & 0o777, 0o444)
        self.assertEqual((release / "ssh_config").stat().st_mode & 0o777, 0o444)

    def test_current_release_excludes_the_1password_bridge(self):
        self.install()
        release = (self.install_root / "current").resolve()
        self.assertFalse((release / "op_agents").exists())
        self.op_binary.write_bytes(b"changed-op\n")
        MANAGER.verify(self.repo, self.install_root, self.launcher, self.uid,
                       self.op_binary, self.gpgv_binary)

    def test_incomplete_old_lock_is_atomically_reclaimed(self):
        self.state.mkdir(parents=True)
        lock = self.state / "coordination.lock"
        lock.mkdir()
        old = time.time() - LAUNCHER.LOCK_INCOMPLETE_GRACE_SECONDS - 1
        os.utime(lock, (old, old))
        acquired = LAUNCHER.acquire_lock(self.state, timeout=0.2)
        self.assertEqual(acquired, lock)
        LAUNCHER.release_lock(acquired)
        self.assertFalse(lock.exists())

    def test_recent_incomplete_lock_fails_closed(self):
        self.state.mkdir(parents=True)
        (self.state / "coordination.lock").mkdir()
        with self.assertRaisesRegex(LAUNCHER.LaunchFailure, "coordination_lock_timeout"):
            LAUNCHER.acquire_lock(self.state, timeout=0.05)


class ControllerBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.release = self.root / "release"
        self.bin = self.root / "bin"
        self.release.mkdir()
        self.bin.mkdir()
        shutil.copyfile(REPO / "config/ssh_config", self.release / "ssh_config")
        self.log = self.root / "ssh.log"
        mocks = {
            "op-agents": "#!/bin/bash\nprintf 'secret\\n'\n",
            "uuidgen": "#!/bin/bash\nprintf '12345678-1234-4123-8123-123456789abc\\n'\n",
            "sleep": "#!/bin/bash\nexit 0\n",
            "date": "#!/bin/bash\nif [[ \"${1:-}\" == -r ]]; then printf '2033-05-18T03:33:20Z\\n'; else printf '2000000000\\n'; fi\n",
            "ssh": """#!/bin/bash
printf '%s\\n' "$*" >>"$SSH_LOG"
case "$*" in
  *"date -u +%s"*) printf '2000000000\\n' ;;
  *"run_lease.py issue"*)
    if [[ -n "${SSH_LEASE_JSON:-}" ]]; then printf '%s\\n' "$SSH_LEASE_JSON"
    else printf '%s\\n' '{"schema":"secure-sandbox-run-lease-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","profile":"standard","issued_at":2000000000,"expires_at":2000000600,"maximum_expires_at":2000003600,"relay_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","model":"abliterated-model-large-v2","limits":{},"pricing":{},"renewals":0}'
    fi ;;
  *"run_lease.py finalize"*)
    if [[ -n "${SSH_GATEWAY_SUMMARY+x}" ]]; then printf '%s\n' "$SSH_GATEWAY_SUMMARY"
    else
      reason=completed
      case "$*" in *session_failed*) reason=session_failed;; *operator_closed*) reason=operator_closed;; *expired*) reason=expired;; *launch_failed*) reason=launch_failed;; esac
      printf '{"schema":"secure-sandbox-run-lease-summary-v1","lease":{"schema":"secure-sandbox-run-lease-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","profile":"standard","issued_at":2000000000,"expires_at":2000000600,"maximum_expires_at":2000003600,"relay_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","model":"abliterated-model-large-v2","limits":{},"pricing":{},"renewals":0},"final_counters":{"schema":"secure-sandbox-run-lease-counter-v1","run_id":"12345678-1234-4123-8123-123456789abc","lease_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","requests":0,"input_tokens":0,"output_tokens":0,"cost_microusd":0,"updated_at":2000000000},"finalized_at":2000000000,"reason":"%s"}\n' "$reason"
    fi ;;
  *"run_lease_watchdog.py arm"*) exit "${SSH_ARM_STATUS:-0}" ;;
  *"run_lease_watchdog.py close"*) exit "${SSH_CLOSE_STATUS:-0}" ;;
  *"session_registry.py refresh-contains"*) exit "${SSH_REFRESH_STATUS:-0}" ;;
  *"session_registry.py refresh"*) exit "${SSH_REFRESH_STATUS:-0}" ;;
  *"session_registry.py contains"*) exit "${SSH_CONTAINS_STATUS:-0}" ;;
  *"pki_generation.py verify"*) printf '{"generation_id":"12345678-1234-4123-8123-123456789abc","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\\n' ;;
  *"research-claude"*) exit "${SSH_FINAL_STATUS:-0}" ;;
esac
exit 0
""",
        }
        for name, body in mocks.items():
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        controller = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        for original, replacement in {
            "/usr/bin/ssh": str(self.bin / "ssh"),
            "/usr/bin/uuidgen": str(self.bin / "uuidgen"),
            "/bin/date": str(self.bin / "date"),
            "/bin/sleep": str(self.bin / "sleep"),
        }.items():
            controller = controller.replace(original, replacement)
        (self.release / "controller").write_text(controller, encoding="utf-8")
        (self.release / "controller").chmod(0o755)
        (self.release / "control_client").write_text(
            """#!/bin/bash
set -e
shift 3
host="$1"; shift
test "$1" = run; shift
operation="$1"; shift
case "$operation" in
  lease-issue) command="run_lease.py issue '$1' '$2'" ;;
  lease-finalize) command="run_lease.py finalize '$1' '$2'" ;;
  watchdog-arm) command="run_lease_watchdog.py arm '$1' '$2' '$3' '$4'" ;;
  watchdog-close) command="run_lease_watchdog.py close '$1'" ;;
  watchdog-commit) command="run_lease_watchdog.py commit '$1' '$2'" ;;
  session-refresh) command="session_registry.py refresh" ;;
  session-refresh-contains) command="session_registry.py refresh-contains '$1'" ;;
  session-contains) command="session_registry.py contains '$1'" ;;
  capture-ready) command="capture-ready" ;;
  pki-verify) command="pki_generation.py verify" ;;
  execution-approval-next) exit 3 ;;
  *) exit 64 ;;
esac
exec SSH_MOCK_PLACEHOLDER "$host" "$command"
""".replace("SSH_MOCK_PLACEHOLDER", str(self.bin / "ssh")),
            encoding="utf-8",
        )
        (self.release / "control_client").chmod(0o755)
        (self.release / "pki_anchor").write_text(
            "#!/bin/bash\nprintf '{\"generation_id\":\"12345678-1234-4123-8123-123456789abc\",\"manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\\n'\n",
            encoding="utf-8",
        )
        (self.release / "pki_anchor").chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def run_controller(self, *arguments, final_status="0", lease_json=None, arm_status="0", close_status="0",
                       gateway_summary=None, refresh_status="0", contains_status="0"):
        state = self.home / "Library/Application Support/SecureSandbox/controller-state"
        state.mkdir(parents=True, exist_ok=True)
        state.chmod(0o700)
        active = state / "active"
        active.mkdir(parents=True, exist_ok=True)
        script = f'''marker="$HOME/Library/Application Support/SecureSandbox/controller-state/active/$$-test.json"
printf '{{"pid":%s,"release_id":"%s"}}\\n' "$$" "{'a' * 64}" >"$marker"
SECURE_SANDBOX_ACTIVE_MARKER="$marker" SECURE_SANDBOX_RELEASE_ID="{'a' * 64}" exec "$CONTROLLER" "$@"
'''
        env = os.environ.copy()
        env.update({
            "HOME": str(self.home),
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "SSH_LOG": str(self.log),
            "SSH_FINAL_STATUS": final_status,
            "SSH_ARM_STATUS": arm_status,
            "SSH_CLOSE_STATUS": close_status,
            "SSH_REFRESH_STATUS": refresh_status,
            "SSH_CONTAINS_STATUS": contains_status,
            "CONTROLLER": str(self.release / "controller"),
            "SECURE_SANDBOX_STATE_ROOT": str(self.home / "Library/Application Support/SecureSandbox/controller-state"),
        })
        if lease_json is not None:
            env["SSH_LEASE_JSON"] = lease_json
        if gateway_summary is not None:
            env["SSH_GATEWAY_SUMMARY"] = gateway_summary
        return subprocess.run(["/bin/bash", "-c", script, "test", *arguments], env=env, text=True, capture_output=True)

    def test_new_session_uses_bash32_safe_branch_and_cleans_marker(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("research-claude --session-id", self.log.read_text(encoding="utf-8"))
        self.assertEqual(list((self.home / "Library/Application Support/SecureSandbox/controller-state/active").iterdir()), [])

    def test_selected_source_is_passed_only_to_new_research_session(self):
        source = "11111111-1111-4111-8111-111111111111"
        result = self.run_controller("--source", source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"research-claude --session-id 12345678-1234-4123-8123-123456789abc --source {source}",
                      self.log.read_text(encoding="utf-8"))

    def test_selected_source_rejects_invalid_or_resumed_context_before_remote_access(self):
        source = "11111111-1111-4111-8111-111111111111"
        session = "22222222-2222-4222-8222-222222222222"
        for arguments in (("--source", "invalid"), ("--source", source, "--resume", session),
                          ("--source", source, "--source", source)):
            with self.subTest(arguments=arguments):
                result = self.run_controller(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())

    def test_watchdog_arm_failure_finalizes_gateway_without_closing_missing_lifecycle(self):
        result = self.run_controller(arm_status="1")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("launch_failed", log)
        self.assertNotIn("run_lease_watchdog.py close", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_execution_approval_relay_fails_closed_after_repeated_transport_errors(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        self.assertIn('if (( failures >= 3 )); then', text)
        self.assertIn('/bin/kill -TERM "$controller_pid"', text)
        self.assertNotIn('/bin/sleep 0.2', text)

    def test_execution_approval_relay_persists_bounded_content_free_diagnostics(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        self.assertIn('approval-relay-last.json', text)
        self.assertIn('secure-sandbox-approval-relay-event-v1', text)
        self.assertIn('os.O_EXCL | os.O_NOFOLLOW', text)
        self.assertIn('os.replace(temporary, path)', text)
        self.assertIn('relay_event authorization "$broker_error"', text)
        self.assertIn('relay_event poll transport_failed', text)

    def test_touchid_ui_uses_real_appkit_lifecycle_and_forces_window_front(self):
        text = (REPO / "macos/TouchIDAuthorization/Sources/SecureSandboxAuthorizationUI/main.swift").read_text(
            encoding="utf-8"
        )
        launched = text.index("func applicationDidFinishLaunching")
        active_space = text.index("window.collectionBehavior.insert(.moveToActiveSpace)")
        level = text.index("window.level = .modalPanel")
        activate = text.index("application.activate(ignoringOtherApps: true)")
        key = text.index("window.makeKeyAndOrderFront(nil)")
        front = text.index("window.orderFrontRegardless()")
        arrange = text.index("application.arrangeInFront(nil)")
        expiry = text.index("TimeInterval(request.expiresAt)")
        timer = text.index("let expiryTimer = Timer(")
        modal_mode = text.index("RunLoop.main.add(expiryTimer, forMode: .modalPanel)")
        modal = text.index("alert.runModal()")
        run = text.index("application.run()")
        self.assertNotIn("application.finishLaunching()", text)
        self.assertIn("application.activationPolicy() == .regular", text)
        self.assertIn("stopModal(withCode: .abort)", text)
        self.assertLess(launched, active_space)
        self.assertLess(active_space, level)
        self.assertLess(level, activate)
        self.assertLess(activate, key)
        self.assertLess(key, front)
        self.assertLess(front, arrange)
        self.assertLess(arrange, expiry)
        self.assertLess(expiry, timer)
        self.assertLess(timer, modal_mode)
        self.assertLess(modal_mode, modal)
        self.assertLess(modal, run)

    def test_resume_preserves_uuid_and_registry_check(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        result = self.run_controller("--resume", session)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("session_registry.py refresh-contains", log)
        self.assertIn(f"research-claude --resume {session}", log)

    def test_resume_fails_closed_when_registry_refresh_fails(self):
        session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        result = self.run_controller("--resume", session, refresh_status="23")
        self.assertNotEqual(result.returncode, 0)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("session_registry.py refresh-contains", log)
        self.assertNotIn("run_lease.py issue", log)
        self.assertNotIn("research-claude --resume", log)

    def test_interrupted_remote_session_still_finalizes_and_cleans(self):
        result = self.run_controller(final_status="130")
        self.assertEqual(result.returncode, 130)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertIn("session_failed", log)
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertIn("run_lease_watchdog.py commit", log)
        self.assertNotIn("manage_run_id.py clear", log)
        active = self.home / "Library/Application Support/SecureSandbox/controller-state/active"
        self.assertEqual(list(active.iterdir()), [])

    def test_controller_waits_on_explicit_session_child_for_signal_cleanup(self):
        text = (REPO / "scripts/claude-run-controller.sh").read_text(encoding="utf-8")
        self.assertIn('interrupt_run()', text)
        self.assertIn('/bin/kill -HUP "$session_pid"', text)
        self.assertIn('session_pid=$!', text)
        self.assertIn('wait "$session_pid"', text)
        self.assertIn('lease_reason=operator_closed', text)

    def test_commit_binds_exact_gateway_summary_file_bytes(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = {
            "schema": "secure-sandbox-run-lease-summary-v1",
            "lease": {
                "schema": "secure-sandbox-run-lease-v1",
                "run_id": "12345678-1234-4123-8123-123456789abc",
                "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "profile": "standard",
                "issued_at": 2000000000,
                "expires_at": 2000000600,
                "maximum_expires_at": 2000003600,
                "relay_sha256": "a" * 64,
                "policy_sha256": "b" * 64,
                "model": "abliterated-model-large-v2",
                "limits": {},
                "pricing": {},
                "renewals": 0,
            },
            "final_counters": {
                "schema": "secure-sandbox-run-lease-counter-v1",
                "run_id": "12345678-1234-4123-8123-123456789abc",
                "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_microusd": 0,
                "updated_at": 2000000000,
            },
            "finalized_at": 2000000000,
            "reason": "completed",
        }
        durable = json.dumps(summary, separators=(",", ":"), sort_keys=True) + "\n"
        expected = hashlib.sha256(durable.encode("utf-8")).hexdigest()
        self.assertIn(
            f"run_lease_watchdog.py commit '12345678-1234-4123-8123-123456789abc' '{expected}'",
            self.log.read_text(encoding="utf-8"),
        )

    def test_invalid_resume_is_rejected_before_remote_access(self):
        result = self.run_controller("--resume", "not-a-uuid")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())

    def test_close_failure_overrides_session_success_and_skips_gateway_commit(self):
        result = self.run_controller(close_status="1")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease_watchdog.py close", log)
        self.assertNotIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_invalid_gateway_summary_blocks_research_commit(self):
        result = self.run_controller(gateway_summary="")
        self.assertEqual(result.returncode, 70)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("run_lease.py finalize", log)
        self.assertNotIn("run_lease_watchdog.py commit", log)

    def test_gateway_summary_must_bind_run_lease_reason_and_counter_schema(self):
        wrong = json.dumps({"schema":"secure-sandbox-run-lease-summary-v1",
                            "lease":{"schema":"secure-sandbox-run-lease-v1",
                                     "run_id":"12345678-1234-4123-8123-123456789abc",
                                     "lease_id":"12345678-1234-4123-8123-123456789abc"},
                            "final_counters":{},"finalized_at":2000000000,
                            "reason":"completed"})
        result = self.run_controller(gateway_summary=wrong)
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

    def test_renewed_gateway_summary_preserves_immutable_lease_binding(self):
        lease = {
            "schema": "secure-sandbox-run-lease-v1",
            "run_id": "12345678-1234-4123-8123-123456789abc",
            "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "profile": "standard", "issued_at": 2000000000,
            "expires_at": 2000000600, "maximum_expires_at": 2000003600,
            "relay_sha256": "a" * 64, "policy_sha256": "b" * 64,
            "model": "abliterated-model-large-v2", "limits": {}, "pricing": {},
            "renewals": 0,
        }
        renewed = {**lease, "expires_at": 2000000900, "renewals": 1}
        summary = {
            "schema": "secure-sandbox-run-lease-summary-v1", "lease": renewed,
            "final_counters": {
                "schema": "secure-sandbox-run-lease-counter-v1",
                "run_id": lease["run_id"], "lease_id": lease["lease_id"],
                "requests": 0, "input_tokens": 0, "output_tokens": 0,
                "cost_microusd": 0, "updated_at": 2000000000,
            },
            "finalized_at": 2000000000, "reason": "completed",
        }
        result = self.run_controller(lease_json=json.dumps(lease),
                                     gateway_summary=json.dumps(summary))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

        tampered = {**summary, "lease": {**renewed, "policy_sha256": "c" * 64}}
        self.log.unlink()
        result = self.run_controller(lease_json=json.dumps(lease),
                                     gateway_summary=json.dumps(tampered))
        self.assertEqual(result.returncode, 70)
        self.assertNotIn("run_lease_watchdog.py commit", self.log.read_text(encoding="utf-8"))

    def test_gateway_expiry_shell_expression_is_rejected_without_execution(self):
        sentinel = self.root / "arithmetic-executed"
        malicious = json.dumps({
            "lease_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "expires_at": f"x[$(/usr/bin/touch {sentinel})]",
        })
        result = self.run_controller(lease_json=malicious)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sentinel.exists())
        self.assertNotIn("run_lease_watchdog.py arm", self.log.read_text(encoding="utf-8"))

    def test_gateway_lease_id_shell_metacharacters_are_rejected_before_research(self):
        malicious = json.dumps({"lease_id": "' ; id ; '", "expires_at": 2000000600})
        result = self.run_controller(lease_json=malicious)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("run_lease_watchdog.py arm", self.log.read_text(encoding="utf-8"))

    def test_launcher_environment_is_allowlisted(self):
        marker = self.root / "marker"
        dangerous = {
            "BASH_ENV": "/tmp/evil", "ENV": "/tmp/evil", "SHELLOPTS": "xtrace",
            "BASHOPTS": "extdebug", "PYTHONPATH": "/tmp/evil", "DYLD_INSERT_LIBRARIES": "/tmp/evil",
        }
        with mock.patch.dict(os.environ, dangerous, clear=False):
            environment = LAUNCHER.controller_environment(marker, "a" * 64)
        self.assertFalse(set(dangerous) & set(environment))
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")


if __name__ == "__main__":
    unittest.main()
