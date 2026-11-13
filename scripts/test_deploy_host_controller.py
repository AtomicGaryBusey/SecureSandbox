#!/usr/bin/env python3

import importlib.util
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).with_name("deploy-host-controller.py")
SPEC = importlib.util.spec_from_file_location("deploy_host_controller", SCRIPT)
DEPLOY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DEPLOY)


class DeployHostControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.broker = self.root / "authorization_broker"
        self.broker.write_text("#!/bin/sh\n", encoding="utf-8")
        self.broker.chmod(0o755)
        self.candidate = DEPLOY.NativeHostCandidate(
            schema="secure-sandbox-native-host-candidate-record-v2",
            generation_path=str(self.root / "candidate/generation"),
            generation_device=101,
            generation_inode=202,
            generation_tree_sha256="1" * 64,
            release_commit="2" * 40,
            source_archive_sha256="3" * 64,
            source_tree_sha256="4" * 64,
            signing_config_sha256="5" * 64,
            host_release_preimage_path=str(
                self.root / "candidate/evidence/SecureSandboxHostReleasePreimage.tar"
            ),
            host_release_preimage_device=303,
            host_release_preimage_inode=404,
            host_release_preimage_size=1024,
            host_release_preimage_sha256="6" * 64,
            host_release_preimage_schema=(
                "secure-sandbox-native-host-release-preimage-v1"
            ),
            developer_id_certificate_sha1="6" * 40,
            notary_submission_id=(
                "12345678-1234-4123-8123-123456789abc"
            ),
            build_custody="trusted-login-principal-v1",
        )
        self.target_plan = {
            "candidate_record_sha256": "1" * 64,
            "payloads": {"release_manager": "2" * 64},
            "release_id": "a" * 64,
            "schema": "secure-sandbox-host-release-target-plan-v1",
            "source_stable_sha256": "3" * 64,
            "target_launcher_sha256": "4" * 64,
        }
        self.target_plan_sha256 = "5" * 64
        self.source_binding = DEPLOY.SourceReleaseBinding(
            "a" * 64, self.candidate, self.target_plan,
            self.target_plan_sha256,
        )
        self.rollback_plan = {
            "operation": "rollback",
            "schema": "secure-sandbox-host-release-rollback-plan-v1",
            "source_stable_sha256": "6" * 64,
            "target_candidate_authority_sha256": "7" * 64,
            "target_launcher_sha256": "8" * 64,
            "target_release_id": "d" * 64,
            "target_release_tree_identity_sha256": "9" * 64,
        }
        self.rollback_binding = DEPLOY.RollbackReleaseBinding(
            "d" * 64, self.rollback_plan, "e" * 64,
        )
        self.real_bootstrap_binding = DEPLOY.bootstrap_binding
        self.real_expected_source_release_binding = (
            DEPLOY.expected_source_release_binding
        )
        self.real_expected_source_release_id = DEPLOY.expected_source_release_id
        self.patches = [
            mock.patch.object(DEPLOY, "BROKER_PATH", self.broker),
            mock.patch.object(DEPLOY.LAUNCHER, "STATE_ROOT", self.root / "state"),
            mock.patch.object(DEPLOY.LAUNCHER, "acquire_lock", return_value=self.root / "lock"),
            mock.patch.object(DEPLOY.LAUNCHER, "release_lock"),
            mock.patch.object(DEPLOY.MANAGER, "active_markers", return_value=[]),
            mock.patch.object(
                DEPLOY, "expected_source_release_binding",
                return_value=self.source_binding,
            ),
            mock.patch.object(DEPLOY, "expected_source_release_id", return_value="a" * 64),
            mock.patch.object(DEPLOY, "previous_release_id", return_value="d" * 64),
            mock.patch.object(
                DEPLOY, "rollback_release_binding",
                return_value=self.rollback_binding,
            ),
            mock.patch.object(DEPLOY, "selector_recovery_required", return_value=False),
            mock.patch.object(DEPLOY, "bootstrap_binding", return_value=DEPLOY.BootstrapBinding(
                "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            )),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def run_main(self, arguments):
        with mock.patch("sys.argv", [str(SCRIPT), *arguments]):
            return DEPLOY.main()

    def pair_identity(self, release_id="a" * 64):
        return {
            "candidate_authority_sha256": "c" * 64,
            "launcher_identity": {
                "ctime_ns": 1, "dev": 2, "gid": 0, "ino": 3,
                "kind": "file", "mode": 0o755, "mtime_ns": 4,
                "nlink": 1, "sha256": "4" * 64, "size": 100,
                "uid": 0,
            },
            "launcher_sha256": "4" * 64,
            "release_id": release_id,
            "release_tree_identity_sha256": "d" * 64,
        }

    def pair_pending(self, transition_id=None):
        return {
            "schema": DEPLOY.MANAGER.SCHEMA,
            "status": "host_pair_transition_pending",
            "operation": "install",
            "transition_id": transition_id or (
                "11111111-1111-4111-8111-111111111111"
            ),
            "transition_sha256": "b" * 64,
            "authorization_request_id": (
                "22222222-2222-4222-8222-222222222222"
            ),
            "authorized_target_plan_sha256": self.target_plan_sha256,
            "target_release_id": "a" * 64,
            "expires_at": int(__import__("time").time()) + 120,
            "recovered_after_child_failure": True,
        }

    def pair_terminal(self, transition_id=None):
        pending = self.pair_pending(transition_id)
        return {
            "schema": DEPLOY.MANAGER.HOST_PAIR_TERMINAL_SCHEMA,
            "status": "target_committed",
            "operation": "install",
            "transition_id": pending["transition_id"],
            "transition_sha256": pending["transition_sha256"],
            "committed_pair": self.pair_identity(),
            "authorization_request_id": pending["authorization_request_id"],
            "authorization_request_sha256": "e" * 64,
            "authorized_target_plan_sha256": self.target_plan_sha256,
            "completed_at": int(__import__("time").time()),
            "service_evidence_sha256": "f" * 64,
            "error": None,
            "authorization_receipt_sha256": "1" * 64,
            "terminal_sha256": "2" * 64,
        }

    def pair_stable(self, terminal):
        return {
            "schema": (
                DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA
            ),
            "required_feature": (
                DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_FEATURE
            ),
            "pair": terminal["committed_pair"],
            "committed_transition_id": terminal["transition_id"],
            "committed_transition_sha256": terminal["transition_sha256"],
            "committed_terminal_sha256": "3" * 64,
        }

    def manager_result(self, operation="install"):
        common = {
            "schema": DEPLOY.MANAGER.SCHEMA,
            "release_id": (
                "a" * 64 if operation == "install" else "d" * 64
            ),
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "transition_sha256": "b" * 64,
            "host_release_launcher_pair_sha256": "c" * 64,
            "candidate_authority_sha256": (
                "c" * 64 if operation == "install" else "7" * 64
            ),
            "release_tree_identity_sha256": (
                "d" * 64 if operation == "install" else "9" * 64
            ),
            "developer_id_team_id": "ABCDE12345",
            "developer_id_team_floor_sha256": "e" * 64,
            "developer_id_team_floor_release_id": "f" * 64,
        }
        if operation == "install":
            return {
                **common, "status": "deployed",
                "launcher_sha256": "4" * 64,
                "payloads": self.target_plan["payloads"],
            }
        return {
            **common, "status": "rolled_back", "repo_match": True,
            "warning": None,
        }

    def host_pair_recovery_binding(self):
        return DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "4" * 64, "4" * 64,
            schema_current_release_id="a" * 64,
            host_pair_pending_sha256="5" * 64,
            host_pair_transition_id=(
                "11111111-1111-4111-8111-111111111111"
            ),
            host_pair_transition_sha256="6" * 64,
            host_pair_operation="install",
            host_pair_target_candidate_authority_sha256="7" * 64,
            host_pair_target_release_tree_identity_sha256="8" * 64,
        )

    def host_pair_recovery_result(self, binding=None):
        binding = binding or self.host_pair_recovery_binding()
        return {
            "candidate_authority_sha256": (
                binding.host_pair_target_candidate_authority_sha256
            ),
            "host_release_launcher_pair_sha256": "9" * 64,
            "operation": binding.host_pair_operation,
            "release_id": binding.release_id,
            "release_tree_identity_sha256": (
                binding.host_pair_target_release_tree_identity_sha256
            ),
            "schema": DEPLOY.MANAGER.SCHEMA,
            "status": "host_pair_transition_recovered",
            "transition_id": binding.host_pair_transition_id,
            "transition_sha256": binding.host_pair_transition_sha256,
        }

    def retained_candidate_fixture(self):
        repo = self.root / "candidate-repo"
        repo.mkdir()
        repo = repo.resolve(strict=True)
        commit = "2" * 40
        submission = "12345678-1234-4123-8123-123456789abc"
        candidate_root = (
            repo / ".private/native-host-product-candidates"
            / f"{commit}-{submission}"
        )
        generation = candidate_root / "generation"
        generation.mkdir(parents=True)
        evidence = candidate_root / "evidence"
        evidence.mkdir(mode=0o700)
        preimage = evidence / "SecureSandboxHostReleasePreimage.tar"
        preimage.write_bytes(b"p" * 1024)
        preimage.chmod(0o400)
        info = generation.lstat()
        preimage_info = preimage.lstat()
        candidate = DEPLOY.NativeHostCandidate(
            schema="secure-sandbox-native-host-candidate-record-v2",
            generation_path=str(generation),
            generation_device=info.st_dev,
            generation_inode=info.st_ino,
            generation_tree_sha256="1" * 64,
            release_commit=commit,
            source_archive_sha256="3" * 64,
            source_tree_sha256="4" * 64,
            signing_config_sha256="5" * 64,
            host_release_preimage_path=str(preimage),
            host_release_preimage_device=preimage_info.st_dev,
            host_release_preimage_inode=preimage_info.st_ino,
            host_release_preimage_size=preimage_info.st_size,
            host_release_preimage_sha256="6" * 64,
            host_release_preimage_schema=(
                "secure-sandbox-native-host-release-preimage-v1"
            ),
            developer_id_certificate_sha1="6" * 40,
            notary_submission_id=submission,
            build_custody="trusted-login-principal-v1",
        )
        build_result = {
            "build_custody": "trusted-login-principal-v1",
            "candidate_evidence": str(candidate_root),
            "developer_id_certificate_sha1": "6" * 40,
            "host_release_preimage_sha256": "6" * 64,
            "release_commit": commit,
            "schema": "secure-sandbox-native-host-products-build-v3",
            "signing_config_sha256": "5" * 64,
            "source_archive_sha256": "3" * 64,
            "source_tree_sha256": "4" * 64,
            "status": "verified",
            "target": str(repo / "artifacts/host"),
        }
        manager_path = repo / "scripts/host-controller-release.py"
        manager_path.parent.mkdir()
        return manager_path, build_result, candidate

    def candidate_classification(self, candidate):
        return {
            "candidate_record": candidate.record(),
            "eligibility": "candidate-admission-eligible",
            "generation_device": candidate.generation_device,
            "generation_inode": candidate.generation_inode,
            "generation_path": candidate.generation_path,
            "generation_tree_sha256": candidate.generation_tree_sha256,
            "receipt_schema": (
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V3_SCHEMA
            ),
            "schema": (
                DEPLOY.MANAGER
                .NATIVE_HOST_RETAINED_CANDIDATE_CLASSIFICATION_SCHEMA
            ),
        }

    @staticmethod
    def candidate_provenance(candidate):
        return {
            "release_commit": candidate.release_commit,
            "signing_config_sha256": candidate.signing_config_sha256,
            "source_archive_sha256": candidate.source_archive_sha256,
            "source_tree_sha256": candidate.source_tree_sha256,
        }

    def historical_candidate_classification(self, generation):
        info = generation.lstat()
        return {
            "candidate_record": None,
            "eligibility": "historical-receipt-v2-ineligible",
            "generation_device": info.st_dev,
            "generation_inode": info.st_ino,
            "generation_path": str(generation),
            "generation_tree_sha256": "7" * 64,
            "receipt_schema": (
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_RECEIPT_V2_SCHEMA
            ),
            "schema": (
                DEPLOY.MANAGER
                .NATIVE_HOST_RETAINED_CANDIDATE_CLASSIFICATION_SCHEMA
            ),
        }

    def test_deploy_routes_through_protected_broker_with_attribution(self):
        result = self.manager_result()
        completed = SimpleNamespace(
            returncode=0, stdout=json.dumps(result), stderr="",
        )
        with (
            mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run,
            mock.patch.object(
                DEPLOY, "wait_for_host_pair_terminal",
            ) as waited,
        ):
            self.assertEqual(self.run_main([
                "deploy", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
                "--purpose", "Publish reviewed DDD",
            ]), 0)
        waited.assert_not_called()
        command = run.call_args.args[0]
        self.assertEqual(command[:2], [str(self.broker), "request"])
        self.assertNotIn("sudo", command)
        self.assertIn("Codex", command)
        self.assertIn("thread-7", command)
        parameters = json.loads(command[command.index("--parameters-json") + 1])
        self.assertEqual(parameters["state_root"], str(self.root / "state"))
        self.assertEqual(parameters["authorized_target_plan"], self.target_plan)
        self.assertEqual(
            parameters["authorized_target_plan_sha256"],
            self.target_plan_sha256,
        )
        self.assertEqual(
            parameters["native_host_candidate"], self.candidate.record(),
        )
        self.assertEqual(command[command.index("--operation") + 1], "host-controller-install")

    def test_ordinary_launcher_migration_is_not_a_public_command(self):
        with self.assertRaises(SystemExit):
            self.run_main([
                "migrate-launcher", "7" * 64,
                "--requesting-agent", "Codex",
                "--requesting-session", "candidate-launcher-migration",
            ])

    def test_terminal_poll_retries_exact_publication_name_gap(self):
        transition_id = "11111111-1111-4111-8111-111111111111"
        pending = self.pair_pending(transition_id)
        terminal = self.pair_terminal(transition_id)
        stable = self.pair_stable(terminal)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            filename = directory / f"{transition_id}.json"

            def opened(*_args, **_kwargs):
                return os.open(directory, os.O_RDONLY | os.O_DIRECTORY)

            def publish(_seconds):
                filename.write_bytes(b"terminal\n")
                filename.chmod(0o444)

            with (
                mock.patch.object(
                    DEPLOY.MANAGER, "open_trusted_absolute_directory",
                    side_effect=opened,
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "read_state_record_at",
                    return_value=(terminal, b"terminal\n", mock.Mock()),
                ) as read,
                mock.patch.object(
                    DEPLOY.MANAGER, "validate_public_host_pair_terminal",
                    return_value=terminal,
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "host_release_launcher_pair_public",
                    return_value=(stable, "4" * 64),
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "verified_public_host_pair_terminal",
                    return_value=(terminal, "2" * 64),
                ),
                mock.patch.object(
                    DEPLOY.time, "sleep", side_effect=publish,
                ) as slept,
            ):
                observed = DEPLOY.wait_for_install_terminal(
                    pending, timeout=1,
                )
        self.assertEqual(observed, terminal)
        slept.assert_called_once()

    def test_terminal_poll_retries_two_link_publication_window(self):
        transition_id = "11111111-1111-4111-8111-111111111111"
        pending = self.pair_pending(transition_id)
        terminal = self.pair_terminal(transition_id)
        stable = self.pair_stable(terminal)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            final = directory / f"{transition_id}.json"
            publication = directory / f".{transition_id}.pending"
            final.write_bytes(b"terminal\n")
            final.chmod(0o444)
            os.link(final, publication)

            def opened(*_args, **_kwargs):
                return os.open(directory, os.O_RDONLY | os.O_DIRECTORY)

            def finish_publication(_seconds):
                publication.unlink()

            with (
                mock.patch.object(
                    DEPLOY.MANAGER, "open_trusted_absolute_directory",
                    side_effect=opened,
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "read_state_record_at",
                    return_value=(terminal, b"terminal\n", mock.Mock()),
                ) as read,
                mock.patch.object(
                    DEPLOY.MANAGER, "validate_public_host_pair_terminal",
                    return_value=terminal,
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "host_release_launcher_pair_public",
                    return_value=(stable, "4" * 64),
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "verified_public_host_pair_terminal",
                    return_value=(terminal, "2" * 64),
                ),
                mock.patch.object(
                    DEPLOY.time, "sleep", side_effect=finish_publication,
                ) as slept,
            ):
                observed = DEPLOY.wait_for_install_terminal(
                    pending, timeout=1,
                )
        self.assertEqual(observed, terminal)
        slept.assert_called_once()
        read.assert_called_once()

    def test_terminal_poll_accepts_public_commit_before_manager_pending_cleanup(self):
        transition_id = "11111111-1111-4111-8111-111111111111"
        pending = self.pair_pending(transition_id)
        terminal = self.pair_terminal(transition_id)
        stable = self.pair_stable(terminal)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "install-transitions"
            directory.mkdir()
            (root / ".install-transition.json").write_text(
                "pending\n", encoding="ascii",
            )
            final = directory / f"{transition_id}.json"
            final.write_bytes(b"terminal\n")
            final.chmod(0o444)

            def opened(*_args, **_kwargs):
                return os.open(directory, os.O_RDONLY | os.O_DIRECTORY)

            with (
                mock.patch.object(
                    DEPLOY.MANAGER, "open_trusted_absolute_directory",
                    side_effect=opened,
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "read_state_record_at",
                    return_value=(terminal, b"terminal\n", mock.Mock()),
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "validate_public_host_pair_terminal",
                    return_value=terminal,
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "host_release_launcher_pair_public",
                    return_value=(stable, "4" * 64),
                ),
                mock.patch.object(
                    DEPLOY.MANAGER, "verified_public_host_pair_terminal",
                    return_value=(terminal, "2" * 64),
                ),
                mock.patch.object(DEPLOY.time, "sleep") as slept,
            ):
                observed = DEPLOY.wait_for_install_terminal(
                    pending, timeout=1,
                )
        self.assertEqual(observed, terminal)
        slept.assert_not_called()

    def test_native_host_products_build_requires_local_signing_inputs(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                RuntimeError,
                "Developer_ID_notary_profile_and_keychain_are_required",
            ):
                DEPLOY.prepare_native_host_products()

    def test_native_host_products_build_rejects_ambiguous_keychain_path(self):
        for value in (
            "Library/Keychains/login.keychain-db",
            "/private/tmp/SecureSandboxNotary.keychain-db\n",
            "/private/tmp/SecureSandboxNotary.keychain-db\r",
        ):
            with (
                self.subTest(value=repr(value)),
                mock.patch.dict(
                    os.environ,
                    {
                        "SECURE_SANDBOX_DEVELOPER_ID": "6" * 40,
                        "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE": "profile",
                        "SECURE_SANDBOX_NOTARY_KEYCHAIN": value,
                    },
                    clear=True,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "Developer_ID_notary_profile_and_keychain_are_required",
                ),
            ):
                DEPLOY.prepare_native_host_products()

    def test_native_host_products_build_is_bounded_and_environment_pinned(self):
        manager_path, build_result, candidate = (
            self.retained_candidate_fixture()
        )
        completed = SimpleNamespace(
            returncode=0, stdout=json.dumps(build_result), stderr="",
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "SECURE_SANDBOX_DEVELOPER_ID": "6" * 40,
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE": "profile",
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN": (
                        "/private/tmp/SecureSandboxNotary.keychain-db"
                    ),
                    "UNRELATED": "retained",
                },
                clear=True,
            ),
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed
            ) as run,
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_record",
                return_value=candidate.record(),
            ) as record,
        ):
            observed = DEPLOY.prepare_native_host_products()
        self.assertEqual(observed, candidate)
        self.assertEqual(run.call_args.args[0], [str(DEPLOY.NATIVE_HOST_PRODUCTS_BUILD)])
        self.assertEqual(run.call_args.kwargs["timeout"], 1800)
        self.assertEqual(run.call_args.kwargs["stdin"], DEPLOY.subprocess.DEVNULL)
        self.assertEqual(
            run.call_args.kwargs["env"]["PATH"],
            "/usr/bin:/bin:/usr/sbin:/sbin",
        )
        self.assertEqual(run.call_args.kwargs["env"]["UNRELATED"], "retained")
        self.assertEqual(
            run.call_args.kwargs["env"]["SECURE_SANDBOX_NOTARY_KEYCHAIN"],
            "/private/tmp/SecureSandboxNotary.keychain-db",
        )
        record.assert_called_once_with(
            manager_path.parent.parent,
            Path(candidate.generation_path),
            expected_certificate_sha1="6" * 40,
        )

    def test_native_host_products_build_rejects_candidate_provenance_disagreement(self):
        manager_path, build_result, candidate = (
            self.retained_candidate_fixture()
        )
        mismatched = candidate._replace(source_tree_sha256="9" * 64)
        completed = SimpleNamespace(
            returncode=0, stdout=json.dumps(build_result), stderr="",
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "SECURE_SANDBOX_DEVELOPER_ID": "6" * 40,
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE": "profile",
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN": (
                        "/private/tmp/SecureSandboxNotary.keychain-db"
                    ),
                },
                clear=True,
            ),
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_record",
                return_value=mismatched.record(),
            ),
            self.assertRaisesRegex(
                RuntimeError, "native_host_products_build_result_invalid",
            ),
        ):
            DEPLOY.prepare_native_host_products()

    def test_native_host_products_build_rejects_non_object_json(self):
        completed = SimpleNamespace(returncode=0, stdout="[]", stderr="")
        with (
            mock.patch.dict(
                os.environ,
                {
                    "SECURE_SANDBOX_DEVELOPER_ID": "6" * 40,
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE": "profile",
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN": (
                        "/private/tmp/SecureSandboxNotary.keychain-db"
                    ),
                },
                clear=True,
            ),
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ),
            self.assertRaisesRegex(
                RuntimeError, "native_host_products_build_result_invalid",
            ),
        ):
            DEPLOY.prepare_native_host_products()

    def test_expected_source_release_resolves_verified_host_products_first(self):
        values = {
            "native_stack_deployer": b"deployer",
            "native_deployment_payloads": b"payloads",
            "native_stack_coordination_contract": b"coordination",
        }
        hashes = {
            name: hashlib.sha256(value).hexdigest()
            for name, value in values.items()
        }
        with (
            mock.patch.object(
                DEPLOY, "source_release_candidate_product",
                return_value=self.candidate,
            ) as resolve,
            mock.patch.object(
                DEPLOY.MANAGER,
                "source_payload",
                return_value=(values, hashes, "a" * 64),
            ) as source,
            mock.patch.object(
                DEPLOY.MANAGER, "verified_host_release_launcher_pair",
                return_value=({}, "7" * 64, None, None, None),
            ) as pair,
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_tracked_source",
                return_value=b"launcher",
            ) as launcher,
            mock.patch.object(
                DEPLOY.MANAGER, "authorized_host_release_target_plan",
                return_value=(self.target_plan, self.target_plan_sha256),
            ) as target_plan,
        ):
            observed = self.real_expected_source_release_binding()
            self.assertEqual(observed.release_id, "a" * 64)
            self.assertEqual(observed.native_host_candidate, self.candidate)
            self.assertEqual(observed.authorized_target_plan, self.target_plan)
            self.assertEqual(
                observed.authorized_target_plan_sha256,
                self.target_plan_sha256,
            )
        resolve.assert_called_once_with()
        source.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent,
            expected_native_host_certificate_sha1=(
                self.candidate.developer_id_certificate_sha1
            ),
            native_host_generation=Path(self.candidate.generation_path),
            expected_native_host_candidate=self.candidate.record(),
        )
        pair.assert_called_once_with(
            DEPLOY.INSTALL_ROOT, DEPLOY.STABLE_LAUNCHER, 0,
            public_only=True,
        )
        launcher.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent,
            Path(self.candidate.generation_path),
            self.candidate.record(), DEPLOY.MANAGER.LAUNCHER_SOURCE,
        )
        target_plan.assert_called_once_with(
            release_id="a" * 64,
            payloads=hashes,
            candidate_record=self.candidate.record(),
            target_launcher_sha256=hashlib.sha256(b"launcher").hexdigest(),
            source_stable_sha256="7" * 64,
        )

    def test_expected_source_release_rejects_missing_deployment_payload(self):
        with (
            mock.patch.object(
                DEPLOY, "source_release_candidate_product",
                return_value=self.candidate,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(
                    {"native_stack_deployer": b"deployer"},
                    {"native_stack_deployer": hashlib.sha256(
                        b"deployer"
                    ).hexdigest()},
                    "a" * 64,
                ),
            ),
            self.assertRaisesRegex(
                RuntimeError, "native_deployment_release_payloads_invalid",
            ),
        ):
            self.real_expected_source_release_binding()

    def test_candidate_schema_replay_reuses_unique_publicly_bound_candidate(self):
        manager_path, _build_result, candidate = self.retained_candidate_fixture()
        public = {
            "schema": "secure-sandbox-native-host-candidate-enforcement-v1",
            "required_feature": "native-host-candidate-admission-v1",
            "required_payload_inventory_sha256": "8" * 64,
            "authoritative_floor_sha256": "9" * 64,
        }
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=(public, "7" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                return_value=self.candidate_classification(candidate),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_floor_records",
                return_value=({}, b"floor\n", public, b"public\n"),
            ),
            mock.patch.object(DEPLOY, "prepare_native_host_products") as build,
        ):
            observed = DEPLOY.native_host_candidate_schema_product()
        self.assertEqual(observed, candidate)
        build.assert_not_called()

    def test_candidate_schema_replay_skips_trusted_power_loss_build_residue(self):
        manager_path, _build_result, candidate = self.retained_candidate_fixture()
        repo = manager_path.parent.parent
        residue = (
            repo / ".private/native-host-product-candidates"
            / ".candidate.7zHjFM"
        )
        residue.mkdir(mode=0o700)
        (residue / "incomplete-build-evidence").write_bytes(b"partial")
        public = {
            "schema": "secure-sandbox-native-host-candidate-enforcement-v1",
            "required_feature": "native-host-candidate-admission-v1",
            "required_payload_inventory_sha256": "8" * 64,
            "authoritative_floor_sha256": "9" * 64,
        }
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                return_value=self.candidate_classification(candidate),
            ) as record,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_floor_records",
                return_value=({}, b"floor\n", public, b"public\n"),
            ),
        ):
            observed = DEPLOY.retained_native_host_candidate_product(
                (public, "7" * 64),
                establishment_mode=(
                    DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                ),
                predecessor_release_id=(
                    DEPLOY.MANAGER
                    .NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            )
        self.assertEqual(observed, candidate)
        record.assert_called_once_with(
            repo, Path(candidate.generation_path),
        )
        self.assertTrue(residue.is_dir())

    def test_candidate_schema_replay_rejects_untrusted_build_residue(self):
        manager_path, _build_result, _candidate = self.retained_candidate_fixture()
        repo = manager_path.parent.parent
        residue = (
            repo / ".private/native-host-product-candidates"
            / ".candidate.7zHjFM"
        )
        residue.mkdir(mode=0o755)
        with self.assertRaisesRegex(
            RuntimeError, "native_host_candidate_replay_inventory_invalid",
        ):
            DEPLOY.retained_native_host_candidate_product(
                ({}, "7" * 64),
                establishment_mode=(
                    DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                ),
                predecessor_release_id=(
                    DEPLOY.MANAGER
                    .NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            )

    def test_candidate_schema_replay_skips_only_authenticated_historical_v2(self):
        manager_path, _build_result, candidate = self.retained_candidate_fixture()
        repo = manager_path.parent.parent
        historical = (
            repo / ".private/native-host-product-candidates"
            / ("1" * 40 + "-12345678-1234-4123-8123-123456789abc")
            / "generation"
        )
        historical.mkdir(parents=True)
        public = {
            "schema": "secure-sandbox-native-host-candidate-enforcement-v1",
            "required_feature": "native-host-candidate-admission-v1",
            "required_payload_inventory_sha256": "8" * 64,
            "authoritative_floor_sha256": "9" * 64,
        }
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}

        def classify(_repo, generation, **_kwargs):
            if generation == historical:
                return self.historical_candidate_classification(historical)
            return self.candidate_classification(candidate)

        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                side_effect=classify,
            ) as classified,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ) as source,
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_floor_records",
                return_value=({}, b"floor\n", public, b"public\n"),
            ),
        ):
            observed = DEPLOY.retained_native_host_candidate_product(
                (public, "7" * 64),
                establishment_mode=(
                    DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                ),
                predecessor_release_id=(
                    DEPLOY.MANAGER
                    .NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            )
        self.assertEqual(observed, candidate)
        self.assertEqual(classified.call_count, 2)
        source.assert_called_once()

    def test_candidate_schema_replay_rejects_tampered_historical_v2(self):
        manager_path, _build_result, _candidate = self.retained_candidate_fixture()
        repo = manager_path.parent.parent
        historical = (
            repo / ".private/native-host-product-candidates"
            / ("1" * 40 + "-12345678-1234-4123-8123-123456789abc")
            / "generation"
        )
        historical.mkdir(parents=True)

        def classify(_repo, generation, **_kwargs):
            if generation == historical:
                raise DEPLOY.MANAGER.ReleaseFailure(
                    "native_host_products_notarization_signature_invalid"
                )
            raise AssertionError("tampered historical entry must fail first")

        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                side_effect=classify,
            ),
            mock.patch.object(DEPLOY.MANAGER, "source_payload") as source,
            self.assertRaisesRegex(
                RuntimeError, "native_host_candidate_replay_inventory_invalid",
            ),
        ):
            DEPLOY.retained_native_host_candidate_product(
                ({}, "7" * 64),
                establishment_mode=(
                    DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_BOOTSTRAP_MODE
                ),
                predecessor_release_id=(
                    DEPLOY.MANAGER
                    .NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
                ),
            )
        source.assert_not_called()

    def test_authorization_bootstrap_replay_uses_exact_predecessor_mode(self):
        manager_path, _build_result, candidate = self.retained_candidate_fixture()
        public = {
            "schema": "secure-sandbox-native-host-candidate-enforcement-v1",
            "required_feature": "native-host-candidate-admission-v1",
            "required_payload_inventory_sha256": "8" * 64,
            "authoritative_floor_sha256": "9" * 64,
        }
        predecessor = "f" * 64
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=(public, "7" * 64),
            ),
            mock.patch.object(
                DEPLOY, "authorization_bootstrap_predecessor_release_id",
                return_value=predecessor,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                return_value=self.candidate_classification(candidate),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_floor_records",
                return_value=({}, b"floor\n", public, b"public\n"),
            ) as floor_records,
            mock.patch.object(DEPLOY, "prepare_native_host_products") as build,
        ):
            observed = DEPLOY.native_host_authorization_bootstrap_product()
        self.assertEqual(observed, candidate)
        build.assert_not_called()
        floor_records.assert_called_once_with(
            release_id="a" * 64,
            candidate_record=candidate.record(),
            establishment_mode=(
                DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_AUTHORIZATION_BOOTSTRAP_MODE
            ),
            predecessor_release_id=predecessor,
        )

    def test_fresh_authorization_bootstrap_reuses_one_transferable_candidate(self):
        manager_path, _build_result, candidate = self.retained_candidate_fixture()
        retained_root = (
            manager_path.parent.parent
            / ".private/native-host-product-candidates"
        )
        retained_root.chmod(0o700)
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=None,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                return_value=self.candidate_classification(candidate),
            ) as classify,
            mock.patch.object(
                DEPLOY.MANAGER,
                "current_native_host_candidate_source_provenance",
                return_value=self.candidate_provenance(candidate),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ) as source,
            mock.patch.object(DEPLOY, "prepare_native_host_products") as build,
        ):
            observed = DEPLOY.native_host_authorization_bootstrap_product()
        self.assertEqual(observed, candidate)
        classify.assert_called_once_with(
            manager_path.parent.parent.resolve(strict=True),
            Path(candidate.generation_path),
        )
        source.assert_called_once_with(
            manager_path.parent.parent.resolve(strict=True),
            expected_native_host_certificate_sha1=(
                candidate.developer_id_certificate_sha1
            ),
            native_host_generation=Path(candidate.generation_path),
            expected_native_host_candidate=candidate.record(),
        )
        build.assert_not_called()

    def test_fresh_candidate_import_rejects_ambiguous_authority(self):
        manager_path, _build_result, first = self.retained_candidate_fixture()
        repo = manager_path.parent.parent.resolve(strict=True)
        retained_root = repo / ".private/native-host-product-candidates"
        retained_root.chmod(0o700)
        second_root = retained_root / (
            first.release_commit + "-abcdefab-cdef-4abc-8def-abcdefabcdef"
        )
        second_generation = second_root / "generation"
        second_generation.mkdir(parents=True)
        second_info = second_generation.lstat()
        second = DEPLOY.NativeHostCandidate(**{
            **first.record(),
            "generation_path": str(second_generation),
            "generation_device": second_info.st_dev,
            "generation_inode": second_info.st_ino,
            "notary_submission_id": (
                "abcdefab-cdef-4abc-8def-abcdefabcdef"
            ),
        })
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}

        def classify(_repo, generation, **_kwargs):
            return self.candidate_classification(
                first if generation == Path(first.generation_path) else second
            )

        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                side_effect=classify,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "current_native_host_candidate_source_provenance",
                return_value=self.candidate_provenance(first),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            self.assertRaisesRegex(
                RuntimeError, "native_host_candidate_import_ambiguous",
            ),
        ):
            DEPLOY.unbound_native_host_candidate_product()

    def test_fresh_candidate_import_rejects_tampered_inventory(self):
        manager_path, _build_result, _candidate = self.retained_candidate_fixture()
        retained_root = (
            manager_path.parent.parent
            / ".private/native-host-product-candidates"
        )
        retained_root.chmod(0o700)
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                side_effect=DEPLOY.MANAGER.ReleaseFailure(
                    "native_host_products_receipt_signature_invalid"
                ),
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "current_native_host_candidate_source_provenance",
                return_value=self.candidate_provenance(_candidate),
            ),
            mock.patch.object(DEPLOY.MANAGER, "source_payload") as source,
            self.assertRaisesRegex(
                RuntimeError,
                "native_host_candidate_import_inventory_invalid",
            ),
        ):
            DEPLOY.unbound_native_host_candidate_product()
        source.assert_not_called()

    def test_candidate_import_skips_historical_identical_product_candidate(self):
        manager_path, _build_result, current = self.retained_candidate_fixture()
        repo = manager_path.parent.parent.resolve(strict=True)
        retained_root = repo / ".private/native-host-product-candidates"
        retained_root.chmod(0o700)
        historical_root = retained_root / (
            "d" * 40 + "-abcdefab-cdef-4abc-8def-abcdefabcdef"
        )
        historical_generation = historical_root / "generation"
        historical_generation.mkdir(parents=True)
        historical_info = historical_generation.lstat()
        historical = DEPLOY.NativeHostCandidate(**{
            **current.record(),
            "generation_path": str(historical_generation),
            "generation_device": historical_info.st_dev,
            "generation_inode": historical_info.st_ino,
            "release_commit": "d" * 40,
            "notary_submission_id": "abcdefab-cdef-4abc-8def-abcdefabcdef",
        })
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}

        def classify(_repo, generation, **_kwargs):
            return self.candidate_classification(
                current if generation == Path(current.generation_path)
                else historical
            )

        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                side_effect=classify,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "current_native_host_candidate_source_provenance",
                return_value=self.candidate_provenance(current),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ) as source,
        ):
            observed = DEPLOY.unbound_native_host_candidate_product()
        self.assertEqual(observed, current)
        source.assert_called_once_with(
            repo,
            expected_native_host_certificate_sha1=(
                current.developer_id_certificate_sha1
            ),
            native_host_generation=Path(current.generation_path),
            expected_native_host_candidate=current.record(),
        )

    def test_source_release_candidate_reuses_transfer_without_credentials(self):
        with (
            mock.patch.object(
                DEPLOY, "unbound_native_host_candidate_product",
                return_value=self.candidate,
            ) as imported,
            mock.patch.object(DEPLOY, "prepare_native_host_products") as build,
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            observed = DEPLOY.source_release_candidate_product()
        self.assertEqual(observed, self.candidate)
        imported.assert_called_once_with()
        build.assert_not_called()

    def test_source_release_candidate_builds_only_without_matching_transfer(self):
        with (
            mock.patch.object(
                DEPLOY, "unbound_native_host_candidate_product",
                return_value=None,
            ) as imported,
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
                return_value=self.candidate,
            ) as build,
        ):
            observed = DEPLOY.source_release_candidate_product()
        self.assertEqual(observed, self.candidate)
        imported.assert_called_once_with()
        build.assert_called_once_with()

    def test_stage_native_host_candidate_copies_bounded_tree_then_verifies(self):
        repo = self.root / "stage-repo"
        manager_path = repo / "scripts/host-controller-release.py"
        manager_path.parent.mkdir(parents=True)
        transfer_parent = self.root / "transfer"
        transfer_parent.mkdir()
        candidate_name = (
            "2" * 40 + "-12345678-1234-4123-8123-123456789abc"
        )
        source = transfer_parent / candidate_name
        generation = source / "generation"
        evidence = source / "evidence"
        generation.mkdir(parents=True)
        evidence.mkdir()
        source.chmod(0o700)
        generation.chmod(0o755)
        evidence.chmod(0o700)
        receipt_name = DEPLOY.MANAGER.PAYLOAD_SOURCES[
            "native_host_products_notarization"
        ].name
        receipt = generation / receipt_name
        receipt.write_bytes(b"receipt\n")
        receipt.chmod(0o444)
        preimage = evidence / "SecureSandboxHostReleasePreimage.tar"
        preimage.write_bytes(b"preimage")
        preimage.chmod(0o400)

        destination_generation = (
            repo.resolve() / ".private/native-host-product-candidates"
            / candidate_name / "generation"
        )
        destination_record = {
            **self.candidate.record(),
            "generation_path": str(destination_generation),
        }
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_products_notarization",
                return_value={
                    "release_commit": "2" * 40,
                    "notary_submission_id": (
                        "12345678-1234-4123-8123-123456789abc"
                    ),
                },
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_record",
                return_value=destination_record,
            ) as verify,
        ):
            observed = DEPLOY.stage_native_host_candidate_transfer(
                source.resolve(strict=True),
            )
        self.assertEqual(observed.record(), destination_record)
        verify.assert_called_once_with(repo.resolve(), destination_generation)
        self.assertEqual((destination_generation / receipt_name).read_bytes(), b"receipt\n")
        self.assertEqual(
            stat.S_IMODE((destination_generation / receipt_name).stat().st_mode),
            0o444,
        )
        self.assertEqual(
            stat.S_IMODE(
                (destination_generation.parent / "evidence"
                 / "SecureSandboxHostReleasePreimage.tar").stat().st_mode
            ),
            0o400,
        )

    def test_stage_native_host_candidate_rejects_symlink(self):
        repo = self.root / "stage-repo"
        manager_path = repo / "scripts/host-controller-release.py"
        manager_path.parent.mkdir(parents=True)
        candidate_name = (
            "2" * 40 + "-12345678-1234-4123-8123-123456789abc"
        )
        source = self.root / candidate_name
        (source / "generation").mkdir(parents=True)
        (source / "evidence").mkdir()
        source.chmod(0o700)
        (source / "generation").chmod(0o755)
        (source / "evidence").chmod(0o700)
        (source / "generation/escape").symlink_to("/etc/passwd")
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_record",
            ) as verify,
            self.assertRaisesRegex(
                RuntimeError, "native_host_candidate_transfer_untrusted",
            ),
        ):
            DEPLOY.stage_native_host_candidate_transfer(
                source.resolve(strict=True),
            )
        verify.assert_not_called()

    def test_stage_native_host_candidate_retains_rejected_tree_as_inert(self):
        repo = self.root / "stage-repo"
        manager_path = repo / "scripts/host-controller-release.py"
        manager_path.parent.mkdir(parents=True)
        candidate_name = (
            "2" * 40 + "-12345678-1234-4123-8123-123456789abc"
        )
        source = self.root / "transfer" / candidate_name
        generation = source / "generation"
        evidence = source / "evidence"
        generation.mkdir(parents=True)
        evidence.mkdir()
        source.chmod(0o700)
        generation.chmod(0o755)
        evidence.chmod(0o700)
        receipt_name = DEPLOY.MANAGER.PAYLOAD_SOURCES[
            "native_host_products_notarization"
        ].name
        receipt = generation / receipt_name
        receipt.write_bytes(b"receipt\n")
        receipt.chmod(0o444)
        retained_root = (
            repo.resolve() / ".private/native-host-product-candidates"
        )
        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(DEPLOY.secrets, "token_hex", return_value="abc123"),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_products_notarization",
                return_value={
                    "release_commit": "2" * 40,
                    "notary_submission_id": (
                        "12345678-1234-4123-8123-123456789abc"
                    ),
                },
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_record",
                side_effect=DEPLOY.MANAGER.ReleaseFailure(
                    "native_host_products_receipt_signature_invalid"
                ),
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "native_host_products_receipt_signature_invalid",
            ),
        ):
            DEPLOY.stage_native_host_candidate_transfer(
                source.resolve(strict=True),
            )
        self.assertFalse((retained_root / candidate_name).exists())
        residue = retained_root / ".candidate.abc123"
        self.assertTrue(residue.is_dir())
        self.assertEqual(
            stat.S_IMODE(residue.stat().st_mode), 0o700,
        )

    def test_stage_native_host_candidate_cli_is_unprivileged_and_attribution_free(self):
        transfer = self.root / (
            "2" * 40 + "-12345678-1234-4123-8123-123456789abc"
        )
        candidate = self.candidate._replace(generation_path=str(
            self.root / "retained/generation"
        ))
        stdout = io.StringIO()
        with (
            mock.patch.object(
                DEPLOY, "stage_native_host_candidate_transfer",
                return_value=candidate,
            ) as stage,
            mock.patch("sys.stdout", stdout),
            mock.patch.object(DEPLOY.LAUNCHER, "acquire_lock") as lock,
            mock.patch.object(DEPLOY.subprocess, "run") as run,
        ):
            result = self.run_main([
                "stage-native-host-candidate", str(transfer),
            ])
        self.assertEqual(result, 0)
        stage.assert_called_once_with(transfer)
        lock.assert_not_called()
        run.assert_not_called()
        value = json.loads(stdout.getvalue())
        self.assertEqual(value, {
            "candidate": candidate.record(),
            "schema": "secure-sandbox-native-host-candidate-transfer-v1",
            "status": "verified",
        })

    def test_candidate_schema_replay_rejects_ambiguous_retained_candidates(self):
        manager_path, _build_result, first = self.retained_candidate_fixture()
        repo = manager_path.parent.parent
        second_root = (
            repo / ".private/native-host-product-candidates"
            / ("d" * 40 + "-abcdefab-cdef-4abc-8def-abcdefabcdef")
        )
        second_generation = second_root / "generation"
        second_generation.mkdir(parents=True)
        second_info = second_generation.lstat()
        second = DEPLOY.NativeHostCandidate(
            **{
                **first.record(),
                "generation_path": str(second_generation),
                "generation_device": second_info.st_dev,
                "generation_inode": second_info.st_ino,
                "release_commit": "d" * 40,
                "notary_submission_id": (
                    "abcdefab-cdef-4abc-8def-abcdefabcdef"
                ),
            }
        )
        public = {
            "schema": "secure-sandbox-native-host-candidate-enforcement-v1",
            "required_feature": "native-host-candidate-admission-v1",
            "required_payload_inventory_sha256": "8" * 64,
            "authoritative_floor_sha256": "9" * 64,
        }
        values = {name: b"payload" for name in DEPLOY.MANAGER.PAYLOAD_NAMES}

        def candidate_classification(_repo, generation, **_kwargs):
            candidate = (
                first
                if generation == Path(first.generation_path)
                else second
            )
            return self.candidate_classification(candidate)

        with (
            mock.patch.object(DEPLOY, "MANAGER_PATH", manager_path),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=(public, "7" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "classify_native_host_retained_candidate",
                side_effect=candidate_classification,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_floor_records",
                return_value=({}, b"floor\n", public, b"public\n"),
            ),
            self.assertRaisesRegex(
                RuntimeError, "native_host_candidate_replay_ambiguous",
            ),
        ):
            DEPLOY.native_host_candidate_schema_product()

    def test_postactivation_selector_preflight_replaces_root_floor_with_live_v2_identity(self):
        install = self.root / "install"
        install.mkdir()
        release = self.root / ("a" * 64)
        identity = {
            "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_epoch":2,
            "public_key_sha256":"b" * 64,
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active",
        }
        original = DEPLOY.MANAGER.enforce_execution_approval_floor

        def verified(*_args, **_kwargs):
            self.assertIsNot(DEPLOY.MANAGER.enforce_execution_approval_floor, original)
            return release, {}

        with (mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
              mock.patch.object(DEPLOY.MANAGER, "verified_release", side_effect=verified),
              mock.patch.object(
                  DEPLOY.MANAGER, "read_regular",
                  return_value=DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY,
              ),
              mock.patch.object(
                  DEPLOY.subprocess, "run",
                  return_value=SimpleNamespace(stdout=json.dumps(identity)),
              )):
            self.assertEqual(
                DEPLOY.postactivation_current_release(
                    expected_uid=self.uid
                ),
                release,
            )
        self.assertIs(DEPLOY.MANAGER.enforce_execution_approval_floor, original)

    def test_postactivation_public_candidate_floor_rejects_old_inventory(self):
        install = self.root / "install-public-candidate-floor"
        install.mkdir()
        release = self.root / ("a" * 64)
        public = {
            "required_payload_inventory_sha256": (
                DEPLOY.MANAGER.native_host_candidate_inventory_sha256()
            ),
        }
        observed_kwargs = {}

        def verified(*_args, **kwargs):
            observed_kwargs.update(kwargs)
            return release, {"payloads": {"authorization_broker": "b" * 64}}

        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY.MANAGER,
                "native_host_candidate_replay_enforcement",
                return_value=(public, "c" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_enforcement",
                return_value=(public, "c" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "verified_release", side_effect=verified,
            ),
            self.assertRaisesRegex(
                RuntimeError, "release_below_native_host_candidate_floor",
            ),
        ):
            DEPLOY.postactivation_current_release(expected_uid=self.uid)
        self.assertTrue(
            observed_kwargs["_bootstrap_without_candidate_admission_floor"]
        )

    def test_postactivation_pending_candidate_projection_fails_closed(self):
        install = self.root / "install-pending-candidate-floor"
        install.mkdir()
        public = {
            "required_payload_inventory_sha256": (
                DEPLOY.MANAGER.native_host_candidate_inventory_sha256()
            ),
        }
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY.MANAGER,
                "native_host_candidate_replay_enforcement",
                return_value=(public, "c" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_enforcement",
                side_effect=DEPLOY.MANAGER.ReleaseFailure(
                    "native_host_candidate_floor_untrusted"
                ),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "verified_release",
            ) as verified,
            self.assertRaisesRegex(
                DEPLOY.MANAGER.ReleaseFailure,
                "native_host_candidate_floor_untrusted",
            ),
        ):
            DEPLOY.postactivation_current_release(expected_uid=self.uid)
        verified.assert_not_called()

    def test_candidate_schema_preflight_allows_exact_floor_crash_replay(self):
        install = self.root / "install-candidate-replay"
        install.mkdir()
        release = self.root / (
            DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        )
        identity = {
            "algorithm": "ecdsa-p256-sha256-x962-low-s",
            "generation_epoch": 2,
            "public_key_sha256": "b" * 64,
            "schema": "secure-sandbox-execution-approval-key-v2",
            "status": "active",
        }
        public = {
            "required_payload_inventory_sha256": (
                DEPLOY.MANAGER.native_host_candidate_inventory_sha256()
            ),
        }
        coordination = {
            "minimum_epoch": 2,
            "minimum_features": ["native-deployment-journal-v1"],
        }

        def verified(*_args, **kwargs):
            self.assertTrue(
                kwargs["_bootstrap_without_candidate_admission_floor"]
            )
            self.assertTrue(
                kwargs["_bootstrap_without_native_coordination_floor"]
            )
            return release, {"payloads": {"authorization_broker": "b" * 64}}

        def read(path):
            if path.name == "native_stack_coordination_contract":
                return b"coordination-contract\n"
            return DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY

        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=(public, "c" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_stack_coordination_enforcement",
                return_value=(coordination, "d" * 64),
            ) as public_coordination,
            mock.patch.object(
                DEPLOY.MANAGER, "verified_release", side_effect=verified,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "validate_native_stack_coordination_contract",
                return_value={
                    "epoch": 2,
                    "features": ["native-deployment-journal-v1"],
                },
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", side_effect=read,
            ),
            mock.patch.object(
                DEPLOY.subprocess, "run",
                return_value=SimpleNamespace(stdout=json.dumps(identity)),
            ),
        ):
            observed = DEPLOY.postactivation_current_release(
                allow_legacy=True,
                expected_uid=self.uid,
                allow_candidate_schema_bootstrap=True,
            )
        self.assertEqual(observed, release)
        public_coordination.assert_called_once_with(install, self.uid)

    def test_candidate_schema_preflight_requires_public_coordination_enforcement(self):
        install = self.root / "install-candidate-missing-coordination"
        install.mkdir()
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=None,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_stack_coordination_enforcement",
                return_value=None,
            ) as public_coordination,
            mock.patch.object(
                DEPLOY.MANAGER, "verified_release",
            ) as verified,
            self.assertRaisesRegex(
                RuntimeError,
                "native_stack_coordination_enforcement_missing",
            ),
        ):
            DEPLOY.postactivation_current_release(
                allow_legacy=True,
                expected_uid=self.uid,
                allow_candidate_schema_bootstrap=True,
            )
        public_coordination.assert_called_once_with(install, self.uid)
        verified.assert_not_called()

    def test_candidate_schema_preflight_rejects_public_coordination_mismatch(self):
        install = self.root / "install-candidate-coordination-mismatch"
        install.mkdir()
        release = self.root / (
            DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        )
        enforcement = {
            "minimum_epoch": 2,
            "minimum_features": ["native-deployment-journal-v1"],
        }
        cases = (
            (
                "epoch",
                {
                    "epoch": 1,
                    "features": ["native-deployment-journal-v1"],
                },
            ),
            ("feature", {"epoch": 2, "features": []}),
        )
        for label, contract in cases:
            with self.subTest(label=label):
                def verified(*_args, **kwargs):
                    self.assertTrue(
                        kwargs[
                            "_bootstrap_without_native_coordination_floor"
                        ]
                    )
                    self.assertTrue(
                        kwargs[
                            "_bootstrap_without_candidate_admission_floor"
                        ]
                    )
                    return release, {"payloads": {}}

                with (
                    mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
                    mock.patch.object(
                        DEPLOY.MANAGER,
                        "native_host_candidate_replay_enforcement",
                        return_value=None,
                    ),
                    mock.patch.object(
                        DEPLOY.MANAGER,
                        "native_stack_coordination_enforcement",
                        return_value=(enforcement, "c" * 64),
                    ),
                    mock.patch.object(
                        DEPLOY.MANAGER, "verified_release",
                        side_effect=verified,
                    ),
                    mock.patch.object(
                        DEPLOY.MANAGER, "read_regular",
                        return_value=b"coordination-contract\n",
                    ),
                    mock.patch.object(
                        DEPLOY.MANAGER,
                        "validate_native_stack_coordination_contract",
                        return_value=contract,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "release_below_native_stack_coordination_floor",
                    ),
                ):
                    DEPLOY.postactivation_current_release(
                        allow_legacy=True,
                        expected_uid=self.uid,
                        allow_candidate_schema_bootstrap=True,
                    )

    def test_postactivation_developer_id_recovery_avoids_reading_root_floor(self):
        install = self.root / "install"
        release = install / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        floor = install / DEPLOY.MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
        floor.write_text("protected\n", encoding="ascii")
        floor.chmod(0o600)
        identity = {
            "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_epoch":2,
            "public_key_sha256":"b" * 64,
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active",
        }
        original = DEPLOY.MANAGER.developer_id_team_floor

        def verified(*_args, **_kwargs):
            self.assertIsNot(
                DEPLOY.MANAGER.developer_id_team_floor, original
            )
            return release, {}

        def read(path):
            if path.name == "authorization_broker":
                return DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY
            return b"authorization-manifest\n"

        with (mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
              mock.patch.object(
                  DEPLOY.MANAGER, "verified_release", side_effect=verified
              ),
              mock.patch.object(DEPLOY.MANAGER, "read_regular", side_effect=read),
              mock.patch.object(
                  DEPLOY.MANAGER,
                  "verified_authorization_ui_signing_policy",
              ) as signing,
              mock.patch.object(
                  DEPLOY.subprocess, "run",
                  return_value=SimpleNamespace(stdout=json.dumps(identity)),
              )):
            self.assertEqual(
                DEPLOY.postactivation_current_release(
                    expected_uid=self.uid
                ),
                release,
            )
        signing.assert_called_once()
        self.assertIs(DEPLOY.MANAGER.developer_id_team_floor, original)

    def test_postactivation_migration_retry_accepts_only_existing_anchor(self):
        install = self.root / "install"
        release = install / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        predecessor = (
            install
            / DEPLOY.MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
        )
        predecessor.symlink_to(f"releases/{release.name}")
        candidate = install / "releases" / ("b" * 64)
        candidate.mkdir()
        (install / "current").symlink_to(f"releases/{candidate.name}")
        floor = install / DEPLOY.MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
        floor.write_text("protected\n", encoding="ascii")
        floor.chmod(0o600)
        pending_floor = (
            install / DEPLOY.MANAGER.DEVELOPER_ID_TEAM_FLOOR_PENDING_NAME
        )
        os.link(floor, pending_floor)
        self.assertEqual(floor.stat().st_nlink, 2)
        identity = {
            "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_epoch":2,
            "public_key_sha256":"b" * 64,
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active",
        }

        def read(path):
            if path.name == "authorization_broker":
                return DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY
            return b"authorization-manifest\n"

        def verified(_root, link, *_args, **kwargs):
            self.assertEqual(
                link,
                install
                / DEPLOY.MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME,
            )
            self.assertTrue(
                kwargs["_bootstrap_without_developer_id_floor"])
            self.assertTrue(
                kwargs[
                    "_bootstrap_without_native_coordination_floor"
                ])
            return release, {}

        with (mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
              mock.patch.object(
                  DEPLOY.MANAGER, "verified_release",
                  side_effect=verified,
              ),
              mock.patch.object(DEPLOY.MANAGER, "read_regular", side_effect=read),
              mock.patch.object(
                  DEPLOY.MANAGER,
                  "verified_existing_authorization_ui_anchor_policy",
              ) as existing_anchor,
              mock.patch.object(
                  DEPLOY.MANAGER,
                  "verified_authorization_ui_signing_policy",
              ) as developer_id_anchor,
              mock.patch.object(
                  DEPLOY.subprocess, "run",
                  return_value=SimpleNamespace(stdout=json.dumps(identity)),
              )):
            self.assertEqual(
                DEPLOY.postactivation_current_release(
                    allow_legacy=True,
                    expected_uid=self.uid,
                    allow_migration_predecessor_anchor=True,
                ),
                release,
            )
        existing_anchor.assert_called_once()
        developer_id_anchor.assert_not_called()

    def test_completed_migration_preflight_uses_public_coordination_enforcement(self):
        install = self.root / "install"
        release = install / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        (install / "current").symlink_to(f"releases/{release.name}")
        floor = install / DEPLOY.MANAGER.DEVELOPER_ID_TEAM_FLOOR_NAME
        floor.write_text("protected\n", encoding="ascii")
        floor.chmod(0o600)
        identity = {
            "algorithm":"ecdsa-p256-sha256-x962-low-s",
            "generation_epoch":2,
            "public_key_sha256":"b" * 64,
            "schema":"secure-sandbox-execution-approval-key-v2",
            "status":"active",
        }
        enforcement = {
            "minimum_epoch": 2,
            "minimum_features": ["native-deployment-journal-v1"],
        }

        def verified(_root, link, *_args, **kwargs):
            self.assertEqual(link, install / "current")
            self.assertTrue(
                kwargs["_bootstrap_without_native_coordination_floor"])
            return release, {}

        def read(path):
            if path.name == "authorization_broker":
                return DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY
            if path.name == "native_stack_coordination_contract":
                return b"coordination-contract\n"
            return b"authorization-manifest\n"

        with (mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
              mock.patch.object(
                  DEPLOY.MANAGER, "verified_release", side_effect=verified,
              ),
              mock.patch.object(
                  DEPLOY.MANAGER, "native_stack_coordination_enforcement",
                  return_value=(enforcement, "c" * 64),
              ) as public_floor,
              mock.patch.object(
                  DEPLOY.MANAGER,
                  "validate_native_stack_coordination_contract",
                  return_value={
                      "epoch": 2,
                      "features": ["native-deployment-journal-v1"],
                  },
              ),
              mock.patch.object(
                  DEPLOY.MANAGER, "read_regular", side_effect=read,
              ),
              mock.patch.object(
                  DEPLOY.MANAGER,
                  "verified_authorization_ui_signing_policy",
              ),
              mock.patch.object(
                  DEPLOY.subprocess, "run",
                  return_value=SimpleNamespace(stdout=json.dumps(identity)),
              )):
            self.assertEqual(
                DEPLOY.postactivation_current_release(
                    expected_uid=self.uid,
                    allow_completed_migration_preflight=True,
                ),
                release,
            )
        public_floor.assert_called_once_with(install, self.uid)

    def test_deploy_reports_silent_protected_authorization_failure(self):
        completed = SimpleNamespace(returncode=23, stdout="", stderr="")
        with (mock.patch.object(DEPLOY.subprocess, "run", return_value=completed),
              mock.patch("sys.stderr") as stderr):
            self.assertEqual(self.run_main([
                "deploy", "--requesting-agent", "Codex",
                "--requesting-session", "thread-7",
            ]), 23)
        self.assertTrue(any(
            "protected_authorization_failed:23" in str(call)
            for call in stderr.write.call_args_list
        ))

    def test_runtime_metadata_recovery_binding_accepts_only_exact_ambiguity(self):
        request_id = str(uuid.UUID(int=101, version=4))
        request_sha256 = "a" * 64
        diagnostic = {
            "action": "inspect_authorization_receipt_before_retry",
            "code": "privileged_operation_outcome_ambiguous",
            "operation": "host-controller-install",
            "outcome": "ambiguous",
            "phase": "result",
            "request_id": request_id,
            "retry": "forbidden",
            "schema": "secure-sandbox-operator-diagnostic-v1",
        }
        completed = SimpleNamespace(
            stdout="",
            stderr=(
                f"Request digest: {request_sha256}\n"
                + json.dumps(diagnostic, separators=(",", ":"), sort_keys=True)
                + "\n"
            ),
        )
        self.assertEqual(
            DEPLOY.runtime_metadata_recovery_binding_from_failure(
                completed, "host-controller-install",
            ),
            (request_id, request_sha256),
        )
        self.assertIsNone(
            DEPLOY.runtime_metadata_recovery_binding_from_failure(
                completed, "host-controller-rollback",
            )
        )
        changed = dict(diagnostic)
        changed["retry"] = "new-request"
        self.assertIsNone(
            DEPLOY.runtime_metadata_recovery_binding_from_failure(
                SimpleNamespace(
                    stdout="",
                    stderr=(
                        f"Request digest: {request_sha256}\n"
                        + json.dumps(changed) + "\n"
                    ),
                ),
                "host-controller-install",
            )
        )
        self.assertIsNone(
            DEPLOY.runtime_metadata_recovery_binding_from_failure(
                SimpleNamespace(
                    stdout=completed.stdout,
                    stderr="Request digest: " + request_sha256 + "\n"
                        + "Request digest: " + request_sha256 + "\n"
                        + json.dumps(diagnostic) + "\n",
                ),
                "host-controller-install",
            )
        )
        self.assertIsNone(
            DEPLOY.runtime_metadata_recovery_binding_from_failure(
                SimpleNamespace(
                    stdout=json.dumps(diagnostic),
                    stderr=f"Request digest: {request_sha256}\n",
                ),
                "host-controller-install",
            )
        )

    def test_install_result_accepts_explicit_runtime_metadata_recovery_marker(self):
        target = {
            "release_id": "1" * 64,
            "target_launcher_sha256": "2" * 64,
            "payloads": {"release_manager": "3" * 64},
        }
        value = {
            "candidate_authority_sha256": "4" * 64,
            "developer_id_team_floor_release_id": "5" * 64,
            "developer_id_team_floor_sha256": "6" * 64,
            "developer_id_team_id": "389K3H8Y32",
            "host_release_launcher_pair_sha256": "7" * 64,
            "launcher_sha256": "2" * 64,
            "payloads": target["payloads"],
            "release_id": "1" * 64,
            "release_tree_identity_sha256": "8" * 64,
            "runtime_metadata_recovery": True,
            "schema": DEPLOY.MANAGER.SCHEMA,
            "status": "deployed",
            "transition_id": str(uuid.UUID(int=102, version=4)),
            "transition_sha256": "9" * 64,
        }
        self.assertEqual(
            DEPLOY.validate_host_pair_operation_result(
                value, operation="install", target_plan=target,
            ),
            value,
        )

    def test_host_pair_recovery_binding_accepts_only_exact_bootstrap_pending(self):
        install = self.root / "install"
        release = install / "releases" / ("a" * 64)
        release.mkdir(parents=True)
        pending_private = (
            install / DEPLOY.MANAGER.INSTALL_TRANSITION_PENDING_NAME
        )
        pending_private.write_text("{}", encoding="ascii")
        pending_private.chmod(0o600)
        launcher = b"stable-launcher"
        broker = (
            b"broker\n" + DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY
        )
        manager = self.root / "manager.py"
        manager.write_bytes(b"manager")
        target = {
            "candidate_authority_sha256": "7" * 64,
            "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
            "release_id": "a" * 64,
            "release_tree_identity_sha256": "8" * 64,
        }
        pending = {
            "operation": "install",
            "prior_stable_sha256": None,
            "required_feature": (
                DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_FEATURE
            ),
            "schema": (
                DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA
            ),
            "source_pair": None,
            "target_pair": target,
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "transition_sha256": "6" * 64,
        }
        tree = {"manifest.json": {"kind": "file"}}
        manifest = {
            "payloads": {
                "authorization_broker": hashlib.sha256(broker).hexdigest(),
            },
        }
        authority = {
            "schema": DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_AUTHORITY_V2_SCHEMA,
            "payloads": manifest["payloads"],
            "release_tree_identity": tree,
            "release_tree_identity_sha256": "8" * 64,
        }

        def read(path):
            if Path(path) == manager:
                return b"manager"
            if Path(path).name == "authorization_broker":
                return broker
            if Path(path).name == "native_stack_coordination_contract":
                return b"contract"
            raise AssertionError(path)

        with (
            mock.patch.object(
                DEPLOY.MANAGER, "host_release_launcher_pair_public",
                return_value=(pending, "5" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "verified_release",
                return_value=(release, manifest),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "validate_native_stack_coordination_contract",
                return_value={
                    "features": [
                        DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_FEATURE
                    ],
                },
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_authority",
                return_value=authority,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "host_release_launcher_pair_generation",
                return_value=target,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "installed_native_host_release_tree_identity",
                return_value=(tree, "8" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "read_trusted_stable_launcher",
                return_value=launcher,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", side_effect=read,
            ),
        ):
            binding = DEPLOY.host_pair_transition_recovery_binding(
                install_root=install,
                launcher_path=self.root / "launcher",
                manager_path=manager,
                expected_uid=self.uid,
            )
            self.assertEqual(binding.release_id, target["release_id"])
            self.assertEqual(binding.host_pair_pending_sha256, "5" * 64)
            self.assertEqual(
                binding.host_pair_transition_id, pending["transition_id"],
            )
            self.assertEqual(
                binding.host_pair_target_candidate_authority_sha256,
                target["candidate_authority_sha256"],
            )
            self.assertEqual(
                binding.manager_sha256,
                hashlib.sha256(b"manager").hexdigest(),
            )

            pending_private.chmod(0o644)
            with self.assertRaisesRegex(
                RuntimeError,
                "host_pair_transition_recovery_private_pending_invalid",
            ):
                DEPLOY.host_pair_transition_recovery_binding(
                    install_root=install,
                    launcher_path=self.root / "launcher",
                    manager_path=manager,
                    expected_uid=self.uid,
                )

    def test_host_pair_recovery_binding_rejects_nonbootstrap_public_state(self):
        target = {
            "candidate_authority_sha256": "7" * 64,
            "launcher_sha256": "4" * 64,
            "release_id": "a" * 64,
            "release_tree_identity_sha256": "8" * 64,
        }
        pending_with_source = {
            "schema": DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_PENDING_SCHEMA,
            "operation": "install",
            "prior_stable_sha256": "1" * 64,
            "source_pair": self.pair_identity("f" * 64),
            "target_pair": target,
        }
        records = (
            {"schema": DEPLOY.MANAGER.HOST_RELEASE_LAUNCHER_PAIR_STABLE_SCHEMA},
            pending_with_source,
        )
        for record in records:
            with (
                self.subTest(schema=record["schema"]),
                mock.patch.object(
                    DEPLOY.MANAGER, "host_release_launcher_pair_public",
                    return_value=(record, "5" * 64),
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "host_pair_transition_recovery_public_pending_invalid",
                ),
            ):
                DEPLOY.host_pair_transition_recovery_binding()

    def test_host_pair_recovery_releases_lock_before_digest_pinned_sudo(self):
        binding = self.host_pair_recovery_binding()
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(self.host_pair_recovery_result(binding)),
            stderr="",
        )
        events = []

        def release(lock):
            self.assertEqual(lock, self.root / "lock")
            events.append("released")

        def run_recovery(command, **kwargs):
            self.assertEqual(events, ["released"])
            self.assertFalse(kwargs["check"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            events.append("spawned")
            return completed

        with (
            mock.patch.object(
                DEPLOY, "host_pair_transition_recovery_binding",
                return_value=binding,
            ) as binding_call,
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ) as notice,
            mock.patch.object(
                DEPLOY.LAUNCHER, "release_lock", side_effect=release,
            ) as release_lock,
            mock.patch.object(
                DEPLOY.subprocess, "run", side_effect=run_recovery,
            ) as run,
            mock.patch("sys.stdout", io.StringIO()),
        ):
            result = self.run_main([
                "recover-host-pair-transition",
                "--requesting-agent", "Codex",
                "--requesting-session", "exact-host-pair-recovery",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with()
        notice.assert_called_once_with(
            "Codex", "exact-host-pair-recovery", binding,
            "recover-host-pair-transition",
        )
        self.assertEqual(events, ["released", "spawned"])
        release_lock.assert_called_once_with(self.root / "lock")
        self.assertEqual(run.call_args.args[0], [
            "sudo", "/usr/bin/python3", "-I", "-c",
            DEPLOY.BOOTSTRAP_LOADER, str(DEPLOY.MANAGER_PATH),
            binding.manager_sha256, "recover-host-pair-transition",
            "--state-root", str(self.root / "state"),
            "--expected-public-pending-sha256",
            binding.host_pair_pending_sha256,
            "--expected-transition-id", binding.host_pair_transition_id,
            "--expected-transition-sha256",
            binding.host_pair_transition_sha256,
            "--expected-operation", binding.host_pair_operation,
            "--expected-target-release-id", binding.release_id,
            "--expected-target-candidate-authority-sha256",
            binding.host_pair_target_candidate_authority_sha256,
            "--expected-target-release-tree-identity-sha256",
            binding.host_pair_target_release_tree_identity_sha256,
            "--expected-target-launcher-sha256",
            binding.installed_launcher_sha256,
            "--json",
        ])

    def test_host_pair_recovery_rejects_mismatched_root_result(self):
        binding = self.host_pair_recovery_binding()
        invalid = self.host_pair_recovery_result(binding)
        invalid["release_id"] = "f" * 64
        completed = SimpleNamespace(
            returncode=0, stdout=json.dumps(invalid), stderr="",
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(
                DEPLOY, "host_pair_transition_recovery_binding",
                return_value=binding,
            ),
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ),
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ),
            mock.patch("sys.stderr", stderr),
        ):
            result = self.run_main([
                "recover-host-pair-transition",
                "--requesting-agent", "Codex",
                "--requesting-session", "mismatched-recovery-result",
            ])
        self.assertEqual(result, 1)
        self.assertIn(
            "host_pair_transition_recovery_result_invalid",
            stderr.getvalue(),
        )

    def test_host_pair_recovery_cancellation_never_invokes_sudo(self):
        binding = self.host_pair_recovery_binding()
        with (
            mock.patch.object(
                DEPLOY, "host_pair_transition_recovery_binding",
                return_value=binding,
            ),
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=False,
            ),
            mock.patch.object(DEPLOY.subprocess, "run") as run,
            mock.patch.object(
                DEPLOY.LAUNCHER, "release_lock",
            ) as release_lock,
        ):
            result = self.run_main([
                "recover-host-pair-transition",
                "--requesting-agent", "Codex",
                "--requesting-session", "cancelled-host-pair-recovery",
            ])
        self.assertEqual(result, 1)
        run.assert_not_called()
        release_lock.assert_called_once_with(self.root / "lock")

    def test_normal_deploy_has_no_sudo_fallback_when_broker_missing(self):
        self.broker.unlink()
        with mock.patch.object(DEPLOY.subprocess, "run") as run:
            result = self.run_main([
                "deploy", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
            ])
        self.assertEqual(result, 1)
        run.assert_not_called()

    def test_restrictive_root_selector_cannot_bypass_candidate_schema_gate(self):
        with (mock.patch.object(DEPLOY, "selector_recovery_required", return_value=True),
              mock.patch.object(DEPLOY, "bootstrap_notice") as notice,
              mock.patch.object(DEPLOY.subprocess, "run") as run):
            result = self.run_main([
                "deploy", "--requesting-agent", "Codex",
                "--requesting-session", "request-bound-execution-ddd-live",
            ])
        self.assertEqual(result, 1)
        DEPLOY.bootstrap_binding.assert_not_called()
        notice.assert_not_called()
        run.assert_not_called()

    def test_implicit_rollback_is_resolved_to_an_exact_release_before_prompt(self):
        completed = SimpleNamespace(
            returncode=0, stdout=json.dumps(self.manager_result("rollback")),
            stderr="",
        )
        with mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run:
            self.assertEqual(self.run_main([
                "rollback", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
            ]), 0)
        command = run.call_args.args[0]
        parameters = json.loads(command[command.index("--parameters-json") + 1])
        self.assertEqual(parameters["authorized_target_plan"], self.rollback_plan)
        self.assertEqual(parameters["authorized_target_plan_sha256"], "e" * 64)
        DEPLOY.rollback_release_binding.assert_called_once_with(None)

    def test_deploy_and_rollback_release_controller_lock_before_broker(self):
        for command, operation in (
            ("deploy", "install"), ("rollback", "rollback"),
        ):
            with self.subTest(command=command):
                events = []

                def release(lock):
                    self.assertEqual(lock, self.root / "lock")
                    events.append("released")

                def run_broker(_command, **_kwargs):
                    self.assertEqual(events, ["released"])
                    events.append("spawned")
                    return SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(self.manager_result(operation)),
                        stderr="",
                    )

                with (
                    mock.patch.object(
                        DEPLOY.LAUNCHER, "release_lock",
                        side_effect=release,
                    ) as release_lock,
                    mock.patch.object(
                        DEPLOY.subprocess, "run", side_effect=run_broker,
                    ),
                ):
                    self.assertEqual(self.run_main([
                        command,
                        "--requesting-agent", "Codex",
                        "--requesting-session", f"{command}-handoff",
                    ]), 0)
                self.assertEqual(events, ["released", "spawned"])
                release_lock.assert_called_once_with(self.root / "lock")

    def test_explicit_bootstrap_is_terminal_bound_and_one_time(self):
        self.broker.unlink()
        completed = SimpleNamespace(returncode=0)
        events = []
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            developer_id_team_id=(
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            ),
            candidate_authorization_manifest_sha256="7" * 64,
            native_host_candidate=self.candidate,
            authorization_predecessor_release_id="8" * 64,
        )

        def release(lock):
            self.assertEqual(lock, self.root / "lock")
            events.append("released")

        def run_bound(command, **kwargs):
            self.assertFalse(kwargs["check"])
            events.append("spawned")
            return completed

        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding,
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(
                  DEPLOY.LAUNCHER, "release_lock", side_effect=release,
              ) as release_lock,
              mock.patch.object(
                  DEPLOY.subprocess, "run", side_effect=run_bound,
              ) as run):
            result = self.run_main([
                "bootstrap-authorization", "--requesting-agent", "Codex",
                "--requesting-session", "thread-7",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(authorization_bootstrap=True)
        notice.assert_called_once_with(
            "Codex", "thread-7", binding,
        )
        self.assertEqual(
            run.call_args.args[0][0:5],
            ["sudo", "/usr/bin/python3", "-I", "-c", DEPLOY.BOOTSTRAP_LOADER],
        )
        self.assertIn("a" * 64, run.call_args.args[0])
        self.assertIn("d" * 64, run.call_args.args[0])
        self.assertIn("e" * 64, run.call_args.args[0])
        self.assertIn("bootstrap-authorization", run.call_args.args[0])
        self.assertEqual(
            json.loads(run.call_args.args[0][
                run.call_args.args[0].index(
                    "--native-host-candidate-json"
                ) + 1
            ]),
            self.candidate.record(),
        )
        self.assertEqual(
            run.call_args.args[0][run.call_args.args[0].index(
                "--expected-developer-id-team-id"
            ) + 1],
            DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
        )
        self.assertEqual(
            run.call_args.args[0][run.call_args.args[0].index(
                "--expected-candidate-authorization-manifest-sha256"
            ) + 1],
            "7" * 64,
        )
        self.assertEqual(
            run.call_args.args[0][run.call_args.args[0].index(
                "--expected-bootstrap-predecessor-release-id"
            ) + 1],
            "8" * 64,
        )
        self.assertNotIn(
            "--clean-machine-bootstrap", run.call_args.args[0],
        )
        self.assertEqual(events, ["released", "spawned"])
        release_lock.assert_called_once_with(self.root / "lock")

    def test_bootstrap_replays_only_exact_candidate_selected_recovery(self):
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            developer_id_team_id=(
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            ),
            candidate_authorization_manifest_sha256="7" * 64,
            native_host_candidate=self.candidate,
            authorization_predecessor_release_id="8" * 64,
        )
        completed = SimpleNamespace(returncode=0)
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ),
            mock.patch.object(
                DEPLOY, "postactivation_current_release",
                return_value=self.root / binding.release_id,
            ) as current,
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ) as notice,
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ) as run,
        ):
            result = self.run_main([
                "bootstrap-authorization", "--requesting-agent", "Codex",
                "--requesting-session", "candidate-service-recovery",
            ])
        self.assertEqual(result, 0)
        current.assert_called_once_with()
        notice.assert_called_once()
        self.assertIn("bootstrap-authorization", run.call_args.args[0])

    def test_bootstrap_refuses_unrelated_deployed_broker(self):
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            developer_id_team_id=(
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            ),
            candidate_authorization_manifest_sha256="7" * 64,
            native_host_candidate=self.candidate,
            authorization_predecessor_release_id="8" * 64,
        )
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ),
            mock.patch.object(
                DEPLOY, "postactivation_current_release",
                return_value=self.root / ("f" * 64),
            ),
            mock.patch.object(DEPLOY, "bootstrap_notice") as notice,
            mock.patch.object(DEPLOY.subprocess, "run") as run,
        ):
            result = self.run_main([
                "bootstrap-authorization", "--requesting-agent", "Codex",
                "--requesting-session", "unrelated-broker",
            ])
        self.assertEqual(result, 1)
        notice.assert_not_called()
        run.assert_not_called()

    def test_controller_lock_handoff_failure_cannot_release_a_new_owner(self):
        self.broker.unlink()
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            developer_id_team_id=(
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            ),
            candidate_authorization_manifest_sha256="7" * 64,
            native_host_candidate=self.candidate,
            authorization_predecessor_release_id="8" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding,
              ),
              mock.patch.object(
                  DEPLOY, "bootstrap_notice", return_value=True,
              ),
              mock.patch.object(
                  DEPLOY.LAUNCHER, "release_lock",
                  side_effect=RuntimeError("release-tombstone-failed"),
              ) as release_lock,
              mock.patch.object(DEPLOY.subprocess, "run") as run,
              self.assertRaisesRegex(
                  RuntimeError, "release-tombstone-failed",
              )):
            self.run_main([
                "bootstrap-authorization", "--requesting-agent", "Codex",
                "--requesting-session", "lock-handoff-failure",
            ])
        release_lock.assert_called_once_with(self.root / "lock")
        run.assert_not_called()

    def test_touchid_ui_recovery_uses_only_the_recovery_binding(self):
        completed = SimpleNamespace(returncode=0)
        with (mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "recover-touchid-ui", "--requesting-agent", "Codex",
                "--requesting-session", "touchid-ui-recovery",
            ])
        self.assertEqual(result, 0)
        DEPLOY.bootstrap_binding.assert_called_once_with(touchid_recovery=True)
        notice.assert_called_once_with(
            "Codex", "touchid-ui-recovery",
            DEPLOY.BootstrapBinding("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64),
            "recover-touchid-ui",
        )
        command = run.call_args.args[0]
        self.assertIn("recover-touchid-ui", command)

    def test_touchid_ui_recovery_binding_does_not_rebuild_the_pinned_artifact(self):
        with (mock.patch.object(DEPLOY, "prepare_touchid_ui") as build,
              mock.patch.object(
                  DEPLOY.MANAGER, "touchid_ui_recovery_payload",
                  return_value=(
                      {"authorization_broker": b"broker"},
                      {
                          "authorization_ui": "1" * 64,
                          "authorization_ui_sources": "2" * 64,
                      },
                      "3" * 64,
                  ),
              ),
              mock.patch.object(
                  DEPLOY.MANAGER, "verified_release",
                  return_value=(Path("/installed/current"), {
                      "payloads": {
                          "authorization_ui": "4" * 64,
                          "authorization_ui_sources": "5" * 64,
                      }
                  }),
              ),
              mock.patch.object(DEPLOY.MANAGER, "read_regular", return_value=b"launcher"),
              mock.patch.object(DEPLOY, "STABLE_LAUNCHER", Path("/stable")),
              mock.patch.object(DEPLOY, "MODULE_PATH", Path("/module"))):
            binding = self.real_bootstrap_binding(touchid_recovery=True)
        build.assert_not_called()
        self.assertEqual(binding.release_id, "3" * 64)

    def test_release_capacity_recovery_is_terminal_bound_to_exact_plan(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            archive_current_release_id="a" * 64,
            archive_previous_release_id="f" * 64,
            archive_plan_sha256="1" * 64,
            archive_release_ids=("2" * 64,),
        )
        with (mock.patch.object(DEPLOY, "bootstrap_binding", return_value=binding) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "recover-release-capacity", "--requesting-agent", "Codex",
                "--requesting-session", "release-capacity-recovery",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(capacity_recovery=True)
        notice.assert_called_once_with(
            "Codex", "release-capacity-recovery", binding,
            "recover-release-capacity",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[:5], [
            "sudo", "/usr/bin/python3", "-I", "-c", DEPLOY.BOOTSTRAP_LOADER,
        ])
        self.assertIn("archive-inactive-releases", command)
        self.assertIn("a" * 64, command)
        self.assertIn("f" * 64, command)
        self.assertIn("1" * 64, command)

    def test_release_capacity_binding_does_not_build_or_mutate_touchid_artifact(self):
        current = Path("/installed/releases") / ("a" * 64)
        plan = {
            "current_release_id": "a" * 64,
            "previous_release_id": "f" * 64,
            "plan_sha256": "1" * 64,
            "archive_release_ids": ["2" * 64],
        }
        def read(path):
            return b"broker" if Path(path).name == "authorization_broker" else b"payload"
        with (mock.patch.object(DEPLOY, "prepare_touchid_ui") as build,
              mock.patch.object(DEPLOY.MANAGER, "source_payload") as source_payload,
              mock.patch.object(DEPLOY, "postactivation_current_release",
                                return_value=current) as selected_release,
              mock.patch.object(DEPLOY, "postactivation_release_archive_plan",
                                return_value=plan) as archive_plan,
              mock.patch.object(DEPLOY.MANAGER, "read_regular", side_effect=read)):
            binding = self.real_bootstrap_binding(capacity_recovery=True)
        build.assert_not_called()
        source_payload.assert_not_called()
        selected_release.assert_called_once_with()
        archive_plan.assert_called_once_with(current)
        self.assertEqual(binding.release_id, "a" * 64)
        self.assertEqual(binding.archive_plan_sha256, "1" * 64)

    def test_release_capacity_plan_delegates_root_floor_but_rechecks_retained_v2_releases(self):
        current_id = "a" * 64
        previous_id = "f" * 64
        current = DEPLOY.INSTALL_ROOT / "releases" / current_id
        plan = {
            "current_release_id": current_id,
            "previous_release_id": previous_id,
            "plan_sha256": "1" * 64,
            "archive_release_ids": ["2" * 64],
        }
        original_floor = DEPLOY.MANAGER.enforce_execution_approval_floor
        capable = b"prefix " + DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY
        with (mock.patch.object(DEPLOY.MANAGER, "release_archive_plan",
                                return_value=plan) as release_plan,
              mock.patch.object(DEPLOY.MANAGER, "read_regular",
                                return_value=capable) as read):
            result = DEPLOY.postactivation_release_archive_plan(current)
        self.assertEqual(result, plan)
        release_plan.assert_called_once_with(DEPLOY.INSTALL_ROOT, 0)
        self.assertEqual(read.call_count, 2)
        self.assertIs(DEPLOY.MANAGER.enforce_execution_approval_floor, original_floor)

    def test_touchid_schema_bootstrap_is_explicit_and_content_bound(self):
        completed = SimpleNamespace(returncode=0)
        with (mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-touchid-schema", "--requesting-agent", "Codex",
                "--requesting-session", "touchid-ddd",
            ])
        self.assertEqual(result, 0)
        notice.assert_called_once_with(
            "Codex", "touchid-ddd",
            DEPLOY.BootstrapBinding("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64),
            "bootstrap-touchid-schema",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[:5], [
            "sudo", "/usr/bin/python3", "-I", "-c", DEPLOY.BOOTSTRAP_LOADER,
        ])
        self.assertIn("bootstrap-touchid-schema", command)
        self.assertIn("a" * 64, command)

    def test_secure_enclave_schema_bootstrap_binds_current_and_proposed_releases(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-secure-enclave-schema", "--requesting-agent", "Codex",
                "--requesting-session", "secure-enclave-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(secure_enclave_schema=True)
        notice.assert_called_once_with(
            "Codex", "secure-enclave-ddd", binding,
            "bootstrap-secure-enclave-schema",
        )
        command = run.call_args.args[0]
        self.assertIn("bootstrap-secure-enclave-schema", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1], "a" * 64
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1], "f" * 64
        )

    def test_profiled_touchid_schema_bootstrap_binds_current_and_proposed_releases(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-profiled-touchid-schema", "--requesting-agent", "Codex",
                "--requesting-session", "profiled-touchid-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(profiled_touchid_schema=True)
        notice.assert_called_once_with(
            "Codex", "profiled-touchid-ddd", binding,
            "bootstrap-profiled-touchid-schema",
        )
        command = run.call_args.args[0]
        self.assertIn("bootstrap-profiled-touchid-schema", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1], "a" * 64
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1], "f" * 64
        )

    def test_touchid_bundle_v2_schema_bootstrap_binds_current_and_proposed_releases(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-touchid-bundle-v2-schema", "--requesting-agent", "Codex",
                "--requesting-session", "touchid-bundle-v2-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(touchid_bundle_v2_schema=True)
        notice.assert_called_once_with(
            "Codex", "touchid-bundle-v2-ddd", binding,
            "bootstrap-touchid-bundle-v2-schema",
        )
        command = run.call_args.args[0]
        self.assertIn("bootstrap-touchid-bundle-v2-schema", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1], "a" * 64
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1], "f" * 64
        )

    def test_model_profile_schema_bootstrap_binds_current_and_proposed_releases(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-model-profile-schema", "--requesting-agent", "Codex",
                "--requesting-session", "model-profile-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(model_profile_schema=True)
        notice.assert_called_once_with(
            "Codex", "model-profile-ddd", binding,
            "bootstrap-model-profile-schema",
        )
        command = run.call_args.args[0]
        self.assertIn("bootstrap-model-profile-schema", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1], "a" * 64
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1], "f" * 64
        )

    def test_model_profile_schema_binding_uses_public_v2_identity_preflight(self):
        current = self.root / ("f" * 64)
        with (mock.patch.object(DEPLOY, "prepare_touchid_ui"),
              mock.patch.object(
                  DEPLOY.MANAGER, "source_payload",
                  return_value=({
                      "release_manager": b"manager", "authorization_broker": b"broker",
                  }, {}, "a" * 64),
              ),
              mock.patch.object(
                  DEPLOY, "postactivation_current_release", return_value=current
              ) as current_release,
              mock.patch.object(DEPLOY.MANAGER, "read_regular", return_value=b"launcher")):
            binding = self.real_bootstrap_binding(model_profile_schema=True)
        self.assertEqual(binding.schema_current_release_id, "f" * 64)
        current_release.assert_called_once_with(allow_legacy=True)

    def test_native_stack_schema_bootstrap_binds_current_and_proposed_releases(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-native-stack-schema", "--requesting-agent", "Codex",
                "--requesting-session", "native-stack-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(native_stack_schema=True)
        notice.assert_called_once_with(
            "Codex", "native-stack-ddd", binding,
            "bootstrap-native-stack-schema",
        )
        command = run.call_args.args[0]
        self.assertIn("bootstrap-native-stack-schema", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1], "a" * 64
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1], "f" * 64
        )

    def test_native_deployment_schema_bootstrap_binds_exact_manager_and_releases(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ) as binding_call,
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ) as notice,
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ) as run,
        ):
            result = self.run_main([
                "bootstrap-native-deployment-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "native-deployment-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(native_deployment_schema=True)
        notice.assert_called_once_with(
            "Codex", "native-deployment-ddd", binding,
            "bootstrap-native-deployment-schema",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[:5], [
            "sudo", "/usr/bin/python3", "-I", "-c",
            DEPLOY.BOOTSTRAP_LOADER,
        ])
        self.assertEqual(command[5], str(DEPLOY.MANAGER_PATH))
        self.assertEqual(command[6], binding.manager_sha256)
        self.assertIn("bootstrap-native-deployment-schema", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1],
            binding.release_id,
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1],
            binding.schema_current_release_id,
        )

    def test_native_deployment_schema_binding_uses_exact_legacy_preflight(self):
        current = self.root / ("f" * 64)
        values = {
            "release_manager": b"manager",
            "authorization_broker": b"broker",
        }
        with (
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
                return_value=self.candidate,
            ) as build,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY, "postactivation_current_release",
                return_value=current,
            ) as current_release,
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", return_value=b"launcher",
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_tracked_source",
                return_value=b"launcher",
            ),
        ):
            binding = self.real_bootstrap_binding(
                native_deployment_schema=True,
            )
        build.assert_called_once_with()
        self.assertEqual(binding.schema_current_release_id, "f" * 64)
        self.assertEqual(
            binding.manager_sha256,
            hashlib.sha256(b"launcher").hexdigest(),
        )
        self.assertNotEqual(
            binding.manager_sha256,
            hashlib.sha256(values["release_manager"]).hexdigest(),
        )
        current_release.assert_called_once_with(allow_legacy=True)

    def test_candidate_schema_bootstrap_binds_exact_old_broker_successor(self):
        completed = SimpleNamespace(returncode=0)
        events = []

        def release_controller_lock(lock):
            self.assertEqual(lock, self.root / "lock")
            events.append("wrapper-lock-released")

        def invoke_root_manager(*_args, **_kwargs):
            self.assertEqual(events, ["wrapper-lock-released"])
            events.append("root-manager-invoked")
            return completed

        predecessor = (
            DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        )
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id=predecessor,
            native_host_candidate=self.candidate,
        )
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ) as binding_call,
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ) as notice,
            mock.patch.object(
                DEPLOY.LAUNCHER, "release_lock",
                side_effect=release_controller_lock,
            ) as release_lock,
            mock.patch.object(
                DEPLOY.subprocess, "run", side_effect=invoke_root_manager,
            ) as run,
        ):
            result = self.run_main([
                "bootstrap-native-host-candidate-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "candidate-schema-ddd",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(
            events, ["wrapper-lock-released", "root-manager-invoked"],
        )
        release_lock.assert_called_once_with(self.root / "lock")
        binding_call.assert_called_once_with(
            native_host_candidate_schema=True,
        )
        notice.assert_called_once_with(
            "Codex", "candidate-schema-ddd", binding,
            "bootstrap-native-host-candidate-schema",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[:5], [
            "sudo", "/usr/bin/python3", "-I", "-c",
            DEPLOY.BOOTSTRAP_LOADER,
        ])
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1],
            binding.release_id,
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1],
            predecessor,
        )
        self.assertEqual(
            json.loads(command[
                command.index("--native-host-candidate-json") + 1
            ]),
            self.candidate.record(),
        )

    def test_candidate_schema_binding_builds_release_from_retained_generation(self):
        predecessor = self.root / (
            DEPLOY.MANAGER.NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
        )
        install = self.root / "candidate-present-selector-install"
        install.mkdir()
        (install / "current").symlink_to(predecessor)
        values = {
            "release_manager": b"manager",
            "authorization_broker": b"broker",
        }
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=None,
            ),
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
                return_value=self.candidate,
            ) as build,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ) as source,
            mock.patch.object(
                DEPLOY, "postactivation_current_release",
                return_value=predecessor,
            ) as current,
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", return_value=b"launcher",
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_tracked_source",
                return_value=b"launcher",
            ) as launcher_source,
        ):
            binding = self.real_bootstrap_binding(
                native_host_candidate_schema=True,
            )
        build.assert_called_once_with()
        source.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent,
            expected_native_host_certificate_sha1=(
                self.candidate.developer_id_certificate_sha1
            ),
            native_host_generation=Path(self.candidate.generation_path),
            expected_native_host_candidate=self.candidate.record(),
        )
        launcher_source.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent,
            Path(self.candidate.generation_path),
            self.candidate.record(),
            DEPLOY.MANAGER.LAUNCHER_SOURCE,
        )
        current.assert_called_once_with(
            allow_legacy=True,
            allow_candidate_schema_bootstrap=True,
        )
        self.assertEqual(binding.schema_current_release_id, predecessor.name)
        self.assertEqual(binding.native_host_candidate, self.candidate)

    def test_candidate_schema_binding_recovers_absent_selector_from_public_replay(self):
        install = self.root / "candidate-absent-selector-install"
        install.mkdir()
        values = {
            "release_manager": b"manager",
            "authorization_broker": b"broker",
        }
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY, "native_host_candidate_schema_product",
                return_value=self.candidate,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "native_host_candidate_replay_enforcement",
                return_value=({"authoritative_floor_sha256": "f" * 64}, "e" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_tracked_source",
                return_value=b"launcher",
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", return_value=b"launcher",
            ),
            mock.patch.object(
                DEPLOY, "postactivation_current_release",
            ) as current,
        ):
            binding = self.real_bootstrap_binding(
                native_host_candidate_schema=True,
            )
        self.assertEqual(binding.schema_current_release_id, "absent")
        self.assertEqual(binding.native_host_candidate, self.candidate)
        current.assert_not_called()

    def test_first_broker_bootstrap_is_bound_to_retained_candidate(self):
        authorization_manifest = b"exact candidate authorization manifest\n"
        team_id = DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
        values = {
            "release_manager": b"manager",
            "authorization_broker": b"broker",
            "authorization_ui_bundle": authorization_manifest,
        }
        with (
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_replay_enforcement",
                return_value=None,
            ),
            mock.patch.object(
                DEPLOY, "unbound_native_host_candidate_product",
                return_value=None,
            ),
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
                return_value=self.candidate,
            ) as build,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ) as source,
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", return_value=b"launcher",
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_tracked_source",
                return_value=b"launcher",
            ) as launcher_source,
            mock.patch.object(
                DEPLOY, "clean_authorization_bootstrap_state",
                return_value=("8" * 64, b"launcher", True),
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "verified_authorization_ui_signing_policy",
                return_value={
                    "access_group": (
                        f"{team_id}.org.zebeth.SecureSandbox.AuthorizationUI"
                    ),
                    "application_identifier": (
                        f"{team_id}.org.zebeth.SecureSandbox.AuthorizationUI"
                    ),
                    "bundle_id": (
                        "org.zebeth.SecureSandbox.AuthorizationUI"
                    ),
                    "team_id": team_id,
                },
            ) as signing_policy,
        ):
            binding = self.real_bootstrap_binding(
                authorization_bootstrap=True,
            )
        build.assert_called_once_with()
        source.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent,
            expected_native_host_certificate_sha1=(
                self.candidate.developer_id_certificate_sha1
            ),
            native_host_generation=Path(self.candidate.generation_path),
            expected_native_host_candidate=self.candidate.record(),
        )
        launcher_source.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent,
            Path(self.candidate.generation_path),
            self.candidate.record(),
            DEPLOY.MANAGER.LAUNCHER_SOURCE,
        )
        signing_policy.assert_called_once_with(
            Path(self.candidate.generation_path)
                / DEPLOY.MANAGER.AUTHORIZATION_UI_APP_NAME,
            authorization_manifest,
            self.uid,
            developer_id_certificate_sha1=(
                self.candidate.developer_id_certificate_sha1
            ),
        )
        self.assertEqual(binding.native_host_candidate, self.candidate)
        self.assertEqual(binding.developer_id_team_id, "389K3H8Y32")
        self.assertEqual(
            binding.candidate_authorization_manifest_sha256,
            hashlib.sha256(authorization_manifest).hexdigest(),
        )
        self.assertEqual(binding.current_authorization_manifest_sha256, "")

    def test_candidate_schema_bootstrap_rejects_any_other_predecessor(self):
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
            native_host_candidate=self.candidate,
        )
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ),
            mock.patch.object(DEPLOY, "bootstrap_notice") as notice,
            mock.patch.object(DEPLOY.subprocess, "run") as run,
        ):
            result = self.run_main([
                "bootstrap-native-host-candidate-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "wrong-predecessor",
            ])
        self.assertEqual(result, 1)
        notice.assert_not_called()
        run.assert_not_called()

    def test_candidate_schema_bootstrap_replays_candidate_selected_crash(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="a" * 64,
            native_host_candidate=self.candidate,
        )
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ),
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ) as notice,
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ) as run,
        ):
            result = self.run_main([
                "bootstrap-native-host-candidate-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "candidate-selected-replay",
            ])
        self.assertEqual(result, 0)
        notice.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1],
            binding.release_id,
        )

    def test_candidate_schema_bootstrap_replays_absent_selector_without_broker(self):
        self.broker.unlink()
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="absent",
            native_host_candidate=self.candidate,
        )
        with (
            mock.patch.object(
                DEPLOY, "bootstrap_binding", return_value=binding,
            ),
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ) as notice,
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ) as run,
        ):
            result = self.run_main([
                "bootstrap-native-host-candidate-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "candidate-absent-replay",
            ])
        self.assertEqual(result, 0)
        notice.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1],
            "absent",
        )

    def test_candidate_schema_notice_discloses_candidate_and_floor(self):
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id=(
                DEPLOY.MANAGER
                .NATIVE_HOST_CANDIDATE_SCHEMA_PREDECESSOR_RELEASE_ID
            ),
            native_host_candidate=self.candidate,
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(
                DEPLOY.subprocess, "run",
                return_value=SimpleNamespace(returncode=0),
            ),
            mock.patch("sys.stderr", stderr),
        ):
            self.assertTrue(DEPLOY.bootstrap_notice(
                "Codex", "candidate-schema-ddd", binding,
                "bootstrap-native-host-candidate-schema",
            ))
        notice = stderr.getvalue()
        for expected in (
            self.candidate.generation_path,
            self.candidate.generation_tree_sha256,
            self.candidate.release_commit,
            self.candidate.source_archive_sha256,
            self.candidate.source_tree_sha256,
            self.candidate.signing_config_sha256,
            self.candidate.host_release_preimage_path,
            str(self.candidate.host_release_preimage_device),
            str(self.candidate.host_release_preimage_inode),
            str(self.candidate.host_release_preimage_size),
            self.candidate.host_release_preimage_sha256,
            self.candidate.host_release_preimage_schema,
            self.candidate.developer_id_certificate_sha1,
            self.candidate.notary_submission_id,
            "Trusted login principal — operator-local only",
            "not hostile same-UID resistant",
            "irreversible native-host feature and inventory admission floor",
            "cannot regain update authority",
        ):
            self.assertIn(expected, notice)

    def test_fresh_bootstrap_notice_binds_initial_developer_id_authority(self):
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            developer_id_team_id=(
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            ),
            candidate_authorization_manifest_sha256="7" * 64,
            native_host_candidate=self.candidate,
            authorization_predecessor_release_id="8" * 64,
            authorization_clean_machine_bootstrap=True,
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(
                DEPLOY.subprocess, "run",
                return_value=SimpleNamespace(returncode=0),
            ),
            mock.patch("sys.stderr", stderr),
        ):
            self.assertTrue(DEPLOY.bootstrap_notice(
                "Codex", "fresh-bootstrap-authority", binding,
                "bootstrap-authorization",
            ))
        notice = stderr.getvalue()
        for expected in (
            "Expected release: " + binding.release_id,
            "Initial Developer ID Team floor: 389K3H8Y32",
            "Candidate Developer ID certificate SHA-1: "
                + self.candidate.developer_id_certificate_sha1,
            "Candidate authorization manifest SHA-256: " + "7" * 64,
            self.candidate.host_release_preimage_path,
            self.candidate.host_release_preimage_sha256,
            "exact retained v3 candidate release",
            "first-install candidate anchor",
            "not the prior-release Developer ID migration",
            "No installed predecessor Apple signing identity grants this authority",
            "candidate-derived clean-machine scaffold",
            "Exact bootstrap predecessor: " + "8" * 64,
        ):
            self.assertIn(expected, notice)

    def test_transferable_candidate_binds_current_bootstrap_manager_separately(self):
        candidate_manager = b"candidate release manager"
        bootstrap_manager = b"current reviewed bootstrap manager"
        values = {
            name: (candidate_manager if name == "release_manager" else b"payload")
            for name in DEPLOY.MANAGER.PAYLOAD_NAMES
        }
        with (
            mock.patch.object(
                DEPLOY, "native_host_authorization_bootstrap_product",
                return_value=self.candidate,
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "native_host_candidate_tracked_source",
                return_value=b"candidate launcher",
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "verified_authorization_ui_signing_policy",
                return_value={
                    "access_group": "group",
                    "application_identifier": "application",
                    "bundle_id": "bundle",
                    "team_id": DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID,
                },
            ),
            mock.patch.object(
                DEPLOY, "clean_authorization_bootstrap_state",
                return_value=("8" * 64, b"candidate launcher", True),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular",
                side_effect=lambda path: (
                    bootstrap_manager
                    if Path(path) == DEPLOY.MANAGER_PATH
                    else b"candidate launcher"
                ),
            ),
        ):
            binding = self.real_bootstrap_binding(authorization_bootstrap=True)
        self.assertEqual(
            binding.manager_sha256,
            hashlib.sha256(bootstrap_manager).hexdigest(),
        )
        self.assertNotEqual(
            binding.manager_sha256,
            hashlib.sha256(candidate_manager).hexdigest(),
        )

    def test_fresh_bootstrap_rejects_incomplete_developer_id_authority_plan(self):
        valid = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            developer_id_team_id=(
                DEPLOY.MANAGER.NATIVE_HOST_PRODUCTS_TEAM_ID
            ),
            candidate_authorization_manifest_sha256="7" * 64,
            native_host_candidate=self.candidate,
            authorization_predecessor_release_id="8" * 64,
        )
        invalid_candidate = DEPLOY.NativeHostCandidate(**{
            **self.candidate.record(),
            "developer_id_certificate_sha1": "A" * 40,
        })
        invalid = (
            valid._replace(developer_id_team_id="ABCDE12345"),
            valid._replace(candidate_authorization_manifest_sha256="7" * 63),
            valid._replace(current_authorization_manifest_sha256="8" * 64),
            valid._replace(native_host_candidate=invalid_candidate),
            valid._replace(native_host_candidate=None),
        )
        for binding in invalid:
            with (
                self.subTest(binding=binding),
                mock.patch.object(DEPLOY, "bootstrap_notice") as notice,
                mock.patch.object(DEPLOY.subprocess, "run") as run,
                mock.patch.object(
                    DEPLOY, "bootstrap_binding", return_value=binding,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "authorization_bootstrap_developer_id_binding_invalid",
                ),
            ):
                self.run_main([
                    "bootstrap-authorization",
                    "--requesting-agent", "Codex",
                    "--requesting-session", "invalid-initial-anchor",
                ])
            notice.assert_not_called()
            run.assert_not_called()

    def test_bootstrap_loader_rejects_wrong_manager_digest_before_execution(self):
        manager = self.root / "manager.py"
        manager.write_text(
            "raise SystemExit('candidate manager executed')\n",
            encoding="utf-8",
        )
        completed = DEPLOY.subprocess.run(
            [
                sys.executable, "-I", "-c", DEPLOY.BOOTSTRAP_LOADER,
                str(manager), "0" * 64, "bootstrap-native-deployment-schema",
            ],
            check=False, capture_output=True, text=True,
            env={**os.environ, "SUDO_UID": str(os.geteuid())},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("bootstrap_manager_digest_mismatch", completed.stderr)
        self.assertNotIn("candidate manager executed", completed.stderr)

    def test_native_vendor_developer_id_bootstrap_binds_team_and_manifests(self):
        completed = SimpleNamespace(returncode=0)
        team = "ABCDE" + "12345"
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
            developer_id_team_id=team,
            current_authorization_manifest_sha256="1" * 64,
            candidate_authorization_manifest_sha256="2" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(
                  DEPLOY, "bootstrap_notice", return_value=True
              ) as notice,
              mock.patch.object(
                  DEPLOY.subprocess, "run", return_value=completed
              ) as run):
            result = self.run_main([
                "bootstrap-native-vendor-developer-id-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "native-vendor-ddd",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(
            native_vendor_developer_id_schema=True
        )
        notice.assert_called_once_with(
            "Codex", "native-vendor-ddd", binding,
            "bootstrap-native-vendor-developer-id-schema",
        )
        command = run.call_args.args[0]
        self.assertIn("bootstrap-native-vendor-developer-id-schema", command)
        self.assertEqual(
            command[command.index("--expected-developer-id-team-id") + 1],
            team,
        )
        self.assertEqual(
            command[
                command.index(
                    "--expected-current-authorization-manifest-sha256"
                ) + 1
            ],
            "1" * 64,
        )
        self.assertEqual(
            command[
                command.index(
                    "--expected-candidate-authorization-manifest-sha256"
                ) + 1
            ],
            "2" * 64,
        )

    def test_native_vendor_retry_allows_only_validated_fenced_predecessor_without_broker(self):
        self.broker.unlink()
        completed = SimpleNamespace(returncode=0)
        with (
            mock.patch.object(
                DEPLOY, "developer_id_migration_recovery_required",
                return_value=True,
            ) as recovery,
            mock.patch.object(
                DEPLOY, "bootstrap_notice", return_value=True,
            ),
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed,
            ),
        ):
            result = self.run_main([
                "bootstrap-native-vendor-developer-id-schema",
                "--requesting-agent", "Codex",
                "--requesting-session", "developer-id-retry",
            ])
        self.assertEqual(result, 0)
        recovery.assert_called_once_with()

    def test_native_vendor_retry_reuses_and_verifies_retained_carrier(self):
        predecessor = self.root / ("f" * 64)
        predecessor.mkdir()
        team = "ABCDE12345"
        values = {
            "release_manager": b"manager",
            "authorization_broker": b"broker",
            "authorization_ui_bundle": b"candidate-manifest\n",
        }

        def read(path):
            if path == predecessor / "authorization_ui_bundle":
                return b"legacy-manifest\n"
            return b"launcher\n"

        policy = {
            "team_id": team,
            "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
        }
        with (
            mock.patch.object(
                DEPLOY, "validated_developer_id_migration_predecessor",
                return_value=predecessor,
            ),
            mock.patch.object(
                DEPLOY,
                "validated_developer_id_migration_completed_release",
            ) as completed,
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
            ) as native_build,
            mock.patch.object(
                DEPLOY, "prepare_touchid_ui",
            ) as touchid_build,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, "a" * 64),
            ) as source_payload,
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", side_effect=read,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "verified_existing_authorization_ui_anchor_policy",
                return_value=policy,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "verified_authorization_ui_signing_policy",
                return_value=policy,
            ),
        ):
            binding = self.real_bootstrap_binding(
                native_vendor_developer_id_schema=True,
            )

        native_build.assert_not_called()
        touchid_build.assert_not_called()
        completed.assert_not_called()
        source_payload.assert_called_once_with(
            DEPLOY.MANAGER_PATH.parent.parent)
        self.assertEqual(binding.schema_current_release_id, predecessor.name)
        self.assertEqual(binding.developer_id_team_id, team)

    def test_native_vendor_completed_retry_reuses_current_artifacts(self):
        completed_release = self.root / ("a" * 64)
        completed_release.mkdir()
        team = "ABCDE12345"
        candidate_manifest = b"candidate-manifest\n"
        values = {
            "release_manager": b"manager",
            "authorization_broker": b"broker",
            "authorization_ui_bundle": candidate_manifest,
        }

        def read(path):
            if path == completed_release / "authorization_ui_bundle":
                return candidate_manifest
            return b"launcher\n"

        policy = {
            "team_id": team,
            "bundle_id": "org.zebeth.SecureSandbox.AuthorizationUI",
        }
        with (
            mock.patch.object(
                DEPLOY, "validated_developer_id_migration_predecessor",
                return_value=None,
            ),
            mock.patch.object(
                DEPLOY, "validated_developer_id_migration_completed_release",
                return_value=completed_release,
            ),
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
            ) as native_build,
            mock.patch.object(
                DEPLOY, "prepare_touchid_ui",
            ) as touchid_build,
            mock.patch.object(
                DEPLOY.MANAGER, "source_payload",
                return_value=(values, {}, completed_release.name),
            ),
            mock.patch.object(
                DEPLOY.MANAGER, "read_regular", side_effect=read,
            ),
            mock.patch.object(
                DEPLOY.MANAGER,
                "verified_existing_authorization_ui_anchor_policy",
            ) as existing_anchor,
            mock.patch.object(
                DEPLOY.MANAGER,
                "verified_authorization_ui_signing_policy",
                return_value=policy,
            ) as developer_id_policy,
        ):
            binding = self.real_bootstrap_binding(
                native_vendor_developer_id_schema=True,
            )

        native_build.assert_not_called()
        touchid_build.assert_not_called()
        existing_anchor.assert_not_called()
        self.assertEqual(developer_id_policy.call_count, 2)
        self.assertEqual(
            binding.schema_current_release_id, completed_release.name)
        self.assertEqual(
            binding.current_authorization_manifest_sha256,
            binding.candidate_authorization_manifest_sha256,
        )

    def test_invalid_migration_predecessor_fails_before_artifact_build(self):
        install = self.root / "install"
        install.mkdir()
        invalid = (
            install
            / DEPLOY.MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME
        )
        invalid.write_text("not-a-selector\n", encoding="ascii")
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install),
            mock.patch.object(
                DEPLOY, "prepare_native_host_products",
            ) as native_build,
            mock.patch.object(
                DEPLOY, "prepare_touchid_ui",
            ) as touchid_build,
            self.assertRaisesRegex(
                RuntimeError,
                "developer_id_migration_predecessor_untrusted",
            ),
        ):
            self.real_bootstrap_binding(
                native_vendor_developer_id_schema=True,
            )
        native_build.assert_not_called()
        touchid_build.assert_not_called()

    def test_native_stack_schema_binding_uses_exact_legacy_preflight(self):
        current = self.root / ("f" * 64)
        with (mock.patch.object(DEPLOY, "prepare_touchid_ui"),
              mock.patch.object(
                  DEPLOY.MANAGER, "source_payload",
                  return_value=({
                      "release_manager": b"manager", "authorization_broker": b"broker",
                  }, {}, "a" * 64),
              ),
              mock.patch.object(
                  DEPLOY, "postactivation_current_release", return_value=current
              ) as current_release,
              mock.patch.object(DEPLOY.MANAGER, "read_regular", return_value=b"launcher")):
            binding = self.real_bootstrap_binding(native_stack_schema=True)
        self.assertEqual(binding.schema_current_release_id, "f" * 64)
        current_release.assert_called_once_with(allow_legacy=True)

    def test_operator_ceremony_recovery_binds_exact_current_and_successor(self):
        completed = SimpleNamespace(returncode=0)
        binding = DEPLOY.BootstrapBinding(
            "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
            schema_current_release_id="f" * 64,
        )
        with (mock.patch.object(
                  DEPLOY, "bootstrap_binding", return_value=binding
              ) as binding_call,
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "recover-operator-ceremony-broker",
                "--requesting-agent", "Codex",
                "--requesting-session", "operator-ceremony-recovery",
            ])
        self.assertEqual(result, 0)
        binding_call.assert_called_once_with(operator_ceremony_broker_recovery=True)
        notice.assert_called_once_with(
            "Codex", "operator-ceremony-recovery", binding,
            "recover-operator-ceremony-broker",
        )
        command = run.call_args.args[0]
        self.assertIn("recover-operator-ceremony-broker", command)
        self.assertEqual(
            command[command.index("--expected-source-release-id") + 1], "a" * 64
        )
        self.assertEqual(
            command[command.index("--expected-current-release-id") + 1], "f" * 64
        )

    def test_identity_is_mandatory(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("sys.argv", [str(SCRIPT), "deploy"]):
            with self.assertRaises(SystemExit):
                DEPLOY.main()

    def test_bootstrap_identity_rejects_visual_spoofing_and_overlength(self):
        self.broker.unlink()
        invalid = [
            ("Codex\nPurpose: forged", "thread-7"),
            ("Codex\u202e", "thread-7"),
            ("Codex", "thread\x1b-7"),
            ("C" * 81, "thread-7"),
            ("Codex", "s" * 129),
        ]
        for agent, session in invalid:
            with self.subTest(agent=agent, session=session), \
                    mock.patch.object(DEPLOY, "bootstrap_notice") as notice, \
                    self.assertRaises(SystemExit):
                self.run_main([
                    "bootstrap-authorization", "--requesting-agent", agent,
                    "--requesting-session", session,
                ])
            notice.assert_not_called()

    def test_clean_authorization_bootstrap_state_binds_absent_machine(self):
        values = {
            name: (name + "\n").encode("utf-8")
            for name in DEPLOY.MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        install_root = self.root / "absent-host"
        launcher = self.root / "absent-launcher"
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install_root),
            mock.patch.object(DEPLOY, "STABLE_LAUNCHER", launcher),
        ):
            predecessor_id, installed, clean = (
                DEPLOY.clean_authorization_bootstrap_state(
                    values, b"candidate-launcher",
                )
            )
        expected = DEPLOY.MANAGER.release_identity({
            name: hashlib.sha256(value).hexdigest()
            for name, value in values.items()
        })
        self.assertEqual(predecessor_id, expected)
        self.assertEqual(installed, b"candidate-launcher")
        self.assertTrue(clean)

    def test_clean_authorization_bootstrap_state_rejects_launcher_only(self):
        values = {
            name: (name + "\n").encode("utf-8")
            for name in DEPLOY.MANAGER.PRE_AUTHORIZATION_PAYLOAD_NAMES
        }
        install_root = self.root / "absent-host"
        launcher = self.root / "unexpected-launcher"
        launcher.write_bytes(b"candidate-launcher")
        with (
            mock.patch.object(DEPLOY, "INSTALL_ROOT", install_root),
            mock.patch.object(DEPLOY, "STABLE_LAUNCHER", launcher),
            self.assertRaisesRegex(
                RuntimeError,
                "authorization_bootstrap_clean_state_ambiguous",
            ),
        ):
            DEPLOY.clean_authorization_bootstrap_state(
                values, b"candidate-launcher",
            )


if __name__ == "__main__":
    unittest.main()
