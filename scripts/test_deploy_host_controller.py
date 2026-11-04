#!/usr/bin/env python3

import importlib.util
import json
import os
import tempfile
import unittest
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
        self.real_bootstrap_binding = DEPLOY.bootstrap_binding
        self.real_expected_source_release_id = DEPLOY.expected_source_release_id
        self.patches = [
            mock.patch.object(DEPLOY, "BROKER_PATH", self.broker),
            mock.patch.object(DEPLOY.LAUNCHER, "STATE_ROOT", self.root / "state"),
            mock.patch.object(DEPLOY.LAUNCHER, "acquire_lock", return_value=self.root / "lock"),
            mock.patch.object(DEPLOY.LAUNCHER, "release_lock"),
            mock.patch.object(DEPLOY.MANAGER, "active_markers", return_value=[]),
            mock.patch.object(DEPLOY, "expected_source_release_id", return_value="a" * 64),
            mock.patch.object(DEPLOY, "previous_release_id", return_value="d" * 64),
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

    def test_deploy_routes_through_protected_broker_with_attribution(self):
        pending = {
            "schema": DEPLOY.MANAGER.SCHEMA,
            "status": "activation_pending",
            "transition_id": "11111111-1111-4111-8111-111111111111",
            "transition_sha256": "b" * 64,
            "candidate_release_id": "a" * 64,
            "expires_at": 2_000_000_120,
        }
        completed = SimpleNamespace(
            returncode=0, stdout=json.dumps(pending), stderr="",
        )
        terminal = {"status": "deployed_verified"}
        with (
            mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run,
            mock.patch.object(
                DEPLOY, "wait_for_install_terminal", return_value=terminal,
            ) as waited,
        ):
            self.assertEqual(self.run_main([
                "deploy", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
                "--purpose", "Publish reviewed DDD",
            ]), 0)
        waited.assert_called_once_with(pending)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], [str(self.broker), "request"])
        self.assertNotIn("sudo", command)
        self.assertIn("Codex", command)
        self.assertIn("thread-7", command)
        parameters = json.loads(command[command.index("--parameters-json") + 1])
        self.assertEqual(parameters["state_root"], str(self.root / "state"))
        self.assertEqual(parameters["expected_source_release_id"], "a" * 64)
        self.assertEqual(command[command.index("--operation") + 1], "host-controller-install")

    def test_terminal_poll_retries_exact_publication_name_gap(self):
        transition_id = "11111111-1111-4111-8111-111111111111"
        pending = {
            "transition_id": transition_id,
            "transition_sha256": "b" * 64,
            "candidate_release_id": "a" * 64,
            "expires_at": int(__import__("time").time()) + 120,
        }
        terminal = {
            "transition_id": transition_id,
            "transition_sha256": "b" * 64,
            "candidate_release_id": "a" * 64,
            "status": "deployed_verified",
        }
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
                    DEPLOY.MANAGER, "validate_terminal_transition",
                    return_value=terminal,
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
        pending = {
            "transition_id": transition_id,
            "transition_sha256": "b" * 64,
            "candidate_release_id": "a" * 64,
            "expires_at": int(__import__("time").time()) + 120,
        }
        terminal = {
            "transition_id": transition_id,
            "transition_sha256": "b" * 64,
            "candidate_release_id": "a" * 64,
            "status": "deployed_verified",
        }
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
                    DEPLOY.MANAGER, "validate_terminal_transition",
                    return_value=terminal,
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

    def test_native_host_products_build_requires_local_signing_inputs(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                RuntimeError,
                "Developer_ID_and_notary_profile_are_required",
            ):
                DEPLOY.prepare_native_host_products()

    def test_native_host_products_build_is_bounded_and_environment_pinned(self):
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            mock.patch.dict(
                os.environ,
                {
                    "SECURE_SANDBOX_DEVELOPER_ID": "identity",
                    "SECURE_SANDBOX_NOTARY_KEYCHAIN_PROFILE": "profile",
                    "UNRELATED": "retained",
                },
                clear=True,
            ),
            mock.patch.object(
                DEPLOY.subprocess, "run", return_value=completed
            ) as run,
        ):
            DEPLOY.prepare_native_host_products()
        self.assertEqual(run.call_args.args[0], [str(DEPLOY.NATIVE_HOST_PRODUCTS_BUILD)])
        self.assertEqual(run.call_args.kwargs["timeout"], 1800)
        self.assertEqual(run.call_args.kwargs["stdin"], DEPLOY.subprocess.DEVNULL)
        self.assertEqual(
            run.call_args.kwargs["env"]["PATH"],
            "/usr/bin:/bin:/usr/sbin:/sbin",
        )
        self.assertEqual(run.call_args.kwargs["env"]["UNRELATED"], "retained")

    def test_expected_source_release_builds_notarized_host_products_first(self):
        with (
            mock.patch.object(DEPLOY, "prepare_native_host_products") as build,
            mock.patch.object(
                DEPLOY.MANAGER,
                "source_payload",
                return_value=({}, {}, "a" * 64),
            ) as source,
        ):
            self.assertEqual(self.real_expected_source_release_id(), "a" * 64)
        build.assert_called_once_with()
        source.assert_called_once_with(DEPLOY.MANAGER_PATH.parent.parent)

    def test_postactivation_selector_preflight_replaces_root_floor_with_live_v2_identity(self):
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

        with (mock.patch.object(DEPLOY.MANAGER, "verified_release", side_effect=verified),
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

        def read(path):
            if path.name == "authorization_broker":
                return DEPLOY.MANAGER.EXECUTION_APPROVAL_V2_CAPABILITY
            return b"authorization-manifest\n"

        def verified(_root, link, *_args, **_kwargs):
            self.assertEqual(
                link,
                install
                / DEPLOY.MANAGER.DEVELOPER_ID_MIGRATION_PREDECESSOR_NAME,
            )
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

    def test_normal_deploy_has_no_sudo_fallback_when_broker_missing(self):
        self.broker.unlink()
        with mock.patch.object(DEPLOY.subprocess, "run") as run:
            result = self.run_main([
                "deploy", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
            ])
        self.assertEqual(result, 1)
        run.assert_not_called()

    def test_restrictive_root_selector_uses_one_time_content_bound_recovery(self):
        completed = SimpleNamespace(returncode=0)
        with (mock.patch.object(DEPLOY, "selector_recovery_required", return_value=True),
              mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "deploy", "--requesting-agent", "Codex",
                "--requesting-session", "request-bound-execution-ddd-live",
            ])
        self.assertEqual(result, 0)
        DEPLOY.bootstrap_binding.assert_called_once_with()
        notice.assert_called_once_with(
            "Codex", "request-bound-execution-ddd-live",
            DEPLOY.BootstrapBinding("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64),
            "recover-release-selector",
        )
        command = run.call_args.args[0]
        self.assertEqual(command[:5], [
            "sudo", "/usr/bin/python3", "-I", "-c", DEPLOY.BOOTSTRAP_LOADER,
        ])
        self.assertIn("install", command)
        self.assertIn("a" * 64, command)

    def test_implicit_rollback_is_resolved_to_an_exact_release_before_prompt(self):
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run:
            self.assertEqual(self.run_main([
                "rollback", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
            ]), 0)
        command = run.call_args.args[0]
        parameters = json.loads(command[command.index("--parameters-json") + 1])
        self.assertEqual(parameters["release_id"], "d" * 64)

    def test_explicit_bootstrap_is_terminal_bound_and_one_time(self):
        self.broker.unlink()
        completed = SimpleNamespace(returncode=0)
        with (mock.patch.object(DEPLOY, "bootstrap_notice", return_value=True) as notice,
              mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run):
            result = self.run_main([
                "bootstrap-authorization", "--requesting-agent", "Codex",
                "--requesting-session", "thread-7",
            ])
        self.assertEqual(result, 0)
        DEPLOY.bootstrap_binding.assert_called_once_with()
        notice.assert_called_once_with(
            "Codex", "thread-7",
            DEPLOY.BootstrapBinding("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64),
        )
        self.assertEqual(
            run.call_args.args[0][0:5],
            ["sudo", "/usr/bin/python3", "-I", "-c", DEPLOY.BOOTSTRAP_LOADER],
        )
        self.assertIn("a" * 64, run.call_args.args[0])
        self.assertIn("d" * 64, run.call_args.args[0])
        self.assertIn("e" * 64, run.call_args.args[0])
        self.assertIn("bootstrap-authorization", run.call_args.args[0])

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


if __name__ == "__main__":
    unittest.main()
