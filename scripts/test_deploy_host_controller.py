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
        completed = SimpleNamespace(returncode=0)
        with mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run:
            self.assertEqual(self.run_main([
                "deploy", "--requesting-agent", "Codex", "--requesting-session", "thread-7",
                "--purpose", "Publish reviewed DDD",
            ]), 0)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], [str(self.broker), "request"])
        self.assertNotIn("sudo", command)
        self.assertIn("Codex", command)
        self.assertIn("thread-7", command)
        parameters = json.loads(command[command.index("--parameters-json") + 1])
        self.assertEqual(parameters["state_root"], str(self.root / "state"))
        self.assertEqual(parameters["expected_source_release_id"], "a" * 64)
        self.assertEqual(command[command.index("--operation") + 1], "host-controller-install")

    def test_deploy_reports_silent_protected_authorization_failure(self):
        completed = SimpleNamespace(returncode=23)
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
        completed = SimpleNamespace(returncode=0)
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
              mock.patch.object(DEPLOY.MANAGER, "verified_release",
                                return_value=(current, {"payloads": {}})),
              mock.patch.object(DEPLOY.MANAGER, "release_archive_plan",
                                return_value=plan),
              mock.patch.object(DEPLOY.MANAGER, "read_regular", side_effect=read)):
            binding = self.real_bootstrap_binding(capacity_recovery=True)
        build.assert_not_called()
        source_payload.assert_not_called()
        self.assertEqual(binding.release_id, "a" * 64)
        self.assertEqual(binding.archive_plan_sha256, "1" * 64)

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
