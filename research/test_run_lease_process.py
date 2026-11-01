#!/usr/bin/env python3

import json
import os
import tempfile
import unittest
import uuid
import sys
import types
from pathlib import Path
from unittest import mock

import run_lease_process
from shared.harness_runtime_binding import container_fields, make_binding


class RunLeaseProcessTests(unittest.TestCase):
    def harness(self, executable: bytes = b"#!/bin/sh\nexit 0\n"):
        binding = make_binding(
            harness_id="claude-code", generation_id="a" * 64,
            manifest_sha256="b" * 64,
            executable_sha256=__import__("hashlib").sha256(executable).hexdigest(),
            inventory_sha256="c" * 64, adapter_id="claude-core-v1",
            adapter_sha256="d" * 64,
        )
        return binding, executable

    def test_model_profile_binding_is_exact_and_bounded(self):
        value = {"adapter":"openai-responses-v1", "model":"daybreak-red",
                 "model_profile_id":"daybreak-red", "model_profile_sha256":"a" * 64,
                 "vendor_id":"openai"}
        run_lease_process.validate_model_profile_binding(value)
        value["model_profile_sha256"] = "bad"
        with self.assertRaises(PermissionError):
            run_lease_process.validate_model_profile_binding(value)

    def test_executable_is_derived_from_protected_generation_and_remeasured(self):
        binding, content = self.harness()
        lease = container_fields(binding)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / binding["harness_generation_id"] / "harness"
            executable.parent.mkdir()
            executable.write_bytes(content); executable.chmod(0o555)
            with mock.patch.object(run_lease_process, "HARNESS_RELEASE_ROOT", root), \
                    mock.patch.object(run_lease_process, "TRUSTED_UID", os.getuid()), \
                    mock.patch.object(run_lease_process, "read_harness_binding",
                                      return_value=binding):
                self.assertEqual(run_lease_process.executable_for_binding(lease), executable)
                executable.chmod(0o755)
                with self.assertRaisesRegex(PermissionError, "untrusted"):
                    run_lease_process.executable_for_binding(lease)

    def test_requires_marker_and_fixed_command(self):
        run_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"; marker.write_text(run_id + "\n")
            command = [run_id, "--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
                       "--no-chrome", "--restricted", "--permission-mode", "manual"]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker):
                self.assertEqual(run_lease_process.validate_arguments(command)[0], run_id)
                with self.assertRaises(ValueError):
                    run_lease_process.validate_arguments([run_id, "--permission-mode", "bypassPermissions"])
                marker.write_text(str(uuid.uuid4()) + "\n")
                with self.assertRaises(PermissionError):
                    run_lease_process.validate_arguments(command)

    def test_resume_uuid_is_validated(self):
        run_id = str(uuid.uuid4()); session_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"; marker.write_text(run_id + "\n")
            base = [run_id, "--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
                    "--no-chrome", "--restricted", "--permission-mode", "manual", "--resume"]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker):
                self.assertEqual(run_lease_process.validate_arguments(base + [session_id])[1][-1], session_id)
                with self.assertRaises(ValueError): run_lease_process.validate_arguments(base + ["invalid"])
            base[-1] = "--session-id"
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker):
                self.assertEqual(run_lease_process.validate_arguments(base + [session_id])[1][-1], session_id)

    def test_selected_source_is_supervisor_context_only_for_new_session(self):
        run_id = str(uuid.uuid4()); session_id = str(uuid.uuid4()); source_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"; marker.write_text(run_id + "\n")
            base = [run_id, "--source", source_id,
                    "--append-system-prompt-file", "/etc/claude-code/secure-sandbox-persona.md",
                    "--no-chrome", "--restricted", "--permission-mode", "manual"]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker):
                _, command, selected = run_lease_process.validate_arguments(base + ["--session-id", session_id])
                self.assertEqual(selected, source_id)
                self.assertNotIn("--source", command)
                with self.assertRaisesRegex(ValueError, "new session"):
                    run_lease_process.validate_arguments(base + ["--resume", session_id])
                with self.assertRaises(ValueError):
                    run_lease_process.validate_arguments([run_id, "--source", "bad", *base[3:]])

    def test_selected_working_directory_requires_verified_registered_source(self):
        source = str(uuid.uuid4())
        path = "/home/agent/research-workspace/repos/registered-source"
        module = types.SimpleNamespace(
            verify_source=lambda selected, scope: {"overall_status": "match"},
            registered_source=lambda selected: {"worktree_path": "repos/registered-source"},
            fixed_tree_path=lambda relative, prefix: path,
        )
        with mock.patch.dict(sys.modules, {"source_integrity": module}):
            self.assertEqual(run_lease_process.source_working_directory(source), path)
            agent = type("Agent", (), {"pw_name":"agent","pw_uid":1001,"pw_gid":1001,
                                        "pw_dir":"/home/agent"})()
            scoped = run_lease_process.scope_command(agent, str(uuid.uuid4()), ["/exact/harness"], path)
            self.assertIn(f"--working-directory={path}", scoped)
            module.verify_source = lambda selected, scope: {"overall_status": "changed_or_unverified"}
            with self.assertRaises(PermissionError):
                run_lease_process.source_working_directory(source)

    def test_invoker_must_be_exact_agent_sudo_identity(self):
        agent = type("Agent", (), {"pw_uid": 1000, "pw_gid": 1000})()
        environment = {"SUDO_USER": "agent", "SUDO_UID": "1000", "SUDO_GID": "1000"}
        with mock.patch("run_lease_process.os.geteuid", return_value=0), \
                mock.patch.dict(os.environ, environment, clear=True):
            run_lease_process.validate_invoker(agent)
        with mock.patch("run_lease_process.os.geteuid", return_value=0), \
                mock.patch.dict(os.environ, {**environment, "SUDO_UID": "1001"}, clear=True):
            with self.assertRaises(PermissionError):
                run_lease_process.validate_invoker(agent)

    def test_scope_command_is_non_delegated_bounded_and_uses_fixed_unit(self):
        run_id = str(uuid.uuid4())
        agent = type("Agent", (), {"pw_name":"agent","pw_uid":1001,"pw_gid":1001,
                                    "pw_dir":"/home/agent"})()
        command = ["/exact/harness", "--restricted"]
        scoped = run_lease_process.scope_command(agent, run_id, command)
        self.assertIn(f"--unit=secure-sandbox-run-{run_id}.scope", scoped)
        self.assertIn("--property=Delegate=no", scoped)
        self.assertIn("--property=KillMode=control-group", scoped)
        self.assertIn("--property=SendSIGKILL=yes", scoped)
        self.assertNotIn("--uid=agent", scoped)
        payload = scoped[scoped.index(run_lease_process.SETPRIV):]
        self.assertEqual(payload[:9], [run_lease_process.SETPRIV, "--reuid=1001",
                                      "--regid=1001", "--clear-groups",
                                      "--inh-caps=-all", "--ambient-caps=-all",
                                      "--bounding-set=-all", "--no-new-privs", "--"])
        self.assertEqual(payload[9:], command)

    def test_gateway_environment_is_explicit_and_uses_nonsecret_bearer(self):
        agent = type("Agent", (), {"pw_name":"agent","pw_uid":1001,"pw_gid":1001,
                                    "pw_dir":"/home/agent"})()
        environment = run_lease_process.child_environment(agent)
        self.assertEqual(environment["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18080")
        self.assertEqual(environment["ANTHROPIC_AUTH_TOKEN"], "sandbox-relay-nonsecret")
        self.assertEqual(environment["CLAUDE_CODE_USE_GATEWAY"], "1")
        self.assertNotIn("ANTHROPIC_API_KEY", environment)

    def test_managed_policy_pins_gateway_environment_and_scrubs_children(self):
        settings = json.loads(
            Path(__file__).with_name("managed-settings.proposed.json").read_text()
        )
        managed = settings["env"]
        self.assertEqual(managed["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18080")
        self.assertEqual(managed["ANTHROPIC_AUTH_TOKEN"], "sandbox-relay-nonsecret")
        self.assertEqual(managed["CLAUDE_CODE_USE_GATEWAY"], "1")
        denied = {
            entry["name"] for entry in settings["sandbox"]["credentials"]["envVars"]
            if entry["mode"] == "deny"
        }
        self.assertIn("ANTHROPIC_BASE_URL", denied)
        self.assertIn("ANTHROPIC_AUTH_TOKEN", denied)

    def test_builtin_commands_remain_enabled_without_opening_customization_surfaces(self):
        launcher = Path(__file__).with_name("research-claude.proposed").read_text()
        self.assertNotIn("--disable-slash-commands", launcher)
        self.assertNotIn("--safe-mode", launcher)
        self.assertNotIn("--bare", launcher)

        settings = json.loads(
            Path(__file__).with_name("managed-settings.proposed.json").read_text()
        )
        self.assertTrue(settings["allowManagedPermissionRulesOnly"])
        self.assertTrue(settings["allowManagedHooksOnly"])
        self.assertTrue(settings["allowManagedMcpServersOnly"])
        self.assertTrue(settings["strictPluginOnlyCustomization"])
        self.assertTrue(settings["disableSideloadFlags"])
        self.assertTrue(settings["disableCommandPluginSources"])
        self.assertTrue(settings["disableSkillShellExecution"])
        self.assertTrue(settings["disableAllHooks"])

    def test_rejected_duplicate_does_not_remove_existing_registration(self):
        """A rejected invocation cannot mutate the existing registration."""
        registration = {"supervisor_pid":42,"supervisor_start_time":100}
        self.assertTrue(run_lease_process.registration_belongs_to(registration, 42, 100))
        self.assertFalse(run_lease_process.registration_belongs_to(registration, 43, 100))
        self.assertFalse(run_lease_process.registration_belongs_to(registration, 42, 101))
        source = Path(run_lease_process.__file__).read_text(encoding="utf-8")
        self.assertIn("if claimed:", source)
        self.assertNotIn("PROCESS_FILE.unlink()", source)

    def test_root_state_loader_rejects_writable_or_wrong_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps({"schema": "expected"}) + "\n")
            path.chmod(0o644)
            with mock.patch.object(os, "getuid", return_value=0):
                with self.assertRaises(PermissionError):
                    run_lease_process.load_root_json(path, "expected")
            path.chmod(0o600)
            with mock.patch("pathlib.Path.lstat") as metadata:
                metadata.return_value = type("Metadata", (), {
                    "st_mode": __import__("stat").S_IFREG | 0o600,
                    "st_uid": 0,
                    "st_nlink": 1,
                })()
                with self.assertRaises(ValueError):
                    run_lease_process.load_root_json(path, "wrong")


if __name__ == "__main__": unittest.main()
