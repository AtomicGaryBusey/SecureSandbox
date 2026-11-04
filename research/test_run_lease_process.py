#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

import run_lease_process
from shared.harness_runtime_binding import make_binding as make_harness
from shared.model_stack_runtime_binding import (
    BROKERED_MODE,
    NATIVE_MODE,
    make_binding as make_model_stack,
    make_brokered_binding,
)
from shared.native_stack_runtime_binding import make_binding as make_native_stack
from shared.runtime_authority import make_binding as make_runtime_authority
from shared.session_context_binding import make_binding as make_session_context
from shared.test_native_vendor_stack import anthropic_stack


class RunLeaseProcessTests(unittest.TestCase):
    FIXED = [
        "--append-system-prompt-file",
        "/etc/claude-code/secure-sandbox-persona.md",
        "--no-chrome",
        "--restricted",
        "--permission-mode",
        "manual",
    ]

    def harness(self, executable: bytes = b"#!/bin/sh\nexit 0\n",
                *, generation: str = "a" * 64,
                adapter: str = "claude-core-v1") -> dict[str, str]:
        return make_harness(
            harness_id="claude-code",
            generation_id=generation,
            manifest_sha256="b" * 64,
            executable_sha256=hashlib.sha256(executable).hexdigest(),
            inventory_sha256="c" * 64,
            adapter_id=adapter,
            adapter_sha256="d" * 64,
        )

    def authority(self, *, session_id: str | None = None,
                  source_id: str | None = None,
                  model: str = "bound-model",
                  harness: dict[str, str] | None = None) -> dict:
        context = make_session_context(
            session_id=session_id or str(uuid.uuid4()),
            source_id=source_id,
            source_manifest_sha256="e" * 64 if source_id is not None else None,
            persona_sha256="1" * 64,
            tool_catalog_sha256="2" * 64,
            extension_set_sha256="3" * 64,
        )
        brokered = make_brokered_binding(
            adapter="anthropic-messages-v1",
            model=model,
            profile_id="test-profile",
            profile_sha256="4" * 64,
            provider_mode="production",
            vendor_id="test-vendor",
        )
        return make_runtime_authority(
            model_stack_binding=make_model_stack(BROKERED_MODE, brokered),
            session_context_binding=context,
            harness_binding=harness or self.harness(),
        )

    def native_authority(self) -> dict:
        stack = anthropic_stack()
        native = make_native_stack(stack)
        matching = self.harness(
            generation=stack["harness"]["generation_id"],
            adapter=stack["harness"]["adapter_id"],
        )
        context = make_session_context(
            session_id=str(uuid.uuid4()), source_id=None,
            source_manifest_sha256=None, persona_sha256="1" * 64,
            tool_catalog_sha256="2" * 64, extension_set_sha256="3" * 64,
        )
        return make_runtime_authority(
            model_stack_binding=make_model_stack(NATIVE_MODE, native),
            session_context_binding=context,
            harness_binding=matching,
        )

    def gateway_lease(self, authority: dict, *, run_id: str | None = None,
                      lease_id: str | None = None) -> dict:
        return {
            "schema": run_lease_process.GATEWAY_LEASE_SCHEMA,
            "lease_id": lease_id or str(uuid.uuid4()),
            "run_id": run_id or str(uuid.uuid4()),
            "profile": "standard",
            "issued_at": 1_000,
            "expires_at": 2_000,
            "maximum_expires_at": 3_000,
            "runtime_authority": authority,
            "brokered_transport": {
                "schema": "secure-sandbox-brokered-run-transport-v1",
                "relay_sha256": "5" * 64,
                "policy_sha256": "6" * 64,
            },
            "limits": {
                "max_requests": 1,
                "max_input_tokens": 2,
                "max_output_tokens": 3,
                "max_cost_microusd": 4,
            },
            "pricing": {
                "input_microusd_per_million_tokens": 5,
                "output_microusd_per_million_tokens": 6,
            },
            "renewals": 0,
        }

    def research_lease(self, authority: dict) -> dict:
        gateway = self.gateway_lease(authority)
        return {
            "schema": run_lease_process.LEASE_SCHEMA,
            "run_id": gateway["run_id"],
            "lease_id": gateway["lease_id"],
            "expires_at": gateway["expires_at"],
            "maximum_expires_at": gateway["maximum_expires_at"],
            "runtime_authority": authority,
            "gateway_lease": gateway,
            "gateway_lease_sha256": hashlib.sha256(
                run_lease_process.canonical_json_line(gateway)
            ).hexdigest(),
        }

    def seed(self, lease: dict) -> dict:
        return {
            "schema": run_lease_process.PROCESS_SCHEMA,
            "run_id": lease["run_id"],
            "lease_id": lease["lease_id"],
            "ready": False,
            "unit": run_lease_process.scope_unit(lease["run_id"]),
            "runtime_authority": lease["runtime_authority"],
            "gateway_lease_sha256": lease["gateway_lease_sha256"],
        }

    def policy(self, authority: dict) -> dict:
        context = authority["session_context_binding"]
        return {
            "schema": "secure-sandbox-session-policy-runtime-v1",
            **{name: context[name] for name in (
                "source_id", "source_manifest_sha256", "persona_sha256",
                "tool_catalog_sha256", "extension_set_sha256",
            )},
        }

    @staticmethod
    def agent():
        return type(
            "Agent", (), {
                "pw_name": "agent", "pw_uid": 1001, "pw_gid": 1001,
                "pw_dir": "/home/agent",
            },
        )()

    def test_research_lease_binds_exact_gateway_lease_and_authority(self):
        lease = self.research_lease(self.authority())
        self.assertEqual(run_lease_process.validate_research_lease(lease), lease)
        for mutation in (
            lambda value: value["gateway_lease"].__setitem__("renewals", 1),
            lambda value: value.__setitem__("gateway_lease_sha256", "0" * 64),
            lambda value: value.__setitem__("expires_at", 1_999),
        ):
            changed = copy.deepcopy(lease)
            mutation(changed)
            with self.assertRaises(ValueError):
                run_lease_process.validate_research_lease(changed)

    def test_process_records_accept_only_exact_authority_preserving_variants(self):
        seed = self.seed(self.research_lease(self.authority()))
        claimed = {**seed, "supervisor_pid": 10, "supervisor_start_time": 20}
        ready = {**claimed, "ready": True, "scope_pid": 30}
        failed = {**claimed, "launch_failed": "PermissionError", "scope_empty": True,
                  "exited_at": 40}
        terminal = {**ready, "scope_empty": True, "exit_status": -9, "exited_at": 40}
        for record in (seed, claimed, ready, failed, terminal):
            self.assertEqual(run_lease_process.validate_process_record(record), record)
        changed = copy.deepcopy(seed)
        changed["unexpected"] = True
        with self.assertRaises(ValueError):
            run_lease_process.validate_process_record(changed)
        changed = copy.deepcopy(seed)
        changed["runtime_authority"]["binding_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            run_lease_process.validate_process_record(changed)

    def test_native_runtime_is_denied_before_launch(self):
        with self.assertRaisesRegex(PermissionError, "native runtime transport"):
            run_lease_process.require_brokered_runtime(self.native_authority())

    def test_executable_is_derived_from_protected_generation_and_remeasured(self):
        content = b"#!/bin/sh\nexit 0\n"
        harness = self.harness(content)
        authority = self.authority(harness=harness)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / harness["harness_generation_id"] / "harness"
            executable.parent.mkdir()
            executable.write_bytes(content)
            executable.chmod(0o555)
            with mock.patch.object(run_lease_process, "HARNESS_RELEASE_ROOT", root), \
                    mock.patch.object(run_lease_process, "TRUSTED_UID", os.getuid()), \
                    mock.patch.object(run_lease_process, "read_harness_binding",
                                      return_value=harness):
                self.assertEqual(run_lease_process.executable_for_binding(authority), executable)
                executable.chmod(0o755)
                with self.assertRaisesRegex(PermissionError, "untrusted"):
                    run_lease_process.executable_for_binding(authority)

    def test_requires_marker_fixed_command_and_bound_session_option(self):
        run_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"
            marker.write_text(run_id + "\n")
            marker.chmod(0o644)
            command = [run_id, *self.FIXED, "--session-id", session_id]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker), \
                    mock.patch.object(run_lease_process, "TRUSTED_UID", os.getuid()):
                self.assertEqual(run_lease_process.validate_arguments(command)[0], run_id)
                with self.assertRaises(ValueError):
                    run_lease_process.validate_arguments([run_id, *self.FIXED])
                with self.assertRaises(ValueError):
                    run_lease_process.validate_arguments(
                        [run_id, "--permission-mode", "bypassPermissions"]
                    )
                marker.write_text(str(uuid.uuid4()) + "\n")
                with self.assertRaises(PermissionError):
                    run_lease_process.validate_arguments(command)

    def test_selected_source_is_supervisor_context_only_for_new_session(self):
        run_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        source_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "run-id"
            marker.write_text(run_id + "\n")
            marker.chmod(0o644)
            base = [run_id, "--source", source_id, *self.FIXED]
            with mock.patch.object(run_lease_process, "RUN_ID_FILE", marker), \
                    mock.patch.object(run_lease_process, "TRUSTED_UID", os.getuid()):
                _, command, selected = run_lease_process.validate_arguments(
                    [*base, "--session-id", session_id]
                )
                self.assertEqual(selected, source_id)
                self.assertNotIn("--source", command)
                with self.assertRaisesRegex(ValueError, "new session"):
                    run_lease_process.validate_arguments([*base, "--resume", session_id])

    def test_launch_identity_remeasures_policy_and_recovers_bound_resume_source(self):
        source_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        authority = self.authority(session_id=session_id, source_id=source_id)
        with mock.patch.object(run_lease_process, "measure_session_policy",
                               return_value=self.policy(authority)) as measure:
            self.assertEqual(
                run_lease_process.validate_bound_launch(
                    authority, [*self.FIXED, "--resume", session_id], None
                ),
                source_id,
            )
        measure.assert_called_once_with(source_id)
        with mock.patch.object(run_lease_process, "measure_session_policy",
                               return_value=self.policy(authority)):
            with self.assertRaisesRegex(PermissionError, "source"):
                run_lease_process.validate_bound_launch(
                    authority, [*self.FIXED, "--session-id", session_id], None
                )
            with self.assertRaisesRegex(PermissionError, "session"):
                run_lease_process.validate_bound_launch(
                    authority, [*self.FIXED, "--resume", str(uuid.uuid4())], None
                )

    def test_stale_policy_measurement_fails_closed(self):
        authority = self.authority()
        changed = self.policy(authority)
        changed["persona_sha256"] = "f" * 64
        options = [*self.FIXED, "--session-id",
                   authority["session_context_binding"]["session_id"]]
        with mock.patch.object(run_lease_process, "measure_session_policy",
                               return_value=changed):
            with self.assertRaisesRegex(PermissionError, "does not match"):
                run_lease_process.validate_bound_launch(authority, options, None)
        changed = self.policy(authority)
        changed["unreviewed_extension"] = "accepted"
        with mock.patch.object(run_lease_process, "measure_session_policy",
                               return_value=changed):
            with self.assertRaisesRegex(PermissionError, "measurement is invalid"):
                run_lease_process.validate_bound_launch(authority, options, None)

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
            module.verify_source = lambda selected, scope: {
                "overall_status": "changed_or_unverified"
            }
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

    def test_scope_command_is_bounded_and_uses_authority_model(self):
        run_id = str(uuid.uuid4())
        authority = self.authority(model="selected-bound-model")
        command = ["/exact/harness", "--restricted"]
        scoped = run_lease_process.scope_command(
            self.agent(), run_id, command, authority, "/bound/worktree"
        )
        self.assertIn(f"--unit=secure-sandbox-run-{run_id}.scope", scoped)
        self.assertIn("--working-directory=/bound/worktree", scoped)
        self.assertIn("--property=Delegate=no", scoped)
        self.assertIn("--setenv=ANTHROPIC_DEFAULT_MODEL=selected-bound-model", scoped)
        self.assertNotIn("--uid=agent", scoped)
        payload = scoped[scoped.index(run_lease_process.SETPRIV):]
        self.assertEqual(payload[:9], [
            run_lease_process.SETPRIV, "--reuid=1001", "--regid=1001",
            "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
            "--bounding-set=-all", "--no-new-privs", "--",
        ])
        self.assertEqual(payload[9:], command)

    def test_gateway_environment_is_explicit_and_uses_nonsecret_bearer(self):
        authority = self.authority(model="selected-model")
        environment = run_lease_process.child_environment(self.agent(), authority)
        self.assertEqual(environment["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18080")
        self.assertEqual(environment["ANTHROPIC_AUTH_TOKEN"], "sandbox-relay-nonsecret")
        self.assertEqual(environment["CLAUDE_CODE_USE_GATEWAY"], "1")
        self.assertEqual(environment["ANTHROPIC_DEFAULT_MODEL"], "selected-model")
        self.assertNotIn("ANTHROPIC_API_KEY", environment)

    def test_managed_policy_has_no_ambient_provider_route_and_scrubs_children(self):
        settings = json.loads(
            Path(__file__).with_name("managed-settings.proposed.json").read_text()
        )
        self.assertNotIn("env", settings)
        denied = {
            entry["name"] for entry in settings["sandbox"]["credentials"]["envVars"]
            if entry["mode"] == "deny"
        }
        self.assertTrue({
            "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "CLAUDE_CONFIG_DIR", "HTTP_PROXY",
            "HTTPS_PROXY", "ACCESS_TOKEN",
        }.issubset(denied))
        self.assertIn(
            "/var/lib/secure-sandbox/native-vendor",
            settings["sandbox"]["filesystem"]["denyRead"],
        )

    def test_native_claude_session_settings_lock_mythos_without_credentials(self):
        settings = json.loads(
            Path(__file__).with_name("native-claude-session-settings.json").read_text()
        )
        self.assertEqual(settings["model"], "claude-mythos-5-1")
        self.assertEqual(settings["availableModels"], ["claude-mythos-5-1"])
        environment = settings["env"]
        self.assertEqual(environment["ANTHROPIC_MODEL"], "claude-mythos-5-1")
        self.assertEqual(environment["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"], "1")
        self.assertEqual(environment["DISABLE_UPDATES"], "1")
        for forbidden in (
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
            "HTTP_PROXY", "HTTPS_PROXY",
        ):
            self.assertNotIn(forbidden, environment)

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
        registration = {"supervisor_pid": 42, "supervisor_start_time": 100}
        self.assertTrue(run_lease_process.registration_belongs_to(registration, 42, 100))
        self.assertFalse(run_lease_process.registration_belongs_to(registration, 43, 100))
        self.assertFalse(run_lease_process.registration_belongs_to(registration, 42, 101))
        source = Path(run_lease_process.__file__).read_text(encoding="utf-8")
        self.assertIn("if claimed:", source)
        self.assertNotIn("PROCESS_FILE.unlink()", source)

    def test_root_state_loader_requires_canonical_bounded_root_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            value = {"schema": "expected"}
            path.write_bytes(run_lease_process.canonical_json_line(value))
            path.chmod(0o600)
            with mock.patch.object(run_lease_process, "TRUSTED_UID", os.getuid()):
                self.assertEqual(run_lease_process.load_root_json(path, "expected"), value)
                path.write_text(json.dumps(value) + "\n")
                with self.assertRaisesRegex(ValueError, "noncanonical"):
                    run_lease_process.load_root_json(path, "expected")
                path.write_bytes(run_lease_process.canonical_json_line(value))
                path.chmod(0o644)
                with self.assertRaises(PermissionError):
                    run_lease_process.load_root_json(path, "expected")


if __name__ == "__main__":
    unittest.main()
