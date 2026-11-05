#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from research import native_claude_adapter as adapter
from shared import harness_runtime_binding, model_stack_runtime_binding
from shared import native_stack_runtime_binding, runtime_authority, session_context_binding


ROOT = Path(__file__).resolve().parent.parent


def command_prefix(uid: int = 501, gid: int = 502) -> tuple[str, ...]:
    return (
        "/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}",
        "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
        "--bounding-set=-all", "--no-new-privs", "--",
    )


class FakeSystemdProcess:
    def __init__(self, handshake: dict, response: dict) -> None:
        request_read, request_write = os.pipe()
        output_read, output_write = os.pipe()
        os.write(output_write, adapter.canonical_bytes(handshake))
        self.stdin = os.fdopen(request_write, "wb", buffering=0)
        self.stdout = os.fdopen(output_read, "rb", buffering=0)
        self.stderr = None
        self.request_read = request_read
        self.request = bytearray()
        self.response = response
        self.output_write = output_write
        self.returncode: int | None = None
        self.terminated = False
        self.worker = threading.Thread(target=self._serve)
        self.worker.start()

    def _serve(self) -> None:
        try:
            while b"\n" not in self.request:
                block = os.read(self.request_read, 4096)
                if not block:
                    break
                self.request.extend(block)
            if self.request:
                os.write(self.output_write, adapter.canonical_bytes(self.response))
        finally:
            os.close(self.output_write)
            os.close(self.request_read)

    def wait(self, timeout: float | None = None) -> int:
        self.worker.join(timeout)
        self.returncode = 0
        return 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    def request_bytes(self) -> bytes:
        self.worker.join()
        return bytes(self.request)


class FakeSystemd:
    def __init__(
        self, root: Path, unit: str, nonce: str, *, output: bytes = b"ok",
        clear_on_stop: bool = True,
    ) -> None:
        self.unit = unit
        self.pid = 4242
        self.cgroup = f"/system.slice/{unit}"
        self.clear_on_stop = clear_on_stop
        self.stopped = False
        self.commands: list[list[str]] = []
        self.proc_root = root / "proc"
        self.cgroup_root = root / "cgroup"
        process = self.proc_root / str(self.pid)
        process.mkdir(parents=True)
        capability = f"{adapter.SUPERVISOR_CAPABILITY_MASK:016x}"
        (process / "status").write_text(
            "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNoNewPrivs:\t1\n"
            "CapInh:\t0000000000000000\n"
            f"CapPrm:\t{capability}\nCapEff:\t{capability}\n"
            f"CapBnd:\t{capability}\nCapAmb:\t0000000000000000\n",
            encoding="ascii",
        )
        (process / "cgroup").write_text(f"0::{self.cgroup}\n", encoding="ascii")
        (process / "cmdline").write_bytes(b"\0".join((
            str(adapter.PYTHON).encode("ascii"),
            str(adapter.COMMAND_SUPERVISOR).encode("ascii"),
            adapter.COMMAND_SUPERVISOR_MODE.encode("ascii"), b"",
        )))
        fields = ["S", *("0" for _ in range(18)), "12345"]
        (process / "stat").write_text(
            f"{self.pid} (python) " + " ".join(fields) + "\n",
            encoding="ascii",
        )
        cgroup = self.cgroup_root / self.cgroup.lstrip("/")
        cgroup.mkdir(parents=True)
        self.cgroup_processes = cgroup / "cgroup.procs"
        self.cgroup_processes.write_text(f"{self.pid}\n", encoding="ascii")
        handshake = {
            "schema": adapter.COMMAND_HANDSHAKE_SCHEMA,
            "unit": unit, "pid": self.pid, "uid": 0, "gid": 0,
            "cgroup": self.cgroup,
        }
        response = {
            "schema": adapter.COMMAND_RESPONSE_SCHEMA,
            "status": "completed", "nonce": nonce, "returncode": 0,
            "stdout_b64": base64.b64encode(output).decode("ascii"),
            "stdout_sha256": hashlib.sha256(output).hexdigest(), "error": None,
        }
        self.process = FakeSystemdProcess(handshake, response)

    def popen(self, command: list[str], **_kwargs: object) -> FakeSystemdProcess:
        self.commands.append(list(command))
        return self.process

    def runner(self, command: list[str], **_kwargs: object):
        self.commands.append(list(command))
        if command[1] == "stop":
            self.stopped = True
            if self.clear_on_stop:
                self.cgroup_processes.write_bytes(b"")
                shutil.rmtree(self.proc_root / str(self.pid))
            else:
                # A forked vendor child may call setsid(), close every output,
                # and outlive the leader, but it cannot leave this cgroup.
                self.cgroup_processes.write_text("9001\n", encoding="ascii")
                shutil.rmtree(self.proc_root / str(self.pid))
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[1] != "show":
            raise AssertionError(command)
        if self.stopped:
            if self.clear_on_stop:
                return subprocess.CompletedProcess(command, 4, b"", b"")
            fields = {
                "LoadState": "loaded", "ActiveState": "inactive",
                "SubState": "dead", "MainPID": "0",
                "ControlGroup": self.cgroup,
            }
        else:
            environment = " ".join(
                f"{name}={value}" for name, value in sorted({
                    **adapter.SUPERVISOR_ENVIRONMENT,
                    "SECURE_SANDBOX_CLAUDE_COMMAND_UNIT": self.unit,
                }.items())
            )
            fields = {
                "LoadState": "loaded", "ActiveState": "active",
                "SubState": "running", "MainPID": str(self.pid),
                "ControlGroup": self.cgroup, "User": "root", "Group": "root",
                "KillMode": "control-group", "SendSIGKILL": "yes",
                "RuntimeMaxUSec": "25s",
                "TimeoutStopUSec": "2s", "TasksMax": "128",
                "NoNewPrivileges": "yes", "UMask": "0077", "Type": "exec",
                "ExitType": "main", "Restart": "no",
                "ExecStart": (
                    f"{{ path={adapter.PYTHON} ; argv[]={adapter.PYTHON} "
                    f"{adapter.COMMAND_SUPERVISOR} "
                    f"{adapter.COMMAND_SUPERVISOR_MODE} ; ignore_errors=no ; }}"
                ),
                "FragmentPath": "", "Transient": "yes",
                "SupplementaryGroups": "",
                "CapabilityBoundingSet": "cap_setgid cap_setuid cap_setpcap",
                "AmbientCapabilities": "", "Delegate": "no",
                "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes",
                "LockPersonality": "yes",
                "BindsTo": "native-harness-supervisor.service",
                "After": "native-harness-supervisor.service",
                "PartOf": "native-harness-supervisor.service",
                "Environment": environment,
            }
        raw = "".join(f"{name}={value}\n" for name, value in fields.items()).encode()
        return subprocess.CompletedProcess(command, 0, raw, b"")


class NativeClaudeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(encoding="ascii")
        )["stacks"][0]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64
        native = native_stack_runtime_binding.make_binding(stack)
        harness = harness_runtime_binding.make_binding(
            harness_id="claude-code",
            generation_id="a" * 64,
            manifest_sha256="d" * 64,
            executable_sha256=hashlib.sha256(b"claude").hexdigest(),
            inventory_sha256="e" * 64,
            adapter_id="claude-native-oauth-v1",
            adapter_sha256="f" * 64,
        )
        context = session_context_binding.make_binding(
            session_id="00000000-0000-4000-8000-000000000001",
            source_id=None,
            source_manifest_sha256=None,
            persona_sha256="1" * 64,
            tool_catalog_sha256="2" * 64,
            extension_set_sha256="3" * 64,
        )
        self.authority = runtime_authority.make_binding(
            model_stack_binding=model_stack_runtime_binding.make_binding(
                model_stack_runtime_binding.NATIVE_MODE, native
            ),
            session_context_binding=context,
            harness_binding=harness,
        )
        self.environment = adapter.child_environment(
            self.authority,
            home=Path("/var/empty/claude-native"),
            config_root=Path("/var/lib/native-test"),
            term="xterm-256color",
        )

    def test_environment_is_reconstructed_and_has_no_projected_credential(self) -> None:
        adapter.validate_environment(self.environment)
        for name in adapter.FORBIDDEN_ENVIRONMENT:
            self.assertNotIn(name, self.environment)
        self.assertEqual(self.environment["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"], "1")
        self.assertEqual(self.environment["DISABLE_UPDATES"], "1")
        self.assertEqual(self.environment["ANTHROPIC_MODEL"], adapter.CLAUDE_MODEL_ID)
        self.assertEqual(self.environment["HTTPS_PROXY"], adapter.PROXY)

    def test_environment_rejects_api_key_base_url_and_proxy_drift(self) -> None:
        for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            changed = {**self.environment, name: "secret"}
            with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "forbidden_environment"):
                adapter.validate_environment(changed)
        with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "proxy_invalid"):
            adapter.validate_environment({**self.environment, "HTTPS_PROXY": "http://evil"})

    def test_exact_pairing_and_harness_match_are_required(self) -> None:
        self.assertEqual(adapter.require_claude_authority(self.authority), self.authority)
        changed = json.loads(json.dumps(self.authority))
        changed["model_stack_binding"]["authority"]["model_id"] = "claude-opus-5"
        with self.assertRaises(adapter.NativeClaudeAdapterError):
            adapter.require_claude_authority(changed)

    def test_executable_is_remeasured_from_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / ("a" * 64)
            release.mkdir()
            executable = release / "harness"
            executable.write_bytes(b"claude")
            executable.chmod(0o555)
            observed = adapter.executable_for_authority(
                self.authority, release_root=root, trusted_uid=os.geteuid()
            )
            self.assertEqual(observed, executable)
            executable.chmod(0o755)
            with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "untrusted"):
                adapter.executable_for_authority(
                    self.authority, release_root=root, trusted_uid=os.geteuid()
                )

    def test_commands_pin_model_and_do_not_offer_fallback(self) -> None:
        command = adapter.session_command(
            Path("/release/harness"),
            session_id="00000000-0000-4000-8000-000000000001",
            effort="high",
            resume=False,
        )
        self.assertEqual(command[command.index("--model") + 1], adapter.CLAUDE_MODEL_ID)
        self.assertNotIn("--fallback-model", command)
        self.assertIn("--restricted", command)
        self.assertEqual(command[command.index("--tools") + 1], "")
        self.assertEqual(command[command.index("--disallowedTools") + 1], "*")
        self.assertIn("--strict-mcp-config", command)
        self.assertIn("--disable-slash-commands", command)
        self.assertNotIn("--dangerously-skip-permissions", command)

        entitlement = adapter.entitlement_command(
            Path("/release/harness"), effort="high"
        )
        self.assertEqual(entitlement[entitlement.index("--tools") + 1], "")
        self.assertEqual(
            entitlement[entitlement.index("--disallowedTools") + 1], "*"
        )

    def test_status_projection_never_returns_vendor_fields_or_paths(self) -> None:
        payload = json.dumps({
            "loggedIn": True,
            "apiProvider": "firstParty",
            "authMethod": "claude.ai",
            "analyticsDisabled": True,
            "configDirectory": self.environment["CLAUDE_CONFIG_DIR"],
            "projectsDirectory": self.environment["CLAUDE_CONFIG_DIR"] + "/projects",
            "loginExpiresAt": 2_000_000_000,
            "email": "operator@example.test",
            "orgId": "org_opaque_identifier",
            "orgName": "Private Organization Name",
            "subscriptionType": "ultra",
        }).encode()
        runner = mock.Mock(return_value=subprocess_result(0, payload))
        status = adapter.observe_status(
            Path("/release/harness"), self.environment, runner=runner, now=100,
            binding_key=b"k" * 32,
        )
        self.assertEqual(status["state"], "signed-in")
        self.assertRegex(status["account_subject_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["workspace_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["subscription_class_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            status["evidence_sha256"], hashlib.sha256(payload).hexdigest())
        differently_keyed = adapter.observe_status(
            Path("/release/harness"), self.environment, runner=runner, now=100,
            binding_key=b"z" * 32)
        self.assertNotEqual(
            status["evidence_sha256"], differently_keyed["evidence_sha256"])
        encoded = adapter.canonical_bytes(status).decode("ascii")
        self.assertNotIn("configDirectory", encoded)
        self.assertNotIn("projectsDirectory", encoded)
        self.assertNotIn("operator@example", encoded)
        self.assertNotIn("Private Organization", encoded)
        self.assertNotIn("org_opaque", encoded)

    def test_current_signed_out_schema_is_exact_and_content_free(self) -> None:
        payload = json.dumps({
            "loggedIn": False,
            "apiProvider": "firstParty",
            "authMethod": "none",
            "analyticsDisabled": True,
            "configDirectory": self.environment["CLAUDE_CONFIG_DIR"],
            "projectsDirectory": self.environment["CLAUDE_CONFIG_DIR"] + "/projects",
            "loginExpiresAt": None,
        }).encode()
        status = adapter.observe_status(
            Path("/release/harness"), self.environment,
            runner=mock.Mock(return_value=subprocess_result(1, payload)), now=100,
            binding_key=b"k" * 32,
        )
        # Claude 2.1.318 returns exit 1 for a valid signed-out status.
        self.assertEqual(status["state"], "signed-out")
        status = adapter.observe_status(
            Path("/release/harness"), self.environment,
            runner=mock.Mock(return_value=subprocess_result(0, payload)), now=100,
            binding_key=b"k" * 32,
        )
        self.assertEqual(status["state"], "signed-out")
        self.assertIsNone(status["account_subject_sha256"])

    def test_unknown_status_is_ambiguous_not_signed_out(self) -> None:
        payload = json.dumps({
            "apiProvider": "other",
            "authMethod": "new-method",
            "configDirectory": self.environment["CLAUDE_CONFIG_DIR"],
            "projectsDirectory": "/x",
        }).encode()
        status = adapter.observe_status(
            Path("/release/harness"), self.environment,
            runner=mock.Mock(return_value=subprocess_result(0, payload)), now=100,
            binding_key=b"k" * 32,
        )
        self.assertEqual(status["state"], "ambiguous")

    def test_entitlement_requires_only_exact_mythos_usage(self) -> None:
        raw = json.dumps({
            "subtype": "success",
            "is_error": False,
            "result": "SECURE_SANDBOX_ENTITLEMENT_READY",
            "modelUsage": {adapter.CLAUDE_MODEL_ID: {"inputTokens": 1, "outputTokens": 1}},
        }, separators=(",", ":")).encode()
        receipt = adapter.observe_entitlement_result(
            raw, binding_key=b"k" * 32, now=100)
        self.assertEqual(receipt["state"], "verified")
        self.assertEqual(receipt["program_state"], "unknown")
        self.assertNotIn("program_id", receipt)
        self.assertNotIn("program_tier", receipt)
        self.assertNotEqual(
            receipt["evidence_sha256"], hashlib.sha256(raw).hexdigest())
        cross_model = json.loads(raw)
        cross_model["modelUsage"]["claude-opus-5"] = {}
        denied = adapter.observe_entitlement_result(
            json.dumps(cross_model, separators=(",", ":")).encode(),
            binding_key=b"k" * 32, now=100
        )
        self.assertEqual(denied["state"], "denied")
        changed_result = json.loads(raw)
        changed_result["result"] = "SECURE_SANDBOX_ENTITLEMENT_READY extra"
        denied = adapter.observe_entitlement_result(
            json.dumps(changed_result, separators=(",", ":")).encode(),
            binding_key=b"k" * 32, now=100
        )
        self.assertEqual(denied["state"], "denied")

    def test_bounded_runner_discards_stderr_and_rejects_oversize(self) -> None:
        runner = mock.Mock(return_value=subprocess_result(0, b"x" * 32))
        with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "oversized"):
            adapter._run_bounded(
                ["/release/harness"], self.environment,
                maximum=16, timeout=1, runner=runner,
            )

    def test_transient_service_command_is_root_supervised_and_secret_free(self) -> None:
        unit = "secure-sandbox-native-claude-command-" + "a" * 32 + ".service"
        command = adapter._systemd_command(unit, 15)
        joined = "\n".join(command)
        for required in (
            "--property=User=root", "--property=Group=root",
            "--property=KillMode=control-group", "--property=ExitType=main",
            "--property=SendSIGKILL=yes", "--property=RuntimeMaxSec=25",
            "--property=TimeoutStopSec=2", "--property=NoNewPrivileges=yes",
            "--property=ProtectControlGroups=yes",
            "--property=CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SETPCAP",
            str(adapter.PYTHON), str(adapter.COMMAND_SUPERVISOR),
            adapter.COMMAND_SUPERVISOR_MODE,
        ):
            self.assertIn(required, command)
        self.assertNotIn("--uid=501", joined)
        for forbidden in (
            "/release/harness", "auth status", "CLAUDE_CONFIG_DIR",
            self.environment["CLAUDE_CONFIG_DIR"], "ANTHROPIC_API_KEY",
        ):
            self.assertNotIn(forbidden, joined)
        with self.assertRaisesRegex(
            adapter.NativeClaudeAdapterError, "identity_prefix_invalid"):
            adapter._identity_from_prefix((
                "/usr/bin/setpriv", "--reuid=501", "--regid=502",
                "--clear-groups", "--no-new-privs", "--",
            ))
        self.assertEqual(
            adapter._systemd_duration_usec("2min 10s"), 130_000_000)

    def test_production_path_accepts_only_after_stop_and_two_absence_reads(self) -> None:
        unit_hex, nonce = "a" * 32, "b" * 32
        unit = f"secure-sandbox-native-claude-command-{unit_hex}.service"
        executable = Path(
            "/usr/local/libexec/secure-sandbox-harnesses/releases/"
            + "c" * 64 + "/harness")
        environment = adapter.child_environment(
            self.authority, home=Path("/var/empty"),
            config_root=adapter.CONFIG_ROOT, term="xterm-256color")
        with tempfile.TemporaryDirectory() as directory:
            systemd = FakeSystemd(Path(directory), unit, nonce)
            hooks = adapter._SystemdTestHooks(
                popen=systemd.popen, runner=systemd.runner,
                cgroup_root=systemd.cgroup_root,
                proc_root=systemd.proc_root, sleep=lambda _seconds: None)
            identifiers = [SimpleNamespace(hex=unit_hex), SimpleNamespace(hex=nonce)]
            with mock.patch.object(adapter.uuid, "uuid4", side_effect=identifiers), \
                    mock.patch.object(
                        adapter, "_trusted_command_digest", return_value="d" * 64):
                result = adapter._run_bounded(
                    adapter.status_command(executable), environment,
                    maximum=adapter.MAX_STATUS_BYTES, timeout=15,
                    command_prefix=command_prefix(),
                    _systemd_test_hooks=hooks)
            self.assertEqual(result.stdout, b"ok")
            self.assertTrue(systemd.stopped)
            show_calls = [item for item in systemd.commands if item[1] == "show"]
            self.assertEqual(len(show_calls), 3)
            service_argv = systemd.commands[0]
            self.assertNotIn(str(executable), service_argv)
            self.assertNotIn(environment["CLAUDE_CONFIG_DIR"], "\n".join(service_argv))
            sent = systemd.process.request_bytes()
            request = json.loads(sent)
            self.assertEqual(request["vendor_uid"], 501)
            self.assertEqual(request["vendor_gid"], 502)
            self.assertEqual(request["command"], adapter.status_command(executable))

    def test_wrong_unit_readback_never_opens_vendor_launch_gate(self) -> None:
        unit_hex, nonce = "a" * 32, "b" * 32
        unit = f"secure-sandbox-native-claude-command-{unit_hex}.service"
        executable = Path(
            "/usr/local/libexec/secure-sandbox-harnesses/releases/"
            + "c" * 64 + "/harness")
        environment = adapter.child_environment(
            self.authority, home=Path("/var/empty"),
            config_root=adapter.CONFIG_ROOT, term="xterm-256color")
        with tempfile.TemporaryDirectory() as directory:
            systemd = FakeSystemd(Path(directory), unit, nonce)

            def wrong_runner(command: list[str], **kwargs: object):
                result = systemd.runner(command, **kwargs)
                if command[1] == "show" and not systemd.stopped:
                    return subprocess.CompletedProcess(
                        command, 0,
                        result.stdout.replace(
                            b"KillMode=control-group\n", b"KillMode=process\n"),
                        b"",
                    )
                return result

            hooks = adapter._SystemdTestHooks(
                popen=systemd.popen, runner=wrong_runner,
                cgroup_root=systemd.cgroup_root,
                proc_root=systemd.proc_root, sleep=lambda _seconds: None)
            identifiers = [SimpleNamespace(hex=unit_hex), SimpleNamespace(hex=nonce)]
            with mock.patch.object(adapter.uuid, "uuid4", side_effect=identifiers), \
                    mock.patch.object(
                        adapter, "_trusted_command_digest", return_value="d" * 64):
                with self.assertRaisesRegex(
                    adapter.NativeClaudeAdapterError, "service_identity_invalid"):
                    adapter._run_bounded(
                        adapter.status_command(executable), environment,
                        maximum=adapter.MAX_STATUS_BYTES, timeout=15,
                        command_prefix=command_prefix(),
                        _systemd_test_hooks=hooks)
            self.assertEqual(systemd.process.request_bytes(), b"")
            self.assertTrue(systemd.stopped)

    def test_setsid_descendant_cgroup_residual_overrides_success_response(self) -> None:
        unit_hex, nonce = "a" * 32, "b" * 32
        unit = f"secure-sandbox-native-claude-command-{unit_hex}.service"
        executable = Path(
            "/usr/local/libexec/secure-sandbox-harnesses/releases/"
            + "c" * 64 + "/harness")
        environment = adapter.child_environment(
            self.authority, home=Path("/var/empty"),
            config_root=adapter.CONFIG_ROOT, term="xterm-256color")
        with tempfile.TemporaryDirectory() as directory:
            systemd = FakeSystemd(
                Path(directory), unit, nonce, clear_on_stop=False)
            hooks = adapter._SystemdTestHooks(
                popen=systemd.popen, runner=systemd.runner,
                cgroup_root=systemd.cgroup_root,
                proc_root=systemd.proc_root, sleep=lambda _seconds: None)
            identifiers = [SimpleNamespace(hex=unit_hex), SimpleNamespace(hex=nonce)]
            with mock.patch.object(adapter.uuid, "uuid4", side_effect=identifiers), \
                    mock.patch.object(
                        adapter, "_trusted_command_digest", return_value="d" * 64):
                with self.assertRaisesRegex(
                    adapter.NativeClaudeAdapterError, "cleanup_failed"):
                    adapter._run_bounded(
                        adapter.status_command(executable), environment,
                        maximum=adapter.MAX_STATUS_BYTES, timeout=15,
                        command_prefix=command_prefix(),
                        _systemd_test_hooks=hooks)

    def test_popen_and_post_popen_setup_failures_still_stop_and_prove_absence(self) -> None:
        executable = Path(
            "/usr/local/libexec/secure-sandbox-harnesses/releases/"
            + "c" * 64 + "/harness")
        environment = adapter.child_environment(
            self.authority, home=Path("/var/empty"),
            config_root=adapter.CONFIG_ROOT, term="xterm-256color")

        for setup_failure in (False, True):
            calls: list[list[str]] = []

            def runner(command: list[str], **_kwargs: object):
                calls.append(list(command))
                if command[1] == "show":
                    return subprocess.CompletedProcess(command, 4, b"", b"")
                return subprocess.CompletedProcess(command, 0, b"", b"")

            process: FakeSystemdProcess | None = None
            if setup_failure:
                process = FakeSystemdProcess({}, {})
                popen = lambda *_args, **_kwargs: process
            else:
                def popen(*_args: object, **_kwargs: object):
                    raise OSError("injected")
            hooks = adapter._SystemdTestHooks(
                popen=popen, runner=runner, cgroup_root=Path("/nonexistent"),
                proc_root=Path("/nonexistent"), sleep=lambda _seconds: None)
            patches = [
                mock.patch.object(adapter, "_trusted_command_digest", return_value="d" * 64),
            ]
            if setup_failure:
                patches.append(mock.patch.object(
                    adapter, "_read_canonical_line", side_effect=RuntimeError("setup")))
            with patches[0]:
                context = patches[1] if len(patches) == 2 else mock.patch.object(
                    adapter, "COMMAND_HANDSHAKE_MAXIMUM", adapter.COMMAND_HANDSHAKE_MAXIMUM)
                with context:
                    with self.assertRaisesRegex(
                        adapter.NativeClaudeAdapterError, "service_failed"):
                        adapter._run_bounded(
                            adapter.status_command(executable), environment,
                            maximum=adapter.MAX_STATUS_BYTES, timeout=15,
                            command_prefix=command_prefix(),
                            _systemd_test_hooks=hooks)
            self.assertEqual(sum(command[1] == "stop" for command in calls), 1)
            self.assertEqual(sum(command[1] == "show" for command in calls), 2)
            if process is not None:
                self.assertEqual(process.request_bytes(), b"")

    def test_controller_liveness_eof_wins_and_vendor_uses_exact_privilege_drop(self) -> None:
        control_read, control_write = os.pipe()

        class VendorProcess:
            def __init__(self) -> None:
                output_read, self.output_write = os.pipe()
                self.stdout = os.fdopen(output_read, "rb", buffering=0)
                self.returncode: int | None = None
                self.terminated = False

            def poll(self):
                return self.returncode

            def terminate(self):
                self.terminated = True
                self.returncode = -15
                os.close(self.output_write)

            def kill(self):
                self.returncode = -9

            def wait(self, timeout=None):
                del timeout
                return self.returncode

        vendor = VendorProcess()
        launched: list[str] = []

        def popen(command: list[str], **_kwargs: object):
            launched.extend(command)
            return vendor

        request = {
            "command": ["/release/harness", "auth", "status", "--json"],
            "environment": self.environment, "maximum": 1024, "timeout": 5,
            "vendor_uid": 501, "vendor_gid": 502,
        }
        closer = threading.Thread(target=lambda: (time.sleep(0.03), os.close(control_write)))
        closer.start()
        try:
            with self.assertRaisesRegex(
                adapter.NativeClaudeAdapterError, "controller_liveness_lost"):
                adapter._execute_supervised_command(
                    request, input_fd=control_read, popen=popen)
        finally:
            closer.join()
            os.close(control_read)
        self.assertTrue(vendor.terminated)
        self.assertEqual(launched[:9], list(command_prefix()))
        self.assertEqual(launched[9:], request["command"])

    def test_supervisor_popen_failure_returns_rejection_without_losing_custody(self) -> None:
        unit = "secure-sandbox-native-claude-command-" + "a" * 32 + ".service"
        executable = Path(
            "/usr/local/libexec/secure-sandbox-harnesses/releases/"
            + "c" * 64 + "/harness")
        environment = adapter.child_environment(
            self.authority, home=Path("/var/empty"),
            config_root=adapter.CONFIG_ROOT, term="xterm-256color")
        request = {
            "schema": adapter.COMMAND_REQUEST_SCHEMA, "unit": unit,
            "nonce": "b" * 32, "command": adapter.status_command(executable),
            "environment": environment, "executable_sha256": "d" * 64,
            "vendor_uid": 501, "vendor_gid": 502,
            "maximum": adapter.MAX_STATUS_BYTES, "timeout": 15,
        }
        control_read, control_write = os.pipe()
        output_read, output_write = os.pipe()
        os.write(control_write, adapter.canonical_bytes(request))
        context = {
            "unit": unit, "pid": 42, "uid": 0, "gid": 0,
            "cgroup": "/system.slice/" + unit,
        }
        try:
            with mock.patch.object(
                adapter, "_trusted_command_digest", return_value="d" * 64):
                result = adapter.command_supervisor_main(
                    input_fd=control_read, output_fd=output_write,
                    _test_context=context,
                    _test_popen=mock.Mock(side_effect=OSError("injected")))
            self.assertEqual(result, 1)
        finally:
            os.close(control_write)
            os.close(control_read)
            os.close(output_write)
        with os.fdopen(output_read, "rb") as output:
            raw = output.read().splitlines()
        self.assertEqual(len(raw), 2)
        rejection = json.loads(raw[1])
        self.assertEqual(rejection["status"], "rejected")
        self.assertEqual(rejection["error"], "native_claude_command_rejected")
        self.assertNotIn("injected", json.dumps(rejection))


def subprocess_result(returncode: int, stdout: bytes):
    return type("Result", (), {"returncode": returncode, "stdout": stdout})()


if __name__ == "__main__":
    unittest.main()
