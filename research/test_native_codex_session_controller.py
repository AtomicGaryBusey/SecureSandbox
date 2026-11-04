#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from research import native_codex_policy as policy
from research import native_codex_session_controller as controller
from shared import (
    harness_runtime_binding,
    model_stack_runtime_binding,
    native_stack_runtime_binding,
    runtime_authority,
    session_context_binding,
)


ROOT = Path(__file__).resolve().parent.parent


def authority() -> dict:
    stack = json.loads(
        (ROOT / "config/native-vendor-stacks.example.json").read_text(encoding="ascii")
    )["stacks"][1]
    stack["harness"]["generation_id"] = "a" * 64
    stack["account_binding"]["account_subject_sha256"] = "b" * 64
    stack["account_binding"]["workspace_sha256"] = "c" * 64
    harness = harness_runtime_binding.make_binding(
        harness_id="codex",
        generation_id="a" * 64,
        manifest_sha256="d" * 64,
        executable_sha256=hashlib.sha256(b"codex").hexdigest(),
        inventory_sha256="e" * 64,
        adapter_id="codex-app-server-oauth-v1",
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
    return runtime_authority.make_binding(
        model_stack_binding=model_stack_runtime_binding.make_binding(
            model_stack_runtime_binding.NATIVE_MODE,
            native_stack_runtime_binding.make_binding(stack),
        ),
        session_context_binding=context,
        harness_binding=harness,
    )


class NativeCodexSessionControllerTests(unittest.TestCase):
    def test_fresh_layout_projects_immutable_policy_and_empty_capability_tree(self) -> None:
        descriptor = policy.make_launch_descriptor(authority())
        uid, gid = os.geteuid(), os.getegid()
        if uid == 0 or gid == 0:
            self.skipTest("test requires a non-root launcher-equivalent identity")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir(mode=0o750)
            state.chmod(0o750)
            baseline = root / "config.toml"
            baseline.write_bytes((ROOT / "research/native-codex-config.toml").read_bytes())
            baseline.chmod(0o640)
            session = controller.create_session_layout(
                descriptor,
                state_root=state,
                baseline_config=baseline,
                trusted_uid=uid,
                launcher_uid=uid,
                launcher_gid=gid,
                installation_id_factory=lambda: "11111111-1111-4111-8111-111111111111",
            )
            self.assertEqual(
                sorted(item.name for item in session.iterdir()),
                ["cache", "codex-home", "home", "tmp"],
            )
            codex_home = session / "codex-home"
            self.assertEqual(
                sorted(item.name for item in codex_home.iterdir()),
                [".tmp", "config.toml", "installation_id", "logs", "skills", "state", "tmp"],
            )
            self.assertEqual((codex_home / "config.toml").read_bytes(), baseline.read_bytes())
            self.assertEqual(list((codex_home / "skills").iterdir()), [])
            self.assertEqual(stat.S_IMODE((codex_home / "skills").stat().st_mode), 0o750)
            for item in ("state", "logs", "tmp", ".tmp"):
                self.assertEqual(stat.S_IMODE((codex_home / item).stat().st_mode), 0o700)

    def test_permit_is_root_claimed_pathless_read_only_and_contains_only_digest(self) -> None:
        descriptor = policy.make_launch_descriptor(authority())
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            now = int(time.time())
            token = b"not-a-real-token-but-never-persist-this-value"
            permit_fd = controller.claim_projection_permit(
                descriptor,
                projection_id="12345678-1234-4234-8234-123456789abc",
                access_token_sha256=hashlib.sha256(token).hexdigest(),
                issued_at_unix=now,
                expires_at_unix=now + 60,
                launcher_uid=uid,
                launcher_gid=gid,
                permit_root=root,
                trusted_uid=uid,
                trusted_gid=gid,
            )
            try:
                information = os.fstat(permit_fd)
                self.assertEqual(information.st_nlink, 0)
                self.assertEqual(stat.S_IMODE(information.st_mode), 0o400)
                self.assertEqual(os.lseek(permit_fd, 0, os.SEEK_CUR), 0)
                encoded = os.read(permit_fd, 4096)
                self.assertNotIn(token, encoded)
                self.assertIn(hashlib.sha256(token).hexdigest().encode(), encoded)
                self.assertEqual(list(root.iterdir()), [])
            finally:
                os.close(permit_fd)

    def test_contract_has_no_token_json_argv_or_environment_path(self) -> None:
        source = (ROOT / "research/native_codex_session_controller.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("This process never reads", source)
        self.assertNotIn("access_token:", source)
        self.assertNotIn("ACCESS_TOKEN=", source)
        self.assertNotIn("sys.stdin", source)
        self.assertIn("os.dup2(input_fd, 0)", source)
        self.assertIn("PROJECTION_PERMIT_FD", source)
        self.assertIn("StartTransientUnit", source)
        self.assertIn('"BindsTo", "as"', source)
        self.assertIn('"After", "as"', source)
        self.assertIn('"PartOf", "as"', source)
        self.assertIn("os.WUNTRACED", source)
        self.assertIn("SIGSTOP before any vendor exec", source)
        self.assertIn("scope/UID readback", source)

    def test_scope_readback_requires_dependencies_cgroup_and_exact_uid(self) -> None:
        unit = "secure-sandbox-native-run-00000000000040008000000000000001.scope"
        uid = os.geteuid()
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root = Path(directory)
            cgroup = cgroup_root / "test" / unit
            cgroup.mkdir(parents=True)
            (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="ascii")
            proc_root = Path(directory) / "proc"
            proc = proc_root / str(os.getpid())
            proc.mkdir(parents=True)
            (proc / "status").write_text(
                f"Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
                encoding="ascii",
            )

            def runner(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 0, (
                    "ActiveState=active\n"
                    "BindsTo=native-harness-supervisor.service\n"
                    "After=native-harness-supervisor.service\n"
                    "PartOf=native-harness-supervisor.service\n"
                    f"ControlGroup=/test/{unit}\n"
                ), "")

            observed = controller.verify_transient_scope(
                unit, launcher_uid=uid, cgroup_root=cgroup_root,
                proc_root=proc_root, runner=runner, deadline_seconds=0.1)
            self.assertEqual(observed["process_count"], 1)

            def missing_edge(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 0, (
                    "ActiveState=active\n"
                    "BindsTo=native-harness-supervisor.service\n"
                    "After=native-harness-supervisor.service\n"
                    "PartOf=\n"
                    f"ControlGroup=/test/{unit}\n"
                ), "")

            with self.assertRaisesRegex(
                controller.NativeCodexSessionError, "scope_dependency_invalid"):
                controller.verify_transient_scope(
                    unit, launcher_uid=uid, cgroup_root=cgroup_root,
                    proc_root=proc_root, runner=missing_edge,
                    deadline_seconds=0.01)

    def test_transient_scope_creation_binds_exact_stopped_pid_and_edges(self) -> None:
        unit = "secure-sandbox-native-run-00000000000040008000000000000001.scope"
        observed = []

        def runner(command, **_kwargs):
            observed.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        controller.start_transient_scope(
            unit, 1234, busctl=Path("/usr/bin/busctl"), runner=runner)
        command = observed[0]
        self.assertIn("StartTransientUnit", command)
        self.assertIn("PIDs", command)
        self.assertIn("1234", command)
        for edge in ("BindsTo", "After", "PartOf"):
            index = command.index(edge)
            self.assertEqual(command[index + 1:index + 4], [
                "as", "1", "native-harness-supervisor.service"
            ])
        self.assertEqual(command[-1], "0")


if __name__ == "__main__":
    unittest.main()
