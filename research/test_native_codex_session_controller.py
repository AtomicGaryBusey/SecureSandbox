#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import inspect
import json
import os
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from research import native_codex_policy as policy
from research import native_codex_session_controller as controller
from shared import (
    harness_runtime_binding,
    model_stack_runtime_binding,
    native_stack_session,
    native_stack_runtime_binding,
    native_vendor_stack,
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


def session_lease(runtime: dict, *, issued_at: int = 1_800_000_000,
                  profile: str = "interactive") -> dict:
    return native_stack_session.make_session_lease(
        lease_profile_id=profile,
        session_id=runtime["session_context_binding"]["session_id"],
        runtime_authority_sha256=runtime["binding_sha256"],
        grant_id="44444444-4444-4444-8444-444444444444",
        grant_sha256="4" * 64,
        issued_at=issued_at,
        expires_at=(issued_at
                    + native_stack_session.LEASE_DURATIONS[profile]),
    )


class NativeCodexSessionControllerTests(unittest.TestCase):
    def test_prepare_rejects_every_nested_session_lease_mutation(self) -> None:
        runtime = authority()
        lease = session_lease(runtime)
        body = {
            "operation_id": "11111111-1111-4111-8111-111111111111",
            "plan_sha256": "1" * 64,
            "authorization_sha256": "2" * 64,
            "session_id": runtime["session_context_binding"]["session_id"],
            "runtime_authority": runtime,
            "projection_id": "22222222-2222-4222-8222-222222222222",
            "access_token_sha256": "3" * 64,
            "expires_at": 1_800_000_060,
            "session_lease": lease,
        }
        accepted = {
            "schema": controller.PREPARE_REQUEST_SCHEMA, **body,
            "request_sha256": controller._digest(body),
        }
        self.assertEqual(
            controller.validate_prepare_request(
                accepted, now=1_800_000_001)["session_lease"],
            lease)
        mutations = {
            "schema": "unsafe",
            "lease_profile_id": "unsafe",
            "session_id": "33333333-3333-4333-8333-333333333333",
            "runtime_authority_sha256": "8" * 64,
            "grant_id": "33333333-3333-4333-8333-333333333333",
            "grant_sha256": "8" * 64,
            "issued_at": lease["issued_at"] + 1,
            "expires_at": lease["expires_at"] + 1,
            "lease_sha256": "8" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed_lease = {**lease, field: replacement}
                changed_body = {**body, "session_lease": changed_lease}
                changed = {
                    "schema": controller.PREPARE_REQUEST_SCHEMA,
                    **changed_body,
                    "request_sha256": controller._digest(changed_body),
                }
                with self.assertRaises(controller.NativeCodexSessionError):
                    controller.validate_prepare_request(
                        changed, now=1_800_000_001)

    def test_ui_claim_is_closed_exact_and_socket_is_outside_codex_home(self) -> None:
        runtime = authority()
        descriptor = policy.make_launch_descriptor(runtime)
        lease = session_lease(runtime)
        claim = controller.make_ui_attach_claim(
            session_id=descriptor["session_id"],
            runtime_authority_sha256=descriptor["runtime_authority_sha256"],
            harness_generation_id=descriptor["harness_generation_id"],
            harness_executable_sha256=descriptor[
                "harness_executable_sha256"],
            session_lease_sha256=lease["lease_sha256"],
            session_expires_at=lease["expires_at"])
        self.assertEqual(
            controller.validate_ui_attach_claim(
                claim, descriptor=descriptor, session_lease=lease),
            claim)
        for mutation in (
                {**claim, "future": "unsafe"},
                {**claim, "runtime_authority_sha256": "9" * 64},
                {**claim, "session_lease_sha256": "9" * 64},
                {**claim, "session_expires_at": lease["expires_at"] + 1}):
            with self.assertRaises(controller.NativeCodexSessionError):
                controller.validate_ui_attach_claim(
                    mutation, descriptor=descriptor, session_lease=lease)

        with mock.patch.object(controller, "relay_ui", return_value=0) as relay:
            self.assertEqual(controller.main([
                "ui", descriptor["session_id"],
                descriptor["runtime_authority_sha256"],
                descriptor["harness_generation_id"],
                descriptor["harness_executable_sha256"],
                lease["lease_sha256"], str(lease["expires_at"]),
            ]), 0)
            relay.assert_called_once()

        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            try:
                listener = controller._create_ui_listener(
                    root, session_id=descriptor["session_id"],
                    trusted_uid=uid, trusted_gid=gid)
            except PermissionError:
                self.skipTest("sandbox denies AF_UNIX pathname creation")
            path = root / f"{descriptor['session_id']}.sock"
            try:
                self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
                self.assertNotIn("codex-home", str(path))
                # An exact root-controlled socket left by a crash is replaced
                # while the launch lock is held.
                listener.close()
                listener = controller._create_ui_listener(
                    root, session_id=descriptor["session_id"],
                    trusted_uid=uid, trusted_gid=gid)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                accepted = None
                try:
                    client.connect(str(path))
                    client.sendall(controller._canonical(claim))
                    accepted = controller._accept_ui(
                        listener, descriptor=descriptor,
                        session_lease=lease,
                        trusted_uid=uid, trusted_gid=gid)
                    self.assertFalse(path.exists())
                    replay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        with self.assertRaises(OSError):
                            replay.connect(str(path))
                    finally:
                        replay.close()
                finally:
                    if accepted is not None:
                        accepted.close()
                    client.close()
            finally:
                listener.close()
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

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
            baseline.chmod(0o444)
            session = controller.create_session_layout(
                descriptor,
                state_root=state,
                baseline_config=baseline,
                baseline_gid=gid,
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
        launch_source = inspect.getsource(controller.launch_prepared)
        self.assertNotIn(".read(", launch_source)
        self.assertNotIn("json", launch_source)
        self.assertIn("policy.PROJECTION_FRAME_FD", source)
        self.assertIn("PROJECTION_PERMIT_FD", source)
        self.assertIn("TOKEN_RECEIPT_FD", source)
        self.assertIn("NativeCodexRuntimeDriver", source)
        self.assertIn("native_codex_runtime_live_qualification_unavailable", source)
        self.assertIn("StartTransientUnit", source)
        self.assertIn('"BindsTo", "as"', source)
        self.assertIn('"After", "as"', source)
        self.assertIn('"PartOf", "as"', source)
        self.assertIn("os.WUNTRACED", source)
        self.assertIn("SIGSTOP before any vendor exec", source)
        self.assertIn("scope/UID readback", source)

    def test_prepare_and_stream_claim_are_exact_one_time_and_content_free(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        runtime = authority()
        stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(
                encoding="ascii"))["stacks"][1]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64
        catalog = {"schema": native_vendor_stack.CATALOG_SCHEMA,
                   "stacks": [stack]}
        harness = runtime["harness_binding"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preparations = root / "preparations"
            preparations.mkdir(mode=0o700)
            journal = root / "journal"
            journal.mkdir(mode=0o700)
            boot_id = root / "boot_id"
            boot_id.write_text(
                "33333333-3333-4333-8333-333333333333\n", encoding="ascii")
            catalog_path = root / "catalog.json"
            catalog_path.write_bytes(native_vendor_stack.canonical_bytes(catalog))
            catalog_path.chmod(0o644)
            fields = {
                "operation_id": "11111111-1111-4111-8111-111111111111",
                "plan_sha256": "1" * 64,
                "authorization_sha256": "2" * 64,
                "session_id": runtime["session_context_binding"]["session_id"],
                "runtime_authority": runtime,
                "projection_id": "22222222-2222-4222-8222-222222222222",
                "access_token_sha256": hashlib.sha256(
                    b"never-persist-this-token").hexdigest(),
                "expires_at": 1_800_000_060,
                "session_lease": session_lease(runtime),
            }
            request = {
                "schema": controller.PREPARE_REQUEST_SCHEMA, **fields,
                "request_sha256": controller._digest(fields),
            }
            with mock.patch.object(
                controller.native_lifecycle_fence, "admission_open",
                return_value=contextlib.nullcontext(),
            ):
                reply = controller.prepare_session(
                    request, preparation_root=preparations,
                    catalog_path=catalog_path,
                    runtime_loader=lambda _generation: harness,
                    trusted_uid=uid, trusted_gid=gid, now=1_800_000_000)
                repeated = controller.prepare_session(
                    request, preparation_root=preparations,
                    catalog_path=catalog_path,
                    runtime_loader=lambda _generation: harness,
                    trusted_uid=uid, trusted_gid=gid, now=1_800_000_000)
            self.assertEqual(reply, repeated)
            self.assertEqual(reply["schema"], controller.PREPARE_REPLY_SCHEMA)
            self.assertEqual(
                reply["session_lease_sha256"],
                fields["session_lease"]["lease_sha256"])
            self.assertEqual(
                reply["session_expires_at"],
                fields["session_lease"]["expires_at"])
            raw = (preparations / f"{fields['operation_id']}.json").read_bytes()
            self.assertNotIn(b"never-persist-this-token", raw)
            read_fd, write_fd = os.pipe()
            try:
                with mock.patch.object(
                    controller.native_lifecycle_fence, "admission_open",
                    return_value=contextlib.nullcontext(),
                ), mock.patch.object(
                    controller, "_launch_and_wait_admitted", return_value=0,
                ) as launch:
                    result = controller.launch_prepared(
                        fields["operation_id"], reply["prepare_sha256"],
                        input_fd=read_fd, preparation_root=preparations,
                        catalog_path=catalog_path,
                        runtime_loader=lambda _generation: harness,
                        journal_root=journal, boot_id_path=boot_id,
                        egress_closer=lambda: "8" * 64,
                        absence_prover=lambda **_options: "9" * 64,
                        trusted_uid=uid, trusted_gid=gid, now=1_800_000_001)
                    self.assertEqual(result, 0)
                    self.assertEqual(launch.call_args.kwargs["input_fd"], read_fd)
                    self.assertEqual(
                        launch.call_args.kwargs["session_lease"],
                        fields["session_lease"])
                    with self.assertRaisesRegex(
                        controller.NativeCodexSessionError, "replay_denied"
                    ):
                        controller.launch_prepared(
                            fields["operation_id"], reply["prepare_sha256"],
                            input_fd=read_fd, preparation_root=preparations,
                            catalog_path=catalog_path,
                            runtime_loader=lambda _generation: harness,
                            journal_root=journal, boot_id_path=boot_id,
                            egress_closer=lambda: "8" * 64,
                            absence_prover=lambda **_options: "9" * 64,
                            trusted_uid=uid, trusted_gid=gid,
                            now=1_800_000_001)
            finally:
                os.close(read_fd)
                os.close(write_fd)
            self.assertTrue((preparations /
                f"{fields['operation_id']}.consumed.json").exists())
            latest = controller.run_journal.latest(
                fields["session_id"], root=journal, trusted_uid=uid,
                trusted_gid=gid)
            self.assertEqual(latest["phase"], "terminal")
            self.assertEqual(
                latest["lease_sha256"],
                fields["session_lease"]["lease_sha256"])

    def test_stop_and_status_require_exact_authority_and_prove_absence(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        runtime = authority()
        lease = session_lease(runtime, issued_at=100)
        session_id = runtime["session_context_binding"]["session_id"]
        unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            common = dict(
                transition_operation_id="11111111-1111-4111-8111-111111111111",
                authority=runtime, scope_unit=unit, boot_id_sha256="1" * 64,
                executable_sha256=runtime["harness_binding"]["harness_executable_sha256"],
                session_lease=lease,
                lease_started_at=lease["issued_at"],
                lease_expires_at=lease["expires_at"], root=root,
                trusted_uid=uid, trusted_gid=gid)
            controller.run_journal.append_event(
                phase="prepared", process_id=None,
                process_start_time_ticks=None, observed_at=100,
                exit_code=None, absence_evidence_sha256=None, **common)
            controller.run_journal.append_event(
                phase="active", process_id=1234,
                process_start_time_ticks=5678, observed_at=101,
                exit_code=None, absence_evidence_sha256=None, **common)
            stop_fields = {
                "operation_id": "22222222-2222-4222-8222-222222222222",
                "plan_sha256": "2" * 64, "authorization_sha256": "3" * 64,
                "session_id": session_id,
                "runtime_authority_sha256": runtime["binding_sha256"],
            }
            stop = {"schema": controller.STOP_REQUEST_SCHEMA, **stop_fields,
                    "request_sha256": controller._digest(stop_fields)}
            reply = controller.session_control(
                stop, status=False, journal_root=root,
                trusted_uid=uid, trusted_gid=gid,
                runner=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                    [], 0, b"", b""),
                egress_closer=lambda: "8" * 64,
                absence_prover=lambda **_options: "9" * 64)
            self.assertEqual(reply["schema"], controller.STOP_REPLY_SCHEMA)
            self.assertEqual(reply["state"], "absent")
            self.assertEqual(controller.run_journal.latest(
                session_id, root=root, trusted_uid=uid,
                trusted_gid=gid)["phase"], "terminal")
            status_fields = {
                "operation_id": "33333333-3333-4333-8333-333333333333",
                "session_id": session_id,
                "runtime_authority_sha256": runtime["binding_sha256"],
            }
            status = {"schema": controller.STATUS_REQUEST_SCHEMA, **status_fields,
                      "request_sha256": controller._digest(status_fields)}
            observed = controller.session_control(
                status, status=True, journal_root=root,
                trusted_uid=uid, trusted_gid=gid,
                egress_observer=lambda: "8" * 64,
                absence_prover=lambda **_options: "9" * 64)
            self.assertEqual(observed["schema"], controller.STATUS_REPLY_SCHEMA)
            self.assertEqual(observed["final_summary_sha256"],
                             reply["final_summary_sha256"])

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
            unit, 1234, runtime_max_usec=3_600_000_000,
            busctl=Path("/usr/bin/busctl"), runner=runner)
        command = observed[0]
        self.assertIn("StartTransientUnit", command)
        self.assertIn("PIDs", command)
        self.assertIn("1234", command)
        for edge in ("BindsTo", "After", "PartOf"):
            index = command.index(edge)
            self.assertEqual(command[index + 1:index + 4], [
                "as", "1", "native-harness-supervisor.service"
            ])
        runtime_index = command.index("RuntimeMaxUSec")
        self.assertEqual(
            command[runtime_index + 1:runtime_index + 3],
            ["t", "3600000000"])
        self.assertEqual(command[-1], "0")


if __name__ == "__main__":
    unittest.main()
