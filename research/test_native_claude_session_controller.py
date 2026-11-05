#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from research import native_claude_session_controller as controller
from shared import (
    harness_runtime_binding,
    model_stack_runtime_binding,
    native_stack_runtime_binding,
    native_stack_session,
    native_vendor_stack,
    runtime_authority,
    session_context_binding,
)


ROOT = Path(__file__).resolve().parent.parent


def fixtures(
    effort: str = "high", *,
    session_id: str = "00000000-0000-4000-8000-000000000001",
) -> tuple[dict, dict, dict]:
    stack = json.loads(
        (ROOT / "config/native-vendor-stacks.example.json").read_text(
            encoding="ascii"))["stacks"][0]
    stack["harness"]["generation_id"] = "a" * 64
    stack["account_binding"]["account_subject_sha256"] = "b" * 64
    stack["account_binding"]["workspace_sha256"] = "c" * 64
    stack["model"]["settings"]["effort"] = effort
    harness = harness_runtime_binding.make_binding(
        harness_id="claude-code", generation_id="a" * 64,
        manifest_sha256="d" * 64,
        executable_sha256=hashlib.sha256(b"claude").hexdigest(),
        inventory_sha256="e" * 64, adapter_id="claude-native-oauth-v1",
        adapter_sha256="f" * 64)
    context = session_context_binding.make_binding(
        session_id=session_id,
        source_id=None, source_manifest_sha256=None,
        persona_sha256="1" * 64, tool_catalog_sha256="2" * 64,
        extension_set_sha256="3" * 64)
    authority = runtime_authority.make_binding(
        model_stack_binding=model_stack_runtime_binding.make_binding(
            model_stack_runtime_binding.NATIVE_MODE,
            native_stack_runtime_binding.make_binding(stack)),
        session_context_binding=context, harness_binding=harness)
    return stack, harness, authority


def write_catalog(root: Path, stack: dict) -> Path:
    path = root / "catalog.json"
    path.write_bytes(native_vendor_stack.canonical_bytes({
        "schema": native_vendor_stack.CATALOG_SCHEMA, "stacks": [stack]}))
    path.chmod(0o644)
    return path


def request(
    authority: dict, *, resume: str | None = None, now: int | None = None,
) -> dict:
    issued_at = int(time.time()) if now is None else now
    session_id = authority["session_context_binding"]["session_id"]
    lease = native_stack_session.make_session_lease(
        lease_profile_id="interactive", session_id=session_id,
        runtime_authority_sha256=authority["binding_sha256"],
        grant_id="33333333-3333-4333-8333-333333333333",
        grant_sha256="7" * 64, issued_at=issued_at,
        expires_at=issued_at + 3600,
    )
    body = {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "plan_sha256": "1" * 64, "authorization_sha256": "2" * 64,
        "session_id": session_id,
        "runtime_authority": authority, "resume_session_id": resume,
        "session_lease": lease,
    }
    return {"schema": controller.PREPARE_REQUEST_SCHEMA, **body,
            "request_sha256": controller.digest(body)}


class NativeClaudeSessionControllerTests(unittest.TestCase):
    def test_launch_contract_binds_vendor_scope_to_exact_owner(self) -> None:
        source = (
            ROOT / "research/native_claude_session_controller.py"
        ).read_text(encoding="utf-8")
        self.assertIn("create_controller_owner_scope", source)
        self.assertIn("owner_unit=owner_unit", source)
        self.assertIn("launcher_gid=service.pw_gid", source)
        self.assertIn("owner_scope_verifier", source)
        self.assertIn("owner_scope_releaser", source)
        self.assertLess(
            source.index("owner_scope_verifier("),
            source.index("signaler(child, signal.SIGCONT)"))
        self.assertEqual(
            source.count("_arm_vendor_parent_death_signal("), 2)
        first_parent_arm = source.index("_arm_vendor_parent_death_signal(")
        credential_drop = source.index("os.setuid(service.pw_uid)")
        second_parent_arm = source.index(
            "_arm_vendor_parent_death_signal(", first_parent_arm + 1)
        self.assertLess(first_parent_arm, credential_drop)
        self.assertLess(credential_drop, second_parent_arm)
        self.assertLess(
            second_parent_arm,
            source.index("os.kill(os.getpid(), signal.SIGSTOP)"))

    def test_effort_is_resolved_from_protected_catalog_not_request(self) -> None:
        for effort in ("low", "medium", "high"):
            with self.subTest(effort=effort), tempfile.TemporaryDirectory() as directory:
                stack, harness, authority = fixtures(effort)
                catalog = write_catalog(Path(directory), stack)
                observed = controller.admitted_runtime(
                    authority, catalog_path=catalog,
                    runtime_loader=lambda _generation: harness)
                self.assertEqual(observed[3], effort)
                self.assertEqual(
                    native_vendor_stack.sha256(stack["model"]["settings"]),
                    authority["model_stack_binding"]["authority"][
                        "model_settings_sha256"])

    def test_prepare_defaults_fail_closed_without_live_qualification(self) -> None:
        stack, harness, authority = fixtures()
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preparation = root / "preparations"
            preparation.mkdir(mode=0o700)
            catalog = write_catalog(root, stack)
            with self.assertRaisesRegex(
                controller.NativeClaudeSessionError,
                "live_isolation_qualification_required",
            ):
                controller.prepare_session(
                    request(authority), preparation_root=preparation,
                    catalog_path=catalog,
                    runtime_loader=lambda _generation: harness,
                    trusted_uid=uid, trusted_gid=gid)

    def test_prepare_is_exact_idempotent_and_claim_is_one_time(self) -> None:
        stack, harness, authority = fixtures("medium")
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preparation = root / "preparations"
            preparation.mkdir(mode=0o700)
            catalog = write_catalog(root, stack)
            qualification = lambda _authority: "9" * 64
            prepared_request = request(authority)
            with mock.patch.object(
                controller.native_lifecycle_fence, "admission_open",
                return_value=contextlib.nullcontext(),
            ):
                reply = controller.prepare_session(
                    prepared_request, preparation_root=preparation,
                    catalog_path=catalog,
                    runtime_loader=lambda _generation: harness,
                    qualification_gate=qualification,
                    trusted_uid=uid, trusted_gid=gid)
                self.assertEqual(reply, controller.prepare_session(
                    prepared_request, preparation_root=preparation,
                    catalog_path=catalog,
                    runtime_loader=lambda _generation: harness,
                    qualification_gate=qualification,
                    trusted_uid=uid, trusted_gid=gid))
            self.assertEqual(reply["schema"], controller.PREPARE_REPLY_SCHEMA)
            self.assertEqual(
                reply["session_lease_sha256"],
                prepared_request["session_lease"]["lease_sha256"],
            )
            self.assertEqual(
                reply["session_expires_at"],
                prepared_request["session_lease"]["expires_at"],
            )
            claimed = controller._claim_preparation(
                prepared_request["operation_id"], reply["prepare_sha256"],
                root=preparation, uid=uid, gid=gid)
            self.assertEqual(claimed["runtime_authority"], authority)
            with self.assertRaisesRegex(
                controller.NativeClaudeSessionError, "replay_denied"
            ):
                controller._claim_preparation(
                    prepared_request["operation_id"],
                    reply["prepare_sha256"], root=preparation,
                    uid=uid, gid=gid)

    def test_prepare_rejects_expired_or_substituted_session_lease(self) -> None:
        _stack, _harness, authority = fixtures()
        expired = request(authority, now=100)
        with self.assertRaisesRegex(
            controller.NativeClaudeSessionError, "prepare_lease_invalid"
        ):
            controller.validate_prepare_request(expired, now=3700)
        changed = request(authority, now=100)
        changed["session_lease"] = native_stack_session.make_session_lease(
            lease_profile_id="interactive",
            session_id="00000000-0000-4000-8000-000000000002",
            runtime_authority_sha256=authority["binding_sha256"],
            grant_id="33333333-3333-4333-8333-333333333333",
            grant_sha256="7" * 64, issued_at=100, expires_at=3700,
        )
        body = {key: changed[key] for key in changed
                if key not in {"schema", "request_sha256"}}
        changed["request_sha256"] = controller.digest(body)
        with self.assertRaisesRegex(
            controller.NativeClaudeSessionError, "prepare_lease_mismatch"
        ):
            controller.validate_prepare_request(changed, now=101)

    def test_scope_delay_cannot_extend_absolute_session_lease(self) -> None:
        monotonic_values = iter((50.0, 111.0))
        monotonic = lambda: next(monotonic_values)
        deadline = controller._absolute_lease_deadline(
            lease_expires_at=160, observed_at=100, monotonic=monotonic)
        self.assertEqual(deadline, 110.0)
        with self.assertRaisesRegex(
            controller.NativeClaudeSessionError, "run_lease_expired"
        ):
            controller._require_lease_open(deadline, monotonic=monotonic)

    def test_owner_revalidation_cannot_resume_after_lease_deadline(self) -> None:
        unit = (
            "secure-sandbox-native-owner-"
            "00000000000040008000000000000001.scope")
        custody = controller.lifecycle.ControllerOwnerCustody(
            unit=unit, watcher_pid=42, watcher_start_time_ticks=7,
            runtime_max_usec=5_000_000, cgroup=f"/test/{unit}")
        signaler = mock.Mock()
        with self.assertRaisesRegex(
            controller.NativeClaudeSessionError, "run_lease_expired"
        ):
            controller._resume_owned_session_child(
                99, custody, lease_deadline=10.0,
                trusted_uid=0, trusted_gid=0,
                systemctl=Path("/bin/systemctl"),
                cgroup_root=Path("/sys/fs/cgroup"),
                proc_root=Path("/proc"),
                owner_scope_verifier=lambda *_args, **_kwargs: {
                    "cgroup": custody.cgroup},
                monotonic=lambda: 10.0, signaler=signaler)
        signaler.assert_not_called()

    def test_full_output_buffer_cannot_block_past_lease_deadline(self) -> None:
        reader, writer = os.pipe()
        try:
            flags = fcntl.fcntl(writer, fcntl.F_GETFL)
            fcntl.fcntl(writer, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            while True:
                try:
                    os.write(writer, b"x" * 4096)
                except BlockingIOError:
                    break
            with self.assertRaisesRegex(
                controller.NativeClaudeSessionError, "run_lease_expired"
            ):
                controller._write_before_deadline(
                    writer, b"blocked", time.monotonic() + 0.02
                )
        finally:
            os.close(reader)
            os.close(writer)

    def test_reaped_session_child_pid_is_never_signalled(self) -> None:
        kill = mock.Mock()
        controller._terminate_direct_child(
            1234,
            waitpid=mock.Mock(side_effect=ChildProcessError),
            kill=kill,
        )
        kill.assert_not_called()

    def test_main_translates_owner_scope_failure_to_fixed_output(self) -> None:
        failure = controller.lifecycle.NativeCodexSessionError(
            "native_codex_owner_scope_unavailable")
        with mock.patch.object(
            controller, "launch_prepared", side_effect=failure
        ), mock.patch.object(controller.os, "write", return_value=1) as writer:
            self.assertEqual(controller.main([
                "launch", "11111111-1111-4111-8111-111111111111",
                "a" * 64,
            ]), 1)
        writer.assert_called_once_with(
            1, b"\r\nSecureSandbox Claude session failed closed.\r\n")

    def test_main_translates_systemd_timeout_to_fixed_output(self) -> None:
        with mock.patch.object(
            controller, "launch_prepared",
            side_effect=subprocess.TimeoutExpired("systemctl", 2),
        ), mock.patch.object(controller.os, "write", return_value=1) as writer:
            self.assertEqual(controller.main([
                "launch", "11111111-1111-4111-8111-111111111111",
                "a" * 64,
            ]), 1)
        writer.assert_called_once_with(
            1, b"\r\nSecureSandbox Claude session failed closed.\r\n")

    def test_resume_requires_exact_prior_terminal_authority(self) -> None:
        prior_session_id = "00000000-0000-4000-8000-000000000001"
        stack, harness, authority = fixtures(
            session_id="00000000-0000-4000-8000-000000000002")
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preparation = root / "preparations"
            preparation.mkdir(mode=0o700)
            journal = root / "journal"
            journal.mkdir(mode=0o700)
            catalog = write_catalog(root, stack)
            with self.assertRaisesRegex(
                controller.NativeClaudeSessionError,
                "resume_evidence_missing",
            ):
                controller.prepare_session(
                    request(authority, resume=prior_session_id),
                    preparation_root=preparation, journal_root=journal,
                    catalog_path=catalog,
                    runtime_loader=lambda _generation: harness,
                    qualification_gate=lambda _authority: "9" * 64,
                    trusted_uid=uid, trusted_gid=gid)

    def test_resume_rejects_reusing_current_session_identifier(self) -> None:
        _stack, _harness, authority = fixtures()
        with self.assertRaisesRegex(
            controller.NativeClaudeSessionError, "resume_binding_mismatch"
        ):
            controller.validate_prepare_request(request(
                authority,
                resume=authority["session_context_binding"]["session_id"]))

    def test_stop_and_status_return_only_absent_summary(self) -> None:
        _stack, _harness, authority = fixtures()
        uid, gid = os.geteuid(), os.getegid()
        session_id = authority["session_context_binding"]["session_id"]
        lease = native_stack_session.make_session_lease(
            lease_profile_id="interactive", session_id=session_id,
            runtime_authority_sha256=authority["binding_sha256"],
            grant_id="33333333-3333-4333-8333-333333333333",
            grant_sha256="7" * 64, issued_at=100, expires_at=3700,
        )
        unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            common = dict(
                transition_operation_id="11111111-1111-4111-8111-111111111111",
                authority=authority, scope_unit=unit,
                boot_id_sha256="4" * 64,
                executable_sha256=authority["harness_binding"][
                    "harness_executable_sha256"],
                session_lease=lease,
                lease_started_at=100, lease_expires_at=3700,
                root=root, trusted_uid=uid, trusted_gid=gid)
            controller.run_journal.append_event(
                phase="prepared", process_id=None,
                process_start_time_ticks=None, observed_at=100,
                exit_code=None, absence_evidence_sha256=None, **common)
            controller.run_journal.append_event(
                phase="active", process_id=1234,
                process_start_time_ticks=5678, observed_at=101,
                exit_code=None, absence_evidence_sha256=None, **common)
            stop_body = {
                "operation_id": "22222222-2222-4222-8222-222222222222",
                "plan_sha256": "5" * 64,
                "authorization_sha256": "6" * 64,
                "session_id": session_id,
                "runtime_authority_sha256": authority["binding_sha256"],
            }
            stop = {"schema": controller.STOP_REQUEST_SCHEMA, **stop_body,
                    "request_sha256": controller.digest(stop_body)}
            reply = controller.session_control(
                stop, status=False, journal_root=root,
                state_root=Path(directory) / "state",
                trusted_uid=uid, trusted_gid=gid,
                runner=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                    [], 0, b"", b""),
                egress_closer=lambda: "7" * 64,
                absence_prover=lambda **_kwargs: "8" * 64)
            self.assertEqual(set(reply), {
                "schema", "operation_id", "session_id", "state",
                "final_summary_sha256", "evidence_sha256"})
            self.assertEqual(reply["state"], "absent")


if __name__ == "__main__":
    unittest.main()
