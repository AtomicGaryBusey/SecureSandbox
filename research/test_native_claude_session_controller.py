#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import tempfile
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


def request(authority: dict, *, resume: str | None = None) -> dict:
    body = {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "plan_sha256": "1" * 64, "authorization_sha256": "2" * 64,
        "session_id": authority["session_context_binding"]["session_id"],
        "runtime_authority": authority, "resume_session_id": resume,
    }
    return {"schema": controller.PREPARE_REQUEST_SCHEMA, **body,
            "request_sha256": controller.digest(body)}


class NativeClaudeSessionControllerTests(unittest.TestCase):
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
            with mock.patch.object(
                controller.native_lifecycle_fence, "admission_open",
                return_value=contextlib.nullcontext(),
            ):
                reply = controller.prepare_session(
                    request(authority), preparation_root=preparation,
                    catalog_path=catalog,
                    runtime_loader=lambda _generation: harness,
                    qualification_gate=qualification,
                    trusted_uid=uid, trusted_gid=gid)
                self.assertEqual(reply, controller.prepare_session(
                    request(authority), preparation_root=preparation,
                    catalog_path=catalog,
                    runtime_loader=lambda _generation: harness,
                    qualification_gate=qualification,
                    trusted_uid=uid, trusted_gid=gid))
            self.assertEqual(reply["schema"], controller.PREPARE_REPLY_SCHEMA)
            claimed = controller._claim_preparation(
                request(authority)["operation_id"], reply["prepare_sha256"],
                root=preparation, uid=uid, gid=gid)
            self.assertEqual(claimed["runtime_authority"], authority)
            with self.assertRaisesRegex(
                controller.NativeClaudeSessionError, "replay_denied"
            ):
                controller._claim_preparation(
                    request(authority)["operation_id"],
                    reply["prepare_sha256"], root=preparation,
                    uid=uid, gid=gid)

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
