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
    native_codex_projection,
    native_stack_session,
    native_stack_runtime_binding,
    native_vendor_stack,
    runtime_authority,
    session_context_binding,
)


ROOT = Path(__file__).resolve().parent.parent
READY_SCOPE_UNIT = (
    "secure-sandbox-native-run-00000000000040008000000000000001.scope")
READY_SCOPE_CGROUP = f"/test/{READY_SCOPE_UNIT}"
READY_SCOPE_UID = 12345
READY_SCOPE_MEMBERS = {4242: 19, 4343: 23}
OWNER_SCOPE_UNIT = (
    "secure-sandbox-native-owner-00000000000040008000000000000002.scope")


def ready_scope_fixture(root: Path) -> tuple[Path, Path, Path]:
    cgroup_root = root / "cgroup"
    scope = cgroup_root / "test" / READY_SCOPE_UNIT
    scope.mkdir(parents=True)
    (scope / "cgroup.freeze").write_text("0\n", encoding="ascii")
    (scope / "cgroup.events").write_text(
        "populated 1\nfrozen 0\n", encoding="ascii")
    (scope / "cgroup.procs").write_text(
        "".join(f"{pid}\n" for pid in READY_SCOPE_MEMBERS),
        encoding="ascii")
    proc_root = root / "proc"
    for pid, start in READY_SCOPE_MEMBERS.items():
        process = proc_root / str(pid)
        process.mkdir(parents=True)
        (process / "status").write_text(
            "Name:\tscope-member\n"
            f"Uid:\t{READY_SCOPE_UID}\t{READY_SCOPE_UID}\t"
            f"{READY_SCOPE_UID}\t{READY_SCOPE_UID}\n",
            encoding="ascii")
        fields = ["S", *("0" for _ in range(18)), str(start)]
        (process / "stat").write_text(
            f"{pid} (scope member) {' '.join(fields)}\n",
            encoding="ascii")
    return cgroup_root, scope, proc_root


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


def projection_prepare_fields(
    runtime: dict, *, observed_at: int = 1_800_000_000,
) -> tuple[dict, dict]:
    descriptor = native_codex_projection.make_launch_descriptor(runtime)
    subject = native_codex_projection.make_qualification_subject(
        descriptor, policy_manifest_sha256="5" * 64,
        probe_executable_sha256="6" * 64,
        protocol_version="0.166.0",
    )
    reply = native_codex_projection.make_projection_status_reply(
        operation_id="11111111-1111-4111-8111-111111111111",
        research_release_id="7" * 64, boot_id_sha256="8" * 64,
        runtime_authority_sha256=descriptor["runtime_authority_sha256"],
        launch_descriptor_sha256=descriptor["descriptor_sha256"],
        qualification_subject=subject,
        qualification_evidence_sha256="9" * 64,
        observed_at=observed_at, expires_at=observed_at + 120,
    )
    stack_sha256 = runtime["model_stack_binding"]["authority"][
        "stack_sha256"
    ]
    projection_authority = native_codex_projection.make_projection_authority(
        consumer_executable_path=(
            "/usr/local/libexec/secure-sandbox-host/releases/"
            + "a" * 64 + "/native_projection_consumer"
        ),
        consumer_executable_sha256="b" * 64,
        host_release_id="a" * 64,
        operation_id="11111111-1111-4111-8111-111111111111",
        request_sha256="c" * 64, stack_sha256=stack_sha256,
        authority=runtime, observation=reply, now=observed_at,
    )
    observation = {
        key: value for key, value in reply.items()
        if key not in {"schema", "operation_id", "evidence_sha256"}
    }
    return {
        "stack_sha256": stack_sha256,
        "operator_request_sha256": "c" * 64,
        "projection_ticket_issued_at": observed_at,
        "projection_ticket_expires_at": observed_at + 120,
        "projection_ticket_sha256": "d" * 64,
        "projection_authority": projection_authority,
    }, observation


class NativeCodexSessionControllerTests(unittest.TestCase):
    def test_ready_quiescence_freezes_every_scope_member_and_resumes_only_on_success(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root, scope, proc_root = ready_scope_fixture(
                Path(directory))
            writes: list[tuple[int, bool]] = []
            snapshots: list[tuple[tuple[int, int], ...]] = []

            def freeze_writer(descriptor: int, frozen: bool) -> None:
                writes.append((descriptor, frozen))
                controller._write_cgroup_freeze(descriptor, frozen)
                (scope / "cgroup.events").write_text(
                    f"populated 1\nfrozen {int(frozen)}\n",
                    encoding="ascii")

            original_snapshot = controller._scope_member_snapshot

            def observed_snapshot(*args, **kwargs):
                value = original_snapshot(*args, **kwargs)
                snapshots.append(value)
                return value

            # An extra same-service-UID process outside the launcher's process
            # group is still covered because custody is cgroup-wide.
            with mock.patch.object(
                    controller.os, "getpgid",
                    side_effect=AssertionError("process groups are irrelevant")), \
                    mock.patch.object(
                        controller, "_scope_member_snapshot",
                        side_effect=observed_snapshot):
                abandoned = controller._quiesce_scope_for_ready(
                    4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                    scope_unit=READY_SCOPE_UNIT,
                    launcher_uid=READY_SCOPE_UID,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    trusted_uid=os.geteuid(), freeze_writer=freeze_writer)
            expected = tuple(sorted(READY_SCOPE_MEMBERS.items()))
            self.assertEqual(snapshots, [expected, expected, expected])
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")
            held = writes[-1][0]
            abandoned.abandon()
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")
            with self.assertRaises(OSError):
                os.fstat(held)

            (scope / "cgroup.freeze").write_text("0\n", encoding="ascii")
            (scope / "cgroup.events").write_text(
                "populated 1\nfrozen 0\n", encoding="ascii")
            admitted = controller._quiesce_scope_for_ready(
                4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                scope_unit=READY_SCOPE_UNIT,
                launcher_uid=READY_SCOPE_UID,
                cgroup_root=cgroup_root, proc_root=proc_root,
                trusted_uid=os.geteuid(), freeze_writer=freeze_writer)
            admitted.resume(time.monotonic() + 5.0)
            self.assertEqual(
                [frozen for _descriptor, frozen in writes],
                [True, True, False])
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "0\n")
            self.assertEqual(
                (scope / "cgroup.events").read_text(encoding="ascii"),
                "populated 1\nfrozen 0\n")

    def test_ready_quiescence_incomplete_or_malformed_freeze_stays_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root, scope, proc_root = ready_scope_fixture(
                Path(directory))
            held: list[int] = []

            def incomplete_writer(descriptor: int, frozen: bool) -> None:
                held.append(descriptor)
                controller._write_cgroup_freeze(descriptor, frozen)

            ticks = iter((0.0, 1.0))
            with self.assertRaisesRegex(
                    controller.NativeCodexSessionError,
                    "native_codex_ready_cgroup_freeze_incomplete"):
                controller._quiesce_scope_for_ready(
                    4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                    scope_unit=READY_SCOPE_UNIT,
                    launcher_uid=READY_SCOPE_UID,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    trusted_uid=os.geteuid(), timeout_seconds=0.1,
                    freeze_writer=incomplete_writer,
                    monotonic=lambda: next(ticks),
                    sleeper=lambda _seconds: None)
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")
            with self.assertRaises(OSError):
                os.fstat(held[-1])

            (scope / "cgroup.freeze").write_text("0\n", encoding="ascii")
            (scope / "cgroup.events").write_text(
                "populated 1\nfrozen 0\n", encoding="ascii")

            def malformed_writer(descriptor: int, frozen: bool) -> None:
                controller._write_cgroup_freeze(descriptor, frozen)
                (scope / "cgroup.events").write_text(
                    "frozen 1\npopulated 1\n", encoding="ascii")

            with self.assertRaisesRegex(
                    controller.NativeCodexSessionError,
                    "native_codex_ready_cgroup_events_invalid"):
                controller._quiesce_scope_for_ready(
                    4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                    scope_unit=READY_SCOPE_UNIT,
                    launcher_uid=READY_SCOPE_UID,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    trusted_uid=os.geteuid(),
                    freeze_writer=malformed_writer)
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")

    def test_ready_quiescence_rejects_unstable_frozen_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root, scope, proc_root = ready_scope_fixture(
                Path(directory))

            def freeze_writer(descriptor: int, frozen: bool) -> None:
                controller._write_cgroup_freeze(descriptor, frozen)
                (scope / "cgroup.events").write_text(
                    f"populated 1\nfrozen {int(frozen)}\n",
                    encoding="ascii")

            complete = tuple(sorted(READY_SCOPE_MEMBERS.items()))
            changed = ((4242, 19),)
            with mock.patch.object(
                    controller, "_scope_member_snapshot",
                    side_effect=(complete, complete, changed)), \
                    self.assertRaisesRegex(
                        controller.NativeCodexSessionError,
                        "native_codex_ready_cgroup_members_changed"):
                controller._quiesce_scope_for_ready(
                    4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                    scope_unit=READY_SCOPE_UNIT,
                    launcher_uid=READY_SCOPE_UID,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    trusted_uid=os.geteuid(), freeze_writer=freeze_writer)
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")

    def test_ready_quiescence_refreezes_after_thaw_readback_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root, scope, proc_root = ready_scope_fixture(
                Path(directory))
            writes: list[tuple[int, bool]] = []

            def hostile_writer(descriptor: int, frozen: bool) -> None:
                writes.append((descriptor, frozen))
                controller._write_cgroup_freeze(descriptor, frozen)
                if not frozen:
                    (scope / "cgroup.events").write_text(
                        "frozen 0\npopulated 1\n", encoding="ascii")
                else:
                    (scope / "cgroup.events").write_text(
                        "populated 1\nfrozen 1\n", encoding="ascii")

            quiescence = controller._quiesce_scope_for_ready(
                4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                scope_unit=READY_SCOPE_UNIT,
                launcher_uid=READY_SCOPE_UID,
                cgroup_root=cgroup_root, proc_root=proc_root,
                trusted_uid=os.geteuid(), freeze_writer=hostile_writer)
            held = writes[-1][0]
            with self.assertRaisesRegex(
                    controller.NativeCodexSessionError,
                    "native_codex_ready_cgroup_events_invalid"):
                quiescence.resume(time.monotonic() + 5.0)
            self.assertEqual(
                [frozen for _descriptor, frozen in writes],
                [True, False, True])
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")
            self.assertEqual(
                (scope / "cgroup.events").read_text(encoding="ascii"),
                "populated 1\nfrozen 1\n")
            with self.assertRaises(OSError):
                os.fstat(held)

    def test_ready_quiescence_never_thaws_after_admission_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root, scope, proc_root = ready_scope_fixture(
                Path(directory))
            writes: list[bool] = []
            clock = [100.0]

            def freeze_writer(descriptor: int, frozen: bool) -> None:
                writes.append(frozen)
                controller._write_cgroup_freeze(descriptor, frozen)
                (scope / "cgroup.events").write_text(
                    f"populated 1\nfrozen {int(frozen)}\n",
                    encoding="ascii")

            quiescence = controller._quiesce_scope_for_ready(
                4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                scope_unit=READY_SCOPE_UNIT,
                launcher_uid=READY_SCOPE_UID,
                cgroup_root=cgroup_root, proc_root=proc_root,
                trusted_uid=os.geteuid(), freeze_writer=freeze_writer,
                monotonic=lambda: clock[0])
            original_snapshot = controller._scope_member_snapshot

            def snapshot_crossing_deadline(*args, **kwargs):
                result = original_snapshot(*args, **kwargs)
                clock[0] = 110.0
                return result

            with mock.patch.object(
                    controller, "_scope_member_snapshot",
                    side_effect=snapshot_crossing_deadline), \
                    self.assertRaisesRegex(
                        controller.NativeCodexSessionError,
                        "native_codex_ready_admission_expired"):
                quiescence.resume(110.0)
            self.assertEqual(writes, [True])
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")
            self.assertEqual(
                (scope / "cgroup.events").read_text(encoding="ascii"),
                "populated 1\nfrozen 1\n")

    def test_ready_quiescence_expired_entry_closes_held_scope(self) -> None:
        for admission_deadline in (100.0, float("nan"), True):
            with self.subTest(admission_deadline=admission_deadline), \
                    tempfile.TemporaryDirectory() as directory:
                cgroup_root, scope, proc_root = ready_scope_fixture(
                    Path(directory))
                writes: list[tuple[int, bool]] = []

                def freeze_writer(descriptor: int, frozen: bool) -> None:
                    writes.append((descriptor, frozen))
                    controller._write_cgroup_freeze(descriptor, frozen)
                    (scope / "cgroup.events").write_text(
                        f"populated 1\nfrozen {int(frozen)}\n",
                        encoding="ascii")

                quiescence = controller._quiesce_scope_for_ready(
                    4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                    scope_unit=READY_SCOPE_UNIT,
                    launcher_uid=READY_SCOPE_UID,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    trusted_uid=os.geteuid(), freeze_writer=freeze_writer,
                    monotonic=lambda: 100.0)
                held = writes[-1][0]
                with self.assertRaisesRegex(
                        controller.NativeCodexSessionError,
                        "native_codex_ready_admission_expired"):
                    quiescence.resume(admission_deadline)
                self.assertEqual(
                    [frozen for _descriptor, frozen in writes], [True])
                self.assertEqual(
                    (scope / "cgroup.freeze").read_text(encoding="ascii"),
                    "1\n")
                with self.assertRaises(OSError):
                    os.fstat(held)

    def test_projection_permit_expiry_is_capped_by_session_lease(self) -> None:
        self.assertEqual(
            controller._projection_permit_expiry(
                issued_at=100, requested_expires_at=220,
                lease_expires_at=110),
            110)
        self.assertEqual(
            controller._projection_permit_expiry(
                issued_at=100, requested_expires_at=None,
                lease_expires_at=105),
            105)
        with self.assertRaisesRegex(
                controller.NativeCodexSessionError,
                "native_codex_run_lease_expired"):
            controller._projection_permit_expiry(
                issued_at=100, requested_expires_at=110,
                lease_expires_at=100)

    def test_ready_quiescence_refreezes_if_thaw_crosses_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root, scope, proc_root = ready_scope_fixture(
                Path(directory))
            writes: list[bool] = []
            clock = [100.0]

            def freeze_writer(descriptor: int, frozen: bool) -> None:
                writes.append(frozen)
                controller._write_cgroup_freeze(descriptor, frozen)
                (scope / "cgroup.events").write_text(
                    f"populated 1\nfrozen {int(frozen)}\n",
                    encoding="ascii")
                if not frozen:
                    clock[0] = 110.0

            quiescence = controller._quiesce_scope_for_ready(
                4242, 19, scope_cgroup=READY_SCOPE_CGROUP,
                scope_unit=READY_SCOPE_UNIT,
                launcher_uid=READY_SCOPE_UID,
                cgroup_root=cgroup_root, proc_root=proc_root,
                trusted_uid=os.geteuid(), freeze_writer=freeze_writer,
                monotonic=lambda: clock[0])
            with self.assertRaisesRegex(
                    controller.NativeCodexSessionError,
                    "native_codex_ready_admission_expired"):
                quiescence.resume(110.0)
            self.assertEqual(writes, [True, False, True])
            self.assertEqual(
                (scope / "cgroup.freeze").read_text(encoding="ascii"),
                "1\n")
            self.assertEqual(
                (scope / "cgroup.events").read_text(encoding="ascii"),
                "populated 1\nfrozen 1\n")

    def test_launcher_gate_release_rechecks_exact_session_lease(self) -> None:
        receipt = mock.sentinel.receipt
        with mock.patch.object(
                controller.runtime_driver,
                "release_launcher_gate") as release:
            with self.assertRaisesRegex(
                    controller.NativeCodexSessionError,
                    "native_codex_run_lease_expired"):
                controller._release_launcher_gate_before_lease_expiry(
                    7, receipt, lease_deadline=100.0,
                    monotonic=lambda: 100.0)
            release.assert_not_called()

            controller._release_launcher_gate_before_lease_expiry(
                7, receipt, lease_deadline=100.0,
                monotonic=lambda: 99.999)
            release.assert_called_once_with(7, receipt)

    def test_prepare_rejects_every_nested_session_lease_mutation(self) -> None:
        runtime = authority()
        lease = session_lease(runtime)
        projection_fields, _observation = projection_prepare_fields(runtime)
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
            **projection_fields,
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

    def test_prepare_projection_expiry_cannot_outlive_session_lease(self) -> None:
        runtime = authority()
        lease = session_lease(runtime, issued_at=1_800_000_000)
        observed_at = lease["expires_at"] - 60
        projection_fields, _observation = projection_prepare_fields(
            runtime, observed_at=observed_at)
        body = {
            "operation_id": "11111111-1111-4111-8111-111111111111",
            "plan_sha256": "1" * 64,
            "authorization_sha256": "2" * 64,
            "session_id": runtime["session_context_binding"]["session_id"],
            "runtime_authority": runtime,
            "projection_id": "22222222-2222-4222-8222-222222222222",
            "access_token_sha256": "3" * 64,
            "expires_at": lease["expires_at"] + 1,
            "session_lease": lease,
            **projection_fields,
        }
        rejected = {
            "schema": controller.PREPARE_REQUEST_SCHEMA, **body,
            "request_sha256": controller._digest(body),
        }
        with self.assertRaisesRegex(
                controller.NativeCodexSessionError,
                "native_codex_prepare_expiry_invalid"):
            controller.validate_prepare_request(
                rejected, now=observed_at)

        admitted_body = {**body, "expires_at": lease["expires_at"]}
        admitted = {
            "schema": controller.PREPARE_REQUEST_SCHEMA, **admitted_body,
            "request_sha256": controller._digest(admitted_body),
        }
        self.assertEqual(
            controller.validate_prepare_request(
                admitted, now=observed_at)["expires_at"],
            lease["expires_at"])

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

    def test_main_translates_systemd_timeout_to_fixed_exit(self) -> None:
        with mock.patch.object(
            controller, "launch_prepared",
            side_effect=subprocess.TimeoutExpired("systemctl", 2),
        ):
            self.assertEqual(controller.main([
                "launch", "11111111-1111-4111-8111-111111111111",
                "a" * 64,
            ]), 1)

        if not hasattr(socket, "SO_PEERCRED"):
            self.skipTest("Linux SO_PEERCRED is unavailable on this host")
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
        admitted_source = inspect.getsource(controller._launch_and_wait_admitted)
        admitted_parameters = inspect.signature(
            controller._launch_and_wait_admitted).parameters
        self.assertEqual(
            admitted_parameters["qualification_journal_root"].default,
            controller.isolation.JOURNAL_ROOT)
        self.assertEqual(
            admitted_parameters["qualification_scratch_root"].default,
            controller.isolation.QUALIFICATION_SCRATCH_ROOT)
        self.assertEqual(
            admitted_parameters["qualification_boot_id_path"].default,
            controller.isolation.BOOT_ID)
        self.assertEqual(
            admitted_parameters["qualification_core_pattern_path"].default,
            controller.isolation.CORE_PATTERN)
        self.assertIn(
            "expected_runtime_max_usec=runtime_max_usec", admitted_source
        )
        self.assertEqual(
            admitted_source.count("_arm_vendor_parent_death_signal("), 2)
        first_parent_arm = admitted_source.index(
            "_arm_vendor_parent_death_signal(")
        credential_drop = admitted_source.index("os.setuid(identity.pw_uid)")
        second_parent_arm = admitted_source.index(
            "_arm_vendor_parent_death_signal(", first_parent_arm + 1)
        self.assertLess(first_parent_arm, credential_drop)
        self.assertLess(credential_drop, second_parent_arm)
        self.assertLess(
            second_parent_arm,
            admitted_source.index("SIGSTOP before any vendor exec"))
        self.assertIn("policy.PROJECTION_FRAME_FD", source)
        self.assertIn("PROJECTION_PERMIT_FD", source)
        self.assertIn("TOKEN_RECEIPT_FD", source)
        self.assertIn("NativeCodexRuntimeDriver", source)
        self.assertIn("native_codex_pre_release_qualification_unavailable", source)
        self.assertIn("pre_release_qualification_gate", admitted_source)
        self.assertNotIn("/environ", admitted_source)
        self.assertNotIn("os.environ", admitted_source)
        self.assertLess(
            admitted_source.index("qualification_evidence ="),
            admitted_source.index("os.kill(child, 18)"),
        )
        self.assertIn("exact_projection_gate", launch_source)
        self.assertIn("StartTransientUnit", source)
        self.assertIn('"BindsTo", "as"', source)
        self.assertIn('"After", "as"', source)
        self.assertIn('"PartOf", "as"', source)
        self.assertIn("os.WUNTRACED", source)
        self.assertIn("SIGSTOP before any vendor exec", source)
        self.assertIn("scope/UID readback", source)
        self.assertLess(
            admitted_source.index("isolation.reconcile_interrupted("),
            admitted_source.index("child = os.fork()"))
        self.assertLess(
            admitted_source.index("isolation.record_reserved("),
            admitted_source.index("isolation.prepare_qualification_scratch("))
        self.assertLess(
            admitted_source.index("isolation.prepare_qualification_scratch("),
            admitted_source.index("isolation.record_prepared("))
        self.assertLess(
            admitted_source.index("isolation.record_prepared("),
            admitted_source.index("isolation.activate_qualification_scratch("))
        self.assertLess(
            admitted_source.index("isolation.cleanup_qualification_scratch("),
            admitted_source.index("isolation.record_terminal("))
        self.assertLess(
            admitted_source.index(
                "_release_launcher_gate_before_lease_expiry("),
            admitted_source.index("driver = driver_factory("))
        self.assertIn(
            "qualification_quiescer=lambda: _quiesce_scope_for_ready(",
            admitted_source)

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
            projection_fields, observation = projection_prepare_fields(runtime)
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
                **projection_fields,
            }
            request = {
                "schema": controller.PREPARE_REQUEST_SCHEMA, **fields,
                "request_sha256": controller._digest(fields),
            }
            with mock.patch.object(
                controller.native_lifecycle_fence, "admission_open",
                return_value=contextlib.nullcontext(),
            ):
                changed_observation = {
                    **observation, "research_release_id": "f" * 64,
                }
                with self.assertRaisesRegex(
                    controller.NativeCodexSessionError,
                    "projection_observation_changed",
                ):
                    controller.prepare_session(
                        request, preparation_root=preparations,
                        catalog_path=catalog_path,
                        runtime_loader=lambda _generation: harness,
                        projection_observer=(
                            lambda _authority, _descriptor:
                                changed_observation
                        ),
                        trusted_uid=uid, trusted_gid=gid,
                        now=1_800_000_000,
                    )
                self.assertFalse(
                    (preparations / f"{fields['operation_id']}.json").exists()
                )
                reply = controller.prepare_session(
                    request, preparation_root=preparations,
                    catalog_path=catalog_path,
                    runtime_loader=lambda _generation: harness,
                    projection_observer=(
                        lambda _authority, _descriptor: observation
                    ),
                    trusted_uid=uid, trusted_gid=gid, now=1_800_000_000)
                repeated = controller.prepare_session(
                    request, preparation_root=preparations,
                    catalog_path=catalog_path,
                    runtime_loader=lambda _generation: harness,
                    projection_observer=(
                        lambda _authority, _descriptor: observation
                    ),
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

    def test_systemd_duration_parser_accepts_exact_fractional_rendering(self) -> None:
        self.assertEqual(
            controller._systemd_duration_usec("3min 59.123456s"),
            239_123_456)
        self.assertEqual(controller._systemd_duration_usec("3000000"),
                         3_000_000)
        with self.assertRaises(ValueError):
            controller._systemd_duration_usec("1.0000001s")
        with self.assertRaises(ValueError):
            controller._systemd_duration_usec("infinity")
        self.assertEqual(
            controller.controller_owner_scope_unit(READY_SCOPE_UNIT),
            "secure-sandbox-native-owner-"
            "00000000000040008000000000000001.scope")

    def test_owner_watcher_hardens_checks_parent_and_polls_only_pidfd(self) -> None:
        events: list[object] = []

        class WatcherExit(BaseException):
            def __init__(self, status: int) -> None:
                self.status = status

        class Poller:
            def register(self, descriptor: int, flags: int) -> None:
                events.append(("register", descriptor, flags))

            def poll(self):
                events.append("poll")
                return [(0, 1)]

        def leave(status: int):
            raise WatcherExit(status)

        with self.assertRaises(WatcherExit) as exited:
            controller._owner_watcher_main(
                9, 111,
                hardener=lambda: events.append("harden"),
                parent_reader=lambda: 111,
                fd_duplicator=lambda source, command, minimum: (
                    events.append(("fcntl", source, command, minimum)) or 10),
                descriptor_duplicator=lambda source, target: (
                    events.append(("dup2", source, target)) or target),
                inheritable_setter=lambda descriptor, inherited: events.append(
                    ("inheritable", descriptor, inherited)),
                range_closer=lambda start, end: events.append(
                    ("close", start, end)),
                signaler=lambda pid, signum: events.append(
                    ("signal", pid, signum)),
                poll_factory=Poller, exit_process=leave)
        self.assertEqual(exited.exception.status, 0)
        self.assertEqual(events[0], "harden")
        self.assertIn(("dup2", 10, 0), events)
        self.assertIn(("inheritable", 0, False), events)
        self.assertIn("poll", events)

        with self.assertRaises(WatcherExit) as raced:
            controller._owner_watcher_main(
                9, 111, hardener=lambda: None,
                parent_reader=lambda: 1,
                exit_process=leave)
        self.assertEqual(raced.exception.status, 126)

    def test_vendor_parent_death_arm_rejects_a_reparented_child(self) -> None:
        events: list[str] = []
        controller._arm_vendor_parent_death_signal(
            111, hardener=lambda: events.append("armed"),
            parent_reader=lambda: 111)
        self.assertEqual(events, ["armed"])
        with self.assertRaisesRegex(
            controller.NativeCodexSessionError,
            "native_codex_vendor_parent_changed",
        ):
            controller._arm_vendor_parent_death_signal(
                111, hardener=lambda: events.append("rearmed"),
                parent_reader=lambda: 1)
        self.assertEqual(events, ["armed", "rearmed"])

    def test_owner_scope_readback_requires_stable_exact_root_generation(
        self,
    ) -> None:
        uid = os.geteuid()
        gid = os.getegid()
        watcher_pid = 4242
        watcher_start = 19
        runtime = 239_123_456
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup_root = root / "cgroup"
            cgroup = cgroup_root / "test" / OWNER_SCOPE_UNIT
            cgroup.mkdir(parents=True)
            (cgroup / "cgroup.procs").write_text(
                f"{watcher_pid}\n", encoding="ascii")
            proc_root = root / "proc"
            process = proc_root / str(watcher_pid)
            process.mkdir(parents=True)
            (process / "status").write_text(
                "Name:\towner-watcher\n"
                f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n",
                encoding="ascii")
            fields = ["S", *("0" for _ in range(18)), str(watcher_start)]
            (process / "stat").write_text(
                f"{watcher_pid} (owner watcher) {' '.join(fields)}\n",
                encoding="ascii")

            calls: list[list[str]] = []

            def runner(command, **_kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, (
                    "LoadState=loaded\n"
                    "ActiveState=active\n"
                    "SubState=running\n"
                    "BindsTo=native-harness-supervisor.service\n"
                    "After=system.slice native-harness-supervisor.service\n"
                    "PartOf=native-harness-supervisor.service\n"
                    "KillMode=control-group\n"
                    "SendSIGKILL=yes\n"
                    "Delegate=no\n"
                    "CollectMode=inactive-or-failed\n"
                    "Transient=yes\n"
                    f"FragmentPath=/run/systemd/transient/{OWNER_SCOPE_UNIT}\n"
                    "RuntimeMaxUSec=3min 59.123456s\n"
                    "TimeoutStopUSec=2s\n"
                    "TasksMax=1\n"
                    "MemoryMax=67108864\n"
                    f"ControlGroup=/test/{OWNER_SCOPE_UNIT}\n"
                ), "")

            observed = controller.verify_controller_owner_scope(
                OWNER_SCOPE_UNIT, watcher_pid=watcher_pid,
                watcher_start_time_ticks=watcher_start,
                trusted_uid=uid, trusted_gid=gid,
                expected_runtime_max_usec=runtime,
                cgroup_root=cgroup_root, proc_root=proc_root,
                runner=runner, deadline_seconds=0.1)
            self.assertEqual(observed["watcher_pid"], watcher_pid)
            self.assertIn("--all", calls[0])

            with self.assertRaisesRegex(
                controller.NativeCodexSessionError,
                "owner_scope_process_invalid",
            ):
                controller.verify_controller_owner_scope(
                    OWNER_SCOPE_UNIT, watcher_pid=watcher_pid,
                    watcher_start_time_ticks=watcher_start + 1,
                    trusted_uid=uid, trusted_gid=gid,
                    expected_runtime_max_usec=runtime,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    runner=runner, deadline_seconds=0.02)

    def test_owner_scope_creation_uses_bounded_exact_watcher_properties(self) -> None:
        observed: list[list[str]] = []

        def runner(command, **_kwargs):
            observed.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        controller.start_controller_owner_scope(
            OWNER_SCOPE_UNIT, 4242, runtime_max_usec=239_123_456,
            busctl=Path("/usr/bin/busctl"), runner=runner)
        command = observed[0]
        self.assertEqual(command[command.index("PIDs") + 1:
                                 command.index("PIDs") + 4],
                         ["au", "1", "4242"])
        for name, expected in (
            ("RuntimeMaxUSec", "239123456"),
            ("TimeoutStopUSec", "2000000"),
            ("TasksMax", "1"),
            ("MemoryMax", "67108864"),
        ):
            index = command.index(name)
            self.assertEqual(command[index + 1:index + 3], ["t", expected])
        self.assertEqual(command[-1], "0")

    def test_owner_setup_failure_stops_reaps_and_proves_absence(self) -> None:
        events: list[object] = []

        def fail_after_start(*_args, **_kwargs):
            events.append("start")
            raise controller.NativeCodexSessionError(
                "native_codex_owner_scope_create_failed")

        def systemctl_runner(command, **_kwargs):
            events.append(tuple(command))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(
            controller.NativeCodexSessionError,
            "owner_scope_create_failed",
        ):
            controller.create_controller_owner_scope(
                OWNER_SCOPE_UNIT, runtime_max_usec=1_000_000,
                trusted_uid=os.geteuid(), trusted_gid=os.getegid(),
                watcher_spawner=lambda **_kwargs: (4242, 19),
                owner_starter=fail_after_start,
                watcher_terminator=lambda pid: events.append(("reap", pid)),
                absence_prover=lambda *args, **kwargs: events.append(
                    ("prove", args, kwargs)),
                systemctl_runner=systemctl_runner)
        self.assertIn(("reap", 4242), events)
        self.assertTrue(any(isinstance(event, tuple)
                            and event and event[0] == "prove"
                            for event in events))
        self.assertTrue(any(isinstance(event, tuple)
                            and "stop" in event for event in events))

    def test_owner_release_reaps_and_proves_even_when_stop_errors(self) -> None:
        calls: list[tuple[str, ...]] = []
        waits = iter(((0, 0), (4242, 9)))
        killed: list[tuple[int, int]] = []

        def runner(command, **_kwargs):
            calls.append(tuple(command))
            if "stop" in command:
                return subprocess.CompletedProcess(command, 1, b"", b"")
            return subprocess.CompletedProcess(command, 4, b"", b"")

        custody = controller.ControllerOwnerCustody(
            unit=OWNER_SCOPE_UNIT, watcher_pid=4242,
            watcher_start_time_ticks=19, runtime_max_usec=1_000_000,
            cgroup=f"/test/{OWNER_SCOPE_UNIT}")
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            controller.NativeCodexSessionError, "owner_scope_stop_failed"
        ):
            root = Path(directory)
            controller.release_controller_owner_scope(
                custody, runner=runner,
                waitpid=lambda _pid, _flags: next(waits),
                kill=lambda pid, signum: killed.append((pid, signum)),
                cgroup_root=root / "cgroup", proc_root=root / "proc",
                deadline_seconds=0.2)
        self.assertEqual(killed, [(4242, 9)])
        self.assertEqual(sum("show" in call for call in calls), 2)
        self.assertEqual(custody.watcher_pid, -1)

    def test_owner_release_retries_only_while_live_custody_is_retained(
        self,
    ) -> None:
        custody = controller.ControllerOwnerCustody(
            unit=OWNER_SCOPE_UNIT, watcher_pid=4242,
            watcher_start_time_ticks=19, runtime_max_usec=1_000_000,
            cgroup=f"/test/{OWNER_SCOPE_UNIT}")
        calls = 0

        def fails_once_then_releases(
            tracked: controller.ControllerOwnerCustody, **_kwargs,
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise controller.NativeCodexSessionError(
                    "native_codex_owner_scope_transient_release_failure")
            tracked.watcher_pid = -1

        release_error = controller._release_controller_owner_with_retry(
            custody, releaser=fails_once_then_releases)
        self.assertIsInstance(
            release_error, controller.NativeCodexSessionError)
        self.assertIn(
            "native_codex_owner_scope_transient_release_failure",
            str(release_error))
        self.assertEqual(calls, 2)
        self.assertEqual(custody.watcher_pid, -1)

        terminal_custody = controller.ControllerOwnerCustody(
            unit=OWNER_SCOPE_UNIT, watcher_pid=4243,
            watcher_start_time_ticks=20, runtime_max_usec=1_000_000,
            cgroup=f"/test/{OWNER_SCOPE_UNIT}")
        terminal_calls = 0

        def terminal_failure(
            tracked: controller.ControllerOwnerCustody, **_kwargs,
        ) -> None:
            nonlocal terminal_calls
            terminal_calls += 1
            tracked.watcher_pid = -1
            raise controller.NativeCodexSessionError(
                "native_codex_owner_scope_post_absence_failure")

        terminal_error = controller._release_controller_owner_with_retry(
            terminal_custody, releaser=terminal_failure)
        self.assertIsInstance(
            terminal_error, controller.NativeCodexSessionError)
        self.assertIn(
            "native_codex_owner_scope_post_absence_failure",
            str(terminal_error))
        self.assertEqual(terminal_calls, 1)
        self.assertEqual(terminal_custody.watcher_pid, -1)

    def test_owner_absence_rejects_malformed_process_readback(self) -> None:
        def runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 4, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "proc" / "4242"
            process.mkdir(parents=True)
            (process / "stat").write_text(
                "4242 (malformed) S\n", encoding="ascii")
            with self.assertRaisesRegex(
                controller.NativeCodexSessionError,
                "owner_scope_teardown_ambiguous",
            ):
                controller.prove_controller_owner_scope_absent(
                    OWNER_SCOPE_UNIT, watcher_pid=4242,
                    watcher_start_time_ticks=19,
                    expected_cgroup=f"/test/{OWNER_SCOPE_UNIT}",
                    cgroup_root=root / "cgroup", proc_root=root / "proc",
                    runner=runner, deadline_seconds=0.03)

    def test_scope_readback_requires_dependencies_cgroup_and_exact_uid(self) -> None:
        unit = "secure-sandbox-native-run-00000000000040008000000000000001.scope"
        uid = os.geteuid()
        with tempfile.TemporaryDirectory() as directory:
            cgroup_root = Path(directory)
            cgroup = cgroup_root / "test" / unit
            cgroup.mkdir(parents=True)
            (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="ascii")
            (cgroup / "memory.max").write_text(
                "4294967296\n", encoding="ascii")
            (cgroup / "memory.swap.max").write_text("0\n", encoding="ascii")
            (cgroup / "pids.max").write_text("256\n", encoding="ascii")
            (cgroup / "cpu.max").write_text(
                "300000 100000\n", encoding="ascii")
            proc_root = Path(directory) / "proc"
            proc = proc_root / str(os.getpid())
            proc.mkdir(parents=True)
            (proc / "status").write_text(
                f"Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                f"Gid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
                encoding="ascii",
            )

            def fields(*, runtime: str = "1h", part_of: str | None = None,
                       tasks: str = "256", kill_signal: str = "9",
                       swap: str = "0") -> str:
                dependencies = (
                    f"native-harness-supervisor.service {OWNER_SCOPE_UNIT}")
                return (
                    "LoadState=loaded\n"
                    "ActiveState=active\n"
                    "SubState=running\n"
                    f"BindsTo={dependencies}\n"
                    f"After=system.slice {dependencies}\n"
                    f"PartOf={dependencies if part_of is None else part_of}\n"
                    "KillMode=control-group\n"
                    f"KillSignal={kill_signal}\n"
                    "SendSIGKILL=yes\n"
                    "Delegate=no\n"
                    "CollectMode=inactive-or-failed\n"
                    "Transient=yes\n"
                    f"FragmentPath=/run/systemd/transient/{unit}\n"
                    f"RuntimeMaxUSec={runtime}\n"
                    "TimeoutStopUSec=2s\n"
                    f"TasksMax={tasks}\n"
                    "MemoryMax=4294967296\n"
                    f"MemorySwapMax={swap}\n"
                    "CPUQuotaPerSecUSec=3s\n"
                    "CPUQuotaPeriodUSec=100ms\n"
                    f"ControlGroup=/test/{unit}\n"
                )

            def runner(*_args, **_kwargs):
                return subprocess.CompletedProcess([], 0, fields(), "")

            observed = controller.verify_transient_scope(
                unit, owner_unit=OWNER_SCOPE_UNIT,
                launcher_uid=uid, launcher_gid=uid,
                cgroup_root=cgroup_root,
                proc_root=proc_root, runner=runner, deadline_seconds=0.1,
                expected_runtime_max_usec=3_600_000_000)
            self.assertEqual(observed["process_count"], 1)

            def wrong_runtime(*_args, **_kwargs):
                return subprocess.CompletedProcess(
                    [], 0, fields(runtime="2h"), "")

            with self.assertRaisesRegex(
                controller.NativeCodexSessionError, "scope_runtime_invalid"
            ):
                controller.verify_transient_scope(
                    unit, owner_unit=OWNER_SCOPE_UNIT,
                    launcher_uid=uid, launcher_gid=uid,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root, runner=wrong_runtime,
                    deadline_seconds=0.01,
                    expected_runtime_max_usec=3_600_000_000)

            def missing_edge(*_args, **_kwargs):
                return subprocess.CompletedProcess(
                    [], 0, fields(part_of="native-harness-supervisor.service"),
                    "")

            with self.assertRaisesRegex(
                controller.NativeCodexSessionError, "scope_dependency_invalid"):
                controller.verify_transient_scope(
                    unit, owner_unit=OWNER_SCOPE_UNIT,
                    launcher_uid=uid, launcher_gid=uid,
                    cgroup_root=cgroup_root,
                    proc_root=proc_root, runner=missing_edge,
                    deadline_seconds=0.01)

            def wrong_resources(*_args, **_kwargs):
                return subprocess.CompletedProcess(
                    [], 0, fields(tasks="max"), "")

            with self.assertRaisesRegex(
                controller.NativeCodexSessionError, "scope_resource_invalid"
            ):
                controller.verify_transient_scope(
                    unit, owner_unit=OWNER_SCOPE_UNIT,
                    launcher_uid=uid, launcher_gid=uid,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    runner=wrong_resources, deadline_seconds=0.01,
                    expected_runtime_max_usec=3_600_000_000)

            for changed in (
                lambda: fields(swap="infinity"),
                lambda: fields(kill_signal="15"),
            ):
                with self.subTest(changed=changed()), self.assertRaises(
                    controller.NativeCodexSessionError
                ):
                    controller.verify_transient_scope(
                        unit, owner_unit=OWNER_SCOPE_UNIT,
                        launcher_uid=uid, launcher_gid=uid,
                        cgroup_root=cgroup_root, proc_root=proc_root,
                        runner=lambda *_args, **_kwargs: (
                            subprocess.CompletedProcess([], 0, changed(), "")),
                        deadline_seconds=0.01,
                        expected_runtime_max_usec=3_600_000_000)

            (cgroup / "memory.swap.max").write_text(
                "max\n", encoding="ascii")
            with self.assertRaisesRegex(
                controller.NativeCodexSessionError,
                "scope_kernel_resource_invalid",
            ):
                controller.verify_transient_scope(
                    unit, owner_unit=OWNER_SCOPE_UNIT,
                    launcher_uid=uid, launcher_gid=uid,
                    cgroup_root=cgroup_root, proc_root=proc_root,
                    runner=runner, deadline_seconds=0.01,
                    expected_runtime_max_usec=3_600_000_000)
            (cgroup / "memory.swap.max").write_text("0\n", encoding="ascii")

    def test_transient_scope_creation_binds_exact_stopped_pid_and_edges(self) -> None:
        unit = "secure-sandbox-native-run-00000000000040008000000000000001.scope"
        observed = []

        def runner(command, **_kwargs):
            observed.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        controller.start_transient_scope(
            unit, 1234, owner_unit=OWNER_SCOPE_UNIT,
            runtime_max_usec=3_600_000_000,
            busctl=Path("/usr/bin/busctl"), runner=runner)
        command = observed[0]
        self.assertIn("StartTransientUnit", command)
        self.assertIn("PIDs", command)
        self.assertIn("1234", command)
        for edge in ("BindsTo", "After", "PartOf"):
            index = command.index(edge)
            self.assertEqual(command[index + 1:index + 5], [
                "as", "2", "native-harness-supervisor.service",
                OWNER_SCOPE_UNIT,
            ])
        runtime_index = command.index("RuntimeMaxUSec")
        self.assertEqual(
            command[runtime_index + 1:runtime_index + 3],
            ["t", "3600000000"])
        for name, expected in (
            ("TasksMax", "256"),
            ("MemoryMax", "4294967296"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "3000000"),
            ("CPUQuotaPeriodUSec", "100000"),
            ("TimeoutStopUSec", "2000000"),
        ):
            index = command.index(name)
            self.assertEqual(command[index + 1:index + 3], ["t", expected])
        kill_signal_index = command.index("KillSignal")
        self.assertEqual(
            command[kill_signal_index + 1:kill_signal_index + 3],
            ["i", "9"])
        self.assertEqual(command[-1], "0")


if __name__ == "__main__":
    unittest.main()
