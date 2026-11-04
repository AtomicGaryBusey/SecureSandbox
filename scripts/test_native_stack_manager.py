#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scripts import native_stack_manager as manager_module
from shared import (
    harness_runtime_binding,
    model_stack_runtime_binding,
    native_egress,
    native_stack_operations as operations,
    native_stack_runtime_binding,
    native_vendor_stack,
    runtime_authority,
    session_context_binding,
)


ROOT = Path(__file__).resolve().parent.parent


def observation(state: str, **extra: object) -> dict:
    return {
        "state": state,
        "observed_at": 2_000_000_000,
        "evidence_sha256": "d" * 64,
        **extra,
    }


def status_for(
    stack: dict,
    *,
    activation: str = "inactive",
    authentication: str = "signed-in",
    account_state: str = "bound",
    program: str = "verified",
    model: str = "verified",
    custody: str = "retained",
    custody_tombstone: str | None = None,
    projection_count: int | None = 0,
    live_runs: int = 0,
    fence_reason: str | None = None,
) -> dict:
    return operations.make_status(
        stack=stack,
        harness=observation(
            "admitted",
            generation_id=stack["harness"]["generation_id"],
            binding_sha256="e" * 64,
        ),
        authentication=observation(authentication),
        credential_custody={
            "state": custody,
            "observed_at": 2_000_000_000,
            "evidence_sha256": "c" * 64,
            "tombstone_sha256": custody_tombstone,
            "projection_count": projection_count,
        },
        account_binding=observation(
            account_state,
            account_subject_sha256=(
                None if account_state == "unbound"
                else stack["account_binding"]["account_subject_sha256"]
            ),
            workspace_sha256=(
                None if account_state == "unbound"
                else stack["account_binding"]["workspace_sha256"]
            ),
        ),
        program_entitlement=observation(program),
        model_entitlement=observation(model),
        network={
            "phase": "closed",
            "grant_sha256": None,
            "expires_at": None,
            "observed_at": 2_000_000_000,
        },
        activation=observation(
            activation,
            receipt_sha256="f" * 64 if activation == "active" else None,
        ),
        live_run_count=live_runs,
        fence_reason=fence_reason,
    )


def runtime_for(stack: dict) -> dict:
    native = native_stack_runtime_binding.make_binding(stack)
    harness = harness_runtime_binding.make_binding(
        harness_id=stack["harness"]["harness_id"],
        generation_id=stack["harness"]["generation_id"],
        manifest_sha256="1" * 64,
        executable_sha256="2" * 64,
        inventory_sha256="3" * 64,
        adapter_id=stack["harness"]["adapter_id"],
        adapter_sha256="4" * 64,
    )
    context = session_context_binding.make_binding(
        session_id="00000000-0000-4000-8000-000000000009",
        source_id=None,
        source_manifest_sha256=None,
        persona_sha256="5" * 64,
        tool_catalog_sha256="6" * 64,
        extension_set_sha256="7" * 64,
    )
    return runtime_authority.make_binding(
        model_stack_binding=model_stack_runtime_binding.make_binding(
            model_stack_runtime_binding.NATIVE_MODE, native
        ),
        session_context_binding=context,
        harness_binding=harness,
    )


class FakeBackend:
    def __init__(self, stack: dict, initial: dict, *, grant: dict | None = None):
        self.stack = copy.deepcopy(stack)
        self.current = initial
        self.grant = grant
        self.steps: list[str] = []
        self.provider_calls: list[str] = []
        self.status_calls = 0

    def status(self, _plan: dict, _authorization: dict) -> dict:
        self.status_calls += 1
        return copy.deepcopy(self.current)

    def prepare_grant(self, _plan: dict, _authorization: dict) -> dict | None:
        return copy.deepcopy(self.grant)

    def rotation_step(
        self, step: str, plan: dict, _grant: dict | None, authorization: dict
    ) -> dict:
        self.steps.append(step)
        if step == "stop-bound-runs" and self.current["live_run_count"]:
            self.current = status_for(
                self.stack,
                activation=self.current["activation"]["state"],
                authentication=self.current["authentication"]["state"],
                live_runs=0,
            )
        return {
            "schema": manager_module.STEP_RESULT_SCHEMA,
            "action_id": plan["action_id"],
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "step": step,
            "status": "verified",
            "evidence_sha256": hashlib.sha256(step.encode()).hexdigest(),
        }

    def provider_action(self, plan: dict, authorization: dict) -> dict:
        action = plan["action"]
        self.provider_calls.append(action)
        if action == "activate":
            self.current = status_for(self.stack, activation="active")
        elif action in {"rollback", "credential-destroy"}:
            self.current = status_for(
                self.stack,
                activation="inactive",
                authentication="signed-out" if action == "credential-destroy" else "signed-in",
                account_state="unbound" if action == "credential-destroy" else "bound",
                program="unknown" if action == "credential-destroy" else "verified",
                model="unknown" if action == "credential-destroy" else "verified",
                custody="absent" if action == "credential-destroy" else "retained",
                custody_tombstone="a" * 64 if action == "credential-destroy" else None,
            )
        elif action == "logout":
            self.current = status_for(
                self.stack, activation="inactive", authentication="signed-out"
            )
        elif action == "recover":
            self.current = status_for(
                self.stack, activation="fenced", fence_reason="operator-recovery"
            )
        elif action == "signin-begin":
            self.current = status_for(self.stack, authentication="signed-in")
        elif action == "entitlement-verify":
            self.current = status_for(self.stack, program="verified", model="verified")
        elif action == "binding-commit":
            self.stack["account_binding"]["account_subject_sha256"] = plan[
                "observed_account_subject_sha256"
            ]
            self.stack["account_binding"]["workspace_sha256"] = plan[
                "observed_workspace_sha256"
            ]
            self.current = status_for(self.stack)
        return {
            "schema": manager_module.PROVIDER_RESULT_SCHEMA,
            "action_id": plan["action_id"],
            "action": action,
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "status": "verified",
            "evidence_sha256": hashlib.sha256(action.encode()).hexdigest(),
        }


class NativeStackManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        catalog = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(encoding="ascii")
        )
        cls.stack = copy.deepcopy(catalog["stacks"][1])
        cls.stack["harness"]["generation_id"] = "a" * 64
        cls.stack["account_binding"]["account_subject_sha256"] = "b" * 64
        cls.stack["account_binding"]["workspace_sha256"] = "c" * 64

    def manager(self, backend: FakeBackend, directory: str, **kwargs: object):
        clock = kwargs.pop("clock", 2_000_000_100)
        catalog = {
            "schema":native_vendor_stack.CATALOG_SCHEMA,
            "stacks":[copy.deepcopy(backend.stack)],
        }
        return manager_module.NativeStackManager(
            backend,
            state_root=Path(directory) / "state",
            receipt_root=Path(directory) / "receipts",
            trusted_uid=os.geteuid(),
            host_release_id="3" * 64,
            now=(clock if callable(clock) else lambda: int(clock)),
            authorization_receipt_verifier=lambda _authorization, _plan: None,
            catalog_resolver=lambda _plan: (
                copy.deepcopy(backend.stack),
                hashlib.sha256(native_vendor_stack.canonical_bytes(catalog)).hexdigest(),
            ),
            **kwargs,
        )

    def test_production_transport_bounds_output_and_process_lifetime(self) -> None:
        success = manager_module.SubprocessBackend._run_bounded_process_group(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdin.buffer.read(); sys.stdout.write('{\"ok\":true}\\n')",
            ],
            b"{}\n",
            2,
        )
        self.assertEqual(success.returncode, 0)
        self.assertEqual(success.stdout, b'{"ok":true}\n')

        with self.assertRaisesRegex(
            manager_module.NativeStackManagerError,
            "control_response_oversized",
        ):
            manager_module.SubprocessBackend._run_bounded_process_group(
                [
                    sys.executable,
                    "-c",
                    f"import sys,time; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'x'*{manager_module.MAX_JSON + 1}); sys.stdout.flush(); time.sleep(10)",
                ],
                b"{}\n",
                2,
            )

        started = time.monotonic()
        with self.assertRaisesRegex(
            manager_module.NativeStackManagerError,
            "control_operation_failed|control_timeout",
        ):
            manager_module.SubprocessBackend._run_bounded_process_group(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                b"{}\n",
                1,
            )
        self.assertLess(time.monotonic() - started, 4)

    def authorization(self, plan: dict) -> dict:
        authorized_at = plan["created_at"] + 100
        value = {
            "schema":manager_module.AUTHORIZATION_SCHEMA,
            "authorization_id":"88888888-8888-4888-8888-888888888888",
            "request_sha256":"1" * 64,
            "pending_receipt_sha256":"2" * 64,
            "action_id":plan["action_id"],
            "action":plan["action"],
            "plan_sha256":plan["plan_sha256"],
            "method":"touch-id",
            "password_fallback":False,
            "authorized_at":authorized_at,
            "expires_at":authorized_at + 120,
            "host_release_id":"3" * 64,
            "requesting_agent_sha256":"4" * 64,
            "requesting_session_sha256":"5" * 64,
        }
        value["authorization_sha256"] = manager_module.digest(value)
        return value

    def apply(self, manager: manager_module.NativeStackManager, plan: dict) -> dict:
        return manager.apply(plan, self.authorization(plan))

    def plan(self, action: str, status: dict, **kwargs: object) -> dict:
        return operations.make_plan(
            stack=self.stack,
            status=status,
            action=action,
            created_at=2_000_000_000,
            **kwargs,
        )

    def test_activate_runs_exact_closed_rotation_and_writes_durable_receipt(self) -> None:
        initial = status_for(self.stack)
        plan = self.plan("activate", initial)
        backend = FakeBackend(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory:
            receipt = self.apply(self.manager(backend, directory), plan)
            self.assertEqual(receipt["result"], "verified")
            self.assertEqual(tuple(backend.steps), native_egress.ROTATION_PROTOCOL)
            receipt_path = Path(directory) / "receipts" / f"{plan['action_id']}.json"
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                operations.validate_receipt(json.loads(receipt_path.read_bytes())), receipt
            )
            with self.assertRaisesRegex(
                manager_module.NativeStackManagerError, "action_replay"
            ):
                self.apply(self.manager(backend, directory), plan)

    def test_destructive_action_stops_bound_runs_before_rotation(self) -> None:
        initial = status_for(self.stack, activation="active", live_runs=2)
        plan = self.plan("rollback", initial)
        backend = FakeBackend(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory:
            self.apply(self.manager(backend, directory), plan)
        self.assertEqual(backend.steps[0], "stop-bound-runs")
        self.assertEqual(tuple(backend.steps[1:]), native_egress.ROTATION_PROTOCOL)

    def test_first_binding_stops_and_reads_back_even_when_run_count_is_zero(self) -> None:
        staged = copy.deepcopy(self.stack)
        staged["account_binding"]["account_subject_sha256"] = None
        staged["account_binding"]["workspace_sha256"] = None
        initial = status_for(
            staged, account_state="unbound", program="unknown", model="unknown"
        )
        plan = operations.make_plan(
            stack=staged,
            status=initial,
            action="binding-commit",
            observed_account_subject_sha256="8" * 64,
            observed_workspace_sha256="9" * 64,
            created_at=2_000_000_000,
        )
        backend = FakeBackend(staged, initial)
        with tempfile.TemporaryDirectory() as directory:
            self.apply(self.manager(backend, directory), plan)
        self.assertEqual(backend.steps[0], "stop-bound-runs")
        self.assertGreaterEqual(backend.status_calls, 3)

    def test_first_binding_rejects_any_preexisting_run_before_mutation(self) -> None:
        staged = copy.deepcopy(self.stack)
        staged["account_binding"]["account_subject_sha256"] = None
        staged["account_binding"]["workspace_sha256"] = None
        initial = status_for(
            staged, account_state="unbound", program="unknown", model="unknown",
            live_runs=1,
        )
        plan = operations.make_plan(
            stack=staged,
            status=initial,
            action="binding-commit",
            observed_account_subject_sha256="8" * 64,
            observed_workspace_sha256="9" * 64,
            created_at=2_000_000_000,
        )
        backend = FakeBackend(staged, initial)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            manager_module.NativeStackManagerError, "binding_precondition_failed"
        ):
            self.apply(self.manager(backend, directory), plan)
        self.assertEqual(backend.steps, [])

    def test_entitlement_grant_is_exact_and_is_closed_after_provider_action(self) -> None:
        initial = status_for(self.stack, program="unknown", model="unknown")
        plan = self.plan("entitlement-verify", initial)
        grant = native_egress.make_grant(
            binding_kind="runtime-authority",
            binding_value=runtime_for(self.stack),
            phase="inference",
            resolved_ipv4={"api.openai.com": ["93.184.216.34"]},
            issued_at=2_000_000_000,
            expires_at=2_000_003_000,
            grant_id="00000000-0000-4000-8000-000000000008",
        )
        backend = FakeBackend(self.stack, initial, grant=grant)
        with tempfile.TemporaryDirectory() as directory:
            self.apply(self.manager(backend, directory), plan)
        self.assertEqual(
            tuple(backend.steps),
            native_egress.ROTATION_PROTOCOL + native_egress.ROTATION_PROTOCOL,
        )

    def test_grant_from_another_account_is_rejected_before_mutation(self) -> None:
        initial = status_for(self.stack, program="unknown", model="unknown")
        plan = self.plan("entitlement-verify", initial)
        changed = copy.deepcopy(self.stack)
        changed["account_binding"]["account_subject_sha256"] = "9" * 64
        grant = native_egress.make_grant(
            binding_kind="runtime-authority",
            binding_value=runtime_for(changed),
            phase="inference",
            resolved_ipv4={"api.openai.com": ["93.184.216.34"]},
            issued_at=2_000_000_000,
            expires_at=2_000_003_000,
        )
        backend = FakeBackend(self.stack, initial, grant=grant)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                manager_module.NativeStackManagerError, "grant_identity_mismatch"
            ):
                self.apply(self.manager(backend, directory), plan)
        self.assertEqual(backend.steps, [])

    def test_binding_commit_is_bound_to_observed_digests_and_new_revision(self) -> None:
        staged = copy.deepcopy(self.stack)
        staged["account_binding"]["account_subject_sha256"] = None
        staged["account_binding"]["workspace_sha256"] = None
        initial = status_for(
            staged, account_state="unbound", program="unknown", model="unknown"
        )
        plan = operations.make_plan(
            stack=staged,
            status=initial,
            action="binding-commit",
            observed_account_subject_sha256="8" * 64,
            observed_workspace_sha256="9" * 64,
            created_at=2_000_000_000,
        )
        backend = FakeBackend(staged, initial)
        with tempfile.TemporaryDirectory() as directory:
            receipt = self.apply(self.manager(backend, directory), plan)
        self.assertEqual(receipt["result"], "verified")
        self.assertEqual(
            backend.current["account_binding"]["account_subject_sha256"], "8" * 64
        )
        self.assertNotEqual(backend.current["stack_sha256"], plan["identity"]["stack_sha256"])

    def test_every_remaining_action_has_a_verified_closed_terminal_state(self) -> None:
        cases = (
            ("signin-begin", status_for(self.stack, authentication="signed-out")),
            ("status-verify", status_for(self.stack)),
            ("logout", status_for(self.stack, activation="active", live_runs=1)),
            ("credential-destroy", status_for(self.stack, activation="active", live_runs=1)),
            (
                "recover",
                status_for(
                    self.stack,
                    activation="recovery-required",
                    fence_reason="interrupted-action",
                ),
            ),
        )
        for action, initial in cases:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                plan = self.plan(action, initial)
                backend = FakeBackend(self.stack, initial)
                receipt = self.apply(self.manager(backend, directory), plan)
                self.assertEqual(receipt["action"], action)
                self.assertEqual(receipt["result"], "verified")
                self.assertEqual(backend.current["network"]["phase"], "closed")

    def test_status_change_and_secret_shaped_serialization_fail_closed(self) -> None:
        initial = status_for(self.stack)
        plan = self.plan("activate", initial)
        changed = status_for(self.stack, authentication="expired")
        backend = FakeBackend(self.stack, changed)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                manager_module.NativeStackManagerError, "current_status_changed"
            ):
                self.apply(self.manager(backend, directory), plan)
        with self.assertRaisesRegex(
            manager_module.NativeStackManagerError, "secret_field_forbidden"
        ):
            manager_module.canonical({"access_token": "never"})

    def test_forged_plan_identity_is_rejected_against_protected_catalog(self) -> None:
        initial = status_for(self.stack)
        original = self.plan("activate", initial)
        mutations = {
            "vendor_id":"anthropic",
            "harness_id":"claude-code",
            "authentication_mode":"anthropic-claude-subscription-oauth",
            "credential_custody":"vendor-harness",
            "model_id":"claude-mythos-5-1",
            "stack_sha256":"9" * 64,
        }
        for field, forged_value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                forged = copy.deepcopy(original)
                forged["identity"][field] = forged_value
                body = {
                    key:value for key, value in forged.items()
                    if key not in {"schema", "plan_sha256"}
                }
                forged["plan_sha256"] = operations.sha256(body)
                backend = FakeBackend(self.stack, initial)
                with self.assertRaisesRegex(
                    manager_module.NativeStackManagerError,
                    "catalog_identity_mismatch",
                ):
                    self.apply(self.manager(backend, directory), forged)
                self.assertEqual(backend.status_calls, 0)
                self.assertEqual(backend.steps, [])

    def test_signin_requires_signed_out_inactive_zero_run_state(self) -> None:
        cases = (
            status_for(self.stack, activation="active", authentication="signed-out"),
            status_for(self.stack, activation="inactive", authentication="signed-in"),
            status_for(
                self.stack, activation="inactive", authentication="signed-out", live_runs=1
            ),
        )
        for initial in cases:
            with self.subTest(state=initial), tempfile.TemporaryDirectory() as directory:
                plan = self.plan("signin-begin", initial)
                backend = FakeBackend(self.stack, initial)
                with self.assertRaisesRegex(
                    manager_module.NativeStackManagerError,
                    "signin_precondition_failed",
                ):
                    self.apply(self.manager(backend, directory), plan)
                self.assertEqual(backend.steps, [])

    def test_provider_failure_uses_close_only_prefix_and_never_restarts(self) -> None:
        class FailingProvider(FakeBackend):
            def provider_action(self, plan: dict, authorization: dict) -> dict:
                raise manager_module.NativeStackManagerError("provider_failed")

        initial = status_for(self.stack)
        plan = self.plan("activate", initial)
        backend = FailingProvider(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(
            manager_module.NativeStackManagerError
        ):
            self.apply(self.manager(backend, directory), plan)
        recovery_steps = backend.steps[-len(manager_module.CLOSE_ONLY_PROTOCOL):]
        self.assertEqual(tuple(recovery_steps), manager_module.CLOSE_ONLY_PROTOCOL)
        self.assertFalse(any(step.startswith("start-") for step in recovery_steps))

    def test_emergency_close_attempts_every_independent_barrier(self) -> None:
        class FailingClose(FakeBackend):
            def rotation_step(
                self, step: str, plan: dict, grant: dict | None, authorization: dict
            ) -> dict:
                self.steps.append(step)
                if step in {
                    "stop-research-native-harness", "apply-research-deny-only"
                }:
                    raise manager_module.NativeStackManagerError("close_failed")
                return super().rotation_step(step, plan, grant, authorization)

        initial = status_for(self.stack)
        plan = self.plan("activate", initial)
        authorization = self.authorization(plan)
        backend = FailingClose(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory:
            self.manager(backend, directory)._emergency_close(plan, authorization)
        for step in manager_module.CLOSE_ONLY_PROTOCOL:
            self.assertIn(step, backend.steps)
        self.assertIn("apply-gateway-deny-only", backend.steps)
        self.assertIn("delete-research-native-conntrack", backend.steps)
        self.assertIn("delete-gateway-native-conntrack", backend.steps)
        self.assertFalse(any(step.startswith("start-") for step in backend.steps))

    def test_recover_requires_exact_fenced_zero_run_state(self) -> None:
        class BadRecovery(FakeBackend):
            def provider_action(self, plan: dict, authorization: dict) -> dict:
                result = super().provider_action(plan, authorization)
                if plan["action"] == "recover":
                    self.current = status_for(self.stack, activation="active")
                return result

        initial = status_for(
            self.stack, activation="recovery-required", fence_reason="ambiguous"
        )
        plan = self.plan("recover", initial)
        backend = BadRecovery(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            manager_module.NativeStackManagerError, "recovery_not_verified"
        ):
            self.apply(self.manager(backend, directory), plan)
        self.assertIn("stop-bound-runs", backend.steps)

    def test_credential_destroy_requires_absence_tombstone_and_no_binding(self) -> None:
        class RetainedCredential(FakeBackend):
            def provider_action(self, plan: dict, authorization: dict) -> dict:
                result = super().provider_action(plan, authorization)
                if plan["action"] == "credential-destroy":
                    self.current = status_for(
                        self.stack,
                        activation="inactive",
                        authentication="signed-out",
                        custody="retained",
                    )
                return result

        initial = status_for(self.stack, activation="active", live_runs=1)
        plan = self.plan("credential-destroy", initial)
        backend = RetainedCredential(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            manager_module.NativeStackManagerError,
            "credential_destroy_not_verified",
        ):
            self.apply(self.manager(backend, directory), plan)

    def test_backend_rejects_noncanonical_json_response(self) -> None:
        def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess([], 0, b'{"ok": true}\n', b"")

        backend = manager_module.SubprocessBackend(runner=runner)
        with self.assertRaisesRegex(
            manager_module.NativeStackManagerError, "response_not_canonical"
        ):
            backend._run(["ignored"], {"request": True})

    def test_root_owned_pending_receipt_and_catalog_are_independently_read_back(self) -> None:
        initial = status_for(self.stack)
        plan = self.plan("activate", initial)
        backend = FakeBackend(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authorization_root = root / "authorization-receipts"
            authorization_root.mkdir(mode=0o700)
            authorization = self.authorization(plan)
            pending = {
                "schema":"secure-sandbox-operator-authorization-receipt-v1",
                "request_id":authorization["authorization_id"],
                "request_sha256":authorization["request_sha256"],
                "status":"executing",
                "started_at":authorization["authorized_at"],
                "completed_at":None,
                "operation":"native-stack-activate",
                "declared_agent":"Codex",
                "declared_session":"native-stack-test",
                "identity_evidence":"operator-declared",
                "authorization_method":"touch-id",
                "ceremony":"approve",
                "purpose":"Activate exact native stack",
                "resource":"Native vendor harness and model stack authority",
                "exit_status":None,
                "stdout_sha256":None,
                "stderr_sha256":None,
                "native_action_id":plan["action_id"],
                "native_plan_sha256":plan["plan_sha256"],
                "host_release_id":authorization["host_release_id"],
            }
            authorization["requesting_agent_sha256"] = hashlib.sha256(
                pending["declared_agent"].encode()
            ).hexdigest()
            authorization["requesting_session_sha256"] = hashlib.sha256(
                pending["declared_session"].encode()
            ).hexdigest()
            authorization["pending_receipt_sha256"] = manager_module.digest(pending)
            authorization["authorization_sha256"] = manager_module.digest({
                key:value for key, value in authorization.items()
                if key != "authorization_sha256"
            })
            receipt_path = authorization_root / f"{authorization['authorization_id']}.json"
            receipt_path.write_bytes(manager_module.canonical(pending))
            receipt_path.chmod(0o600)

            catalog_path = root / "catalog/catalog.json"
            native_vendor_stack.write_catalog(catalog_path, {
                "schema":native_vendor_stack.CATALOG_SCHEMA,
                "stacks":[copy.deepcopy(self.stack)],
            })
            protected = manager_module.NativeStackManager(
                backend,
                state_root=root / "state",
                receipt_root=root / "native-receipts",
                authorization_receipt_root=authorization_root,
                catalog_path=catalog_path,
                trusted_uid=os.geteuid(),
                host_release_id="3" * 64,
                now=lambda:2_000_000_100,
            )
            forged = copy.deepcopy(authorization)
            forged["pending_receipt_sha256"] = "0" * 64
            forged["authorization_sha256"] = manager_module.digest({
                key:value for key, value in forged.items()
                if key != "authorization_sha256"
            })
            with self.assertRaisesRegex(
                manager_module.NativeStackManagerError,
                "authorization_receipt_mismatch",
            ):
                protected.apply(plan, forged)
            self.assertEqual(backend.status_calls, 0)
            receipt = protected.apply(plan, authorization)
            self.assertEqual(receipt["result"], "verified")
            journal = manager_module.trusted_json(
                root / "state" / "archive" / f"{plan['action_id']}.json",
                os.geteuid(),
            )
            self.assertEqual(
                journal["authorization_sha256"], authorization["authorization_sha256"]
            )
            self.assertEqual(
                journal["catalog_sha256"],
                hashlib.sha256(
                    native_vendor_stack.canonical_bytes({
                        "schema":native_vendor_stack.CATALOG_SCHEMA,
                        "stacks":[self.stack],
                    })
                ).hexdigest(),
            )

    def test_hard_crash_at_each_persisted_phase_reconciles_or_recovers(self) -> None:
        initial = status_for(self.stack)
        discovery_backend = FakeBackend(self.stack, initial)
        phases: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            discovery_plan = self.plan("activate", initial)
            self.apply(
                self.manager(
                    discovery_backend,
                    directory,
                    crash_hook=lambda phase: phases.append(phase),
                ),
                discovery_plan,
            )
        self.assertGreater(len(phases), 20)

        for target in phases:
            with self.subTest(phase=target), tempfile.TemporaryDirectory() as directory:
                backend = FakeBackend(self.stack, initial)

                def crash(phase: str) -> None:
                    if phase == target:
                        raise manager_module.SimulatedHardCrash(phase)

                action = self.plan("activate", initial)
                with self.assertRaises(manager_module.SimulatedHardCrash):
                    self.apply(
                        self.manager(backend, directory, crash_hook=crash), action
                    )
                records = list((Path(directory) / "state").glob("*.json"))
                self.assertEqual(len(records), 1)
                current = backend.current
                recover = operations.make_plan(
                    stack=self.stack,
                    status=current,
                    action="recover",
                    created_at=2_000_000_000,
                )
                receipt = self.apply(self.manager(backend, directory), recover)
                self.assertEqual(receipt["result"], "verified")
                recovered = manager_module.trusted_json(
                    Path(directory) / "state" / "archive" / records[0].name,
                    os.geteuid(),
                )
                self.assertIn(recovered["phase"], {"committed", "recovered-fenced"})

    def test_delayed_recovery_uses_only_fresh_recovery_authority(self) -> None:
        class FreshAuthorityBackend(FakeBackend):
            def __init__(self, stack: dict, initial: dict) -> None:
                super().__init__(stack, initial)
                self.clock = 2_000_000_100
                self.seen_actions: list[str] = []

            def _fresh(self, plan: dict) -> None:
                operations.validate_plan(
                    plan, now=self.clock, require_fresh=True
                )
                self.seen_actions.append(plan["action"])

            def status(self, plan: dict, authorization: dict) -> dict:
                self._fresh(plan)
                return super().status(plan, authorization)

            def rotation_step(
                self, step: str, plan: dict, grant: dict | None,
                authorization: dict,
            ) -> dict:
                self._fresh(plan)
                return super().rotation_step(step, plan, grant, authorization)

        initial = status_for(self.stack)
        backend = FreshAuthorityBackend(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory:
            old = self.plan("activate", initial)

            def crash(phase: str) -> None:
                if phase == "prepared":
                    raise manager_module.SimulatedHardCrash(phase)

            with self.assertRaises(manager_module.SimulatedHardCrash):
                self.apply(
                    self.manager(backend, directory, crash_hook=crash), old
                )

            delayed = 2_000_001_000
            backend.clock = delayed + 100
            backend.seen_actions.clear()
            recover = operations.make_plan(
                stack=self.stack,
                status=backend.current,
                action="recover",
                created_at=delayed,
            )
            receipt = self.apply(
                self.manager(backend, directory, clock=delayed + 100), recover
            )
            self.assertEqual(receipt["result"], "verified")
            self.assertTrue(backend.seen_actions)
            self.assertEqual(set(backend.seen_actions), {"recover"})

    def test_commit_decision_recovers_publication_without_provider_replay(self) -> None:
        initial = status_for(self.stack)
        for phase in ("commit-decided", "receipt-published"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                backend = FakeBackend(self.stack, initial)

                def crash(observed: str) -> None:
                    if observed == phase:
                        raise manager_module.SimulatedHardCrash(observed)

                action = self.plan("activate", initial)
                manager = self.manager(backend, directory, crash_hook=crash)
                with self.assertRaises(manager_module.SimulatedHardCrash):
                    self.apply(manager, action)
                self.assertEqual(backend.provider_calls, ["activate"])

                reconciler = self.manager(backend, directory)
                with reconciler.locked():
                    reconciler._reconcile_decided_commits()
                self.assertEqual(backend.provider_calls, ["activate"])
                journal = manager_module.trusted_json(
                    Path(directory) / "state" / f"{action['action_id']}.json",
                    os.geteuid(),
                )
                self.assertEqual(journal["phase"], "committed")
                receipt = operations.validate_receipt(json.loads(
                    (Path(directory) / "receipts" / f"{action['action_id']}.json")
                    .read_text(encoding="ascii")
                ))
                self.assertEqual(receipt["plan_sha256"], action["plan_sha256"])

    def test_terminal_journals_archive_without_capacity_brick_or_replay(self) -> None:
        initial = status_for(self.stack)
        backend = FakeBackend(self.stack, initial)
        with tempfile.TemporaryDirectory() as directory:
            first: dict | None = None
            for _index in range(manager_module.MAX_RECORDS + 2):
                action = self.plan("status-verify", backend.current)
                first = action if first is None else first
                receipt = self.apply(self.manager(backend, directory), action)
                self.assertEqual(receipt["result"], "verified")
            self.assertEqual(
                list((Path(directory) / "state").glob("*.json")), []
            )
            self.assertEqual(
                len(list((Path(directory) / "state" / "archive").glob("*.json"))),
                manager_module.MAX_RECORDS + 2,
            )
            assert first is not None
            with self.assertRaisesRegex(
                manager_module.NativeStackManagerError, "action_replay"
            ):
                self.apply(self.manager(backend, directory), first)


class NativeStackOperationTests(unittest.TestCase):
    def test_operation_module_imports_without_exposing_secret_fields(self) -> None:
        path = ROOT / "scripts/native-stack-operation.py"
        spec = importlib.util.spec_from_file_location("native_stack_operation", path)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        source = path.read_text(encoding="utf-8")
        self.assertNotIn("client_secret", source)
        self.assertNotIn("refresh_token", source)
        self.assertNotIn("access_token", source)


if __name__ == "__main__":
    unittest.main()
