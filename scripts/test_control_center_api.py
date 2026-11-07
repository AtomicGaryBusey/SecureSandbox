import importlib.util
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from shared.harness_runtime_binding import make_binding as make_harness_binding
from shared.model_stack_runtime_binding import (
    BROKERED_MODE,
    make_binding as make_model_stack_binding,
    make_brokered_binding,
)
from shared.runtime_authority import make_binding as make_runtime_authority
from shared.session_context_binding import make_binding as make_session_context_binding
from shared import native_stack_catalog_promotion
from shared import native_stack_operations
from shared import native_stack_session
from shared import native_codex_ui_handle
from shared import native_terminal_handle
from shared import native_program_attestation
from shared import native_projection_identity_recovery
from shared import native_projection_reconciliation
from shared import native_vendor_stack
from shared.test_native_vendor_stack import anthropic_stack, openai_stack
from scripts.test_native_stack_manager import runtime_for, status_for


SPEC = importlib.util.spec_from_file_location(
    "control_center_api", Path(__file__).with_name("control-center-api.py")
)
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


class CatalogTests(unittest.TestCase):
    @staticmethod
    def _custody_test_harness(
        root: Path, *, ignore_term: bool = False,
    ) -> tuple[Path, Path, Path, Path]:
        child_pid = root / "custody-child.pid"
        nested_pid = root / "custody-nested.pid"
        request = root / "one-shot-request.json"
        child = root / "custody-child.py"
        normal_body = (
            "def run(_arguments=None):\n"
            "  child_pid.write_text(str(os.getpid()))\n"
            "  request.write_bytes(b'pending')\n"
            "  nested=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "  nested_pid.write_text(str(nested.pid))\n"
            "  try:\n"
            "    time.sleep(30)\n"
            "  finally:\n"
            "    try: request.unlink()\n"
            "    except FileNotFoundError: pass\n"
            "    try: nested.wait(timeout=3)\n"
            "    except subprocess.TimeoutExpired:\n"
            "      nested.kill();nested.wait(timeout=3)\n"
            "  return 0\n"
            "operation._main=run\n"
            "raise SystemExit(operation.main([]))\n"
        )
        ignoring_body = (
            "import signal\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "operation.start_supervisor_liveness_monitor()\n"
            "child_pid.write_text(str(os.getpid()))\n"
            "request.write_bytes(b'pending')\n"
            "nested=subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "nested_pid.write_text(str(nested.pid))\n"
            "time.sleep(30)\n"
        )
        child.write_text(
            "import importlib.util,os,pathlib,subprocess,sys,time\n"
            f"module_path=pathlib.Path({str(Path(__file__).with_name('native-stack-operation.py'))!r})\n"
            "spec=importlib.util.spec_from_file_location('custody_operation',module_path)\n"
            "operation=importlib.util.module_from_spec(spec);spec.loader.exec_module(operation)\n"
            f"child_pid=pathlib.Path({str(child_pid)!r});nested_pid=pathlib.Path({str(nested_pid)!r});request=pathlib.Path({str(request)!r})\n"
            + (ignoring_body if ignore_term else normal_body),
            encoding="utf-8",
        )
        harness = root / "custody-api.py"
        harness.write_text(
            "import importlib.util,pathlib,sys\n"
            f"module_path=pathlib.Path({str(Path(__file__).with_name('control-center-api.py'))!r})\n"
            "spec=importlib.util.spec_from_file_location('custody_api',module_path)\n"
            "api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)\n"
            "def run():\n"
            f"  pathlib.Path({str(root / 'staged-input.bin')!r}).write_bytes(sys.stdin.buffer.read())\n"
            f"  api.bounded_command([sys.executable,{str(child)!r}],timeout=30,env={{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}},supervise_on_parent_exit=True)\n"
            "  return 0\n"
            "api._main=run\n"
            "raise SystemExit(api.main())\n",
            encoding="utf-8",
        )
        return harness, child_pid, nested_pid, request

    @staticmethod
    def _wait_for_paths(*paths: Path) -> None:
        deadline = time.monotonic() + 5
        while not all(path.exists() for path in paths):
            if time.monotonic() >= deadline:
                raise AssertionError("custody child did not become ready")
            time.sleep(0.02)

    def _assert_process_inactive(self, pid: int) -> None:
        deadline = time.monotonic() + 9
        while True:
            status = subprocess.run(
                ["/bin/ps", "-o", "stat=", "-p", str(pid)],
                capture_output=True, text=True, check=False,
            ).stdout.strip()
            if not status or status.startswith("Z"):
                return
            if time.monotonic() >= deadline:
                self.fail(f"residual process {pid} stayed active: {status}")
            time.sleep(0.02)

    @staticmethod
    def native_status(stack: dict) -> dict:
        now = int(time.time())
        observed = {"state": "signed-out", "observed_at": now,
                    "evidence_sha256": "1" * 64}
        return native_stack_operations.make_status(
            stack=stack,
            harness={"state": "admitted", "observed_at": now,
                     "evidence_sha256": "2" * 64,
                     "generation_id": stack["harness"]["generation_id"],
                     "binding_sha256": "3" * 64},
            authentication=observed,
            credential_custody={"state": "absent", "observed_at": now,
                                "evidence_sha256": "4" * 64,
                                "tombstone_sha256": "5" * 64,
                                "projection_count": 0},
            account_binding={"state": "unbound", "observed_at": now,
                             "evidence_sha256": "6" * 64,
                             "account_subject_sha256": None,
                             "workspace_sha256": None},
            program_entitlement={"state": "unknown", "observed_at": now,
                                 "evidence_sha256": "7" * 64,
                                 "assurance": "unknown"},
            model_entitlement={"state": "unknown", "observed_at": now,
                               "evidence_sha256": "8" * 64,
                               "assurance": "unknown"},
            network={"phase": "closed", "grant_sha256": None,
                     "expires_at": None, "observed_at": now},
            activation={"state": "inactive", "observed_at": now,
                        "evidence_sha256": "9" * 64,
                        "receipt_sha256": None},
            live_run_count=0,
        )

    @staticmethod
    def attestable_native_status(stack: dict) -> dict:
        now = int(time.time())
        return native_stack_operations.make_status(
            stack=stack,
            harness={"state": "admitted", "observed_at": now,
                     "evidence_sha256": "2" * 64,
                     "generation_id": stack["harness"]["generation_id"],
                     "binding_sha256": "3" * 64},
            authentication={"state": "signed-in", "observed_at": now,
                            "evidence_sha256": "1" * 64},
            credential_custody={"state": "retained", "observed_at": now,
                                "evidence_sha256": "4" * 64,
                                "tombstone_sha256": None,
                                "projection_count": 0},
            account_binding={
                "state": "bound", "observed_at": now,
                "evidence_sha256": "6" * 64,
                "account_subject_sha256": stack["account_binding"][
                    "account_subject_sha256"
                ],
                "workspace_sha256": stack["account_binding"][
                    "workspace_sha256"
                ],
            },
            program_entitlement={"state": "unknown", "observed_at": now,
                                 "evidence_sha256": "7" * 64,
                                 "assurance": "unknown"},
            model_entitlement={"state": "verified", "observed_at": now,
                               "evidence_sha256": "8" * 64,
                               "assurance": "provider-enforced"},
            network={"phase": "closed", "grant_sha256": None,
                     "expires_at": None, "observed_at": now},
            activation={"state": "inactive", "observed_at": now,
                        "evidence_sha256": "9" * 64,
                        "receipt_sha256": None},
            live_run_count=0,
        )

    @staticmethod
    def lease_fixture(run_id: str, lease_id: str, *, expires_at: int = 1000,
                      renewals: int = 0, summary: bool = False) -> dict:
        harness = make_harness_binding(
            harness_id="claude-code", generation_id="1" * 64,
            manifest_sha256="2" * 64, executable_sha256="3" * 64,
            inventory_sha256="4" * 64, adapter_id="claude-core-v1",
            adapter_sha256="5" * 64,
        )
        brokered = make_brokered_binding(
            adapter="anthropic-messages-v1", model="abliterated-model-large-v2",
            profile_id="abliterated-glm", profile_sha256="6" * 64,
            provider_mode="mock", vendor_id="abliteration",
        )
        model_stack = make_model_stack_binding(BROKERED_MODE, brokered)
        context = make_session_context_binding(
            session_id="33333333-3333-4333-8333-333333333333",
            source_id=None, source_manifest_sha256=None,
            persona_sha256="7" * 64, tool_catalog_sha256="8" * 64,
            extension_set_sha256="9" * 64,
        )
        authority = make_runtime_authority(
            model_stack_binding=model_stack,
            session_context_binding=context,
            harness_binding=harness,
        )
        lease = {
            "schema": "secure-sandbox-run-lease-v3", "run_id": run_id,
            "lease_id": lease_id, "profile": "standard", "issued_at": 900,
            "expires_at": expires_at, "maximum_expires_at": 2000,
            "runtime_authority": authority,
            "brokered_transport": {
                "schema": "secure-sandbox-brokered-run-transport-v1",
                "relay_sha256": "a" * 64, "policy_sha256": "b" * 64,
            },
            "limits": {"max_requests": 10, "max_input_tokens": 1000,
                       "max_output_tokens": 1000, "max_cost_microusd": 1000},
            "pricing": {"input_microusd_per_million_tokens": 1,
                        "output_microusd_per_million_tokens": 1},
            "renewals": renewals,
        }
        counters = {
            "schema": "secure-sandbox-run-lease-counter-v1", "run_id": run_id,
            "lease_id": lease_id, "requests": 2, "input_tokens": 3,
            "output_tokens": 4, "cost_microusd": 1, "reservations": {},
            "settled_reservations": [], "updated_at": 950,
        }
        final = None
        if summary:
            final = {"schema": "secure-sandbox-run-lease-summary-v2",
                     "lease": lease, "final_counters": counters,
                     "finalized_at": max(expires_at, 1000), "reason": "completed"}
        return {"lease": lease, "counters": counters, "summary": final}

    @staticmethod
    def acceptance_catalog():
        cases = []
        for index in range(1, 92):
            kinds = ["readback", "receipt"]
            if index <= 16:
                kinds.append("boundary")
            procedure = {"schema": "secure-sandbox-harness-lifecycle-acceptance-procedure-v1",
                         "case_id": f"case-{index}", "driver": "test-driver",
                         "baseline": "test-baseline", "action": f"case-{index}",
                         "interaction": "none", "network": "no-new-egress",
                         "interruption_checkpoint": None,
                         "postcondition": "protected-state-unchanged",
                         "reset": "restore-test-baseline"}
            procedure["procedure_sha256"] = hashlib.sha256((json.dumps(
                procedure, ensure_ascii=True, allow_nan=False,
                separators=(",", ":"), sort_keys=True,
            ) + "\n").encode("ascii")).hexdigest()
            cases.append({"case_id": f"case-{index}", "category": "example",
                          "expected": "passed", "evidence_kinds": kinds,
                          "collectors": {kind: "secure-sandbox-host-controller-v1"
                                         for kind in kinds},
                          "procedure": procedure,
                          "requires_touch_id": False, "requires_reboot": False,
                          "destructive": False})
        return {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-catalog-v1",
            "suite_id": "secure-sandbox-disposable-mac-harness-lifecycle-v4",
            "suite_sha256": "a" * 64,
            "case_count": 91,
            "authority": "none",
            "cases": cases,
        }

    def test_harness_acceptance_status_is_read_only_and_absent_is_not_enrolled(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(API, "_harness_acceptance_json",
                             return_value=self.acceptance_catalog()):
            value = API.harness_acceptance_status(Path(temporary) / "absent")
        self.assertEqual(value["availability"], "not-enrolled")
        self.assertEqual(value["reason"], "campaign_absent")
        self.assertEqual(value["authority"], "none")
        self.assertEqual(value["observation_count"], 198)

    def test_native_stack_settings_bridge_preserves_inert_readiness(self):
        value = API.native_vendor_stack_settings()
        self.assertEqual(
            value["schema"],
            "secure-sandbox-native-vendor-stack-catalog-status-v1",
        )
        self.assertEqual(value["source"], "example")
        self.assertEqual(
            {item["readiness"]["status"] for item in value["stacks"]},
            {"configuration-required"},
        )

    def test_native_stack_settings_bridge_rejects_false_ready_state(self):
        valid = API.native_vendor_stack_settings()
        valid["stacks"][0]["readiness"]["status"] = "active"
        completed = subprocess.CompletedProcess(
            ["native-vendor-stack-config.py"],
            0,
            json.dumps(valid).encode("utf-8"),
            b"",
        )
        with patch.object(API.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "native_stack_settings_invalid"):
                API.native_vendor_stack_settings()

    def test_native_stack_action_plan_is_exact_and_one_shot_staged(self):
        stack = anthropic_stack()
        catalog = {"schema": native_vendor_stack.CATALOG_SCHEMA, "stacks": [stack]}
        status = self.native_status(stack)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "catalog.json"
            staged.write_bytes(native_vendor_stack.canonical_bytes(catalog))
            staged.chmod(0o600)
            plans = root / "plans"
            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", staged), \
                    patch.object(API, "NATIVE_STACK_PLAN_ROOT", plans):
                plan = API.native_stack_action_plan(
                    "signin-begin", stack["stack_id"],
                    native_stack_operations.canonical_bytes(status), None, None,
                )
                path = plans / f'{plan["action_id"]}.json'
                self.assertEqual(
                    path.read_bytes(), native_stack_operations.canonical_bytes(plan)
                )
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(plan["current_status_sha256"], status["status_sha256"])

    def test_native_stack_action_authorize_removes_local_plan_after_receipt(self):
        stack = anthropic_stack()
        status = self.native_status(stack)
        plan = native_stack_operations.make_plan(
            stack=stack, status=status, action="signin-begin"
        )
        receipt = native_stack_operations.make_receipt(
            plan=plan, status=status, result="verified", evidence_sha256="a" * 64
        )
        completed = subprocess.CompletedProcess(
            ["native-stack-operation"], 0,
            native_stack_operations.canonical_bytes(receipt), b"",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = API._write_private_plan(
                root, plan["action_id"], native_stack_operations.canonical_bytes(plan)
            )
            with patch.object(API, "NATIVE_STACK_PLAN_ROOT", root), \
                    patch.object(API, "bounded_command", return_value=completed):
                observed = API.native_stack_action_authorize(
                    plan["action_id"], plan["plan_sha256"],
                    "Control Center", "11111111-1111-4111-8111-111111111111",
                )
            self.assertEqual(observed, receipt)
            self.assertFalse(path.exists())

    def test_program_attestation_has_distinct_plan_and_touchid_surface(self):
        stack = anthropic_stack()
        catalog = {
            "schema": native_vendor_stack.CATALOG_SCHEMA, "stacks": [stack],
        }
        catalog_raw = native_vendor_stack.canonical_bytes(catalog)
        catalog_sha256 = hashlib.sha256(catalog_raw).hexdigest()
        status = self.attestable_native_status(stack)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = root / "catalog.json"
            staged.write_bytes(catalog_raw)
            staged.chmod(0o600)
            plans = root / "program-plans"
            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", staged), \
                    patch.object(
                        API, "NATIVE_PROGRAM_ATTESTATION_PLAN_ROOT", plans
                    ):
                plan = API.native_program_attestation_plan(
                    stack["stack_id"], catalog_sha256,
                    native_stack_operations.canonical_bytes(status),
                )
            self.assertEqual(plan["assurance"], "operator-external")
            self.assertEqual(plan["catalog_sha256"], catalog_sha256)
            self.assertEqual(plan["status_sha256"], status["status_sha256"])
            path = plans / f'{plan["attestation_id"]}.json'
            self.assertEqual(
                path.read_bytes(), native_program_attestation.canonical_bytes(plan)
            )

            result = {
                "schema": "secure-sandbox-native-stack-provider-result-v1",
                "action_id": plan["attestation_id"],
                "action": "program-attest",
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": "d" * 64,
                "status": "verified",
                "evidence_sha256": "e" * 64,
            }
            completed = subprocess.CompletedProcess(
                ["authorization_broker"], 0,
                native_program_attestation.canonical_bytes(result), b"",
            )
            with patch.object(
                    API, "NATIVE_PROGRAM_ATTESTATION_PLAN_ROOT", plans
                 ), patch.object(API, "bounded_command", return_value=completed):
                observed = API.native_program_attestation_authorize(
                    plan["attestation_id"], plan["plan_sha256"],
                    "Control Center", "11111111-1111-4111-8111-111111111111",
                )
            self.assertEqual(observed, result)
            self.assertFalse(path.exists())

    def test_program_attestation_rejects_unpromoted_catalog(self):
        stack = anthropic_stack()
        catalog = {
            "schema": native_vendor_stack.CATALOG_SCHEMA, "stacks": [stack],
        }
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary) / "catalog.json"
            staged.write_bytes(native_vendor_stack.canonical_bytes(catalog))
            staged.chmod(0o600)
            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", staged):
                with self.assertRaisesRegex(
                    ValueError, "native_program_attestation_input_changed"
                ):
                    API.native_program_attestation_plan(
                        stack["stack_id"], "f" * 64,
                        native_stack_operations.canonical_bytes(
                            self.attestable_native_status(stack)
                        ),
                    )

    def test_native_session_authorize_returns_vendor_specific_result(self):
        stack = anthropic_stack()
        authority = runtime_for(stack)
        status = status_for(stack, activation="active")
        now = int(time.time())
        for action in ("session-start", "session-stop"):
            with self.subTest(action=action):
                action_id = str(__import__("uuid").uuid4())
                plan = native_stack_session.make_plan(
                    action=action, action_id=action_id,
                    session_id=authority["session_context_binding"][
                        "session_id"
                    ],
                    stack_id=stack["stack_id"],
                    stack_sha256=native_vendor_stack.stack_revision(stack),
                    catalog_sha256="1" * 64,
                    status_sha256=status["status_sha256"],
                    runtime_authority_value=authority,
                    source_id=None, source_manifest_sha256=None,
                    resume_session_id=None,
                    lease_profile_id=(
                        "interactive" if action == "session-start" else None
                    ),
                    created_at=now,
                )
                if action == "session-start":
                    record = native_terminal_handle.make_record(
                        handle_id=str(__import__("uuid").uuid4()),
                        kind="claude-session", operation_id=action_id,
                        plan_sha256=plan["plan_sha256"],
                        authorization_sha256="2" * 64,
                        stack_sha256=plan["stack_sha256"],
                        catalog_sha256=plan["catalog_sha256"],
                        session_id=plan["session_id"],
                        remote_arguments=[action_id, "3" * 64],
                        issued_at=now, expires_at=now + 120,
                    )
                    expected = native_terminal_handle.public_record(record)
                    output = native_terminal_handle.canonical_bytes(expected)
                else:
                    expected = {
                        "schema": (
                            "secure-sandbox-native-claude-session-stop-reply-v1"
                        ),
                        "operation_id": action_id,
                        "session_id": plan["session_id"], "state": "absent",
                        "final_summary_sha256": "4" * 64,
                        "evidence_sha256": "5" * 64,
                    }
                    output = native_stack_session.canonical_bytes(expected)
                completed = subprocess.CompletedProcess(
                    ["authorization_broker"], 0, output, b""
                )
                with patch.object(
                    API, "bounded_command", return_value=completed
                ) as run:
                    observed = API.native_session_authorize(
                        action_id, plan["plan_sha256"], "Control Center",
                        "11111111-1111-4111-8111-111111111111",
                        native_stack_session.canonical_bytes(plan),
                    )
                self.assertEqual(observed, expected)
                command = run.call_args.args[0]
                self.assertIn(f"native-{action}", command)
                self.assertEqual(
                    command[command.index("--resource") + 1],
                    "Native vendor harness session authority",
                )

    def test_native_session_authorize_exactly_validates_codex_typed_ui_handle(self):
        stack = openai_stack()
        authority = runtime_for(stack)
        status = status_for(stack, activation="active")
        now = int(time.time())
        action_id = str(__import__("uuid").uuid4())
        plan = native_stack_session.make_plan(
            action="session-start", action_id=action_id,
            session_id=authority["session_context_binding"]["session_id"],
            stack_id=stack["stack_id"],
            stack_sha256=native_vendor_stack.stack_revision(stack),
            catalog_sha256="1" * 64, status_sha256=status["status_sha256"],
            runtime_authority_value=authority,
            source_id=None, source_manifest_sha256=None,
            resume_session_id=None, lease_profile_id="interactive",
            created_at=now,
        )
        lease = native_stack_session.make_session_lease(
            lease_profile_id="interactive", session_id=plan["session_id"],
            runtime_authority_sha256=plan["runtime_authority_sha256"],
            grant_id=str(__import__("uuid").uuid4()), grant_sha256="2" * 64,
            issued_at=now, expires_at=now + 3600,
        )
        record = native_codex_ui_handle.make_record(
            handle_id=str(__import__("uuid").uuid4()),
            operation_id=action_id, plan_sha256=plan["plan_sha256"],
            authorization_sha256="3" * 64,
            stack_sha256=plan["stack_sha256"],
            catalog_sha256=plan["catalog_sha256"],
            session_id=plan["session_id"],
            runtime_authority_sha256=plan["runtime_authority_sha256"],
            harness_generation_id=authority["harness_binding"][
                "harness_generation_id"
            ],
            harness_executable_sha256=authority["harness_binding"][
                "harness_executable_sha256"
            ],
            session_lease=lease, issued_at=now, expires_at=now + 120,
        )
        expected = native_codex_ui_handle.public_record(record)
        completed = subprocess.CompletedProcess(
            ["authorization_broker"], 0,
            native_codex_ui_handle.canonical_bytes(expected), b"",
        )
        with patch.object(API, "bounded_command", return_value=completed):
            observed = API.native_session_authorize(
                action_id, plan["plan_sha256"], "Control Center",
                "11111111-1111-4111-8111-111111111111",
                native_stack_session.canonical_bytes(plan),
            )
        self.assertEqual(observed, expected)
        changed = dict(expected, unexpected=None)
        rejected = subprocess.CompletedProcess(
            ["authorization_broker"], 0,
            native_codex_ui_handle.canonical_bytes(changed), b"",
        )
        with patch.object(API, "bounded_command", return_value=rejected), \
                self.assertRaisesRegex(
                    ValueError, "native_session_authorization_result_invalid"
                ):
            API.native_session_authorize(
                action_id, plan["plan_sha256"], "Control Center",
                "11111111-1111-4111-8111-111111111111",
                native_stack_session.canonical_bytes(plan),
            )

    def test_projection_reconciliation_authorize_is_exact_and_distinct(self):
        now = int(time.time())
        plan = native_projection_reconciliation.make_plan(
            recovery_operation_id=str(__import__("uuid").uuid4()),
            original_operation_id=str(__import__("uuid").uuid4()),
            session_id="00000000-0000-4000-8000-000000000009",
            stack_id="codex-daybreak-blue-native",
            stack_sha256="1" * 64,
            session_authority_sha256="2" * 64,
            process_identifier=4242, process_start_time_us=123456,
            consumer_executable_sha256="3" * 64,
            guest_absence_evidence_sha256="4" * 64,
            egress_closed_evidence_sha256="5" * 64,
            host_release_id="6" * 64, created_at=now,
        )
        body = {
            "outcome": "verified",
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "process_identifier": plan["process_identifier"],
            "process_start_time_us": plan["process_start_time_us"],
            "consumer_executable_sha256": plan[
                "consumer_executable_sha256"
            ],
            "session_authority_sha256": plan[
                "session_authority_sha256"
            ],
            "reconciliation_evidence_sha256": "7" * 64,
        }
        result = {
            "schema": native_projection_reconciliation.REPLY_SCHEMA,
            **body,
            "reply_sha256": native_projection_reconciliation.sha256(body),
        }
        completed = subprocess.CompletedProcess(
            ["authorization_broker"], 0,
            native_projection_reconciliation.canonical_bytes(result), b"",
        )
        with patch.object(
            API, "bounded_command", return_value=completed
        ) as run:
            observed = API.native_projection_reconciliation_authorize(
                plan["recovery_operation_id"], plan["plan_sha256"],
                "Control Center",
                "11111111-1111-4111-8111-111111111111",
                native_projection_reconciliation.canonical_bytes(plan),
            )
        self.assertEqual(observed, result)
        command = run.call_args.args[0]
        self.assertIn(native_projection_reconciliation.OPERATION, command)
        self.assertEqual(
            command[command.index("--resource") + 1],
            native_projection_reconciliation.RESOURCE,
        )
        hostile = dict(result, process_identifier=4243)
        rejected = subprocess.CompletedProcess(
            ["authorization_broker"], 0,
            native_projection_reconciliation.canonical_bytes(hostile), b"",
        )
        with patch.object(API, "bounded_command", return_value=rejected), \
                self.assertRaisesRegex(
                    ValueError, "reconciliation_result_invalid"
                ):
            API.native_projection_reconciliation_authorize(
                plan["recovery_operation_id"], plan["plan_sha256"],
                "Control Center",
                "11111111-1111-4111-8111-111111111111",
                native_projection_reconciliation.canonical_bytes(plan),
            )

    def test_projection_identity_recovery_authorize_is_exact_and_distinct(self):
        now = int(time.time())
        plan = native_projection_identity_recovery.make_plan(
            recovery_operation_id=str(__import__("uuid").uuid4()),
            original_operation_id=str(__import__("uuid").uuid4()),
            session_id="00000000-0000-4000-8000-000000000009",
            stack_id="codex-daybreak-blue-native",
            stack_sha256="1" * 64,
            session_authority_sha256="2" * 64,
            host_release_id="3" * 64,
            created_at=now,
        )
        body = {
            "outcome": "verified",
            "recovery_operation_id": plan["recovery_operation_id"],
            "original_operation_id": plan["original_operation_id"],
            "process_identifier": 4242,
            "process_start_time_us": 123456,
            "consumer_executable_sha256": "4" * 64,
            "session_authority_sha256": plan[
                "session_authority_sha256"
            ],
            "identity_evidence_sha256": "5" * 64,
        }
        result = {
            "schema": native_projection_identity_recovery.REPLY_SCHEMA,
            **body,
            "reply_sha256": native_projection_identity_recovery.sha256(body),
        }
        completed = subprocess.CompletedProcess(
            ["authorization_broker"], 0,
            native_projection_identity_recovery.canonical_bytes(result), b"",
        )
        with patch.object(
            API, "bounded_command", return_value=completed
        ) as run:
            observed = API.native_projection_identity_recovery_authorize(
                plan["recovery_operation_id"], plan["plan_sha256"],
                "Control Center",
                "11111111-1111-4111-8111-111111111111",
                native_projection_identity_recovery.canonical_bytes(plan),
            )
        self.assertEqual(observed, result)
        command = run.call_args.args[0]
        self.assertIn(native_projection_identity_recovery.OPERATION, command)
        self.assertEqual(
            command[command.index("--resource") + 1],
            native_projection_identity_recovery.RESOURCE,
        )
        self.assertNotIn("reconcile", " ".join(command).lower())
        hostile = dict(result, process_identifier=4243)
        rejected = subprocess.CompletedProcess(
            ["authorization_broker"], 0,
            native_projection_identity_recovery.canonical_bytes(hostile), b"",
        )
        with patch.object(API, "bounded_command", return_value=rejected), \
                self.assertRaisesRegex(
                    ValueError, "identity_recovery_result_invalid"
                ):
            API.native_projection_identity_recovery_authorize(
                plan["recovery_operation_id"], plan["plan_sha256"],
                "Control Center",
                "11111111-1111-4111-8111-111111111111",
                native_projection_identity_recovery.canonical_bytes(plan),
            )

    def test_native_catalog_promotion_plan_and_receipt_remain_distinct_authority(self):
        now = int(time.time())
        plan = native_stack_catalog_promotion.make_plan(
            source_uid=os.geteuid(), source_sha256="a" * 64,
            previous_catalog_sha256="b" * 64, host_release_id="c" * 64,
            now=now,
        )
        plan_completed = subprocess.CompletedProcess(
            ["native-stack-catalog-promoter"], 0,
            native_stack_catalog_promotion.canonical_bytes(plan), b"",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "catalog.json"
            catalog.write_bytes(b"placeholder")
            promotion_plans = root / "plans"
            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", catalog), \
                    patch.object(API, "NATIVE_STACK_PROMOTION_PLAN_ROOT", promotion_plans), \
                    patch.object(API.subprocess, "run", return_value=plan_completed):
                observed_plan = API.native_stack_catalog_promotion_plan(
                    "b" * 64, "c" * 64
                )
            body = {
                "promotion_id": plan["promotion_id"],
                "plan_sha256": plan["plan_sha256"],
                "authorization_sha256": "d" * 64,
                "authorization_receipt_sha256": "e" * 64,
                "source_sha256": plan["source_sha256"],
                "previous_catalog_sha256": plan["previous_catalog_sha256"],
                "catalog_sha256": plan["catalog_sha256"],
                "host_release_id": plan["host_release_id"],
                "promoted_at": now + 1,
                "status": "authorized-for-publication",
            }
            receipt = {
                "schema": native_stack_catalog_promotion.RECEIPT_SCHEMA,
                **body,
                "receipt_sha256": native_stack_catalog_promotion.sha256(body),
            }
            receipt_completed = subprocess.CompletedProcess(
                ["authorization_broker"], 0,
                native_stack_catalog_promotion.canonical_bytes(receipt),
                b"SecureSandbox approval request\n",
            )
            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", catalog), \
                    patch.object(API, "NATIVE_STACK_PROMOTION_PLAN_ROOT", promotion_plans), \
                    patch.object(
                        API, "bounded_command", return_value=receipt_completed
                    ) as authorize_run:
                observed_receipt = API.native_stack_catalog_promotion_authorize(
                    plan["promotion_id"], plan["plan_sha256"], "Control Center",
                    "22222222-2222-4222-8222-222222222222",
                )
            self.assertEqual(observed_plan, plan)
            self.assertEqual(observed_receipt, receipt)
            self.assertEqual(
                authorize_run.call_args.kwargs["timeout"],
                API.NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS,
            )
            self.assertFalse((promotion_plans / f'{plan["promotion_id"]}.json').exists())

            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", catalog), \
                    patch.object(API, "NATIVE_STACK_PROMOTION_PLAN_ROOT", promotion_plans), \
                    patch.object(API.subprocess, "run", return_value=plan_completed):
                API.native_stack_catalog_promotion_plan("b" * 64, "c" * 64)
            oversized_diagnostic = subprocess.CompletedProcess(
                ["authorization_broker"], 0,
                native_stack_catalog_promotion.canonical_bytes(receipt),
                b"x" * (API.NATIVE_PRIVILEGED_STDERR_LIMIT + 1),
            )
            with patch.object(API, "NATIVE_STACK_STAGED_CATALOG", catalog), \
                    patch.object(API, "NATIVE_STACK_PROMOTION_PLAN_ROOT", promotion_plans), \
                    patch.object(
                        API, "bounded_command", return_value=oversized_diagnostic
                    ), self.assertRaisesRegex(
                        ValueError, "native_catalog_promotion_authorization_rejected"
                    ):
                API.native_stack_catalog_promotion_authorize(
                    plan["promotion_id"], plan["plan_sha256"], "Control Center",
                    "22222222-2222-4222-8222-222222222222",
                )

    def test_harness_acceptance_status_verifies_campaign_projection(self):
        catalog = self.acceptance_catalog()
        missing = [{"case_id": case["case_id"], "evidence_kinds": case["evidence_kinds"]}
                   for case in catalog["cases"]]
        status = {"schema": "secure-sandbox-harness-lifecycle-acceptance-status-v1",
                  "campaign_id": "campaign", "suite_sha256": "a" * 64,
                  "case_count": 91, "observation_count": 198,
                  "completed_case_count": 0, "completed_cases": [],
                  "missing": missing,
                  "next_case": "case-1", "ready_for_assembly": False, "authority": "none"}
        next_value = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-next-v1",
            "campaign_id": "campaign", "suite_sha256": "a" * 64,
            "status": "pending", "case": catalog["cases"][0],
            "missing_evidence": [
                {"kind": kind, "collector": catalog["cases"][0]["collectors"][kind]}
                for kind in catalog["cases"][0]["evidence_kinds"]
            ],
            "authority": "none",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "campaign"
            root.mkdir(mode=0o700)
            (root / "campaign.json").write_text("{}", encoding="ascii")
            (root / "observations").mkdir(mode=0o700)
            def response(*arguments):
                if arguments == ("catalog",):
                    return catalog
                return next_value if arguments[0] == "next" else status
            with patch.object(API, "_harness_acceptance_json", side_effect=response):
                value = API.harness_acceptance_status(root)
                status["authority"] = "admission"
                rejected = API.harness_acceptance_status(root)
        self.assertEqual(value["availability"], "available")
        self.assertIs(value["status"], status)
        self.assertIs(value["next"], next_value)
        self.assertEqual(rejected["availability"], "rejected")
        self.assertEqual(rejected["reason"], "campaign_status_invalid")

    def test_harness_acceptance_status_rejects_untrusted_campaign_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "campaign"
            root.mkdir(mode=0o755)
            with patch.object(API, "_harness_acceptance_json",
                              return_value=self.acceptance_catalog()):
                value = API.harness_acceptance_status(root)
        self.assertEqual(value["availability"], "rejected")
        self.assertEqual(value["reason"], "campaign_root_untrusted")

    def test_harness_generation_plan_is_stored_and_summarized_without_authority(self):
        wrapper = {"schema":"secure-sandbox-harness-consumer-plan-v1",
                   "stage_id":"11111111-1111-4111-8111-111111111111",
                   "wrapper_sha256":"a" * 64,
                   "plan":{"operation":"rollback", "expires_at":2_000_000_300,
                           "candidate":{"generation_id":"b" * 64}}, "reference":None}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(API, "_harness_operation", return_value=wrapper), \
                patch.object(API, "HARNESS_PLAN_ROOT", Path(temporary) / "plans"):
            value = API.harness_generation_plan("rollback", "b" * 64, None)
            self.assertEqual(value["schema"], "secure-sandbox-harness-control-center-plan-v1")
            self.assertEqual(value["plan_sha256"], "a" * 64)
            self.assertTrue((Path(temporary) / "plans" / f'{wrapper["stage_id"]}.json').is_file())

    def test_harness_status_preserves_zero_authority_and_fails_closed_without_consumer(self):
        lifecycle = {"authority": "none", "automatic_download": False,
                     "automatic_install": False, "floor": None, "generations": [],
                     "policy_configured": False, "policy_sha256": None,
                     "schema": "secure-sandbox-harness-lifecycle-status-v1"}
        def response(command, *, timeout=60):
            if command == ("status",):
                return lifecycle
            raise API.HarnessBridgeError("operation_invalid", "operation_invalid")
        with patch.object(API, "_harness_json", side_effect=response):
            value = API.harness_status()
        self.assertEqual(value["protected"]["availability"], "unavailable")
        self.assertFalse(value["protected_actions"]["activate"])
        self.assertTrue(value["protected_actions"]["requires_touch_id"])
        self.assertFalse(value["protected_actions"]["password_fallback"])
        def tampered(command, *, timeout=60):
            if command == ("status",):
                return lifecycle
            raise API.HarnessBridgeError("protected_store_io_failed", "protected_store_io_failed")
        with patch.object(API, "_harness_json", side_effect=tampered):
            rejected = API.harness_status()
        self.assertEqual(rejected["protected"]["availability"], "rejected")
        self.assertEqual(rejected["protected"]["reason"], "protected_status_verification_failed")

    def test_harness_release_catalog_requires_signed_metadata_authority(self):
        digest = "a" * 64
        release = {"generation_id": digest,
                   "artifact": {"sha256": digest}, "evidence": [],
                   "compatibility": {"adapter_sha256": digest}}
        catalog = {"schema": "secure-sandbox-harness-release-catalog-v1",
                   "authority": "signed-metadata-only", "sequence": 1,
                   "envelope_sha256": digest, "policy_sha256": digest,
                   "releases": [release]}
        with patch.object(API, "_harness_json", return_value=catalog):
            self.assertEqual(API.harness_releases()["releases"][0]["generation_id"], digest)
        catalog["authority"] = "admitted"
        with patch.object(API, "_harness_json", return_value=catalog):
            with self.assertRaisesRegex(ValueError, "catalog"):
                API.harness_releases()

    def test_harness_fixture_report_cannot_claim_admission(self):
        report = {"schema": "secure-sandbox-harness-qualification-report-v1",
                  "status": "fixture_qualified", "authority": "none",
                  "note": "fixture_qualified_not_admitted", "report_sha256": "b" * 64,
                  "case_results": [{"status": "passed", "failures": []}]}
        with patch.object(API, "_harness_json", return_value=report):
            self.assertEqual(API.harness_action("qualify-self-test")["authority"], "none")
        report["authority"] = "admission"
        with patch.object(API, "_harness_json", return_value=report):
            with self.assertRaisesRegex(ValueError, "self-test"):
                API.harness_action("qualify-self-test")

    def test_bounded_command_timeout_stops_local_child_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "child.pid"
            runner = root / "runner.py"
            runner.write_text(
                "import pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])\n"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n"
                "time.sleep(5)\n", encoding="utf-8"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                API.bounded_command([sys.executable, str(runner), str(pid_file)], timeout=0.5)
            child_pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(40):
                status = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(child_pid)],
                                        capture_output=True, text=True).stdout.strip()
                if not status or status.startswith("Z"):
                    break
                time.sleep(0.05)
            self.assertTrue(not status or status.startswith("Z"), "timed-out child stayed active")

    def test_bounded_command_cancellation_stops_nested_broker_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "broker.pid"
            wrapper = root / "wrapper.py"
            wrapper.write_text(
                "import pathlib,subprocess,sys,time\n"
                "broker=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "pathlib.Path(sys.argv[1]).write_text(str(broker.pid))\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            real_selector = API.selectors.DefaultSelector
            selector = real_selector()

            class CancellingSelector:
                def register(self, *args, **kwargs):
                    return selector.register(*args, **kwargs)

                def unregister(self, *args, **kwargs):
                    return selector.unregister(*args, **kwargs)

                def get_map(self):
                    return selector.get_map()

                def select(self, _timeout=None):
                    deadline = time.monotonic() + 2
                    while not pid_file.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    raise KeyboardInterrupt

                def close(self):
                    selector.close()

            with patch.object(
                API.selectors, "DefaultSelector", return_value=CancellingSelector()
            ), self.assertRaises(KeyboardInterrupt):
                API.bounded_command(
                    [sys.executable, str(wrapper), str(pid_file)], timeout=5
                )
            broker_pid = int(pid_file.read_text(encoding="ascii"))
            status = subprocess.run(
                ["/bin/ps", "-o", "stat=", "-p", str(broker_pid)],
                capture_output=True, text=True, check=False,
            ).stdout.strip()
            self.assertTrue(not status or status.startswith("Z"))

    def test_bounded_command_cleans_residual_after_leader_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_file = root / "broker.pid"
            wrapper = root / "wrapper.py"
            wrapper.write_text(
                "import pathlib,subprocess,sys\n"
                "broker=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "pathlib.Path(sys.argv[1]).write_text(str(broker.pid))\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "descendant_unreaped"):
                API.bounded_command(
                    [sys.executable, str(wrapper), str(pid_file)], timeout=5
                )
            broker_pid = int(pid_file.read_text(encoding="ascii"))
            status = subprocess.run(
                ["/bin/ps", "-o", "stat=", "-p", str(broker_pid)],
                capture_output=True, text=True, check=False,
            ).stdout.strip()
            self.assertTrue(not status or status.startswith("Z"))

    def test_owned_command_cleanup_fails_bounded_when_child_cannot_reap(self):
        process = Mock(spec=subprocess.Popen)
        process.pid = 4242
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["child"], 1),
            subprocess.TimeoutExpired(["child"], 2),
        ]
        with patch.object(API.os, "killpg") as killpg, \
                self.assertRaisesRegex(RuntimeError, "process_unreaped"):
            API._terminate_owned_command_group(process)
        self.assertIn(
            __import__("unittest.mock").mock.call(4242, signal.SIGKILL),
            killpg.call_args_list,
        )

    def test_owned_group_signal_permission_race_requires_absence_readback(self):
        with patch.object(
            API.os, "killpg",
            side_effect=[PermissionError(), ProcessLookupError()],
        ) as killpg:
            API._signal_owned_command_group(4242, signal.SIGKILL)
        self.assertEqual(killpg.call_count, 2)

        with patch.object(
            API.os, "killpg",
            side_effect=[PermissionError(), PermissionError(), PermissionError()],
        ), patch.object(API.time, "sleep"), self.assertRaisesRegex(
            RuntimeError, "process_group_readback_denied",
        ):
            API._signal_owned_command_group(4242, signal.SIGKILL)

    def test_native_stack_wrapper_cleanup_fails_bounded_when_child_cannot_reap(self):
        operation_path = Path(__file__).with_name("native-stack-operation.py")
        specification = importlib.util.spec_from_file_location(
            "native_stack_operation_cleanup", operation_path
        )
        assert specification is not None and specification.loader is not None
        operation = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(operation)
        process = Mock(spec=subprocess.Popen)
        process.pid = 4343
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["child"], 2),
            subprocess.TimeoutExpired(["child"], 2),
        ]
        with patch.object(operation.os, "killpg") as killpg, \
                patch.object(operation, "_group_exists", return_value=True), \
                self.assertRaisesRegex(
                    operation.NativeStackOperationClientError,
                    "process_unreaped",
                ):
            operation._terminate(process, owns_group=True)
        self.assertIn(
            __import__("unittest.mock").mock.call(4343, signal.SIGKILL),
            killpg.call_args_list,
        )

    def test_authorization_supervisor_invalidates_request_on_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            request_root = Path(temporary) / "requests"
            request_root.mkdir(mode=0o700)
            observed = {}

            def timeout(command, **_kwargs):
                request_id = command[command.index("--request-id") + 1]
                observed["request_id"] = request_id
                path = request_root / f"{request_id}.json"
                path.write_bytes(b"pending")
                path.chmod(0o600)
                raise subprocess.TimeoutExpired(command, 1)

            with patch.object(API, "AUTHORIZATION_REQUEST_ROOT", request_root), \
                    patch.object(API, "bounded_command", side_effect=timeout), \
                    self.assertRaises(subprocess.TimeoutExpired):
                API.bounded_authorization_command(
                    ["/fixed/broker", "request"], timeout=1,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                )
            self.assertRegex(observed["request_id"], API.UUID4)
            self.assertFalse(
                (request_root / f'{observed["request_id"]}.json').exists()
            )

    def test_external_sigterm_unwinds_api_group_and_revokes_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request_root = root / "requests"
            request_root.mkdir(mode=0o700)
            wrapper_pid = root / "wrapper.pid"
            broker_pid = root / "broker.pid"
            wrapper = root / "wrapper.py"
            wrapper.write_text(
                "import os,pathlib,subprocess,sys,time\n"
                "request_id=sys.argv[sys.argv.index('--request-id')+1]\n"
                "request_root=pathlib.Path(sys.argv[1]);wrapper_pid=pathlib.Path(sys.argv[2]);"
                "broker_pid=pathlib.Path(sys.argv[3])\n"
                "wrapper_pid.write_text(str(os.getpid()))\n"
                "(request_root/f'{request_id}.json').write_bytes(b'pending')\n"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "broker_pid.write_text(str(child.pid));time.sleep(30)\n",
                encoding="utf-8",
            )
            harness = root / "harness.py"
            harness.write_text(
                "import importlib.util,pathlib,subprocess,sys\n"
                f"path=pathlib.Path({str(Path(__file__).with_name('control-center-api.py'))!r})\n"
                "spec=importlib.util.spec_from_file_location('api_signal_test',path)\n"
                "api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)\n"
                f"api.AUTHORIZATION_REQUEST_ROOT=pathlib.Path({str(request_root)!r})\n"
                "def run():\n"
                "  try:\n"
                f"    api.bounded_authorization_command([sys.executable,{str(wrapper)!r},{str(request_root)!r},{str(wrapper_pid)!r},{str(broker_pid)!r}],timeout=30,env={{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}})\n"
                "  except RuntimeError:\n"
                "    return 1\n"
                "  return 0\n"
                "api._main=run\n"
                "raise SystemExit(api.main())\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [sys.executable, str(harness)], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5
            while (not broker_pid.exists() or not list(request_root.glob("*.json"))):
                if time.monotonic() >= deadline:
                    process.kill(); process.wait()
                    self.fail("authorization child did not become ready")
                time.sleep(0.02)
            process.terminate()
            # Owner-lifetime revocation is distinct from an ordinary catalog
            # failure and crosses RuntimeError recovery before main maps it.
            self.assertEqual(process.wait(timeout=8), 130)
            self.assertEqual(list(request_root.glob("*.json")), [])
            for pid_path in (wrapper_pid, broker_pid):
                pid = int(pid_path.read_text(encoding="ascii"))
                status = subprocess.run(
                    ["/bin/ps", "-o", "stat=", "-p", str(pid)],
                    capture_output=True, text=True, check=False,
                ).stdout.strip()
                self.assertTrue(not status or status.startswith("Z"))

    def test_signal_at_selector_construction_reaps_spawned_command_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_pid = root / "selector-child.pid"
            nested_pid = root / "selector-nested.pid"
            child = root / "selector-child.py"
            child.write_text(
                "import os,pathlib,subprocess,sys,time\n"
                f"child_pid=pathlib.Path({str(child_pid)!r})\n"
                f"nested_pid=pathlib.Path({str(nested_pid)!r})\n"
                "child_pid.write_text(str(os.getpid()))\n"
                "nested=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "nested_pid.write_text(str(nested.pid))\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            harness = root / "selector-window.py"
            harness.write_text(
                "import importlib.util,os,pathlib,signal,sys,time\n"
                f"module_path=pathlib.Path({str(Path(__file__).with_name('control-center-api.py'))!r})\n"
                "spec=importlib.util.spec_from_file_location('selector_window_api',module_path)\n"
                "api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)\n"
                f"child_pid=pathlib.Path({str(child_pid)!r});nested_pid=pathlib.Path({str(nested_pid)!r})\n"
                "def inject_signal():\n"
                "  deadline=time.monotonic()+5\n"
                "  while not (child_pid.exists() and nested_pid.exists()):\n"
                "    if time.monotonic()>=deadline: raise RuntimeError('selector_injection_child_not_ready')\n"
                "    time.sleep(0.01)\n"
                "  os.kill(os.getpid(),signal.SIGTERM)\n"
                "  raise RuntimeError('selector_injection_signal_not_delivered')\n"
                "api.selectors.DefaultSelector=inject_signal\n"
                "def run():\n"
                f"  api.bounded_command([sys.executable,{str(child)!r}],timeout=30,env={{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}},supervise_on_parent_exit=True)\n"
                "  return 0\n"
                "api._main=run\n"
                "raise SystemExit(api.main())\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [sys.executable, str(harness)], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertNotEqual(process.wait(timeout=12), 0)
            self._wait_for_paths(child_pid, nested_pid)
            self._assert_process_inactive(
                int(child_pid.read_text(encoding="ascii"))
            )
            self._assert_process_inactive(
                int(nested_pid.read_text(encoding="ascii"))
            )

    def test_parent_liveness_stages_input_then_eof_unwinds_child_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, child_pid_path, nested_pid_path, request = (
                self._custody_test_harness(root)
            )
            staged_input = root / "staged-input.bin"
            payload = b'{"exact":"protected-plan"}\n'
            environment = dict(os.environ)
            environment[API.PARENT_LIVENESS_ENV] = "0"
            environment[API.PARENT_INPUT_LENGTH_ENV] = str(len(payload))
            owner, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            process = subprocess.Popen(
                [sys.executable, str(harness)], stdin=child,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=environment,
            )
            child.close()
            owner.sendall(payload)
            self._wait_for_paths(
                child_pid_path, nested_pid_path, request, staged_input,
            )
            self.assertEqual(staged_input.read_bytes(), payload)
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            nested_pid = int(nested_pid_path.read_text(encoding="ascii"))
            owner.shutdown(socket.SHUT_WR)
            owner.close()
            self.assertNotEqual(process.wait(timeout=10), 0)
            self._assert_process_inactive(child_pid)
            self._assert_process_inactive(nested_pid)
            self.assertFalse(request.exists())

    def test_api_sigkill_triggers_child_custody_watchdog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, child_pid_path, nested_pid_path, request = (
                self._custody_test_harness(root)
            )
            process = subprocess.Popen(
                [sys.executable, str(harness)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._wait_for_paths(child_pid_path, nested_pid_path, request)
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            nested_pid = int(nested_pid_path.read_text(encoding="ascii"))
            os.kill(process.pid, signal.SIGKILL)
            self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
            self._assert_process_inactive(child_pid)
            self._assert_process_inactive(nested_pid)
            deadline = time.monotonic() + 5
            while request.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(request.exists())

    def test_api_sigkill_watchdog_escalates_past_term_ignoring_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness, child_pid_path, nested_pid_path, request = (
                self._custody_test_harness(root, ignore_term=True)
            )
            process = subprocess.Popen(
                [sys.executable, str(harness)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._wait_for_paths(child_pid_path, nested_pid_path, request)
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            nested_pid = int(nested_pid_path.read_text(encoding="ascii"))
            os.kill(process.pid, signal.SIGKILL)
            self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
            self._assert_process_inactive(child_pid)
            self._assert_process_inactive(nested_pid)

    def test_native_stack_deadline_classes_are_strictly_nested(self):
        operation_path = Path(__file__).with_name("native-stack-operation.py")
        specification = importlib.util.spec_from_file_location(
            "native_stack_operation_deadlines", operation_path
        )
        assert specification is not None and specification.loader is not None
        operation = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(operation)
        broker_path = Path(__file__).with_name("operator-authorization.py")
        broker_specification = importlib.util.spec_from_file_location(
            "operator_authorization_deadlines", broker_path
        )
        assert (
            broker_specification is not None
            and broker_specification.loader is not None
        )
        broker = importlib.util.module_from_spec(broker_specification)
        broker_specification.loader.exec_module(broker)
        expected = {
            "signin-begin": (1440, 1500, 1560),
            "entitlement-verify": (840, 900, 960),
            "activate": (420, 480, 720),
        }
        for action, (broker_bound, wrapper, api) in expected.items():
            with self.subTest(action=action):
                self.assertEqual(
                    broker.authorization_client_timeout(
                        f"native-stack-{action}"
                    ),
                    broker_bound,
                )
                self.assertEqual(operation.authorization_timeout(action), wrapper)
                self.assertEqual(API.native_stack_authorization_timeout(action), api)
                self.assertLess(broker_bound, wrapper)
                self.assertLess(wrapper, api)

        repository = Path(__file__).resolve().parents[1]
        policy_source = (
            repository
            / "macos/ControlCenter/Sources/"
            "SecureSandboxNativeSessionUIProtocol/NativeOperationDeadlinePolicy.swift"
        ).read_text(encoding="utf-8")
        client_source = (
            repository
            / "macos/ControlCenter/Sources/"
            "SecureSandboxControlCenter/Services/CatalogClient.swift"
        ).read_text(encoding="utf-8")
        self.assertIn("nativeStackActionBridgeSeconds = 1_620", policy_source)
        self.assertIn(
            "NativeOperationDeadlinePolicy.nativeStackActionBridgeSeconds",
            client_source,
        )
        self.assertIn("terminationGraceSeconds: 8", client_source)
        self.assertIn("parentLiveness: true", client_source)
        runner_source = (
            repository
            / "macos/ControlCenter/Sources/"
            "SecureSandboxNativeSessionUIProtocol/BoundedProcessRunner.swift"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'environment["SECURE_SANDBOX_PARENT_LIVENESS_FD"] = "0"',
            runner_source,
        )
        self.assertIn(
            'environment["SECURE_SANDBOX_PARENT_INPUT_LENGTH"] = String(',
            runner_source,
        )
        self.assertLess(1560, 1620)

    def test_session_catalog_preserves_content_free_fields(self):
        raw = (
            "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL\n"
            "11111111-1111-1111-1111-111111111111\t2026-10-28T01:00:00Z\t"
            "2026-10-28T02:00:00Z\t2\t0\t1\tExample\n"
        )
        with patch.object(API, "run_labctl", return_value=raw):
            result = API.catalog("sessions")
        self.assertEqual(result[0]["label"], "Example")
        self.assertEqual(result[0]["id"], "11111111-1111-1111-1111-111111111111")

    def test_session_catalog_rejects_extra_fields(self):
        raw = "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL\n" + "x\t" * 7
        with patch.object(API, "run_labctl", return_value=raw):
            with self.assertRaises(ValueError):
                API.catalog("sessions")

    def test_source_catalog_rejects_invalid_commit(self):
        raw = "2026-10-28T01:00:00Z\t11111111-1111-1111-1111-111111111111\towner/repo\tbad\tpath\n"
        with patch.object(API, "run_labctl", return_value=raw):
            with self.assertRaises(ValueError):
                API.catalog("sources")

    def test_artifact_catalog_accepts_verified_metadata_and_rejects_extra_fields(self):
        artifact_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        raw = f"2026-10-28T01:00:00Z\t{artifact_id}\tv2\treport.md\t{run_id}\t{'a' * 64}\n"
        with patch.object(API, "run_labctl", return_value=raw):
            self.assertEqual(API.catalog("artifacts")[0]["file_name"], "report.md")
        with patch.object(API, "run_labctl", return_value=raw.replace(run_id, "preflight")):
            self.assertEqual(API.catalog("artifacts")[0]["run_id"], "preflight")
        with patch.object(API, "run_labctl", return_value=raw.replace(run_id, "invalid")):
            with self.assertRaisesRegex(ValueError, "identity"):
                API.catalog("artifacts")
        with patch.object(API, "run_labctl", return_value=raw.rstrip() + "\textra\n"):
            with self.assertRaises(ValueError):
                API.catalog("artifacts")

    def test_artifact_detail_requires_selected_identity_and_verified_render(self):
        artifact_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        raw = (f"Artifact: {artifact_id}\nCaptured: 2026-10-28T01:00:00Z\n"
               f"Source: report.md (version 2)\nRun: {run_id}\nSHA-256: {'a' * 64}\n"
               "---\nReport text\n")
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.artifact_detail(artifact_id)
        self.assertEqual(detail["content"], "Report text\n")
        command.assert_called_once_with("artifact", artifact_id)
        with patch.object(API, "run_labctl", return_value=raw.replace(run_id, "preflight")):
            self.assertEqual(API.artifact_detail(artifact_id)["run_id"], "preflight")
        with patch.object(API, "run_labctl", return_value=raw.replace(artifact_id, run_id)):
            with self.assertRaises(ValueError):
                API.artifact_detail(artifact_id)

    def test_status_requires_versioned_record(self):
        with patch.object(API, "run_labctl", return_value='{"schema":"wrong"}'):
            with self.assertRaises(ValueError):
                API.catalog("overview")

    def test_github_url_rejects_credentials_query_and_subpaths(self):
        for url in (
            "https://github.com/owner/repo?x=1",
            "https://github.com/owner/repo/tree/main",
            "http://github.com/owner/repo",
            "https://github.com:443/owner/repo",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                API.normalize_github_url(url)
        self.assertEqual(API.normalize_github_url("https://github.com/owner/repo"), "owner/repo")

    def test_plan_binds_exact_repository_and_ref(self):
        raw = (
            "Plan:       11111111-1111-4111-8111-111111111111\n"
            "Repository: owner/repo\nRequested:  main\n"
            "Commit:     " + "a" * 40 + "\nExpires:    2026-10-28T02:00:00Z\n"
        )
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.plan_source("https://github.com/owner/repo", "main")
        command.assert_called_once_with("source", "plan", "owner/repo", "main")
        self.assertEqual(plan["resolved_commit"], "a" * 40)

    def test_npm_plan_binds_exact_package_and_version(self):
        raw = ("Plan:       11111111-1111-4111-8111-111111111111\n"
               "Package:    @scope/package\nVersion:    1.2.3\n"
               "Integrity:  " + "a" * 40 + "\nExpires:    2026-10-28T02:00:00Z\n")
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.plan_npm("@scope/package", "1.2.3")
        self.assertEqual(plan["repository"], "npm/scope--package")
        command.assert_called_once_with("source", "npm-plan", "@scope/package", "1.2.3")
        with self.assertRaises(ValueError):
            API.plan_npm("@scope/package", "latest")

    def test_label_is_bounded_and_identity_checked(self):
        session_id = "11111111-1111-1111-1111-111111111111"
        with patch.object(API, "run_labctl", return_value=f"labeled\t{session_id}\tResearch\n") as command:
            result = API.label_session(session_id, "Research")
        self.assertEqual(result, {"session_id": session_id, "label": "Research"})
        command.assert_called_once_with("session", "label", session_id, "Research")
        for bad in ("", " leading", "x" * 121, "has\nnewline"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                API.label_session(session_id, bad)

    def test_unlabel_requires_exact_response(self):
        session_id = "11111111-1111-1111-1111-111111111111"
        with patch.object(API, "run_labctl", return_value=f"unlabeled\t{session_id}\n") as command:
            self.assertEqual(API.unlabel_session(session_id)["label"], "")
        command.assert_called_once_with("session", "unlabel", session_id)
        with patch.object(API, "run_labctl", return_value="wrong"):
            with self.assertRaises(ValueError):
                API.unlabel_session(session_id)

    def test_host_error_sanitizes_gateway_diagnostics(self):
        raw = b'{"error":"github_status_422","event":"source_controller_rejected"}\n'
        self.assertIn("ref", API.host_error(raw, 1))
        self.assertNotIn("source_controller_rejected", API.host_error(raw, 1))
        self.assertEqual(API.host_error(b"private traceback", 7), "The host operation failed with status 7.")
        self.assertIn("installed host controller", API.host_error(b'{"error":"operation_invalid"}\n', 1))
        lifecycle = (b'private detail\n{"schema":"secure-sandbox-host-lifecycle-v1",'
                     b'"phase":"preflight","action_failures":["parallels_gui_running"]}\n')
        self.assertIn("parallels_gui_running", API.host_error(lifecycle, 1))
        self.assertNotIn("private detail", API.host_error(lifecycle, 1))
        boundary = (b'{"schema":"secure-sandbox-host-lifecycle-v1",'
                    b'"phase":"boundary_verification",'
                    b'"action_failures":["boundary_verification_failed"]}\n')
        self.assertIn("Boundary Verification in Maintenance", API.host_error(boundary, 1))
        service = (b'{"schema":"secure-sandbox-host-lifecycle-v1",'
                   b'"phase":"readback",'
                   b'"action_failures":["parallels_service_unavailable"]}\n')
        message = API.host_error(service, 1)
        self.assertEqual(message, "Parallels Desktop needs to be started.")

    def test_import_reconciles_one_time_plan_to_completed_source(self):
        plan_id = "11111111-1111-4111-8111-111111111111"
        source_id = "22222222-2222-4222-8222-222222222222"
        base = {"schema": "secure-sandbox-source-plan-status-v1", "plan_id": plan_id,
                "repository": "owner/repo", "resolved_commit": "a" * 40,
                "requested_ref": "main", "expires_at": "2026-10-28T02:00:00Z"}
        import json
        initial = json.dumps({**base, "state": "planned"})
        final = json.dumps({**base, "state": "completed", "source_id": source_id})
        output = (f"Source: {source_id}\nBaseline: path\nRepository: owner/repo\n"
                  "Index: repos/INDEX.json\nEvidence: archived and verified\n")
        with (patch.object(API, "run_labctl", side_effect=[initial, output, final]) as command,
              patch.object(API, "catalog", return_value=[])):
            result = API.apply_source(plan_id)
        self.assertEqual(result["source_id"], source_id)
        self.assertEqual(command.call_count, 3)

    def test_import_rejects_existing_repository_commit_before_submission(self):
        plan_id = "11111111-1111-4111-8111-111111111111"
        import json
        state = json.dumps({"schema": "secure-sandbox-source-plan-status-v1",
                            "plan_id": plan_id, "repository": "npm/rc",
                            "requested_ref": "1.2.8", "expires_at": "2026-10-30T18:00:00Z",
                            "resolved_commit": "a" * 40, "state": "planned"})
        with (patch.object(API, "run_labctl", return_value=state) as command,
              patch.object(API, "catalog", return_value=[{
                  "id": "22222222-2222-4222-8222-222222222222",
                  "repository": "npm/rc", "commit": "a" * 40,
              }])):
            with self.assertRaisesRegex(ValueError, "already imported"):
                API.apply_source(plan_id)
        command.assert_called_once_with("source", "status", plan_id)

    def test_import_never_replays_claimed_plan(self):
        plan_id = "11111111-1111-4111-8111-111111111111"
        import json
        state = json.dumps({"schema": "secure-sandbox-source-plan-status-v1",
                            "plan_id": plan_id, "repository": "owner/repo",
                            "resolved_commit": "a" * 40, "state": "claimed"})
        with patch.object(API, "run_labctl", return_value=state) as command:
            with self.assertRaises(ValueError):
                API.apply_source(plan_id)
        command.assert_called_once_with("source", "status", plan_id)

    def test_activity_projects_only_metadata(self):
        raw = ('{"TimeGenerated":"2026-10-28T01:00:00Z","EventType":"heartbeat",'
               '"Severity":"info","Status":0,"VmId":"gateway",'
               '"Message":"ready","private_payload":"do not expose"}\n')
        with patch.object(API, "run_labctl", return_value=raw):
            rows = API.catalog("activity")
        self.assertEqual(rows[0]["sequence"], 0)
        self.assertNotIn("private_payload", rows[0])

    def test_maintenance_reports_independent_checks(self):
        clocks = ("sandbox-gateway: skew=0s\n"
                  "sandbox-research-admin: skew=0s\n"
                  "sandbox-target-admin: skew=0s\n"
                  "SecureSandbox guest clocks are within 5s of the Mac.\n")
        with patch.object(API, "run_labctl", side_effect=[clocks, RuntimeError("policy")]):
            status = API.maintenance()
        self.assertEqual(status, {"time_sync": "verified", "snapshot_policy": "attention"})

    def test_owner_loss_cannot_be_recovered_as_maintenance_attention(self):
        revoked = API.ControlCenterInterrupted("control_center_interrupted")
        with (
            patch.object(
                API, "run_labctl", side_effect=revoked
            ) as command,
            self.assertRaises(API.ControlCenterInterrupted),
        ):
            API.maintenance()
        command.assert_called_once_with("time-sync")

    def test_main_maps_owner_loss_to_nonzero_after_unwind(self):
        with patch.object(API, "_start_parent_liveness_monitor"), \
                patch.object(
                    API, "_main",
                    side_effect=API.ControlCenterInterrupted(
                        "control_center_interrupted"
                    ),
                ):
            self.assertEqual(API.main(), 130)

    def test_owner_loss_stays_nonrecoverable_when_child_cleanup_fails(self):
        process = type("Process", (), {
            "stdout": __import__("io").BytesIO(),
            "stderr": __import__("io").BytesIO(),
        })()
        with (
            patch.object(API.subprocess, "Popen", return_value=process),
            patch.object(
                API.selectors, "DefaultSelector",
                side_effect=API.ControlCenterInterrupted(
                    "control_center_interrupted"
                ),
            ),
            patch.object(
                API, "_terminate_owned_command_group",
                side_effect=RuntimeError("cleanup_unverified"),
            ),
            self.assertRaisesRegex(
                API.ControlCenterInterrupted, "cleanup_unverified"
            ),
        ):
            API.bounded_command(["/usr/bin/true"], timeout=1)

    def test_finding_detail_requires_explicit_id_and_projects_text(self):
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        candidate = {"finding_id": finding_id, "claim": "Claim", "counterargument": "Counter",
                     "limitations": "Limit", "claim_evidence_support": "supported",
                     "proposed_severity": "low", "submitted_at": "2026-10-28T01:00:00Z",
                     "evidence": [{"class": "static_source_review"}], "private_payload": "hidden",
                     "content_sha256": "a" * 64}
        raw = json.dumps({"candidate": candidate, "amendments": [], "events": [],
                          "current_state": "candidate"})
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.finding_detail(finding_id)
        self.assertEqual(detail["evidence_count"], 1)
        self.assertEqual(detail["evidence"][0]["sha256"],
                         __import__("hashlib").sha256(b'{"class":"static_source_review"}').hexdigest())
        self.assertNotIn("private_payload", detail)
        command.assert_called_once_with("finding", "show", finding_id)

    def test_finding_transition_stages_exact_request_and_verifies_journal_receipt(self):
        import json
        import tempfile
        from subprocess import CompletedProcess
        finding_id = "11111111-1111-4111-8111-111111111111"
        event_id = "22222222-2222-4222-8222-222222222222"
        evidence = "b" * 64
        request = {"schema": "secure-sandbox-control-center-finding-transition-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "candidate", "to_state": "needs_evidence",
                   "verification_method": "inspected_evidence", "consulted_evidence": [evidence],
                   "actor_id": "operator", "actor_role": "research_lead",
                   "rationale": "More measurement needed", "conflict_note": "No conflict disclosed"}
        before = {"content_sha256": "a" * 64, "current_state": "candidate",
                  "evidence": [{"sha256": evidence}], "claim_requires_execution": False}
        receipt = {"status": "recorded", "finding_id": finding_id,
                   "event_id": event_id, "entry_sha256": "c" * 64}
        after = {"current_state": "needs_evidence", "events": [{
            "event_id": event_id, "entry_sha256": "c" * 64,
            "to_state": "needs_evidence", "consulted_evidence": [evidence]}]}
        staged_paths = []
        def command(argv, *, timeout):
            staged_paths.append(Path(argv[-1]))
            payload = json.loads(staged_paths[-1].read_text())
            self.assertEqual(payload["actor"], {"id": "operator", "role": "research_lead"})
            self.assertEqual(payload["consulted_evidence"], [evidence])
            return CompletedProcess(argv, 0, json.dumps(receipt).encode(), b"")
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".private").mkdir()
            with (patch.object(API, "ROOT", Path(directory)),
                  patch.object(API, "finding_detail", return_value=before),
                  patch.object(API, "bounded_command", side_effect=command),
                  patch.object(API, "run_labctl", return_value=json.dumps(after))):
                self.assertEqual(API.apply_finding_transition(request)["status"], "verified")
            self.assertFalse(staged_paths[0].exists())
        with patch.object(API, "finding_detail", return_value={**before, "current_state": "disputed"}):
            with self.assertRaisesRegex(ValueError, "changed since review"):
                API.apply_finding_transition(request)
        validate = {**request, "to_state": "validated"}
        with (patch.object(API, "finding_detail", return_value={**before, "claim_requires_execution": True}),
              patch.object(API, "bounded_command") as command):
            with self.assertRaisesRegex(ValueError, "requires reviewed evidence"):
                API.apply_finding_transition(validate)
            command.assert_not_called()

    def test_finding_relation_binds_selected_target_and_journal_event(self):
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        target_id = "22222222-2222-4222-8222-222222222222"
        event_id = "33333333-3333-4333-8333-333333333333"
        request = {"schema": "secure-sandbox-control-center-finding-relation-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "candidate", "relation": "duplicate_of",
                   "target_finding_id": target_id, "actor_id": "operator",
                   "actor_role": "research_lead", "rationale": "Same cause",
                   "conflict_note": "No conflict disclosed"}
        before = {"finding_id": finding_id, "content_sha256": "a" * 64, "current_state": "candidate"}
        target = {"finding_id": target_id}
        receipt = {"status": "recorded", "finding_id": finding_id,
                   "event_id": event_id, "entry_sha256": "b" * 64}
        after = {"current_state": "candidate", "events": [{"event_id": event_id,
                 "entry_sha256": "b" * 64, "relation": "duplicate_of", "target_finding_id": target_id}]}
        with (patch.object(API, "finding_detail", side_effect=[before, target]),
              patch.object(API, "submit_finding_action", return_value=receipt) as submit,
              patch.object(API, "run_labctl", return_value=json.dumps(after))):
            self.assertEqual(API.apply_finding_relation(request)["status"], "verified")
        self.assertEqual(submit.call_args.args[0]["target_finding_id"], target_id)

    def test_reopen_options_exclude_terminal_evidence_and_bind_new_digest(self):
        import hashlib
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        old = {"class": "operator_reported", "observation": "old"}
        new = {"class": "operator_reported", "observation": "new"}
        digest = lambda item: hashlib.sha256(json.dumps(item, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        raw = {"candidate": {"evidence": [old]}, "amendments": [{"evidence": [new]}],
               "events": [{"event": "state_changed", "to_state": "rejected",
                           "terminal_evidence_sha256": [digest(old)],
                           "terminal_report_content_sha256": []}]}
        detail = {"current_state": "rejected", "content_sha256": "a" * 64,
                  "evidence": [{"sha256": digest(old)}, {"sha256": digest(new)}]}
        with (patch.object(API, "finding_detail", return_value=detail),
              patch.object(API, "run_labctl", return_value=json.dumps(raw))):
            options = API.finding_reopen_options(finding_id)
        self.assertEqual([item["sha256"] for item in options["options"]], [digest(new)])

        request = {"schema": "secure-sandbox-control-center-finding-reopen-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "rejected", "new_evidence_sha256": digest(new),
                   "actor_id": "operator", "actor_role": "research_lead",
                   "rationale": "New evidence", "conflict_note": "No conflict disclosed"}
        event_id = "22222222-2222-4222-8222-222222222222"
        receipt = {"status": "recorded", "finding_id": finding_id,
                   "event_id": event_id, "entry_sha256": "b" * 64}
        after = {"current_state": "needs_evidence", "events": [{"event": "reopened",
                 "event_id": event_id, "entry_sha256": "b" * 64,
                 "new_evidence_sha256": digest(new)}]}
        with (patch.object(API, "finding_reopen_options", return_value=options),
              patch.object(API, "submit_finding_action", return_value=receipt),
              patch.object(API, "run_labctl", return_value=json.dumps(after))):
            self.assertEqual(API.apply_finding_reopen(request)["state"], "needs_evidence")

    def test_disposition_requires_matching_archive_marker_readback(self):
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        request = {"schema": "secure-sandbox-control-center-finding-disposition-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "rejected", "actor_id": "operator",
                   "actor_role": "research_lead", "rationale": "Archive terminal record",
                   "conflict_note": "No conflict disclosed"}
        before = {"content_sha256": "a" * 64, "current_state": "rejected"}
        receipt = {"status": "disposed", "finding_id": finding_id,
                   "terminal_state": "rejected", "content_sha256": "b" * 64}
        observed = {"schema": "secure-sandbox-finding-disposition-status-v1",
                    "finding_id": finding_id, "state": "rejected",
                    "content_sha256": "b" * 64, "candidate_sha256": "a" * 64}
        with (patch.object(API, "finding_detail", return_value=before),
              patch.object(API, "catalog", return_value=[{"finding_id": finding_id,
                "disposition": "active", "content_sha256": "a" * 64}]),
              patch.object(API, "submit_finding_action", return_value=receipt),
              patch.object(API, "run_labctl", return_value=json.dumps(observed))):
            self.assertEqual(API.apply_finding_disposition(request)["status"], "verified")
        observed["content_sha256"] = "c" * 64
        with (patch.object(API, "finding_detail", return_value=before),
              patch.object(API, "catalog", return_value=[{"finding_id": finding_id,
                "disposition": "active", "content_sha256": "a" * 64}]),
              patch.object(API, "submit_finding_action", return_value=receipt),
              patch.object(API, "run_labctl", return_value=json.dumps(observed))):
            with self.assertRaisesRegex(ValueError, "archive readback"):
                API.apply_finding_disposition(request)

    def test_boundary_verification_requires_final_success_marker(self):
        from subprocess import CompletedProcess
        good = "PASS  first\nPASS  second\nGATE  notice\nBOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use.\n"
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, good.encode(), b"")):
            result = API.verify_boundaries()
        self.assertEqual(result, {"status": "verified", "passed_checks": 2, "gate_notices": 1,
                                  "failed_checks": 0, "failure_labels": []})
        failed = "PASS  first\nFAIL  Gateway source mismatch\nFAIL  Research control files mismatch\nBOUNDARY VERIFICATION FAILED: 2 check(s)\n"
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, failed.encode(), b"")):
            result = API.verify_boundaries()
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["failure_labels"], ["Gateway source mismatch", "Research control files mismatch"])
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, b"PASS  first\n", b"")):
            with self.assertRaises(ValueError):
                API.verify_boundaries()
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 1,
                          failed.replace("2 check(s)", "3 check(s)").encode(), b"")):
            with self.assertRaises(RuntimeError):
                API.verify_boundaries()

    def test_lifecycle_requires_final_record_and_independent_state(self):
        import json
        before = {"status": "verified", "observed": {"gateway": "running", "research": "running", "target": "running"}}
        after = {"status": "verified", "observed": {"gateway": "stopped", "research": "stopped", "target": "stopped"}}
        completed = json.dumps({"schema": "secure-sandbox-host-lifecycle-v1", "operation": "stop",
                                "status": "verified", "phase": "complete"}) + "\n"
        from subprocess import CompletedProcess
        with (patch.object(API, "catalog", side_effect=[before, after]) as catalog,
              patch.object(API, "run_labctl", return_value=completed) as command,
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b""))):
            self.assertEqual(API.lifecycle("stop")["status"], "verified")
        self.assertEqual(catalog.call_count, 2)
        command.assert_called_once_with("stop")
        after["observed"]["target"] = "running"
        with (patch.object(API, "catalog", side_effect=[before, after]),
              patch.object(API, "run_labctl", return_value=completed),
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b""))):
            with self.assertRaisesRegex(ValueError, "independent VM state"):
                API.lifecycle("stop")

    def test_lifecycle_refuses_open_parallels_gui(self):
        from subprocess import CompletedProcess
        before = {"status": "verified", "observed": {"gateway": "running", "research": "running", "target": "running"}}
        with (patch.object(API, "catalog", return_value=before),
              patch.object(API, "run_labctl") as command,
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 0, b"", b""))):
            with self.assertRaisesRegex(ValueError, "Quit Parallels"):
                API.lifecycle("stop")
        command.assert_not_called()

    def test_start_completion_exposes_verified_clocks_boundaries_and_uplink(self):
        import json
        from subprocess import CompletedProcess
        before = {"status": "verified", "observed": {"gateway": "stopped", "research": "stopped", "target": "stopped"}}
        after = {"status": "verified",
                 "observed": {"gateway": "running", "research": "running", "target": "running",
                              "gateway_net0": "connected"},
                 "reachability": {"gateway": "reachable", "research": "reachable", "target": "reachable"}}
        completed = json.dumps({"schema": "secure-sandbox-host-lifecycle-v1", "operation": "start",
                                "status": "verified", "phase": "complete"}) + "\n"
        with (patch.object(API, "catalog", side_effect=[before, after]),
              patch.object(API, "run_labctl", return_value=completed),
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b""))):
            result = API.lifecycle("start")
        self.assertEqual(result["gateway_net0"], "connected")
        self.assertEqual(result["guest_reachability"], "verified")
        self.assertEqual(result["clock_sync"], "verified")
        self.assertEqual(result["boundary_verification"], "verified")

    def test_lifecycle_progress_rejects_untrusted_phase(self):
        import json
        active = {"schema": "secure-sandbox-host-lifecycle-progress-v1",
                  "state": "active", "operation": "start", "phase": "guest_readiness",
                  "target": "research", "transition_id": "11111111-1111-4111-8111-111111111111",
                  "observed_at": "2026-10-29T00:00:00Z"}
        with patch.object(API, "run_labctl", return_value=json.dumps(active)):
            self.assertEqual(API.lifecycle_progress()["phase"], "guest_readiness")
        with patch.object(API, "run_labctl", return_value=json.dumps({**active, "phase": "complete"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.lifecycle_progress()
        with patch.object(API, "run_labctl", return_value=json.dumps({"schema": active["schema"], "state": "idle"})):
            self.assertEqual(API.lifecycle_progress()["state"], "idle")

    def test_dependency_plan_parses_exact_readiness(self):
        source_id = "11111111-1111-4111-8111-111111111111"
        plan_id = "22222222-2222-4222-8222-222222222222"
        raw = (f"Plan: {plan_id}\nRoot: @scope/root@1.2.3\nSet SHA256: {'a' * 64}\n"
               "Expires: 2026-10-28T01:00:00Z\nMISSING\tleft-pad\t1.0.0\t-\n")
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.dependency_plan(source_id)
        self.assertEqual(plan["dependencies"][0]["state"], "MISSING")
        command.assert_called_once_with("dependencies", "plan", source_id)
        with self.assertRaises(ValueError):
            API.dependency_rows("READY\tleft-pad\t1.0.0\t-\n")

    def test_dependency_bundle_apply_requires_ready_and_catalog_readback(self):
        plan_id = "22222222-2222-4222-8222-222222222222"
        bundle_id = "33333333-3333-4333-8333-333333333333"
        source_id = "44444444-4444-4444-8444-444444444444"
        digest = "a" * 64
        ready = {"plan_id": plan_id, "dependencies": [
            {"state": "READY", "package": "left-pad", "version": "1.0.0", "source_id": source_id}]}
        raw = (f"Bundle: {bundle_id}\nRoot: root@1.0.0\nDependencies: 1\n"
               f"Set SHA256: {digest}\nLifecycle: disabled\n")
        bundles = [{"id": bundle_id, "dependency_set_sha256": digest}]
        with (patch.object(API, "dependency_status", return_value=ready),
              patch.object(API, "run_labctl", return_value=raw) as command,
              patch.object(API, "dependency_bundles", return_value=bundles)):
            self.assertEqual(API.dependency_apply(plan_id, digest)["bundle_id"], bundle_id)
        command.assert_called_once_with("dependencies", "apply", plan_id)
        ready["dependencies"][0]["state"] = "MISSING"
        with (patch.object(API, "dependency_status", return_value=ready),
              patch.object(API, "run_labctl") as command):
            with self.assertRaisesRegex(ValueError, "Import the missing"):
                API.dependency_apply(plan_id, digest)
        command.assert_not_called()

    def test_index_source_accepts_only_matching_sealed_result(self):
        import json
        source_id = "11111111-1111-4111-8111-111111111111"
        result = {"schema": "secure-sandbox-corpus-index-v1", "source_id": source_id,
                  "status": "indexed", "index_content_sha256": "a" * 64,
                  "indexed_documents": 10}
        with patch.object(API, "run_labctl", return_value=json.dumps(result)) as command:
            self.assertEqual(API.index_source("corpus", source_id)["item_count"], 10)
        command.assert_called_once_with("corpus", "index", source_id)
        with patch.object(API, "run_labctl", return_value=json.dumps({**result, "source_id": "other"})):
            with self.assertRaises(ValueError):
                API.index_source("corpus", source_id)
        with self.assertRaises(ValueError):
            API.index_source("shell", source_id)

    def test_index_source_status_accepts_indexed_and_absent_readback(self):
        import json
        source_id = "11111111-1111-4111-8111-111111111111"
        indexed = {"schema": "secure-sandbox-codegraph-index-status-v1",
                   "source_id": source_id, "status": "indexed",
                   "codegraph_index_sha256": "b" * 64, "nodes_created": 12}
        with patch.object(API, "run_labctl", return_value=json.dumps(indexed)) as command:
            result = API.index_source_status("codegraph", source_id)
        self.assertEqual(result["item_count"], 12)
        command.assert_called_once_with("codegraph", "status", source_id)
        absent = {"schema": "secure-sandbox-corpus-index-status-v1",
                  "source_id": source_id, "status": "not_indexed"}
        with patch.object(API, "run_labctl", return_value=json.dumps(absent)):
            result = API.index_source_status("corpus", source_id)
        self.assertEqual(result, {"kind": "corpus", "source_id": source_id,
                                  "status": "not_indexed", "digest": "", "item_count": 0})
        with patch.object(API, "run_labctl", return_value=json.dumps({**indexed, "nodes_created": -1})):
            with self.assertRaisesRegex(ValueError, "status is invalid"):
                API.index_source_status("codegraph", source_id)

    def test_backup_preflight_requires_encryption_capacity_and_stopped_stack(self):
        import tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as destination:
            stopped = {"status": "verified", "observed": {
                "gateway": "stopped", "research": "stopped", "target": "stopped"}}
            backup = SimpleNamespace(backup=SimpleNamespace(
                host_config_inventory=lambda _config: []
            ))
            with (patch.object(API, "vm_footprint", return_value={"gateway": 10, "research": 20, "target": 30}),
                  patch.object(API, "backup_operations", return_value=backup),
                  patch.object(API, "destination_volume", return_value={"volume_uuid": "a" * 36, "encrypted": True}),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=512))):
                self.assertTrue(API.backup_preflight(destination)["ready"])
            with (patch.object(API, "vm_footprint", return_value={"gateway": 10, "research": 20, "target": 30}),
                  patch.object(API, "backup_operations", return_value=backup),
                  patch.object(API, "destination_volume", return_value={"volume_uuid": "a" * 36, "encrypted": False}),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=512))):
                self.assertFalse(API.backup_preflight(destination)["ready"])

    def test_destination_requires_encryption_of_apfs_volume_itself(self):
        import plistlib
        from subprocess import CompletedProcess
        import tempfile
        with tempfile.TemporaryDirectory() as destination:
            info = {"FilesystemName": "APFS", "VolumeUUID": "11111111-1111-1111-1111-111111111111",
                    "Encryption": True, "EncryptionThisVolumeProper": False, "FileVault": False}
            with patch.object(API.subprocess, "run", side_effect=[
                CompletedProcess([], 0, b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk9s1 1 1 1 1% /Volumes/Test\n", b""),
                CompletedProcess([], 0, plistlib.dumps(info), b"")]):
                self.assertFalse(API.destination_volume(Path(destination))["encrypted"])

    def test_backup_inventory_and_restore_preview_verify_selected_generation(self):
        import tempfile
        from types import SimpleNamespace
        from scripts import control_center_backup as backup
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "vms"
            source.mkdir()
            config = root / "config"
            config.mkdir()
            for name in backup.HOST_CONFIG_FILES:
                (config / name).write_text(name)
            identities = {}
            for index, name in enumerate(backup.NAMES, 1):
                bundle = source / f"{name}.pvm"
                bundle.mkdir()
                (bundle / "config.pvs").write_text(name)
                identities[name] = f"{index:08x}-1111-4111-8111-111111111111"
            volume = "11111111-1111-4111-8111-111111111111"
            generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            key = b"k" * 32
            backup.create_backup(source, config, root, identities, volume, key,
                                 copier=lambda source_path, target_path: __import__("shutil").copytree(source_path, target_path),
                                 generation=generation)
            stopped = {"status": "verified", "observed": {
                "gateway": "stopped", "research": "stopped", "target": "stopped"}}
            operations = SimpleNamespace(backup=SimpleNamespace(read_backup_key=lambda: key,
                                                                 verify_backup=backup.verify_backup,
                                                                 host_config_inventory=backup.host_config_inventory),
                                         vm_identities=lambda _: {
                                             name: {"uuid": value} for name, value in identities.items()})
            with (patch.object(API, "ROOT", root),
                  patch.object(API, "backup_operations", return_value=operations),
                  patch.object(API, "destination_volume", return_value={"volume_uuid": volume, "encrypted": True}),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=512))):
                entries = API.backup_inventory(str(root))["entries"]
                self.assertEqual(entries[0]["state"], "unverified")
                preview = API.restore_preview(str(root), generation)
                self.assertTrue(preview["ready"])
                self.assertEqual(preview["file_count"], 3 + len(backup.HOST_CONFIG_FILES))
                (config / backup.HOST_CONFIG_FILES[0]).write_text("changed")
                changed = API.restore_preview(str(root), generation)
                self.assertFalse(changed["ready"])
                self.assertEqual(changed["differing_host_config"], [backup.HOST_CONFIG_FILES[0]])
                (config / backup.HOST_CONFIG_FILES[0]).write_text(backup.HOST_CONFIG_FILES[0])
                stage = root / f".secure-sandbox-backup-{generation}.incomplete"
                stage.mkdir()
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    API.restore_preview(str(root), generation)
                stage.rmdir()
                (root / f"secure-sandbox-backup-{generation}/vms/{backup.NAMES[0]}.pvm/config.pvs").write_text("tampered")
                with self.assertRaises(backup.BackupError):
                    API.restore_preview(str(root), generation)

    def test_memory_proposals_expose_only_bounded_metadata(self):
        import json
        item = {"proposal_id": "11111111-1111-4111-8111-111111111111",
                "run_id": "22222222-2222-4222-8222-222222222222",
                "created_at": "2026-10-29T00:00:00Z", "category": "workflow",
                "title": "Review this", "content_sha256": "a" * 64,
                "status": "pending_operator_review", "authority": "untrusted_proposal"}
        with patch.object(API, "run_labctl", return_value=json.dumps(item) + "\n") as command:
            self.assertEqual(API.memory_proposals()[0]["title"], "Review this")
        command.assert_called_once_with("memory", "proposals")
        with patch.object(API, "run_labctl", return_value=json.dumps({**item, "content": "untrusted"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.memory_proposals()
        with patch.object(API, "run_labctl", return_value=json.dumps({**item, "run_id": "unknown"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.memory_proposals()
        with patch.object(API, "run_labctl", return_value=json.dumps({**item, "authority": "operator_adjudication"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.memory_proposals()

    def test_restore_plan_requires_ready_preview_and_binds_current_identities(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        preview = {"ready": True, "destination": "/Volumes/Backup", "volume_uuid": "b" * 36,
                   "manifest_hmac_sha256": "c" * 64, "file_count": 12, "logical_bytes": 1000}
        identities = {"vm": {"uuid": generation}}
        created = {"restore_id": generation}
        service = SimpleNamespace(backup=SimpleNamespace(read_backup_key=lambda: b"k" * 32),
                                  base=SimpleNamespace(vm_identities=lambda _: identities),
                                  default_root=lambda: Path("/tmp/restore-plans"),
                                  create_plan=Mock(return_value=created),
                                  plan_detail=Mock(return_value={"restore_id": generation}))
        with (patch.object(API, "restore_preview", return_value=preview),
              patch.object(API, "restore_operations", return_value=service)):
            self.assertEqual(API.plan_restore("/Volumes/Backup", generation)["restore_id"], generation)
        self.assertEqual(service.create_plan.call_args.args[5], identities)
        with (patch.object(API, "restore_preview", return_value={"ready": False}),
              patch.object(API, "restore_operations") as operations):
            with self.assertRaisesRegex(ValueError, "not ready"):
                API.plan_restore("/Volumes/Backup", generation)
        operations.assert_not_called()

    def test_restore_retirement_bridge_uses_authenticated_operation_service(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        restore_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        key = b"k" * 32
        preview = Mock(return_value={"restore_id": restore_id, "state": "available"})
        submit = Mock(return_value={"restore_id": restore_id, "state": "submitted"})
        status = Mock(return_value={"restore_id": restore_id, "state": "retired"})
        service = SimpleNamespace(
            backup=SimpleNamespace(read_backup_key=lambda: key),
            default_root=lambda: Path("/tmp/restore-plans"),
            retirement_preview=preview, submit_retirement=submit,
            retirement_status=status)
        with patch.object(API, "restore_operations", return_value=service):
            self.assertEqual(API.restore_retirement_preview(restore_id)["state"], "available")
            self.assertEqual(API.retire_restore_generation(restore_id)["state"], "submitted")
            self.assertEqual(API.restore_retirement_status(restore_id)["state"], "retired")
        preview.assert_called_once_with(Path("/tmp/restore-plans"), API.ROOT, restore_id, key)
        submit.assert_called_once_with(Path("/tmp/restore-plans"), API.ROOT, restore_id, key)
        status.assert_called_once_with(Path("/tmp/restore-plans"), API.ROOT, restore_id, key)
        with patch.object(API, "restore_operations") as operations:
            with self.assertRaisesRegex(ValueError, "canonical restore"):
                API.restore_retirement_preview("invalid")
        operations.assert_not_called()

    def test_transcript_requires_selected_run_and_escapes_untrusted_records(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        raw = '{"type":"assistant","text":"\\u001b[31mtool output"}\n'
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.transcript_detail(run_id)
        command.assert_called_once_with("transcript", run_id)
        self.assertEqual(detail["record_count"], 1)
        self.assertIn("\\u001b", detail["content"])
        with patch.object(API, "run_labctl") as command:
            with self.assertRaises(ValueError):
                API.transcript_detail("invalid")
        command.assert_not_called()
        with patch.object(API, "run_labctl", return_value='["not an object"]\n'):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.transcript_detail(run_id)

    def test_transcript_archive_uses_archive_deadline(self):
        from subprocess import CompletedProcess
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, b"{}\n", b"")) as command:
            API.run_labctl("transcript", "11111111-1111-4111-8111-111111111111")
        self.assertEqual(command.call_args.kwargs["timeout"], 300)

    def test_transcript_export_streams_verified_records_and_preserves_destination_on_failure(self):
        import hashlib
        import tempfile
        from pathlib import Path
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "labctl"
            destination = root / "transcript.jsonl"
            command.write_text("#!/usr/bin/env python3\nimport sys\nprint('{\"type\":\"user\",\"text\":\"\\\\u001b[31m\"}')\n")
            command.chmod(0o700)
            with patch.object(API, "LABCTL", command):
                result = API.export_transcript(run_id, str(destination))
            content = destination.read_bytes()
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["record_count"], 1)
            self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
            self.assertIn(b"\\u001b", content)
            destination.write_text("keep")
            command.write_text("#!/usr/bin/env python3\nprint('{\"type\":\"user\"}')\nraise SystemExit(1)\n")
            with patch.object(API, "LABCTL", command):
                with self.assertRaises(RuntimeError):
                    API.export_transcript(run_id, str(destination))
            self.assertEqual(destination.read_text(), "keep")
            self.assertEqual(list(root.glob(".secure-sandbox-transcript-*.tmp")), [])

    def test_transcript_export_exceeds_preview_limit_without_bridge_bulk_output(self):
        import tempfile
        from pathlib import Path
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "labctl"
            command.write_text("#!/usr/bin/env python3\nimport json\nfor _ in range(9000):\n"
                               "    print(json.dumps({'type': 'user', 'text': 'x' * 1024}))\n")
            command.chmod(0o700)
            destination = root / "large.jsonl"
            with patch.object(API, "LABCTL", command):
                result = API.export_transcript(run_id, str(destination))
            self.assertEqual(result["record_count"], 9000)
            self.assertGreater(result["byte_count"], API.MAX_OUTPUT)
            self.assertEqual(destination.stat().st_size, result["byte_count"])

    def test_tool_result_catalog_binds_exact_archived_block_digest(self):
        import hashlib
        import json
        run_id = "11111111-1111-4111-8111-111111111111"
        records = [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "toolu_abc", "name": "Bash", "input": {"command": "true"}}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_abc", "content": "ok\\u001b[31m", "is_error": False}]}},
        ]
        raw = "\n".join(json.dumps(record) for record in records) + "\n"
        def stage_fixture(_run_id, destination):
            Path(destination).write_text(raw)
            return {"status": "verified"}
        with patch.object(API, "export_transcript", side_effect=stage_fixture):
            catalog = API.tool_result_catalog(run_id)
            row = catalog["results"][0]
            detail = API.tool_result_detail(run_id, "toolu_abc", row["sha256"])
            self.assertEqual(hashlib.sha256(detail["content"].encode()).hexdigest(), row["sha256"])
            with self.assertRaisesRegex(ValueError, "digest changed"):
                API.tool_result_detail(run_id, "toolu_abc", "0" * 64)

    def test_tool_result_catalog_reads_run_larger_than_preview_limit(self):
        import json
        import tempfile
        from pathlib import Path
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "labctl"
            command.write_text("#!/usr/bin/env python3\nimport json\n"
                               "for _ in range(9000):\n"
                               "    print(json.dumps({'type':'assistant','text':'x'*1024}))\n"
                               "print(json.dumps({'type':'assistant','message':{'content':[{'type':'tool_use','id':'toolu_large','name':'Bash'}]}}))\n"
                               "print(json.dumps({'type':'user','message':{'content':[{'type':'tool_result','tool_use_id':'toolu_large','content':'ok'}]}}))\n")
            command.chmod(0o700)
            with patch.object(API, "LABCTL", command):
                catalog = API.tool_result_catalog(run_id)
                self.assertEqual(catalog["results"][0]["tool_use_id"], "toolu_large")
                detail = API.tool_result_detail(run_id, "toolu_large", catalog["results"][0]["sha256"])
                self.assertIn('"content":"ok"', detail["content"])

    def test_session_run_links_accept_exact_private_catalog_projection(self):
        import json
        session_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        value = {"schema": "secure-sandbox-session-runs-v2", "session_id": session_id,
                 "total_runs": 3, "run_ids": [run_id]}
        with patch.object(API, "run_labctl", return_value=json.dumps(value)) as command:
            self.assertEqual(API.session_runs(session_id)["run_ids"], [run_id])
        command.assert_called_once_with("session", "runs", session_id)
        with patch.object(API, "run_labctl", return_value=json.dumps({**value, "run_ids": ["bad"]})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.session_runs(session_id)

    def test_lease_renewal_uses_fixed_duration_and_independent_readback(self):
        import json
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        initial_value = self.lease_fixture(run_id, lease_id)
        lease = initial_value["lease"]
        initial = json.dumps(initial_value)
        renewed_value = self.lease_fixture(run_id, lease_id, expires_at=1300, renewals=1)
        renewed_lease = renewed_value["lease"]
        renewed = json.dumps(renewed_value)
        with patch.object(API, "run_labctl", side_effect=[initial, json.dumps(renewed_lease), renewed]) as command:
            result = API.renew_lease(run_id, 300)
        self.assertEqual(result["expires_at"], 1300)
        self.assertEqual(result["runtime_authority_sha256"],
                         lease["runtime_authority"]["binding_sha256"])
        self.assertRegex(result["immutable_lease_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["model"], "abliterated-model-large-v2")
        self.assertEqual(result["harness_id"], "claude-code")
        self.assertEqual(command.call_args_list[1].args, ("lease", "renew", run_id, "300"))
        with patch.object(API, "run_labctl") as command:
            with self.assertRaises(ValueError):
                API.renew_lease(run_id, 60)
        command.assert_not_called()

    def test_lease_renewal_rejects_valid_but_changed_brokered_transport(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        initial_value = self.lease_fixture(run_id, lease_id)
        renewed_value = self.lease_fixture(run_id, lease_id, expires_at=1300, renewals=1)
        mutated = json.loads(json.dumps(renewed_value["lease"]))
        mutated["brokered_transport"]["policy_sha256"] = "c" * 64
        with patch.object(API, "run_labctl", side_effect=[
                json.dumps(initial_value), json.dumps(mutated), json.dumps(renewed_value)]):
            with self.assertRaisesRegex(ValueError, "readback is ambiguous"):
                API.renew_lease(run_id, 300)

    def test_lease_status_requires_v3_authority_and_summary_v2(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        closed = self.lease_fixture(run_id, lease_id, summary=True)
        with patch.object(API, "run_labctl", return_value=json.dumps(closed)):
            value = API.lease_status(run_id)
        self.assertEqual(value["state"], "closed")
        self.assertEqual(value["profile_id"], "abliterated-glm")
        self.assertEqual(value["session_id"], "33333333-3333-4333-8333-333333333333")

        legacy = json.loads(json.dumps(closed))
        legacy["lease"]["schema"] = "secure-sandbox-run-lease-v2"
        legacy["summary"]["lease"] = legacy["lease"]
        with patch.object(API, "run_labctl", return_value=json.dumps(legacy)):
            with self.assertRaisesRegex(ValueError, "identity or schema"):
                API.lease_status(run_id)

    def test_lease_status_rejects_authority_mutation_and_extra_counter_fields(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        value = self.lease_fixture(run_id, lease_id)
        value["lease"]["runtime_authority"]["session_context_binding"]["session_id"] = run_id
        with patch.object(API, "run_labctl", return_value=json.dumps(value)):
            with self.assertRaisesRegex(ValueError, "identity or schema"):
                API.lease_status(run_id)
        value = self.lease_fixture(run_id, lease_id)
        value["counters"]["token"] = "forbidden"
        with patch.object(API, "run_labctl", return_value=json.dumps(value)):
            with self.assertRaisesRegex(ValueError, "identity or schema"):
                API.lease_status(run_id)

    def test_time_sync_apply_requires_running_vms_and_independent_check(self):
        overview = {"status": "verified", "observed": {
            "gateway": "running", "research": "running", "target": "running"}}
        clocks = ("sandbox-gateway: skew=0s\n"
                  "sandbox-research-admin: skew=0s\n"
                  "sandbox-target-admin: skew=0s\n"
                  "SecureSandbox guest clocks are within 5s of the Mac.\n")
        with (patch.object(API, "catalog", return_value=overview),
              patch.object(API, "run_labctl", side_effect=[clocks, clocks]) as command):
            self.assertEqual(API.apply_time_sync()["status"], "verified")
        self.assertEqual(command.call_count, 2)
        overview["observed"]["target"] = "stopped"
        with (patch.object(API, "catalog", return_value=overview),
              patch.object(API, "run_labctl") as command):
            with self.assertRaisesRegex(ValueError, "All three VMs"):
                API.apply_time_sync()
        command.assert_not_called()
        with self.assertRaises(ValueError):
            API.check_time_output(clocks.replace("sandbox-target-admin: skew=0s", "sandbox-gateway: skew=99s"))

    def test_safety_audit_projects_failed_posture_without_traceback(self):
        import json
        from subprocess import CompletedProcess
        report = {"schema": "secure-sandbox-external-containment-audit-v1",
                  "host_direct": {"posture_tier": 0},
                  "secure_sandbox_launch_path": {"verified": False,
                                                 "error": "Traceback private path active_release_source_mismatch"}}
        with patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, json.dumps(report).encode(), b"")):
            result = API.safety_audit()
        self.assertFalse(result["verified"])
        self.assertIn("deployment", result["detail"])
        self.assertNotIn("Traceback", result["detail"])

    def test_bounded_command_rejects_output_before_process_completion(self):
        with patch.object(API, "MAX_OUTPUT", 1024):
            with self.assertRaisesRegex(ValueError, "size limit"):
                API.bounded_command([sys.executable, "-c", "import sys; sys.stdout.write('x' * 2048)"], timeout=5)
        result = API.bounded_command([sys.executable, "-c", "import sys; sys.stderr.write('e' * 5000); print('ok')"], timeout=5)
        self.assertEqual(result.stdout, b"ok\n")
        self.assertEqual(len(result.stderr), 4096)

    def test_snapshot_policy_surfaces_missing_milestone_without_raw_diagnostic(self):
        from subprocess import CompletedProcess
        rejected = CompletedProcess([], 1, b"", b"Retention milestone missing or duplicated for SecretVM: private\n")
        with patch.object(API, "bounded_command", return_value=rejected):
            result = API.snapshot_policy()
        self.assertFalse(result["verified"])
        self.assertIn("required retained snapshot", result["detail"])

    def test_snapshot_preview_requires_exact_retained_counts_and_cold_stack(self):
        import json
        import tempfile
        from subprocess import CompletedProcess
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/snapshot-retention.json").write_text(json.dumps({
                "schema": "secure-sandbox-snapshot-retention-v1",
                "minimum_free_gib_for_apply": 50, "maximum_snapshots_per_vm": 5,
                "virtual_machines": [f"SecureSandbox-{role}" for role in ("Gateway", "Research", "Target")],
                "retain_names": ["a", "b", "c", "d", "e"]}))
            raw = "\n".join(f"SecureSandbox-{role}: 6 snapshots; retain 5; remove 1"
                            for role in ("Gateway", "Research", "Target")) + "\n"
            stopped = {"status": "verified", "observed": {
                "gateway": "stopped", "research": "stopped", "target": "stopped"}}
            with (patch.object(API, "ROOT", root),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=60 * 1024**3, f_frsize=1)),
                  patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b"")),
                  patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, raw.encode(), b""))):
                preview = API.snapshot_preview()
                self.assertTrue(preview["ready"])
                self.assertEqual(sum(row["remove"] for row in preview["rows"]), 3)
                stopped["observed"]["target"] = "running"
                self.assertFalse(API.snapshot_preview()["ready"])

    def test_snapshot_apply_requires_preflight_and_independent_retained_readback(self):
        from subprocess import CompletedProcess
        before = {"ready": True}
        after = {"policy_verified": True, "stack_stopped": True, "gui_closed": True,
                 "rows": [{"vm": vm, "count": 5, "retain": 5, "remove": 0}
                          for vm in ("gateway", "research", "target")]}
        with (patch.object(API, "snapshot_preview", side_effect=[before, after]),
              patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, b"", b"lost response"))):
            self.assertEqual(API.apply_snapshot_retention()["status"], "verified")
        with (patch.object(API, "snapshot_preview", return_value={"ready": False}),
              patch.object(API, "bounded_command") as command):
            with self.assertRaisesRegex(ValueError, "preflight"):
                API.apply_snapshot_retention()
            command.assert_not_called()

    def test_panic_requires_independent_containment_readback(self):
        import json
        from subprocess import CompletedProcess
        record = {"schema": "secure-sandbox-host-lifecycle-v1", "operation": "panic",
                  "status": "verified", "observed": {"gateway": "running",
                  "research": "stopped", "target": "stopped", "gateway_net0": "disconnected"},
                  "action_failures": []}
        overview = {"status": "verified", "observed": {"gateway": "running",
                    "research": "stopped", "target": "stopped", "gateway_net0": "disconnected"}}
        with (patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, json.dumps(record).encode(), b"")),
              patch.object(API, "catalog", return_value=overview)):
            self.assertEqual(API.panic()["status"], "verified")
            overview["observed"]["target"] = "running"
            self.assertEqual(API.panic()["status"], "incomplete")

    def test_identity_reload_checks_both_agent_sockets_without_returning_keys(self):
        from subprocess import CompletedProcess
        calls = []
        def command(argv, *, timeout, env=None):
            calls.append((argv, env))
            if argv[-1] == "key-load":
                return CompletedProcess(argv, 0, b"private diagnostic\n", b"")
            return CompletedProcess(argv, 0, b"256 SHA256:public-fingerprint key\n", b"")
        with patch.object(API, "bounded_command", side_effect=command):
            result = API.reload_control_identities()
        self.assertEqual(result, {"status": "verified", "provisioning": "loaded", "control": "loaded"})
        self.assertEqual([entry[1]["SSH_AUTH_SOCK"] for entry in calls[1:]],
                         ["/tmp/secure-sandbox-ssh-agent.sock", "/tmp/secure-sandbox-control-ssh-agent.sock"])

    def test_reconciliation_binds_gateway_summary_and_completed_research_record(self):
        import json
        from subprocess import CompletedProcess
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        digest = "a" * 64
        plan = {"schema": "secure-sandbox-lease-reconcile-plan-v1", "run_id": run_id,
                "lease_id": lease_id, "gateway_summary_sha256": digest}
        closed = {"state": "closed", "lease_id": lease_id}
        with (patch.object(API, "run_labctl", return_value=json.dumps(plan)),
              patch.object(API, "lease_status", return_value=closed)):
            self.assertEqual(API.reconcile_plan(run_id), plan)
            closed["state"] = "active"
            with self.assertRaisesRegex(ValueError, "not finalized"):
                API.reconcile_plan(run_id)
        completed = {"run_id": run_id, "lease_id": lease_id, "phase": "committed",
                     "gateway_summary_sha256": digest}
        with (patch.object(API, "reconcile_plan", return_value=plan),
              patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, b"", b"lost response")),
              patch.object(API, "completed_lease", return_value=completed)):
            self.assertEqual(API.reconcile_lease(run_id, digest), completed)
        with (patch.object(API, "reconcile_plan", return_value=plan),
              patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, b"", b"lost response")),
              patch.object(API, "completed_lease", side_effect=RuntimeError("unavailable"))):
            with self.assertRaisesRegex(ValueError, "outcome is unclear"):
                API.reconcile_lease(run_id, digest)


class NativeDeploymentControlCodecTests(unittest.TestCase):
    def deployment_plan_response(self, host_release_id="a" * 64):
        now = int(time.time())
        gateway = API.native_deployment.make_status(
            role="gateway", package_sha256=None, release_id=None,
            catalog_sha256=None, closed_evidence_sha256=None,
            observed_at=now, state="absent",
            generation_kind="absent")
        research = API.native_deployment.make_status(
            role="research", package_sha256=None, release_id=None,
            catalog_sha256=None, closed_evidence_sha256=None,
            observed_at=now, state="absent",
            generation_kind="absent")
        plan = API.native_deployment.make_plan(
            deployment_id="00000000-0000-4000-8000-000000000000",
            host_release_id=host_release_id, catalog_sha256="b" * 64,
            gateway_package_sha256="c" * 64,
            research_package_sha256="d" * 64,
            previous_gateway_package_sha256=None,
            previous_research_package_sha256=None,
            previous_gateway_status_sha256=(
                API.native_deployment.stable_status_sha256(gateway)),
            previous_research_status_sha256=(
                API.native_deployment.stable_status_sha256(research)),
            created_at=now, expires_at=now + 3600)
        body = {
            "plan": plan, "prior_gateway": gateway,
            "prior_research": research,
            "payload_container_sha256": "e" * 64,
        }
        return {
            "schema": "secure-sandbox-native-deployment-plan-response-v1",
            **body, "response_sha256": API.native_deployment.digest(body),
        }

    def recovery_plan(self, response=None):
        response = response or self.deployment_plan_response()
        body = {
            "active_journal_sha256": "f" * 64,
            "deployment_id": response["plan"]["deployment_id"],
            "host_release_id": response["plan"]["host_release_id"],
            "phase": "recovery-required", "observed_pair": "prior-prior",
            "allowed_actions": ["rollback", "resume"],
            "plan_response": response,
            "gateway_status_sha256": response["plan"][
                "previous_gateway_status_sha256"],
            "research_status_sha256": response["plan"][
                "previous_research_status_sha256"],
        }
        return {
            "schema": "secure-sandbox-native-deployment-recovery-plan-v1",
            **body,
            "recovery_plan_sha256": API.native_deployment.digest(body),
        }

    def deployment_reply(self, command, request, result, host_release_id="a" * 64):
        body = {
            "query_id": request["query_id"], "command": command,
            "request_sha256": request["request_sha256"],
            "host_release_id": host_release_id, "result": result,
        }
        value = {
            "schema": API.NATIVE_DEPLOYMENT_REPLY_SCHEMAS[command],
            **body, "reply_sha256": API.native_deployment.digest(body),
        }
        return API.native_deployment.canonical(value)

    def deployment_terminal(self, response=None, *, phase="committed"):
        response = response or self.deployment_plan_response()
        plan = response["plan"]
        if phase == "committed":
            gateway = API.native_deployment.stable_status_projection(
                API.native_deployment.make_status(
                    role="gateway", state="verified",
                    generation_kind="protected",
                    package_sha256=plan["gateway_package_sha256"],
                    release_id="5" * 64, catalog_sha256=None,
                    closed_evidence_sha256="6" * 64, observed_at=1))
            research = API.native_deployment.stable_status_projection(
                API.native_deployment.make_status(
                    role="research", state="verified",
                    generation_kind="protected",
                    package_sha256=plan["research_package_sha256"],
                    release_id="7" * 64,
                    catalog_sha256=plan["catalog_sha256"],
                    closed_evidence_sha256="8" * 64, observed_at=1))
        else:
            gateway = API.native_deployment.stable_status_projection(
                response["prior_gateway"])
            research = API.native_deployment.stable_status_projection(
                response["prior_research"])
        evidence = {
            "gateway_status": gateway, "research_status": research,
            "gateway_status_sha256": (
                API.native_deployment.status_projection_sha256(gateway)),
            "research_status_sha256": (
                API.native_deployment.status_projection_sha256(research)),
            "fence_evidence_sha256": None, "result_sha256": None,
            "terminal_sha256": "9" * 64, "outcome": phase,
        }
        body = {
            "deployment_id": plan["deployment_id"], "sequence": 6,
            "phase": phase, "plan": plan,
            "apply_authorization_sha256": "1" * 64,
            "authorization_sha256": "1" * 64,
            "host_release_id": plan["host_release_id"],
            "payload_container_sha256": response["payload_container_sha256"],
            "prior_gateway": response["prior_gateway"],
            "prior_research": response["prior_research"],
            "event": phase, "evidence": evidence, "transport": None,
            "prior_record_sha256": "a" * 64,
            "updated_at": 2_000_000_200,
        }
        return {
            "schema": "secure-sandbox-native-deployment-journal-record-v1",
            **body, "record_sha256": API.native_deployment.digest(body),
        }

    def catalog_gate(self, state="active"):
        body = {
            "state": state,
            "active_promotion_id": (
                "00000000-0000-4000-8000-000000000001"
                if state == "active" else None),
            "active_state_sha256": "5" * 64 if state == "active" else None,
        }
        return {
            "schema": API.NATIVE_CATALOG_PROMOTION_GATE_SCHEMA,
            **body, "gate_sha256": API.native_deployment.digest(body),
        }

    def catalog_terminal(self, host_release_id="a" * 64):
        body = {
            "state": "finalized",
            "promotion_id": "00000000-0000-4000-8000-000000000001",
            "catalog_sha256": "b" * 64,
            "host_release_id": host_release_id,
            "promotion_receipt_sha256": "6" * 64,
            "replay_authority_sha256": "7" * 64,
            "expected_gate_sha256": self.catalog_gate()["gate_sha256"],
            "recovery_intent_sha256": "8" * 64,
        }
        return {
            "schema": "secure-sandbox-native-stack-catalog-recovery-terminal-v1",
            **body, "terminal_sha256": API.native_deployment.digest(body),
        }

    def test_deployment_query_digest_is_command_domain_separated(self):
        query_id = "00000000-0000-4000-8000-000000000002"
        requests = {
            command: API.native_deployment_query_request(
                command, query_id=query_id)
            for command in API.NATIVE_DEPLOYMENT_QUERY_SCHEMAS
        }
        self.assertEqual(len({
            item["request_sha256"] for item in requests.values()
        }), 3)
        response = self.deployment_plan_response()
        raw = self.deployment_reply("plan", requests["plan"], response)
        self.assertEqual(
            API.native_deployment_query_reply("plan", requests["plan"], raw),
            response)
        with self.assertRaisesRegex(ValueError, "query_reply_invalid"):
            API.native_deployment_query_reply(
                "status", requests["status"], raw)

    def test_deployment_authorize_binds_reviewed_plan_and_terminal_intent(self):
        request = API.native_deployment_query_request(
            "plan", query_id="00000000-0000-4000-8000-000000000002")
        response = self.deployment_plan_response()
        reply = self.deployment_reply("plan", request, response)
        terminal = self.deployment_terminal(response)
        completed = subprocess.CompletedProcess(
            [], 0, API.native_deployment.canonical(terminal),
            b"SecureSandbox approval request\n")
        with patch.object(API, "bounded_command", return_value=completed) as run:
            self.assertEqual(API.native_deployment_authorize(
                "apply", response["response_sha256"], "Control Center",
                "00000000-0000-4000-8000-000000000009", request, reply),
                terminal)
        command = run.call_args.args[0]
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            API.NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS,
        )
        self.assertIn(API.native_deployment.APPLY_OPERATION, command)
        self.assertIn(response["response_sha256"], json.dumps(
            json.loads(command[command.index("--parameters-json") + 1])))
        with patch.object(
            API, "bounded_command", return_value=subprocess.CompletedProcess(
                [], 0, API.native_deployment.canonical(terminal),
                b"x" * (API.NATIVE_PRIVILEGED_STDERR_LIMIT + 1),
            )), self.assertRaisesRegex(
                ValueError, "native_deployment_authorization_rejected"
            ):
            API.native_deployment_authorize(
                "apply", response["response_sha256"], "Control Center",
                "00000000-0000-4000-8000-000000000009", request, reply)
        opposite = self.deployment_terminal(response, phase="rolled-back")
        with patch.object(
            API, "bounded_command", return_value=subprocess.CompletedProcess(
                [], 0, API.native_deployment.canonical(opposite), b"")), \
                self.assertRaisesRegex(ValueError, "result_invalid"):
            API.native_deployment_authorize(
                "apply", response["response_sha256"], "Control Center",
                "00000000-0000-4000-8000-000000000009", request, reply)

    def test_privileged_client_timeout_outlives_root_mutation_window(self):
        self.assertEqual(
            API.NATIVE_PRIVILEGED_OPERATION_TIMEOUT_SECONDS, 3_900)
        self.assertEqual(
            API.NATIVE_PRIVILEGED_AUTHORIZATION_TIMEOUT_SECONDS, 4_140)
        self.assertEqual(
            API.NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS, 4_200)
        delayed_approval = API.NATIVE_AUTHORIZATION_REQUEST_TTL_SECONDS - 1
        near_bound_child = API.NATIVE_PRIVILEGED_OPERATION_TIMEOUT_SECONDS - 1
        self.assertLess(
            delayed_approval + near_bound_child,
            API.NATIVE_PRIVILEGED_AUTHORIZATION_TIMEOUT_SECONDS,
        )
        self.assertLess(
            API.NATIVE_PRIVILEGED_AUTHORIZATION_TIMEOUT_SECONDS,
            API.NATIVE_PRIVILEGED_CLIENT_TIMEOUT_SECONDS,
        )

    def test_deployment_recovery_authorize_binds_action_and_active_journal(self):
        response = self.deployment_plan_response()
        recovery = self.recovery_plan(response)
        request = API.native_deployment_query_request(
            "recovery-plan",
            query_id="00000000-0000-4000-8000-000000000002")
        reply = self.deployment_reply(
            "recovery-plan", request, recovery)
        terminal = self.deployment_terminal(response, phase="rolled-back")
        completed = subprocess.CompletedProcess(
            [], 0, API.native_deployment.canonical(terminal), b"")
        with patch.object(API, "bounded_command", return_value=completed) as run:
            self.assertEqual(API.native_deployment_authorize(
                "rollback", recovery["recovery_plan_sha256"],
                "Control Center", "00000000-0000-4000-8000-000000000009",
                request, reply), terminal)
        command = run.call_args.args[0]
        parameters = json.loads(command[command.index("--parameters-json") + 1])
        self.assertEqual(command[command.index("--operation") + 1],
                         API.native_deployment.RECOVER_OPERATION)
        self.assertEqual(parameters["action"], "rollback")
        self.assertEqual(parameters["recovery"]["active_journal_sha256"],
                         "f" * 64)
        restricted = json.loads(json.dumps(recovery))
        restricted["allowed_actions"] = ["resume"]
        body = {
            key: item for key, item in restricted.items()
            if key not in {"schema", "recovery_plan_sha256"}
        }
        restricted["recovery_plan_sha256"] = API.native_deployment.digest(body)
        restricted_reply = self.deployment_reply(
            "recovery-plan", request, restricted)
        with self.assertRaisesRegex(ValueError, "plan_changed"):
            API.native_deployment_authorize(
                "rollback", restricted["recovery_plan_sha256"],
                "Control Center", "00000000-0000-4000-8000-000000000009",
                request, restricted_reply)

    def test_catalog_gate_and_recovery_codecs_reject_cross_replay(self):
        query_id = "00000000-0000-4000-8000-000000000002"
        gate_request = API.native_catalog_promotion_gate_request(
            query_id=query_id)
        gate = self.catalog_gate()
        gate_body = {
            "query_id": query_id,
            "command": API.NATIVE_CATALOG_PROMOTION_GATE_COMMAND,
            "request_sha256": gate_request["request_sha256"],
            "host_release_id": "a" * 64,
            "gate": gate,
        }
        gate_reply = {
            "schema": API.NATIVE_CATALOG_PROMOTION_GATE_REPLY_SCHEMA,
            **gate_body,
            "reply_sha256": API.native_deployment.digest(gate_body),
        }
        raw_gate = API.native_deployment.canonical(gate_reply)
        self.assertEqual(
            API.native_catalog_promotion_gate_reply(gate_request, raw_gate),
            gate)
        recovery_request = API.native_catalog_promotion_recovery_request(
            gate["gate_sha256"], recovery_id=query_id)
        self.assertNotEqual(
            gate_request["request_sha256"],
            recovery_request["request_sha256"])
        terminal = self.catalog_terminal()
        recovery_body = {
            "recovery_id": query_id,
            "command": API.NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
            "request_sha256": recovery_request["request_sha256"],
            "host_release_id": "a" * 64,
            "terminal": terminal,
        }
        recovery_reply = {
            "schema": API.NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA,
            **recovery_body,
            "reply_sha256": API.native_deployment.digest(recovery_body),
        }
        raw_recovery = API.native_deployment.canonical(recovery_reply)
        self.assertEqual(API.native_catalog_promotion_recovery_reply(
            recovery_request, raw_recovery), terminal)
        changed = dict(recovery_request, expected_gate_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "recovery_reply_invalid"):
            API.native_catalog_promotion_recovery_reply(changed, raw_recovery)

    def test_catalog_recovery_reply_binds_current_release_separately_from_provenance(self):
        gate = self.catalog_gate()
        request = API.native_catalog_promotion_recovery_request(
            gate["gate_sha256"],
            recovery_id="00000000-0000-4000-8000-000000000002")
        terminal = self.catalog_terminal(host_release_id="b" * 64)
        body = {
            "recovery_id": request["recovery_id"],
            "command": API.NATIVE_CATALOG_PROMOTION_RECOVERY_COMMAND,
            "request_sha256": request["request_sha256"],
            "host_release_id": "a" * 64,
            "terminal": terminal,
        }
        reply = {
            "schema": API.NATIVE_CATALOG_PROMOTION_RECOVERY_REPLY_SCHEMA,
            **body, "reply_sha256": API.native_deployment.digest(body),
        }
        self.assertEqual(
            API.native_catalog_promotion_recovery_reply(
                request, API.native_deployment.canonical(reply)),
            terminal,
        )


if __name__ == "__main__":
    unittest.main()
