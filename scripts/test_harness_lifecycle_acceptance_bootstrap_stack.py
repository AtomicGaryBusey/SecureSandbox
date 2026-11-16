#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_bootstrap_stack",
    ROOT / "scripts/harness-lifecycle-acceptance-bootstrap-stack.py",
)
assert SPEC is not None and SPEC.loader is not None
stack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stack)


def result(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class AcceptanceBootstrapStackTests(unittest.TestCase):
    def setUp(self):
        self.campaign = {
            "campaign_id": str(uuid.uuid4()),
            "campaign_sha256": "a" * 64,
            "source_commit": "b" * 40,
        }
        self.case = {"case_id": stack.CASE_ID}
        self.intermediate = {
            "gateway": "running", "research": "stopped",
            "target": "stopped", "gateway_net0": "disconnected",
        }
        self.final = {
            "gateway": "running", "research": "running",
            "target": "stopped", "gateway_net0": "disconnected",
        }

    @staticmethod
    def readiness(*, available: bool = True):
        count = len(stack.BOOTSTRAP.ACCEPTANCE_CLI.DRIVER_ENTRYPOINTS)
        return {
            "status": "ready" if available else "incomplete",
            "driver_count": count,
            "available_driver_count": count if available else count - 1,
            "drivers": [{"available": available} for _ in range(count)],
            "campaign_initialization_allowed": available,
        }

    def test_preflight_requires_complete_protected_driver_inventory(self):
        with mock.patch.object(
            stack.BOOTSTRAP, "preflight",
            return_value=(self.campaign, self.case),
        ), mock.patch.object(
            stack.BOOTSTRAP.ACCEPTANCE_CLI, "driver_readiness",
            return_value=self.readiness(),
        ) as readiness:
            self.assertEqual(stack.preflight(123), (self.campaign, self.case))
        readiness.assert_called_once_with(
            stack.ROOT, source_commit=self.campaign["source_commit"],
        )

    def test_preflight_rejects_incomplete_protected_driver_inventory(self):
        with mock.patch.object(
            stack.BOOTSTRAP, "preflight",
            return_value=(self.campaign, self.case),
        ), mock.patch.object(
            stack.BOOTSTRAP.ACCEPTANCE_CLI, "driver_readiness",
            return_value=self.readiness(available=False),
        ), self.assertRaisesRegex(
            stack.AcceptanceStackError, "acceptance_stack_drivers_unready",
        ):
            stack.preflight(123)

    def test_time_sync_rejects_active_research_run_before_clock_mutation(self):
        with mock.patch.object(
            stack, "command", return_value=result(stdout=b"active-run\n"),
        ) as command:
            with self.assertRaisesRegex(
                stack.AcceptanceStackError,
                "acceptance_stack_active_run_or_time_unavailable",
            ):
                stack.synchronize_time()
        command.assert_called_once()

    def test_time_sync_applies_only_gateway_and_research_and_reads_back(self):
        with mock.patch.object(
            stack.time, "time", return_value=2_000_000_000,
        ), mock.patch.object(
            stack, "command", side_effect=[
                result(), result(stdout=b"{}"), result(stdout=b"{}"),
                result(stdout=b"2000000000\n"),
                result(stdout=b"2000000000\n"),
            ],
        ) as command:
            stack.synchronize_time()
        calls = [item.args[0] for item in command.call_args_list]
        self.assertEqual(len(calls), 5)
        self.assertIn(stack.GATEWAY_CONTROL, calls[1])
        self.assertIn(stack.RESEARCH_CONTROL, calls[2])
        self.assertNotIn("sandbox-target-control", sum(calls, []))
        self.assertNotIn("sandbox-target-admin", sum(calls, []))

    def test_time_sync_rejects_independent_skew_readback(self):
        with mock.patch.object(
            stack.time, "time", return_value=2_000_000_000,
        ), mock.patch.object(
            stack, "command", side_effect=[
                result(), result(stdout=b"{}"), result(stdout=b"{}"),
                result(stdout=b"1999999900\n"),
            ],
        ), self.assertRaisesRegex(
            stack.AcceptanceStackError,
            "acceptance_stack_time_readback_invalid",
        ):
            stack.synchronize_time()

    def test_transition_preserves_isolation_starts_only_research_and_validates(self):
        readbacks = {"host-install-readback.json": {"status": "verified"}}
        with mock.patch.object(
            stack.LIFECYCLE, "require_mutation_prerequisites",
        ), mock.patch.object(
            stack.LIFECYCLE, "gui_running", return_value=False,
        ), mock.patch.object(
            stack.LIFECYCLE, "observe",
            side_effect=[(self.intermediate, {}), (self.final, {})],
        ), mock.patch.object(
            stack.LIFECYCLE, "mutate", return_value=True,
        ) as mutate, mock.patch.object(
            stack.LIFECYCLE, "gateway_gamepad_sharing_disabled",
            return_value=True,
        ), mock.patch.object(
            stack.LIFECYCLE, "wait_guest", return_value=True,
        ) as wait_guest, mock.patch.object(
            stack, "synchronize_time",
        ), mock.patch.object(
            stack.BOOTSTRAP, "clean_install_readback", return_value=readbacks,
        ) as readback, mock.patch.object(stack, "emit") as emit:
            value = stack.continue_start(
                inherited_lock=11, prior_outcomes=[], campaign=self.campaign,
                case=self.case,
            )
        self.assertEqual(value, 0)
        commands = [item.args[0] for item in mutate.call_args_list]
        self.assertEqual(commands[0][-2:], ["start", "SecureSandbox-Research"])
        self.assertFalse(any("SecureSandbox-Target" in part
                             for command in commands for part in command))
        self.assertEqual(
            [item.args[0] for item in wait_guest.call_args_list],
            [stack.GATEWAY_CONTROL, stack.RESEARCH_CONTROL],
        )
        readback.assert_called_once_with(self.campaign, self.case, mock.ANY)
        self.assertEqual(emit.call_args.args[:2], ("verified", "complete"))

    def test_transition_rejects_connected_gateway_without_post_power_repair(self):
        connected = dict(self.intermediate, gateway_net0="connected")
        with mock.patch.object(
            stack.LIFECYCLE, "require_mutation_prerequisites",
        ), mock.patch.object(
            stack.LIFECYCLE, "gui_running", return_value=False,
        ), mock.patch.object(
            stack.LIFECYCLE, "observe", return_value=(connected, {}),
        ), mock.patch.object(
            stack.LIFECYCLE, "mutate",
        ) as mutate, mock.patch.object(stack, "emit") as emit:
            value = stack.continue_start(
                inherited_lock=11, prior_outcomes=[], campaign=self.campaign,
                case=self.case,
            )
        self.assertEqual(value, 1)
        mutate.assert_not_called()
        self.assertIn("acceptance_stack_post_power_uplink_not_isolated",
                      emit.call_args.args[3])

    def test_verified_emit_downgrades_changed_final_readback(self):
        connected = dict(self.final, gateway_net0="connected")
        with mock.patch.object(
            stack.LIFECYCLE, "observe",
            return_value=(connected, {
                "gateway": "reachable", "research": "reachable",
                "target": "unreachable",
            }),
        ), mock.patch("builtins.print") as output:
            accepted = stack.emit(
                "verified", "complete", [], [], campaign=self.campaign,
                required_observed=self.final,
            )
        self.assertFalse(accepted)
        encoded = output.call_args.args[0]
        self.assertIn('"status":"rejected"', encoded)
        self.assertIn("acceptance_stack_final_readback_invalid", encoded)

    def test_transition_rejects_if_target_is_running_at_final_readback(self):
        invalid = dict(self.final, target="running")
        with mock.patch.object(
            stack.LIFECYCLE, "require_mutation_prerequisites",
        ), mock.patch.object(
            stack.LIFECYCLE, "gui_running", return_value=False,
        ), mock.patch.object(
            stack.LIFECYCLE, "observe",
            side_effect=[(self.intermediate, {}), (invalid, {})],
        ), mock.patch.object(
            stack.LIFECYCLE, "mutate", return_value=True,
        ), mock.patch.object(
            stack.LIFECYCLE, "gateway_gamepad_sharing_disabled",
            return_value=True,
        ), mock.patch.object(
            stack.LIFECYCLE, "wait_guest", return_value=True,
        ), mock.patch.object(
            stack, "synchronize_time",
        ), mock.patch.object(
            stack.BOOTSTRAP, "clean_install_readback", return_value={},
        ), mock.patch.object(stack, "emit") as emit:
            value = stack.continue_start(
                inherited_lock=11, prior_outcomes=[], campaign=self.campaign,
                case=self.case,
            )
        self.assertEqual(value, 1)
        self.assertIn("acceptance_stack_final_state_invalid",
                      emit.call_args.args[3])

    def test_run_passes_only_internal_fixed_continuation(self):
        captured = {}

        def service_run(*, continuation, initial_validator):
            captured["continuation"] = continuation
            captured["initial_validator"] = initial_validator
            return 9

        with mock.patch.object(
            stack, "preflight", return_value=(self.campaign, self.case),
        ), mock.patch.object(
            stack.SERVICE_BOOTSTRAP, "run", side_effect=service_run,
        ):
            self.assertEqual(stack.run(), 9)
        with mock.patch.object(stack, "continue_start", return_value=4) as start:
            self.assertEqual(captured["continuation"](
                inherited_lock=12, prior_outcomes=[],
            ), 4)
        start.assert_called_once_with(
            inherited_lock=12, prior_outcomes=[], campaign=self.campaign,
            case=self.case,
        )
        captured["initial_validator"](dict(
            self.intermediate, gateway_net0="disconnected",
        ))
        with self.assertRaisesRegex(
            stack.SERVICE_BOOTSTRAP.ServiceBootstrapError,
            "acceptance_stack_uplink_must_be_disconnected_before_start",
        ):
            captured["initial_validator"](dict(
                self.intermediate, gateway_net0="connected",
            ))


if __name__ == "__main__":
    unittest.main()
