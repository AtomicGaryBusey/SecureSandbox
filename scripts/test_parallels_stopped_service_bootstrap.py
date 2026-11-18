#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "parallels_stopped_service_bootstrap",
    ROOT / "scripts/parallels-stopped-service-bootstrap.py",
)
assert SPEC is not None and SPEC.loader is not None
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class StoppedServiceBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.progress = Path(self.temporary.name) / "progress.json"
        self.initial = {
            "gateway": "stopped", "research": "stopped", "target": "stopped",
            "gateway_net0": "connected",
        }
        self.intermediate = {
            "gateway": "running", "research": "stopped", "target": "stopped",
            "gateway_net0": "connected",
        }
        self.wait_guest = mock.patch.object(
            bootstrap.LIFECYCLE, "wait_guest", return_value=True,
        )
        self.wait_guest_mock = self.wait_guest.start()
        self.addCleanup(self.wait_guest.stop)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def descriptor() -> int:
        return os.open("/dev/null", os.O_RDONLY)

    @staticmethod
    def applied_mutation(argv, action, target, outcomes, verify):
        outcomes.append({"action": action, "target": target, "result": "succeeded"})
        return verify()

    def common(self, observations, gui_ids):
        return (
            mock.patch.object(bootstrap.os, "geteuid", return_value=501),
            mock.patch.object(
                bootstrap.LIFECYCLE, "acquire_lock", side_effect=self.descriptor,
            ),
            mock.patch.multiple(
                bootstrap.LIFECYCLE,
                require_mutation_prerequisites=mock.DEFAULT,
                require_background_vm_policy=mock.DEFAULT,
            ),
            mock.patch.object(
                bootstrap.LIFECYCLE, "PROGRESS_PATH", self.progress,
            ),
            mock.patch.object(
                bootstrap.LIFECYCLE, "observe", side_effect=observations,
            ),
            mock.patch.object(
                bootstrap, "gui_process_ids", side_effect=gui_ids,
            ),
            mock.patch.object(bootstrap, "terminate_gui"),
            mock.patch.object(bootstrap.LIFECYCLE, "emit"),
        )

    def test_all_stopped_bootstraps_only_gateway_then_delegates_closed_start(self):
        patches = self.common(
            [(self.initial, {}), (self.intermediate, {}), (self.intermediate, {})],
            [(41,), (41,), (41,)],
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6] as terminate_gui, patches[7], \
                mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate", side_effect=self.applied_mutation,
                ) as mutate, mock.patch.object(
                    bootstrap.LIFECYCLE, "wait_vm", return_value=True,
                ), mock.patch.object(
                    bootstrap.LIFECYCLE, "start", return_value=0,
                ) as start:
            self.assertEqual(bootstrap.run(), 0)
        mutate.assert_called_once()
        self.assertEqual(mutate.call_args.args[1:3], (
            "parallels_service_bootstrap", "gateway",
        ))
        terminate_gui.assert_called_once_with(41)
        self.assertEqual(start.call_args.kwargs["prior_outcomes"], [{
            "action": "parallels_service_bootstrap",
            "target": "gateway", "result": "succeeded",
        }])
        self.assertGreaterEqual(start.call_args.kwargs["inherited_lock"], 0)

    def test_verified_gateway_recovery_does_not_start_it_again(self):
        patches = self.common(
            [(self.intermediate, {}), (self.intermediate, {}), (self.intermediate, {})],
            [(52,), (52,), (52,)],
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate",
                ) as mutate, mock.patch.object(
                    bootstrap.LIFECYCLE, "start", return_value=0,
                ) as start:
            self.assertEqual(bootstrap.run(), 0)
        mutate.assert_not_called()
        self.assertEqual(start.call_args.kwargs["prior_outcomes"][0]["result"],
                         "already_satisfied")

    def test_fixed_caller_can_continue_under_same_lock(self):
        patches = self.common(
            [(self.intermediate, {}), (self.intermediate, {}),
             (self.intermediate, {})],
            [(53,), (53,), (53,)],
        )
        continuation = mock.Mock(return_value=7)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate",
                ) as mutate:
            self.assertEqual(bootstrap.run(continuation=continuation), 7)
        mutate.assert_not_called()
        continuation.assert_called_once_with(
            inherited_lock=mock.ANY,
            prior_outcomes=[{
                "action": "parallels_service_bootstrap", "target": "gateway",
                "result": "already_satisfied",
            }],
        )

    def test_fixed_initial_validator_rejects_before_gateway_start(self):
        patches = self.common([(self.initial, {}), (self.initial, {})], [(54,)])
        validator = mock.Mock(side_effect=bootstrap.ServiceBootstrapError(
            "acceptance_stack_uplink_must_be_disconnected_before_start"
        ))
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7] as emit, mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate",
                ) as mutate:
            self.assertEqual(bootstrap.run(initial_validator=validator), 1)
        validator.assert_called_once_with(self.initial)
        mutate.assert_not_called()
        self.assertIn(
            "acceptance_stack_uplink_must_be_disconnected_before_start",
            emit.call_args.args[4],
        )

    def test_fixed_initial_validator_rechecks_immediately_before_gateway_start(self):
        isolated = dict(self.initial, gateway_net0="disconnected")
        intermediate = dict(self.intermediate, gateway_net0="disconnected")
        patches = self.common(
            [(isolated, {}), (isolated, {}), (intermediate, {}),
             (intermediate, {})],
            [(55,), (55,), (55,)],
        )
        validator = mock.Mock()
        continuation = mock.Mock(return_value=0)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate",
                    side_effect=self.applied_mutation,
                ), mock.patch.object(
                    bootstrap.LIFECYCLE, "wait_vm", return_value=True,
                ):
            self.assertEqual(bootstrap.run(
                continuation=continuation,
                initial_validator=validator,
            ), 0)
        self.assertEqual(validator.call_args_list, [
            mock.call(isolated), mock.call(isolated),
        ])
        continuation.assert_called_once()

    def test_other_partial_state_rejects_before_mutation(self):
        invalid = dict(self.intermediate, research="running")
        patches = self.common([(invalid, {}), (invalid, {})], [(61,)])
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7] as emit, mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate",
                ) as mutate, mock.patch.object(
                    bootstrap.LIFECYCLE, "start",
                ) as start:
            self.assertEqual(bootstrap.run(), 1)
        mutate.assert_not_called()
        start.assert_not_called()
        self.assertIn("parallels_service_bootstrap_state_invalid",
                      emit.call_args.args[4])

    def test_invalid_background_policy_rejects_before_gateway_start(self):
        patches = self.common([(self.initial, {}), (self.initial, {})], [(62,)])
        with patches[0], patches[1], patches[2] as prerequisites, patches[3], \
                patches[4], patches[5], patches[6], patches[7] as emit, \
                mock.patch.object(bootstrap.LIFECYCLE, "mutate") as mutate:
            prerequisites["require_background_vm_policy"].side_effect = (
                bootstrap.LIFECYCLE.LifecycleError(
                    "gateway_background_policy_invalid"
                )
            )
            self.assertEqual(bootstrap.run(), 1)
        mutate.assert_not_called()
        self.assertIn("gateway_background_policy_invalid", emit.call_args.args[4])

    def test_background_policy_requires_headless_keep_running_for_every_vm(self):
        valid = [{
            "Startup and Shutdown": {
                "Autostart": "off", "Autostop": "stop",
                "Startup view": "headless",
                "On window close": "keep-running",
            },
        }]
        with mock.patch.object(
            bootstrap.LIFECYCLE, "command",
        ) as command, mock.patch.object(
            bootstrap.LIFECYCLE, "parse_json_output",
            side_effect=[valid, valid, valid],
        ):
            bootstrap.LIFECYCLE.require_background_vm_policy()
        self.assertEqual(command.call_count, 3)

        invalid = [{
            "Startup and Shutdown": {
                "Autostart": "off", "Autostop": "stop",
                "Startup view": "same", "On window close": "ask",
            },
        }]
        with mock.patch.object(
            bootstrap.LIFECYCLE, "command",
        ), mock.patch.object(
            bootstrap.LIFECYCLE, "parse_json_output", return_value=invalid,
        ), self.assertRaisesRegex(
            bootstrap.LIFECYCLE.LifecycleError,
            "gateway_background_policy_invalid",
        ):
            bootstrap.LIFECYCLE.require_background_vm_policy()

    def test_gui_pid_change_after_gateway_start_rejects_before_close(self):
        patches = self.common(
            [(self.initial, {}), (self.intermediate, {}), (self.intermediate, {})],
            [(71,), (71,), (72,)],
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6] as terminate_gui, patches[7] as emit, \
                mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate", side_effect=self.applied_mutation,
                ), mock.patch.object(
                    bootstrap.LIFECYCLE, "wait_vm", return_value=True,
                ), mock.patch.object(bootstrap.LIFECYCLE, "start") as start:
            self.assertEqual(bootstrap.run(), 1)
        terminate_gui.assert_not_called()
        start.assert_not_called()
        self.assertIn("parallels_gui_session_changed", emit.call_args.args[4])

    def test_gateway_control_must_authenticate_before_gui_close(self):
        patches = self.common(
            [(self.initial, {}), (self.intermediate, {}), (self.intermediate, {})],
            [(75,), (75,)],
        )
        self.wait_guest_mock.return_value = False
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6] as terminate_gui, patches[7] as emit, \
                mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate", side_effect=self.applied_mutation,
                ), mock.patch.object(
                    bootstrap.LIFECYCLE, "wait_vm", return_value=True,
                ), mock.patch.object(bootstrap.LIFECYCLE, "start") as start:
            self.assertEqual(bootstrap.run(), 1)
        self.wait_guest_mock.assert_called_once_with(
            bootstrap.GATEWAY_CONTROL,
        )
        terminate_gui.assert_not_called()
        start.assert_not_called()
        self.assertIn(
            "gateway_control_unreachable_before_gui_close",
            emit.call_args.args[4],
        )

    def test_closed_service_loss_rejects_without_ordinary_start(self):
        unavailable = {
            "gateway": "unknown", "research": "unknown", "target": "unknown",
            "gateway_net0": "unknown",
        }
        patches = self.common(
            [(self.initial, {}), (self.intermediate, {}), (unavailable, {}),
             (unavailable, {})],
            [(81,), (81,), (81,)],
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7] as emit, mock.patch.object(
                    bootstrap.LIFECYCLE, "mutate", side_effect=self.applied_mutation,
                ), mock.patch.object(
                    bootstrap.LIFECYCLE, "wait_vm", return_value=True,
                ), mock.patch.object(bootstrap.LIFECYCLE, "start") as start:
            self.assertEqual(bootstrap.run(), 1)
        start.assert_not_called()
        self.assertIn("parallels_closed_service_readback_invalid",
                      emit.call_args.args[4])

    def test_untrusted_prerequisite_rejects_before_gui_probe_or_lock(self):
        with mock.patch.object(
            bootstrap.os, "geteuid", return_value=501,
        ), mock.patch.object(
            bootstrap.LIFECYCLE, "require_mutation_prerequisites",
            side_effect=bootstrap.LIFECYCLE.LifecycleError(
                "prerequisite_untrusted:control_client"
            ),
        ), mock.patch.object(
            bootstrap, "gui_process_ids",
        ) as gui, mock.patch.object(
            bootstrap.LIFECYCLE, "acquire_lock",
        ) as acquire, self.assertRaisesRegex(
            bootstrap.ServiceBootstrapError,
            "prerequisite_untrusted:control_client",
        ):
            bootstrap.run()
        gui.assert_not_called()
        acquire.assert_not_called()

    def test_gui_termination_uses_only_term_when_pid_exits(self):
        killer = mock.Mock()
        with mock.patch.object(
            bootstrap, "gui_process_ids", return_value=(),
        ):
            bootstrap.terminate_gui(91, now=mock.Mock(return_value=0),
                                    sleep=mock.Mock(), killer=killer)
        killer.assert_called_once_with(91, bootstrap.signal.SIGTERM)

    def test_gui_termination_escalates_only_unchanged_pid(self):
        killer = mock.Mock()
        with mock.patch.object(
            bootstrap, "gui_process_ids", side_effect=[(92,), ()],
        ):
            bootstrap.terminate_gui(
                92, now=mock.Mock(side_effect=[0, 3, 3]),
                sleep=mock.Mock(), killer=killer,
            )
        self.assertEqual(killer.call_args_list, [
            mock.call(92, bootstrap.signal.SIGTERM),
            mock.call(92, bootstrap.signal.SIGKILL),
        ])

    def test_gui_termination_rejects_changed_pid_without_kill(self):
        killer = mock.Mock()
        with mock.patch.object(
            bootstrap, "gui_process_ids", return_value=(94,),
        ), self.assertRaisesRegex(
            bootstrap.ServiceBootstrapError, "parallels_gui_session_changed",
        ):
            bootstrap.terminate_gui(
                93, now=mock.Mock(return_value=0),
                sleep=mock.Mock(), killer=killer,
            )
        killer.assert_called_once_with(93, bootstrap.signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
