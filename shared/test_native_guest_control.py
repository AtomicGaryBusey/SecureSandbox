#!/usr/bin/env python3

from __future__ import annotations

import copy
import fcntl
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shared import native_guest_control as control
from shared.test_native_egress import NOW, inference_grant


ACTION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def closed(step: str = "apply-gateway-deny-only") -> dict:
    body = {
        "action_id": ACTION_ID,
        "plan_sha256": "1" * 64,
        "stack_id": "anthropic-claude-mythos",
        "stack_sha256": "2" * 64,
        "state": "closed",
    }
    successor = {
        "schema": control.CLOSED_SCHEMA,
        **body,
        "policy_sha256": control.digest(body),
    }
    return {
        "schema": control.REQUEST_SCHEMA,
        "action_id": ACTION_ID,
        "plan_sha256": "1" * 64,
        "authorization_sha256": "3" * 64,
        "step": step,
        "successor": successor,
    }


class NativeGuestControlTests(unittest.TestCase):
    @staticmethod
    def nft_ruleset(*, open_grant: dict | None = None) -> dict:
        def chain(name: str) -> dict:
            return {"chain": {
                "family": "inet", "table": "filter", "name": name,
                "type": "filter", "hook": name, "prio": 0,
                "policy": "drop",
            }}

        def rule(name: str, expressions: list[dict]) -> dict:
            return {"rule": {
                "family": "inet", "table": "filter", "chain": name,
                "expr": expressions,
            }}

        match = lambda left, op, right: {
            "match": {"left": left, "op": op, "right": right}
        }
        mark_left = {"ct": {"key": "mark"}}
        uid_left = {"meta": {"key": "skuid"}}
        items: list[dict] = [
            {"table": {"family": "inet", "name": "filter"}},
            chain("input"), chain("forward"), chain("output"),
            rule("input", [match({"meta": {"key": "iifname"}}, "==", "lo"),
                           {"accept": None}]),
        ]
        input_native: list[dict] = []
        output_native: list[dict] = []
        if open_grant is not None:
            mark = int(control.native_egress.conntrack_mark(
                open_grant, "research"
            ), 16)
            items.append({"set": {
                "family": "inet", "table": "filter",
                "name": "native_gateway_ipv4", "flags": ["timeout"],
                "elem": ["172.30.10.1"],
            }})
            input_native.append(rule("input", [
                match(mark_left, "==", mark),
                match({"payload": {"protocol": "tcp", "field": "sport"}},
                      "==", 8643), {"accept": None},
            ]))
            for uid in (502, 503):
                for state in ("new", "established"):
                    output_native.append(rule("output", [
                        match(uid_left, "==", uid),
                        match({"payload": {"protocol": "tcp", "field": "dport"}},
                              "==", 8643),
                        match(mark_left, "==", mark),
                        {"accept": None},
                    ]))
        items.extend(input_native)
        items.extend([
            rule("input", [match(mark_left, "!=", 0), {"drop": None}]),
            rule("input", [match({"ct": {"key": "state"}}, "in",
                                 ["established", "related"]), {"accept": None}]),
        ])
        items.extend(output_native)
        for uid in (501, 502, 503):
            items.append(rule("output", [
                match(uid_left, "==", uid), {"drop": None},
            ]))
        items.extend([
            rule("output", [match(mark_left, "!=", 0), {"drop": None}]),
            rule("output", [match({"meta": {"key": "oifname"}}, "==", "lo"),
                            {"accept": None}]),
            rule("output", [match({"ct": {"key": "state"}}, "in",
                                  ["established", "related"]), {"accept": None}]),
        ])
        return {"nftables": items}

    def test_closed_request_is_exact_role_and_digest_bound(self) -> None:
        value = closed()
        self.assertEqual(
            control.validate_request(value, value["step"], "gateway"), value
        )
        with self.assertRaisesRegex(control.NativeGuestControlError, "request_invalid"):
            control.validate_request(value, value["step"], "research")
        for mutation in (
            {**value, "extra": True},
            {**value, "authorization_sha256": "x" * 64},
            {**value, "successor": {**value["successor"], "state": "open"}},
        ):
            with self.assertRaises(control.NativeGuestControlError):
                control.validate_request(mutation, value["step"], "gateway")

    @mock.patch.object(control.time, "time", return_value=NOW)
    def test_open_successor_is_fully_revalidated(self, _now: mock.Mock) -> None:
        value = closed("apply-gateway-successor-policy")
        value["successor"] = inference_grant()
        self.assertEqual(
            control.validate_request(value, value["step"], "gateway")["successor"],
            value["successor"],
        )
        mutated = copy.deepcopy(value)
        mutated["successor"]["destinations"][0]["ipv4"] = ["127.0.0.1"]
        with self.assertRaisesRegex(control.NativeGuestControlError, "successor_invalid"):
            control.validate_request(mutated, mutated["step"], "gateway")

    def test_wire_input_requires_canonical_newline_and_bound(self) -> None:
        value = closed()
        self.assertEqual(control.read_request(io.BytesIO(control.canonical(value))), value)
        with self.assertRaisesRegex(control.NativeGuestControlError, "not_canonical"):
            control.read_request(io.BytesIO(json.dumps(value).encode()))
        with self.assertRaisesRegex(control.NativeGuestControlError, "size_invalid"):
            control.read_request(io.BytesIO(b"{}" + b"x" * control.MAX_REQUEST_BYTES))

    def test_step_dispatch_cannot_cross_roles(self) -> None:
        for step, role in control.STEP_ROLE.items():
            value = closed(step)
            # The successor's own action/plan binding remains valid for every
            # operation; only the fixed role-to-step registry decides routing.
            self.assertEqual(
                control.validate_request(value, step, role)["step"], step
            )
            other = "research" if role == "gateway" else "gateway"
            with self.assertRaises(control.NativeGuestControlError):
                control.validate_request(value, step, other)

    def test_execute_emits_only_content_free_binding_and_evidence_digest(self) -> None:
        value = closed("stop-gateway-native-tunnel")
        with mock.patch.object(
            control, "_stop_service", return_value={"service": "x", "state": "inactive"}
        ):
            result = control.execute("gateway", value["step"], value)
        self.assertEqual(set(result), {
            "schema", "action_id", "plan_sha256", "authorization_sha256",
            "step", "status", "evidence_sha256",
        })
        self.assertEqual(result["status"], "verified")
        self.assertRegex(result["evidence_sha256"], r"^[0-9a-f]{64}$")

    def test_conntrack_query_error_is_never_absence(self) -> None:
        results = [
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 1, b"", b"query failed"),
        ]
        with (
            mock.patch.object(control, "_retired_grant", return_value=inference_grant()),
            mock.patch.object(control.subprocess, "run", side_effect=results),
            self.assertRaisesRegex(
                control.NativeGuestControlError, "command_failed"
            ),
        ):
            control._delete_conntrack("gateway")

    def test_missing_systemd_unit_is_not_verified_stopped(self) -> None:
        with mock.patch.object(
            control,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, b"not-found\n", b""),
        ), self.assertRaisesRegex(
            control.NativeGuestControlError, "service_unit_untrusted"
        ):
            control._service_state("native-opaque-tunnel.service")

    def test_explicit_role_must_match_installed_role(self) -> None:
        with (
            mock.patch.object(control.os, "geteuid", return_value=0),
            mock.patch.object(control.native_egress, "load_install_state", return_value=True),
            mock.patch.object(control, "installed_role", return_value="research"),
            self.assertRaisesRegex(
                control.NativeGuestControlError, "installed_role_mismatch"
            ),
        ):
            control.operation("gateway", "stop-gateway-native-tunnel", closed(
                "stop-gateway-native-tunnel"
            ))

    def test_installer_held_lock_rejects_instead_of_queueing_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary)
            lock = state_root / ".lock"
            lock.write_bytes(b"")
            lock.chmod(0o600)
            holder = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            actual_fstat = os.fstat

            def root_owned(descriptor: int) -> os.stat_result:
                value = list(actual_fstat(descriptor))
                value[stat.ST_UID] = 0
                value[stat.ST_GID] = 0
                return os.stat_result(value)

            def state_descriptor(*_args: object, **_kwargs: object) -> int:
                return os.open(
                    state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                )

            try:
                with (
                    mock.patch.object(control.os, "geteuid", return_value=0),
                    mock.patch.object(control, "installed_role", return_value="gateway"),
                    mock.patch.object(
                        control.native_egress, "load_install_state", return_value=True
                    ),
                    mock.patch.object(control, "_trusted_directory", side_effect=state_descriptor),
                    mock.patch.object(control.os, "fstat", side_effect=root_owned),
                    mock.patch.object(control, "STATE_ROOT", state_root),
                    mock.patch.object(control, "execute") as execute,
                    self.assertRaisesRegex(
                        control.NativeGuestControlError, "native_guest_control_busy"
                    ),
                ):
                    control.operation(
                        "gateway",
                        "stop-gateway-native-tunnel",
                        closed("stop-gateway-native-tunnel"),
                    )
                execute.assert_not_called()
            finally:
                fcntl.flock(holder, fcntl.LOCK_UN)
                os.close(holder)

    def test_live_policy_requires_kernel_readback_guards(self) -> None:
        identity = type("Identity", (), {"pw_uid": 501})()
        with (
            mock.patch.object(
                control,
                "_run",
                return_value=subprocess.CompletedProcess(
                    [], 0, b"table inet filter { chain output { policy accept; } }\n", b""
                ),
            ),
            mock.patch.object(control.pwd, "getpwnam", return_value=identity),
            self.assertRaisesRegex(
                control.NativeGuestControlError, "live_policy_untrusted"
            ),
        ):
            control._verify_live_policy("research")

    def test_structural_readback_rejects_stale_open_rules_without_grant(self) -> None:
        grant = inference_grant()
        identities = {
            "native-harness": type("Identity", (), {"pw_uid": 501})(),
            "native-claude": type("Identity", (), {"pw_uid": 502})(),
            "native-codex": type("Identity", (), {"pw_uid": 503})(),
        }
        raw = json.dumps(self.nft_ruleset(open_grant=grant)).encode()
        with (
            mock.patch.object(
                control, "_run",
                return_value=subprocess.CompletedProcess([], 0, raw, b""),
            ),
            mock.patch.object(
                control.pwd, "getpwnam", side_effect=lambda name: identities[name]
            ),
            self.assertRaisesRegex(
                control.NativeGuestControlError, "live_policy_not_closed"
            ),
        ):
            control._verify_live_policy("research", expected_grant=None)

    def test_structural_readback_requires_exact_timed_open_grant(self) -> None:
        grant = inference_grant()
        identities = {
            "native-harness": type("Identity", (), {"pw_uid": 501})(),
            "native-claude": type("Identity", (), {"pw_uid": 502})(),
            "native-codex": type("Identity", (), {"pw_uid": 503})(),
        }
        raw = json.dumps(self.nft_ruleset(open_grant=grant)).encode()
        with (
            mock.patch.object(
                control, "_run",
                return_value=subprocess.CompletedProcess([], 0, raw, b""),
            ),
            mock.patch.object(
                control.pwd, "getpwnam", side_effect=lambda name: identities[name]
            ),
        ):
            self.assertRegex(
                control._verify_live_policy(
                    "research", expected_grant=grant
                ),
                r"^[0-9a-f]{64}$",
            )

    def test_deny_transition_recovers_after_every_durable_phase(self) -> None:
        phases = (
            "deny-journal", "deny-fence", "deny-retired", "deny-unlinked",
            "deny-policy", "deny-conntrack", "deny-verified",
            "deny-complete",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                state = {"active": inference_grant(), "record": None}
                crashed = {"value": False}

                def atomic(path: Path, raw: bytes, **_kwargs: object) -> None:
                    if path == control.DENY_TRANSITION:
                        state["record"] = json.loads(raw)

                def checkpoint(observed: str) -> None:
                    if observed == phase and not crashed["value"]:
                        crashed["value"] = True
                        raise RuntimeError("simulated-hard-crash")

                with (
                    mock.patch.object(control, "atomic_bytes", side_effect=atomic),
                    mock.patch.object(
                        control, "_read_deny_record",
                        side_effect=lambda _role: state["record"],
                    ),
                    mock.patch.object(
                        control, "_active_grant",
                        side_effect=lambda _role, **_kwargs: state["active"],
                    ),
                    mock.patch.object(
                        control, "_unlink_active_grant",
                        side_effect=lambda _role: state.update(active=None),
                    ),
                    mock.patch.object(
                        control, "_unlink_deny_record",
                        side_effect=lambda: state.update(record=None),
                    ),
                    mock.patch.object(control, "_stop_service"),
                    mock.patch.object(control, "_apply_emergency_fence") as fence,
                    mock.patch.object(control, "_install_policy", return_value="a" * 64),
                    mock.patch.object(
                        control, "_delete_conntrack_mark",
                        return_value={"mark": "x", "absence": "verified"},
                    ),
                    mock.patch.object(control, "_verify_live_policy"),
                    mock.patch.object(control, "_verify_persistent_closed_policy"),
                    mock.patch.object(control, "_service_state", return_value="inactive"),
                    mock.patch.object(control, "CRASH_HOOK", side_effect=checkpoint),
                ):
                    with self.assertRaisesRegex(RuntimeError, "simulated-hard-crash"):
                        control._deny_only("research")
                    control._deny_only("research")
                self.assertIsNone(state["active"])
                self.assertIsNone(state["record"])
                self.assertTrue(fence.called)


if __name__ == "__main__":
    unittest.main()
