#!/usr/bin/env python3

from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from shared import native_egress
from shared.harness_runtime_binding import make_binding as make_harness
from shared.model_stack_runtime_binding import NATIVE_MODE, make_binding as make_model_stack
from shared.native_stack_runtime_binding import make_binding as make_native_stack
from shared.runtime_authority import make_binding as make_authority
from shared.session_context_binding import make_binding as make_context
from shared.test_native_vendor_stack import anthropic_stack, openai_stack


NOW = 1_800_000_000


def authority(stack: dict | None = None) -> dict:
    value = anthropic_stack() if stack is None else stack
    return make_authority(
        model_stack_binding=make_model_stack(NATIVE_MODE, make_native_stack(value)),
        session_context_binding=make_context(
            session_id="11111111-1111-4111-8111-111111111111",
            source_id=None,
            source_manifest_sha256=None,
            persona_sha256="1" * 64,
            tool_catalog_sha256="2" * 64,
            extension_set_sha256="3" * 64,
        ),
        harness_binding=make_harness(
            harness_id=value["harness"]["harness_id"],
            generation_id=value["harness"]["generation_id"],
            manifest_sha256="4" * 64,
            executable_sha256="5" * 64,
            inventory_sha256="6" * 64,
            adapter_id=value["harness"]["adapter_id"],
            adapter_sha256="7" * 64,
        ),
    )


def addresses(policy_id: str, phase: str) -> dict[str, list[str]]:
    hosts = native_egress.POLICIES[policy_id]["phases"][phase]["hosts"]
    return {host: ["8.8.8.8"] for host in hosts}


def inference_grant(stack: dict | None = None) -> dict:
    value = anthropic_stack() if stack is None else stack
    return native_egress.make_grant(
        binding_kind="runtime-authority",
        binding_value=authority(value),
        phase=native_egress.PHASE_INFERENCE,
        resolved_ipv4=addresses(
            value["network_policy_id"], native_egress.PHASE_INFERENCE
        ),
        issued_at=NOW,
        expires_at=NOW + 600,
        grant_id="22222222-2222-4222-8222-222222222222",
    )


class NativeEgressTests(unittest.TestCase):
    def test_login_intent_allows_missing_account_but_requires_exact_generation(self) -> None:
        stack = anthropic_stack()
        stack["account_binding"]["account_subject_sha256"] = None
        stack["account_binding"]["workspace_sha256"] = None
        intent = native_egress.make_stack_intent(stack)
        grant = native_egress.make_grant(
            binding_kind="stack-intent",
            binding_value=intent,
            phase=native_egress.PHASE_LOGIN,
            resolved_ipv4=addresses(
                stack["network_policy_id"], native_egress.PHASE_LOGIN
            ),
            issued_at=NOW,
            expires_at=NOW + 300,
            grant_id="33333333-3333-4333-8333-333333333333",
        )
        self.assertEqual(
            native_egress.validate_grant(grant, now=NOW)["phase"], "login"
        )
        stack["harness"]["generation_id"] = None
        with self.assertRaises(native_egress.NativeEgressError):
            native_egress.make_stack_intent(stack)

    def test_inference_binds_full_native_runtime_authority(self) -> None:
        grant = inference_grant()
        self.assertEqual(
            grant["binding"]["value"]["binding_sha256"],
            authority()["binding_sha256"],
        )
        self.assertEqual(native_egress.validate_grant(grant, now=NOW), grant)

    def test_phase_and_vendor_cross_pairings_fail_closed(self) -> None:
        native = make_native_stack(anthropic_stack())
        with self.assertRaisesRegex(native_egress.NativeEgressError, "binding_mismatch"):
            native_egress.make_grant(
                binding_kind="native-stack",
                binding_value=native,
                phase=native_egress.PHASE_INFERENCE,
                resolved_ipv4=addresses(
                    "anthropic-claude-native-oauth-v1", native_egress.PHASE_INFERENCE
                ),
                issued_at=NOW,
                expires_at=NOW + 60,
            )
        intent = native_egress.make_stack_intent(openai_stack())
        crossed = copy.deepcopy(intent)
        crossed["harness_adapter_id"] = "claude-native-oauth-v1"
        crossed["binding_sha256"] = native_egress.sha256(
            {field: crossed[field] for field in native_egress.INTENT_FIELDS}
        )
        with self.assertRaisesRegex(native_egress.NativeEgressError, "pairing_mismatch"):
            native_egress.validate_stack_intent(crossed)
        with self.assertRaisesRegex(native_egress.NativeEgressError, "not_admitted"):
            native_egress.make_grant(
                binding_kind="stack-intent",
                binding_value=intent,
                phase=native_egress.PHASE_LOGIN,
                resolved_ipv4={},
                issued_at=NOW,
                expires_at=NOW + 60,
            )

    def test_unknown_destination_private_pin_and_expiry_are_rejected(self) -> None:
        grant = inference_grant()
        unknown = copy.deepcopy(grant)
        unknown["destinations"][0]["hostname"] = "evil.example"
        with self.assertRaises(native_egress.NativeEgressError):
            native_egress.validate_grant(unknown)
        private = copy.deepcopy(grant)
        private["destinations"][0]["ipv4"] = ["127.0.0.1"]
        with self.assertRaisesRegex(native_egress.NativeEgressError, "not_global"):
            native_egress.validate_grant(private)
        with self.assertRaisesRegex(native_egress.NativeEgressError, "inactive"):
            native_egress.validate_grant(grant, now=grant["expires_at"])

    def test_digest_detects_every_semantic_mutation(self) -> None:
        grant = inference_grant()
        mutations = {
            "phase": "login",
            "vendor_id": "openai",
            "expires_at": grant["expires_at"] - 1,
        }
        for field, value in mutations.items():
            changed = copy.deepcopy(grant)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(native_egress.NativeEgressError):
                native_egress.validate_grant(changed)
        changed = copy.deepcopy(grant)
        changed["limits"]["max_connections"] -= 1
        with self.assertRaisesRegex(native_egress.NativeEgressError, "digest_mismatch"):
            native_egress.validate_grant(changed)

    def test_limits_cannot_exceed_closed_policy(self) -> None:
        grant = inference_grant()
        grant["limits"]["max_connections"] += 1
        with self.assertRaisesRegex(native_egress.NativeEgressError, "exceeds_policy"):
            native_egress.validate_grant(grant)

    def test_canonical_root_file_read_rejects_mode_and_noncanonical_bytes(self) -> None:
        grant = inference_grant()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "grant.json"
            path.write_bytes(native_egress.canonical_bytes(grant))
            path.chmod(0o600)
            self.assertEqual(
                native_egress.load_grant(
                    path, now=NOW, expected_uid=os.geteuid()
                ),
                grant,
            )
            path.write_text("{}", encoding="ascii")
            with self.assertRaises(native_egress.NativeEgressError):
                native_egress.load_grant(path, expected_uid=os.geteuid())
            path.write_bytes(native_egress.canonical_bytes(grant))
            path.chmod(0o644)
            with self.assertRaisesRegex(native_egress.NativeEgressError, "file_untrusted"):
                native_egress.load_grant(path, expected_uid=os.geteuid())

    def test_flattened_addresses_are_unique_and_sorted(self) -> None:
        self.assertEqual(native_egress.flattened_ipv4(inference_grant()), ["8.8.8.8"])

    def test_conntrack_marks_are_nonzero_domain_and_grant_specific(self) -> None:
        first = inference_grant()
        second = copy.deepcopy(first)
        second["grant_id"] = "88888888-8888-4888-8888-888888888888"
        body = {
            field: second[field]
            for field in second
            if field not in {"schema", "grant_sha256"}
        }
        second["grant_sha256"] = native_egress.sha256(body)
        second = native_egress.validate_grant(second, now=NOW)
        marks = {
            native_egress.conntrack_mark(first, "provider"),
            native_egress.conntrack_mark(first, "research"),
            native_egress.conntrack_mark(second, "provider"),
            native_egress.conntrack_mark(second, "research"),
        }
        self.assertEqual(len(marks), 4)
        self.assertNotIn("0x00000000", marks)
        with self.assertRaises(native_egress.NativeEgressError):
            native_egress.conntrack_mark(first, "unknown")

    def test_install_sentinel_is_exact_trusted_and_absence_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native-egress-installed"
            self.assertFalse(
                native_egress.load_install_state(
                    path,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            )
            path.write_bytes(native_egress.INSTALL_STATE_BYTES)
            path.chmod(0o600)
            self.assertTrue(
                native_egress.load_install_state(
                    path,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            )
            path.write_bytes(b"enabled\n")
            with self.assertRaises(native_egress.NativeEgressError):
                native_egress.load_install_state(
                    path,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )

    def test_rotation_protocol_is_closed_and_orders_deny_before_successor(self) -> None:
        protocol = native_egress.validate_rotation_protocol(
            native_egress.ROTATION_PROTOCOL
        )
        self.assertLess(
            protocol.index("apply-gateway-deny-only"),
            protocol.index("apply-gateway-successor-policy"),
        )
        self.assertLess(
            protocol.index("delete-research-native-conntrack"),
            protocol.index("start-research-native-harness"),
        )
        changed = list(protocol)
        changed[2], changed[6] = changed[6], changed[2]
        with self.assertRaises(native_egress.NativeEgressError):
            native_egress.validate_rotation_protocol(changed)


if __name__ == "__main__":
    unittest.main()
