#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from shared import native_vendor_stack as stack


GENERATION = "a" * 64
ACCOUNT = "b" * 64
WORKSPACE = "c" * 64
ROOT = Path(__file__).resolve().parent.parent


def anthropic_stack() -> dict:
    return {
        "account_binding": {
            "account_subject_sha256": ACCOUNT,
            "program_id": "anthropic-cvp",
            "program_tier": "defense",
            "workspace_sha256": WORKSPACE,
        },
        "authentication": {
            "credential_custody": "vendor-harness",
            "mode": "anthropic-claude-subscription-oauth",
        },
        "display_name": "Claude Code + Mythos 5.1 (CVP Defense)",
        "harness": {
            "adapter_id": "claude-native-oauth-v1",
            "generation_id": GENERATION,
            "harness_id": "claude-code",
        },
        "mode": stack.MODE,
        "model": {
            "model_id": "claude-mythos-5-1",
            "model_name": "Claude Mythos 5.1",
            "settings": {"effort": "high"},
        },
        "network_policy_id": "anthropic-claude-native-oauth-v1",
        "stack_id": "claude-mythos-native",
        "vendor_id": "anthropic",
    }


def openai_stack() -> dict:
    return {
        "account_binding": {
            "account_subject_sha256": ACCOUNT,
            "program_id": "openai-daybreak",
            "program_tier": "blue",
            "workspace_sha256": WORKSPACE,
        },
        "authentication": {
            "credential_custody": "secure-sandbox-host",
            "mode": "openai-sign-in-with-chatgpt",
        },
        "display_name": "Codex + GPT-6 Sol (Daybreak Blue)",
        "harness": {
            "adapter_id": "codex-app-server-oauth-v1",
            "generation_id": GENERATION,
            "harness_id": "codex",
        },
        "mode": stack.MODE,
        "model": {
            "model_id": "gpt-6-sol",
            "model_name": "GPT-6 Sol",
            "settings": {
                "cyber_access": "daybreak_blue",
                "reasoning_effort": "high",
            },
        },
        "network_policy_id": "openai-codex-siwc-v1",
        "stack_id": "codex-daybreak-blue-native",
        "vendor_id": "openai",
    }


class NativeVendorStackTests(unittest.TestCase):
    def test_example_is_canonical_valid_and_staged_only(self) -> None:
        path = ROOT / "config/native-vendor-stacks.example.json"
        value = json.loads(path.read_bytes())
        self.assertEqual(stack.validate_catalog(value), value)
        self.assertEqual(path.read_bytes(), stack.canonical_bytes(value))
        self.assertEqual(
            {stack.activation_readiness(item)["status"] for item in value["stacks"]},
            {"configuration-required"},
        )

    def test_initial_pairings_validate(self) -> None:
        self.assertEqual(stack.validate_stack(anthropic_stack())["vendor_id"], "anthropic")
        self.assertEqual(stack.validate_stack(openai_stack())["vendor_id"], "openai")

    def test_cross_vendor_harness_composition_is_rejected(self) -> None:
        value = anthropic_stack()
        value["harness"]["harness_id"] = "codex"
        with self.assertRaisesRegex(stack.NativeVendorStackError, "pairing_not_admitted"):
            stack.validate_stack(value)

    def test_custody_cannot_be_weakened_in_catalog_data(self) -> None:
        value = anthropic_stack()
        value["authentication"]["credential_custody"] = "secure-sandbox-host"
        with self.assertRaisesRegex(stack.NativeVendorStackError, "custody_mismatch"):
            stack.validate_stack(value)

    def test_program_tier_cannot_cross_pairing(self) -> None:
        value = openai_stack()
        value["account_binding"]["program_tier"] = "red"
        with self.assertRaisesRegex(stack.NativeVendorStackError, "program_pairing_mismatch"):
            stack.validate_stack(value)

    def test_model_must_be_in_reviewed_pairing(self) -> None:
        value = anthropic_stack()
        value["model"]["model_id"] = "claude-opus-5-5"
        with self.assertRaisesRegex(stack.NativeVendorStackError, "model_pairing_mismatch"):
            stack.validate_stack(value)

    def test_unknown_settings_are_rejected(self) -> None:
        value = openai_stack()
        value["model"]["settings"]["temperature"] = "1"
        with self.assertRaisesRegex(stack.NativeVendorStackError, "settings_fields_invalid"):
            stack.validate_stack(value)

    def test_non_scalar_setting_fails_with_stable_validation_error(self) -> None:
        value = openai_stack()
        value["model"]["settings"]["reasoning_effort"] = ["high"]
        with self.assertRaisesRegex(
            stack.NativeVendorStackError,
            "setting_reasoning_effort_invalid",
        ):
            stack.validate_stack(value)

    def test_login_required_is_content_only(self) -> None:
        value = anthropic_stack()
        value["account_binding"]["account_subject_sha256"] = None
        value["account_binding"]["workspace_sha256"] = None
        readiness = stack.activation_readiness(value)
        self.assertEqual(readiness["status"], "login-required")
        self.assertEqual(
            readiness["missing"],
            ["account_subject_sha256", "workspace_sha256"],
        )

    def test_content_ready_never_claims_live_activation(self) -> None:
        readiness = stack.activation_readiness(anthropic_stack())
        self.assertEqual(readiness["status"], "content-ready")
        self.assertEqual(readiness["missing"], [])

    def test_catalog_is_ordered_and_unique(self) -> None:
        catalog = {
            "schema": stack.CATALOG_SCHEMA,
            "stacks": [openai_stack(), anthropic_stack()],
        }
        with self.assertRaisesRegex(stack.NativeVendorStackError, "catalog_order_invalid"):
            stack.validate_catalog(catalog)
        catalog["stacks"] = sorted(catalog["stacks"], key=lambda item: item["stack_id"])
        stack.validate_catalog(catalog)
        duplicate = copy.deepcopy(catalog)
        duplicate["stacks"][1]["stack_id"] = duplicate["stacks"][0]["stack_id"]
        with self.assertRaises(stack.NativeVendorStackError):
            stack.validate_catalog(duplicate)

    def test_write_and_private_load_are_atomic_and_mode_0600(self) -> None:
        value = {
            "schema": stack.CATALOG_SCHEMA,
            "stacks": [anthropic_stack(), openai_stack()],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            path = root / "native-stacks.json"
            result = stack.write_catalog(path, value)
            self.assertEqual(result["status"], "staged")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(stack.load_catalog(path), value)
            self.assertEqual(stack.stack_by_id(value, "claude-mythos-native"), value["stacks"][0])

    def test_private_load_rejects_symlink_and_noncanonical_file(self) -> None:
        value = {"schema": stack.CATALOG_SCHEMA, "stacks": [anthropic_stack()]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            target = root / "target.json"
            target.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(target, 0o600)
            link = root / "native-stacks.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                stack.NativeVendorStackError,
                "file_untrusted",
            ):
                stack.load_catalog(link)
            link.unlink()
            target.rename(link)
            with self.assertRaisesRegex(
                stack.NativeVendorStackError,
                "not_canonical",
            ):
                stack.load_catalog(link)


if __name__ == "__main__":
    unittest.main()
