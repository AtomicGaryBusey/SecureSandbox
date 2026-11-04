#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared.harness_runtime_binding import make_binding as make_harness_binding
from shared.native_stack_runtime_binding import (
    NativeStackBindingError,
    assert_harness_match,
    container_fields,
    from_container,
    make_binding,
    validate_binding,
)
from shared.test_native_vendor_stack import anthropic_stack, openai_stack


def harness_for(stack: dict) -> dict[str, str]:
    return make_harness_binding(
        harness_id=stack["harness"]["harness_id"],
        generation_id=stack["harness"]["generation_id"],
        manifest_sha256="d" * 64,
        executable_sha256="e" * 64,
        inventory_sha256="f" * 64,
        adapter_id=stack["harness"]["adapter_id"],
        adapter_sha256="1" * 64,
    )


class NativeStackRuntimeBindingTests(unittest.TestCase):
    def test_initial_pairings_make_exact_runtime_bindings(self) -> None:
        claude = make_binding(anthropic_stack())
        codex = make_binding(openai_stack())
        self.assertEqual(claude["model_id"], "claude-mythos-5-1")
        self.assertEqual(claude["credential_custody"], "vendor-harness")
        self.assertEqual(codex["program_tier"], "blue")
        self.assertEqual(
            codex["program_requirements_version"],
            "openai-daybreak-blue-2026-10-31",
        )
        self.assertEqual(codex["credential_custody"], "secure-sandbox-host")

    def test_incomplete_staged_stack_cannot_make_runtime_binding(self) -> None:
        value = anthropic_stack()
        value["account_binding"]["workspace_sha256"] = None
        with self.assertRaisesRegex(NativeStackBindingError, "not_content_ready"):
            make_binding(value)

    def test_binding_digest_detects_semantic_mutation(self) -> None:
        binding = make_binding(openai_stack())
        mutated = copy.deepcopy(binding)
        mutated["program_tier"] = "red"
        with self.assertRaisesRegex(NativeStackBindingError, "digest_mismatch"):
            validate_binding(mutated)

    def test_container_projection_round_trips_without_schema(self) -> None:
        binding = make_binding(anthropic_stack())
        projected = from_container(container_fields(binding))
        self.assertEqual(projected, {key: value for key, value in binding.items() if key != "schema"})

    def test_native_stack_must_match_exact_harness_generation_and_adapter(self) -> None:
        value = anthropic_stack()
        native = make_binding(value)
        harness = harness_for(value)
        assert_harness_match(native, harness)
        wrong = copy.deepcopy(harness)
        wrong["harness_generation_id"] = "2" * 64
        wrong["binding_sha256"] = "3" * 64
        with self.assertRaises(NativeStackBindingError):
            assert_harness_match(native, wrong)


if __name__ == "__main__":
    unittest.main()
