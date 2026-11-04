#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared.model_stack_runtime_binding import (
    BROKERED_MODE,
    NATIVE_MODE,
    ModelStackBindingError,
    identity_projection,
    make_binding,
    make_brokered_binding,
    validate_binding,
)
from shared.native_stack_runtime_binding import make_binding as make_native_binding
from shared.test_native_vendor_stack import anthropic_stack, openai_stack


def brokered() -> dict[str, str]:
    return make_brokered_binding(
        adapter="anthropic-messages-v1",
        model="abliterated-model-large-v2[1m]",
        profile_id="abliterated-glm",
        profile_sha256="a" * 64,
        provider_mode="production",
        vendor_id="abliteration",
    )


class ModelStackRuntimeBindingTests(unittest.TestCase):
    def test_brokered_and_native_are_disjoint_exact_modes(self) -> None:
        brokered_value = make_binding(BROKERED_MODE, brokered())
        native_value = make_binding(NATIVE_MODE, make_native_binding(anthropic_stack()))
        self.assertEqual(brokered_value["mode"], BROKERED_MODE)
        self.assertEqual(native_value["mode"], NATIVE_MODE)
        self.assertNotEqual(brokered_value["binding_sha256"], native_value["binding_sha256"])

    def test_provider_mode_is_bound_for_brokered_profiles(self) -> None:
        value = make_binding(BROKERED_MODE, brokered())
        mutated = copy.deepcopy(value)
        mutated["authority"]["provider_mode"] = "mock"
        with self.assertRaises(ModelStackBindingError):
            validate_binding(mutated)

    def test_mode_cannot_be_relabelled_around_another_authority(self) -> None:
        value = make_binding(NATIVE_MODE, make_native_binding(openai_stack()))
        value["mode"] = BROKERED_MODE
        with self.assertRaisesRegex(ModelStackBindingError, "brokered_model_binding"):
            validate_binding(value)

    def test_identity_projection_is_mode_aware(self) -> None:
        brokered_value = make_binding(BROKERED_MODE, brokered())
        native_value = make_binding(NATIVE_MODE, make_native_binding(openai_stack()))
        self.assertEqual(
            identity_projection(brokered_value),
            {
                "adapter": "anthropic-messages-v1",
                "model": "abliterated-model-large-v2[1m]",
                "vendor_id": "abliteration",
            },
        )
        self.assertEqual(
            identity_projection(native_value),
            {
                "adapter": "codex-app-server-oauth-v1",
                "model": "gpt-6-sol",
                "vendor_id": "openai",
            },
        )

    def test_unknown_or_extra_fields_fail_closed(self) -> None:
        value = make_binding(BROKERED_MODE, brokered())
        value["fallback"] = "native"
        with self.assertRaisesRegex(ModelStackBindingError, "fields_invalid"):
            validate_binding(value)


if __name__ == "__main__":
    unittest.main()
