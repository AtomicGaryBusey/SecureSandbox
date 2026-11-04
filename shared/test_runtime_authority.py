#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared.harness_runtime_binding import make_binding as make_harness
from shared.model_stack_runtime_binding import (
    BROKERED_MODE,
    NATIVE_MODE,
    make_binding as make_model_stack,
    make_brokered_binding,
)
from shared.native_stack_runtime_binding import make_binding as make_native
from shared.runtime_authority import (
    RuntimeAuthorityError,
    make_binding,
    validate_binding,
)
from shared.session_context_binding import make_binding as make_context
from shared.test_native_vendor_stack import anthropic_stack


SESSION = "11111111-1111-4111-8111-111111111111"


def context() -> dict:
    return make_context(
        session_id=SESSION,
        source_id=None,
        source_manifest_sha256=None,
        persona_sha256="1" * 64,
        tool_catalog_sha256="2" * 64,
        extension_set_sha256="3" * 64,
    )


def harness(generation: str = "4" * 64, adapter: str = "claude-core-v1") -> dict:
    return make_harness(
        harness_id="claude-code",
        generation_id=generation,
        manifest_sha256="5" * 64,
        executable_sha256="6" * 64,
        inventory_sha256="7" * 64,
        adapter_id=adapter,
        adapter_sha256="8" * 64,
    )


def brokered_authority() -> dict:
    model = make_model_stack(
        BROKERED_MODE,
        make_brokered_binding(
            adapter="anthropic-messages-v1",
            model="model",
            profile_id="profile",
            profile_sha256="9" * 64,
            provider_mode="production",
            vendor_id="vendor",
        ),
    )
    return make_binding(
        model_stack_binding=model,
        session_context_binding=context(),
        harness_binding=harness(),
    )


class RuntimeAuthorityTests(unittest.TestCase):
    def test_brokered_authority_round_trips(self) -> None:
        value = brokered_authority()
        self.assertEqual(validate_binding(value), value)

    def test_component_splicing_breaks_outer_digest(self) -> None:
        value = brokered_authority()
        other = copy.deepcopy(value["session_context_binding"])
        other["persona_sha256"] = "a" * 64
        from shared.session_context_binding import make_binding as new_context

        value["session_context_binding"] = new_context(
            session_id=SESSION,
            source_id=None,
            source_manifest_sha256=None,
            persona_sha256="a" * 64,
            tool_catalog_sha256="2" * 64,
            extension_set_sha256="3" * 64,
        )
        with self.assertRaisesRegex(RuntimeAuthorityError, "digest_mismatch"):
            validate_binding(value)

    def test_native_authority_requires_same_harness_identity(self) -> None:
        stack = anthropic_stack()
        native = make_model_stack(NATIVE_MODE, make_native(stack))
        with self.assertRaisesRegex(RuntimeAuthorityError, "component_invalid"):
            make_binding(
                model_stack_binding=native,
                session_context_binding=context(),
                harness_binding=harness(),
            )
        matching = harness(
            generation=stack["harness"]["generation_id"],
            adapter=stack["harness"]["adapter_id"],
        )
        self.assertEqual(
            make_binding(
                model_stack_binding=native,
                session_context_binding=context(),
                harness_binding=matching,
            )["model_stack_binding"]["mode"],
            NATIVE_MODE,
        )

    def test_unknown_fallback_fails_closed(self) -> None:
        value = brokered_authority()
        value["fallback"] = "brokered"
        with self.assertRaisesRegex(RuntimeAuthorityError, "fields_invalid"):
            validate_binding(value)


if __name__ == "__main__":
    unittest.main()
