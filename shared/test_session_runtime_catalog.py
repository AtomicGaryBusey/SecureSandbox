#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared.harness_runtime_binding import container_fields, make_binding as make_harness
from shared.model_stack_runtime_binding import (
    BROKERED_MODE,
    NATIVE_MODE,
    make_binding as make_model_stack,
    make_brokered_binding,
)
from shared.native_stack_runtime_binding import make_binding as make_native
from shared.session_runtime_catalog import (
    CURRENT_SCHEMA,
    HARNESS_BOUND_SCHEMA,
    SessionRuntimeCatalogError,
    is_current_record,
    validate_catalog,
)
from shared.session_context_binding import make_binding as make_session_context
from shared.runtime_authority import make_binding as make_runtime_authority
from shared.test_native_vendor_stack import anthropic_stack


SESSION = "11111111-1111-4111-8111-111111111111"
RUN = "22222222-2222-4222-8222-222222222222"


def harness(
    adapter: str = "claude-core-v1", generation_id: str = "b" * 64
) -> dict[str, str]:
    return make_harness(
        harness_id="claude-code",
        generation_id=generation_id,
        manifest_sha256="c" * 64,
        executable_sha256="d" * 64,
        inventory_sha256="e" * 64,
        adapter_id=adapter,
        adapter_sha256="f" * 64,
    )


def brokered_record() -> dict:
    model = make_model_stack(
        BROKERED_MODE,
        make_brokered_binding(
            adapter="anthropic-messages-v1",
            model="abliterated-model-large-v2[1m]",
            profile_id="abliterated-glm",
            profile_sha256="a" * 64,
            provider_mode="production",
            vendor_id="abliteration",
        ),
    )
    return {
        "adapter": "anthropic-messages-v1",
        "last_started_at": 1,
        "model": "abliterated-model-large-v2[1m]",
        "runtime_authority": make_runtime_authority(
            model_stack_binding=model,
            session_context_binding=make_session_context(
                session_id=SESSION,
                source_id=None,
                source_manifest_sha256=None,
                persona_sha256="2" * 64,
                tool_catalog_sha256="3" * 64,
                extension_set_sha256="4" * 64,
            ),
            harness_binding=harness(),
        ),
        "run_ids": [RUN],
        "runs": 1,
        "vendor_id": "abliteration",
    }


def native_record() -> dict:
    stack = anthropic_stack()
    stack["harness"]["adapter_id"] = "claude-native-oauth-v1"
    native = make_native(stack)
    model = make_model_stack(NATIVE_MODE, native)
    return {
        "adapter": "claude-native-oauth-v1",
        "last_started_at": 1,
        "model": "claude-mythos-5-1",
        "runtime_authority": make_runtime_authority(
            model_stack_binding=model,
            session_context_binding=make_session_context(
                session_id=SESSION,
                source_id=None,
                source_manifest_sha256=None,
                persona_sha256="2" * 64,
                tool_catalog_sha256="3" * 64,
                extension_set_sha256="4" * 64,
            ),
            harness_binding=harness(
                "claude-native-oauth-v1", stack["harness"]["generation_id"]
            ),
        ),
        "run_ids": [RUN],
        "runs": 1,
        "vendor_id": "anthropic",
    }


class SessionRuntimeCatalogTests(unittest.TestCase):
    def test_v5_accepts_exact_brokered_and_native_records(self) -> None:
        value = {
            "schema": CURRENT_SCHEMA,
            "sessions": {SESSION: brokered_record()},
        }
        self.assertEqual(validate_catalog(value), value)
        self.assertTrue(is_current_record(value["sessions"][SESSION]))
        value["sessions"][SESSION] = native_record()
        self.assertEqual(validate_catalog(value), value)

    def test_v5_retains_legacy_v4_records_as_noncurrent_history(self) -> None:
        current = brokered_record()
        legacy = {
            key: item
            for key, item in current.items()
            if key != "runtime_authority"
        }
        legacy.update(
            {
                "model_profile_id": "abliterated-glm",
                "model_profile_sha256": "a" * 64,
                **container_fields(
                    current["runtime_authority"]["harness_binding"]
                ),
            }
        )
        value = {"schema": CURRENT_SCHEMA, "sessions": {SESSION: legacy}}
        self.assertEqual(validate_catalog(value), value)
        self.assertFalse(is_current_record(legacy))

    def test_later_catalogs_may_retain_older_records_but_not_the_reverse(self) -> None:
        legacy = {"last_started_at": 1, "runs": 1}
        self.assertEqual(
            validate_catalog({"schema": CURRENT_SCHEMA, "sessions": {SESSION: legacy}}),
            {"schema": CURRENT_SCHEMA, "sessions": {SESSION: legacy}},
        )
        model_bound = {
            "adapter": "anthropic-messages-v1",
            "last_started_at": 1,
            "model": "model",
            "model_profile_id": "profile",
            "model_profile_sha256": "a" * 64,
            "run_ids": [RUN],
            "runs": 1,
            "vendor_id": "vendor",
        }
        with self.assertRaisesRegex(SessionRuntimeCatalogError, "schema_mismatch"):
            validate_catalog(
                {
                    "schema": "secure-sandbox-session-runs-v2",
                    "sessions": {SESSION: model_bound},
                }
            )

    def test_native_stack_must_match_independent_harness_binding(self) -> None:
        value = {"schema": CURRENT_SCHEMA, "sessions": {SESSION: native_record()}}
        value["sessions"][SESSION]["runtime_authority"]["harness_binding"][
            "harness_generation_id"
        ] = "9" * 64
        with self.assertRaises(SessionRuntimeCatalogError):
            validate_catalog(value)

    def test_top_level_projection_cannot_lie_about_model_or_vendor(self) -> None:
        value = {"schema": CURRENT_SCHEMA, "sessions": {SESSION: brokered_record()}}
        value["sessions"][SESSION]["model"] = "another-model"
        with self.assertRaisesRegex(SessionRuntimeCatalogError, "projection_mismatch"):
            validate_catalog(value)

    def test_nested_binding_mutation_is_rejected(self) -> None:
        value = {"schema": CURRENT_SCHEMA, "sessions": {SESSION: brokered_record()}}
        mutated = copy.deepcopy(value)
        mutated["sessions"][SESSION]["runtime_authority"]["model_stack_binding"][
            "authority"
        ]["provider_mode"] = "mock"
        with self.assertRaises(SessionRuntimeCatalogError):
            validate_catalog(mutated)
        self.assertFalse(is_current_record(mutated["sessions"][SESSION]))

    def test_legacy_harness_digest_is_recomputed(self) -> None:
        current = brokered_record()
        legacy = {
            key: item for key, item in current.items() if key != "runtime_authority"
        }
        legacy.update({
            "model_profile_id": "abliterated-glm",
            "model_profile_sha256": "a" * 64,
            **container_fields(current["runtime_authority"]["harness_binding"]),
        })
        legacy["harness_generation_id"] = "9" * 64
        with self.assertRaisesRegex(SessionRuntimeCatalogError, "legacy_harness_invalid"):
            validate_catalog({"schema": CURRENT_SCHEMA, "sessions": {SESSION: legacy}})

    def test_non_string_schema_uses_stable_catalog_error(self) -> None:
        with self.assertRaises(SessionRuntimeCatalogError):
            validate_catalog({"schema": [], "sessions": {}})

    def test_catalog_key_must_match_bound_session_identity(self) -> None:
        value = {"schema": CURRENT_SCHEMA, "sessions": {SESSION: brokered_record()}}
        authority = value["sessions"][SESSION]["runtime_authority"]
        value["sessions"][SESSION]["runtime_authority"] = make_runtime_authority(
            model_stack_binding=authority["model_stack_binding"],
            session_context_binding=make_session_context(
                session_id="99999999-9999-4999-8999-999999999999",
                source_id=None,
                source_manifest_sha256=None,
                persona_sha256="2" * 64,
                tool_catalog_sha256="3" * 64,
                extension_set_sha256="4" * 64,
            ),
            harness_binding=authority["harness_binding"],
        )
        with self.assertRaisesRegex(SessionRuntimeCatalogError, "context_mismatch"):
            validate_catalog(value)

    def test_v4_schema_cannot_claim_v5_record(self) -> None:
        value = {"schema": HARNESS_BOUND_SCHEMA, "sessions": {SESSION: brokered_record()}}
        with self.assertRaisesRegex(SessionRuntimeCatalogError, "current_schema_mismatch"):
            validate_catalog(value)


if __name__ == "__main__":
    unittest.main()
