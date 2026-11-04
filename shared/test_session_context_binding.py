#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from shared.session_context_binding import (
    SessionContextBindingError,
    make_binding,
    validate_binding,
)


SESSION = "11111111-1111-4111-8111-111111111111"
SOURCE = "22222222-2222-4222-8222-222222222222"


def binding(*, source: bool = True) -> dict:
    return make_binding(
        session_id=SESSION,
        source_id=SOURCE if source else None,
        source_manifest_sha256="a" * 64 if source else None,
        persona_sha256="b" * 64,
        tool_catalog_sha256="c" * 64,
        extension_set_sha256="d" * 64,
    )


class SessionContextBindingTests(unittest.TestCase):
    def test_source_and_source_free_contexts_are_exact(self) -> None:
        self.assertEqual(validate_binding(binding()), binding())
        self.assertEqual(validate_binding(binding(source=False)), binding(source=False))

    def test_partial_source_identity_is_rejected(self) -> None:
        value = binding()
        value["source_manifest_sha256"] = None
        with self.assertRaisesRegex(SessionContextBindingError, "source_partial"):
            validate_binding(value)

    def test_policy_or_source_mutation_breaks_digest(self) -> None:
        for field in (
            "source_manifest_sha256",
            "persona_sha256",
            "tool_catalog_sha256",
            "extension_set_sha256",
        ):
            value = copy.deepcopy(binding())
            value[field] = "9" * 64
            with self.subTest(field=field), self.assertRaisesRegex(
                SessionContextBindingError, "digest_mismatch"
            ):
                validate_binding(value)

    def test_unknown_context_fields_fail_closed(self) -> None:
        value = binding()
        value["plugin_set_sha256"] = "e" * 64
        with self.assertRaisesRegex(SessionContextBindingError, "fields_invalid"):
            validate_binding(value)


if __name__ == "__main__":
    unittest.main()
