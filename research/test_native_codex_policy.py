#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from research import native_codex_policy as policy
from shared import (
    harness_runtime_binding,
    model_stack_runtime_binding,
    native_stack_runtime_binding,
    runtime_authority,
    session_context_binding,
)


ROOT = Path(__file__).resolve().parent.parent


class NativeCodexPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(
                encoding="ascii"
            )
        )["stacks"][1]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64
        native = native_stack_runtime_binding.make_binding(stack)
        harness = harness_runtime_binding.make_binding(
            harness_id="codex",
            generation_id="a" * 64,
            manifest_sha256="d" * 64,
            executable_sha256=hashlib.sha256(b"codex").hexdigest(),
            inventory_sha256="e" * 64,
            adapter_id="codex-app-server-oauth-v1",
            adapter_sha256="f" * 64,
        )
        context = session_context_binding.make_binding(
            session_id="00000000-0000-4000-8000-000000000001",
            source_id=None,
            source_manifest_sha256=None,
            persona_sha256="1" * 64,
            tool_catalog_sha256="2" * 64,
            extension_set_sha256="3" * 64,
        )
        self.authority = runtime_authority.make_binding(
            model_stack_binding=model_stack_runtime_binding.make_binding(
                model_stack_runtime_binding.NATIVE_MODE, native
            ),
            session_context_binding=context,
            harness_binding=harness,
        )

    def test_exact_codex_daybreak_authority_is_required(self) -> None:
        self.assertEqual(policy.require_codex_authority(self.authority), self.authority)
        for path, replacement in (
            (("model_stack_binding", "authority", "program_tier"), "red"),
            (("model_stack_binding", "authority", "harness_id"), "claude-code"),
            (("model_stack_binding", "authority", "model_id"), "gpt-6-astra"),
            (("harness_binding", "harness_generation_id"), "9" * 64),
        ):
            changed = json.loads(json.dumps(self.authority))
            target = changed
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = replacement
            with self.assertRaises(policy.NativeCodexPolicyError):
                policy.require_codex_authority(changed)

    def test_only_reviewed_daybreak_blue_high_settings_are_admitted(self) -> None:
        stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(
                encoding="ascii"
            )
        )["stacks"][1]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64
        stack["model"]["settings"]["reasoning_effort"] = "low"
        native = native_stack_runtime_binding.make_binding(stack)
        changed = runtime_authority.make_binding(
            model_stack_binding=model_stack_runtime_binding.make_binding(
                model_stack_runtime_binding.NATIVE_MODE, native
            ),
            session_context_binding=self.authority["session_context_binding"],
            harness_binding=self.authority["harness_binding"],
        )
        with self.assertRaisesRegex(policy.NativeCodexPolicyError, "settings_invalid"):
            policy.require_codex_authority(changed)

    def test_descriptor_is_exact_canonical_and_contains_no_account_or_credential(self) -> None:
        descriptor = policy.make_launch_descriptor(self.authority)
        raw = policy.descriptor_bytes(descriptor)
        self.assertEqual(raw, policy.descriptor_bytes(descriptor))
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("ascii")
        self.assertIn("session_id=00000000-0000-4000-8000-000000000001\n", text)
        self.assertIn("cyber_access_program=daybreakBlue\n", text)
        self.assertIn("reasoning_effort=high\n", text)
        self.assertIn("model_id=gpt-6-sol\n", text)
        for forbidden in (
            "access_token",
            "refresh_token",
            "authorization_code",
            "account_subject",
            "workspace_sha256",
            "email",
        ):
            self.assertNotIn(forbidden, text.lower())

    def test_descriptor_digest_rejects_mutation_and_extra_fields(self) -> None:
        descriptor = policy.make_launch_descriptor(self.authority)
        changed = {**descriptor, "model_id": "gpt-6-luna"}
        with self.assertRaisesRegex(policy.NativeCodexPolicyError, "digest_mismatch"):
            policy.validate_launch_descriptor(changed)
        with self.assertRaises(policy.NativeCodexPolicyError):
            policy.validate_launch_descriptor({**descriptor, "fallback": "api-key"})

    def test_projection_permit_is_short_lived_exact_and_descriptor_bound(self) -> None:
        descriptor = policy.make_launch_descriptor(self.authority)
        issued = int(time.time())
        token_digest = hashlib.sha256(b"short-lived-access-token").hexdigest()
        permit = policy.make_projection_permit(
            descriptor,
            projection_id="12345678-1234-4234-8234-123456789abc",
            access_token_sha256=token_digest,
            issued_at_unix=issued,
            expires_at_unix=issued + 60,
            launcher_uid=os.geteuid(),
            launcher_gid=os.getegid(),
        )
        self.assertEqual(
            policy.validate_projection_permit(
                permit,
                descriptor_value=descriptor,
                now_unix=issued,
                launcher_uid=os.geteuid(),
                launcher_gid=os.getegid(),
            ),
            permit,
        )
        encoded = policy.projection_permit_bytes(permit)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertIn(b"session_id=00000000-0000-4000-8000-000000000001\n", encoded)
        self.assertIn(f"access_token_sha256={token_digest}\n".encode(), encoded)
        self.assertNotIn(b"short-lived-access-token", encoded)

    def test_projection_permit_rejects_rebinding_expiry_and_mutation(self) -> None:
        descriptor = policy.make_launch_descriptor(self.authority)
        issued = int(time.time())
        permit = policy.make_projection_permit(
            descriptor,
            projection_id="12345678-1234-4234-8234-123456789abc",
            access_token_sha256="7" * 64,
            issued_at_unix=issued,
            expires_at_unix=issued + 60,
            launcher_uid=os.geteuid(),
            launcher_gid=os.getegid(),
        )

        def resigned(**changes: object) -> dict[str, object]:
            body = {name: permit[name] for name in policy.PROJECTION_PERMIT_FIELDS}
            body.update(changes)
            return {
                "schema": policy.PROJECTION_PERMIT_SCHEMA,
                **body,
                "permit_sha256": policy.sha256(body),
            }

        for changed in (
            resigned(projection_id="22222222-2222-4222-8222-222222222222"),
            resigned(session_id="00000000-0000-4000-8000-000000000002"),
            resigned(runtime_authority_sha256="8" * 64),
            resigned(harness_generation_id="9" * 64),
            resigned(harness_executable_sha256="a" * 64),
            resigned(model_id="gpt-6-luna"),
            resigned(expires_at_unix=issued + 121),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(policy.NativeCodexPolicyError):
                    policy.validate_projection_permit(
                        changed,
                        descriptor_value=descriptor,
                        now_unix=issued,
                        expected_projection_id=permit["projection_id"],
                    )
        with self.assertRaisesRegex(policy.NativeCodexPolicyError, "expired"):
            policy.validate_projection_permit(
                permit, descriptor_value=descriptor, now_unix=issued + 60
            )
        with self.assertRaisesRegex(policy.NativeCodexPolicyError, "uid_invalid"):
            policy.validate_projection_permit(
                permit, descriptor_value=descriptor, launcher_uid=os.geteuid() + 1
            )
        with self.assertRaisesRegex(policy.NativeCodexPolicyError, "digest_mismatch"):
            policy.validate_projection_permit({**permit, "access_token_sha256": "6" * 64})

    def test_atomic_descriptor_publish_is_owner_controlled(self) -> None:
        descriptor = policy.make_launch_descriptor(self.authority)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            target = parent / "launch.authority"
            digest = policy.write_launch_descriptor(
                target,
                descriptor,
                uid=os.geteuid(),
                gid=os.getegid(),
            )
            self.assertEqual(digest, descriptor["descriptor_sha256"])
            self.assertEqual(target.read_bytes(), policy.descriptor_bytes(descriptor))
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            parent.chmod(0o777)
            with self.assertRaisesRegex(policy.NativeCodexPolicyError, "parent_untrusted"):
                policy.write_launch_descriptor(
                    target,
                    descriptor,
                    uid=os.geteuid(),
                    gid=os.getegid(),
                )

    def test_status_projection_is_content_free(self) -> None:
        status = policy.content_free_status(
            policy.make_launch_descriptor(self.authority), state="ready"
        )
        encoded = policy.canonical_bytes(status)
        self.assertNotIn(b"token", encoded.lower())
        self.assertNotIn(b"account", encoded.lower())
        self.assertNotIn(b"workspace", encoded.lower())
        self.assertEqual(status["model_id"], "gpt-6-sol")


if __name__ == "__main__":
    unittest.main()
