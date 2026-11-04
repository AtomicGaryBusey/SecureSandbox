#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from research import native_claude_adapter as adapter
from shared import harness_runtime_binding, model_stack_runtime_binding
from shared import native_stack_runtime_binding, runtime_authority, session_context_binding


ROOT = Path(__file__).resolve().parent.parent


class NativeClaudeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        stack = json.loads(
            (ROOT / "config/native-vendor-stacks.example.json").read_text(encoding="ascii")
        )["stacks"][0]
        stack["harness"]["generation_id"] = "a" * 64
        stack["account_binding"]["account_subject_sha256"] = "b" * 64
        stack["account_binding"]["workspace_sha256"] = "c" * 64
        native = native_stack_runtime_binding.make_binding(stack)
        harness = harness_runtime_binding.make_binding(
            harness_id="claude-code",
            generation_id="a" * 64,
            manifest_sha256="d" * 64,
            executable_sha256=hashlib.sha256(b"claude").hexdigest(),
            inventory_sha256="e" * 64,
            adapter_id="claude-native-oauth-v1",
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
        self.environment = adapter.child_environment(
            self.authority,
            home=Path("/var/empty/claude-native"),
            config_root=Path("/var/lib/native-test"),
            term="xterm-256color",
        )

    def test_environment_is_reconstructed_and_has_no_projected_credential(self) -> None:
        adapter.validate_environment(self.environment)
        for name in adapter.FORBIDDEN_ENVIRONMENT:
            self.assertNotIn(name, self.environment)
        self.assertEqual(self.environment["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"], "1")
        self.assertEqual(self.environment["DISABLE_UPDATES"], "1")
        self.assertEqual(self.environment["ANTHROPIC_MODEL"], adapter.CLAUDE_MODEL_ID)
        self.assertEqual(self.environment["HTTPS_PROXY"], adapter.PROXY)

    def test_environment_rejects_api_key_base_url_and_proxy_drift(self) -> None:
        for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            changed = {**self.environment, name: "secret"}
            with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "forbidden_environment"):
                adapter.validate_environment(changed)
        with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "proxy_invalid"):
            adapter.validate_environment({**self.environment, "HTTPS_PROXY": "http://evil"})

    def test_exact_pairing_and_harness_match_are_required(self) -> None:
        self.assertEqual(adapter.require_claude_authority(self.authority), self.authority)
        changed = json.loads(json.dumps(self.authority))
        changed["model_stack_binding"]["authority"]["model_id"] = "claude-opus-5"
        with self.assertRaises(adapter.NativeClaudeAdapterError):
            adapter.require_claude_authority(changed)

    def test_executable_is_remeasured_from_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / ("a" * 64)
            release.mkdir()
            executable = release / "harness"
            executable.write_bytes(b"claude")
            executable.chmod(0o555)
            observed = adapter.executable_for_authority(
                self.authority, release_root=root, trusted_uid=os.geteuid()
            )
            self.assertEqual(observed, executable)
            executable.chmod(0o755)
            with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "untrusted"):
                adapter.executable_for_authority(
                    self.authority, release_root=root, trusted_uid=os.geteuid()
                )

    def test_commands_pin_model_and_do_not_offer_fallback(self) -> None:
        command = adapter.session_command(
            Path("/release/harness"),
            session_id="00000000-0000-4000-8000-000000000001",
            effort="high",
            resume=False,
        )
        self.assertEqual(command[command.index("--model") + 1], adapter.CLAUDE_MODEL_ID)
        self.assertNotIn("--fallback-model", command)
        self.assertIn("--restricted", command)
        self.assertEqual(command[command.index("--tools") + 1], "")
        self.assertEqual(command[command.index("--disallowedTools") + 1], "*")
        self.assertIn("--strict-mcp-config", command)
        self.assertIn("--disable-slash-commands", command)
        self.assertNotIn("--dangerously-skip-permissions", command)

        entitlement = adapter.entitlement_command(
            Path("/release/harness"), effort="high"
        )
        self.assertEqual(entitlement[entitlement.index("--tools") + 1], "")
        self.assertEqual(
            entitlement[entitlement.index("--disallowedTools") + 1], "*"
        )

    def test_status_projection_never_returns_vendor_fields_or_paths(self) -> None:
        payload = json.dumps({
            "loggedIn": True,
            "apiProvider": "firstParty",
            "authMethod": "claude.ai",
            "analyticsDisabled": True,
            "configDirectory": self.environment["CLAUDE_CONFIG_DIR"],
            "projectsDirectory": self.environment["CLAUDE_CONFIG_DIR"] + "/projects",
            "loginExpiresAt": 2_000_000_000,
            "email": "operator@example.test",
            "orgId": "org_opaque_identifier",
            "orgName": "Private Organization Name",
            "subscriptionType": "ultra",
        }).encode()
        runner = mock.Mock(return_value=subprocess_result(0, payload))
        status = adapter.observe_status(
            Path("/release/harness"), self.environment, runner=runner, now=100,
            binding_key=b"k" * 32,
        )
        self.assertEqual(status["state"], "signed-in")
        self.assertRegex(status["account_subject_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["workspace_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["subscription_class_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            status["evidence_sha256"], hashlib.sha256(payload).hexdigest())
        differently_keyed = adapter.observe_status(
            Path("/release/harness"), self.environment, runner=runner, now=100,
            binding_key=b"z" * 32)
        self.assertNotEqual(
            status["evidence_sha256"], differently_keyed["evidence_sha256"])
        encoded = adapter.canonical_bytes(status).decode("ascii")
        self.assertNotIn("configDirectory", encoded)
        self.assertNotIn("projectsDirectory", encoded)
        self.assertNotIn("operator@example", encoded)
        self.assertNotIn("Private Organization", encoded)
        self.assertNotIn("org_opaque", encoded)

    def test_current_signed_out_schema_is_exact_and_content_free(self) -> None:
        payload = json.dumps({
            "loggedIn": False,
            "apiProvider": "firstParty",
            "authMethod": "none",
            "analyticsDisabled": True,
            "configDirectory": self.environment["CLAUDE_CONFIG_DIR"],
            "projectsDirectory": self.environment["CLAUDE_CONFIG_DIR"] + "/projects",
            "loginExpiresAt": None,
        }).encode()
        status = adapter.observe_status(
            Path("/release/harness"), self.environment,
            runner=mock.Mock(return_value=subprocess_result(1, payload)), now=100,
            binding_key=b"k" * 32,
        )
        # Claude 2.1.318 returns exit 1 for a valid signed-out status.
        self.assertEqual(status["state"], "signed-out")
        status = adapter.observe_status(
            Path("/release/harness"), self.environment,
            runner=mock.Mock(return_value=subprocess_result(0, payload)), now=100,
            binding_key=b"k" * 32,
        )
        self.assertEqual(status["state"], "signed-out")
        self.assertIsNone(status["account_subject_sha256"])

    def test_unknown_status_is_ambiguous_not_signed_out(self) -> None:
        payload = json.dumps({
            "apiProvider": "other",
            "authMethod": "new-method",
            "configDirectory": self.environment["CLAUDE_CONFIG_DIR"],
            "projectsDirectory": "/x",
        }).encode()
        status = adapter.observe_status(
            Path("/release/harness"), self.environment,
            runner=mock.Mock(return_value=subprocess_result(0, payload)), now=100,
            binding_key=b"k" * 32,
        )
        self.assertEqual(status["state"], "ambiguous")

    def test_entitlement_requires_only_exact_mythos_usage(self) -> None:
        raw = json.dumps({
            "subtype": "success",
            "is_error": False,
            "result": "SECURE_SANDBOX_ENTITLEMENT_READY",
            "modelUsage": {adapter.CLAUDE_MODEL_ID: {"inputTokens": 1, "outputTokens": 1}},
        }, separators=(",", ":")).encode()
        receipt = adapter.observe_entitlement_result(
            raw, binding_key=b"k" * 32, now=100)
        self.assertEqual(receipt["state"], "verified")
        self.assertEqual(receipt["program_state"], "unknown")
        self.assertNotIn("program_id", receipt)
        self.assertNotIn("program_tier", receipt)
        self.assertNotEqual(
            receipt["evidence_sha256"], hashlib.sha256(raw).hexdigest())
        cross_model = json.loads(raw)
        cross_model["modelUsage"]["claude-opus-5"] = {}
        denied = adapter.observe_entitlement_result(
            json.dumps(cross_model, separators=(",", ":")).encode(),
            binding_key=b"k" * 32, now=100
        )
        self.assertEqual(denied["state"], "denied")
        changed_result = json.loads(raw)
        changed_result["result"] = "SECURE_SANDBOX_ENTITLEMENT_READY extra"
        denied = adapter.observe_entitlement_result(
            json.dumps(changed_result, separators=(",", ":")).encode(),
            binding_key=b"k" * 32, now=100
        )
        self.assertEqual(denied["state"], "denied")

    def test_bounded_runner_discards_stderr_and_rejects_oversize(self) -> None:
        runner = mock.Mock(return_value=subprocess_result(0, b"x" * 32))
        with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "oversized"):
            adapter._run_bounded(
                ["/release/harness"], self.environment,
                maximum=16, timeout=1, runner=runner,
            )

    def test_production_reader_stops_output_before_unbounded_buffering(self) -> None:
        with self.assertRaisesRegex(adapter.NativeClaudeAdapterError, "oversized"):
            adapter._run_bounded(
                [sys.executable, "-c", "import os; os.write(1, b'x' * 1048576)"],
                self.environment,
                maximum=1024,
                timeout=5,
            )


def subprocess_result(returncode: int, stdout: bytes):
    return type("Result", (), {"returncode": returncode, "stdout": stdout})()


if __name__ == "__main__":
    unittest.main()
