#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shared import native_vendor_stack
from shared import native_stack_catalog_promotion as promotion_authority
from shared.test_native_vendor_stack import anthropic_stack, openai_stack


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_stack_catalog_promote",
    ROOT / "scripts/native-stack-catalog-promote.py",
)
assert SPEC and SPEC.loader
PROMOTE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROMOTE)


def catalog() -> dict:
    stacks = sorted(
        [anthropic_stack(), openai_stack()], key=lambda value: value["stack_id"]
    )
    return {"schema": native_vendor_stack.CATALOG_SCHEMA, "stacks": stacks}


class NativeStackCatalogPromotionTests(unittest.TestCase):
    def test_research_fence_acquire_and_release_bind_exact_catalog_digest(self) -> None:
        plan = promotion_authority.make_plan(
            source_uid=os.getuid(),
            source_sha256="a" * 64,
            previous_catalog_sha256=None,
            host_release_id="b" * 64,
            now=2_000_000_000,
            promotion_id="11111111-1111-4111-8111-111111111111",
        )
        acquire_reply = {
            "schema": "secure-sandbox-native-stack-lifecycle-idle-reply-v1",
            "state": "idle",
            "live_run_count": 0,
            "evidence_sha256": "c" * 64,
        }
        release_reply = {
            "schema": "secure-sandbox-native-stack-lifecycle-release-reply-v1",
            "state": "released",
            "catalog_sha256": plan["catalog_sha256"],
            "evidence_sha256": "d" * 64,
        }
        responses = [
            subprocess.CompletedProcess([], 0, PROMOTE.canonical(acquire_reply), b""),
            subprocess.CompletedProcess([], 0, PROMOTE.canonical(release_reply), b""),
        ]
        with mock.patch.object(PROMOTE.subprocess, "run", side_effect=responses) as run:
            self.assertEqual(
                PROMOTE.require_guest_idle(
                    plan, control_client=Path("/control"), ssh_config=Path("/ssh")
                ),
                "c" * 64,
            )
            self.assertEqual(
                PROMOTE.release_guest_lifecycle(
                    plan, control_client=Path("/control"), ssh_config=Path("/ssh")
                ),
                "d" * 64,
            )
        for call, schema in zip(
            run.call_args_list,
            (
                "secure-sandbox-native-stack-lifecycle-idle-request-v1",
                "secure-sandbox-native-stack-lifecycle-release-request-v1",
            ),
            strict=True,
        ):
            request = json.loads(call.kwargs["input"])
            self.assertEqual(request["schema"], schema)
            body = {
                key: request[key]
                for key in ("promotion_id", "plan_sha256", "catalog_sha256")
            }
            self.assertEqual(body, {
                "promotion_id": plan["promotion_id"],
                "plan_sha256": plan["plan_sha256"],
                "catalog_sha256": plan["catalog_sha256"],
            })
            self.assertEqual(request["request_sha256"], PROMOTE.digest(body))

    def test_promoter_has_explicit_release_identity_injection_only_for_tests(self) -> None:
        parameters = inspect.signature(PROMOTE.promote).parameters
        self.assertIn("expected_host_release_id", parameters)
        source = (ROOT / "scripts/native-stack-catalog-promote.py").read_text()
        self.assertIn('SHA256.fullmatch(expected_release)', source)

    def test_source_requires_exact_owner_mode_canonical_bytes_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            raw = native_vendor_stack.canonical_bytes(catalog())
            path.write_bytes(raw)
            path.chmod(0o600)
            expected = hashlib.sha256(raw).hexdigest()
            value, observed = PROMOTE.read_operator_catalog(
                path, expected_uid=os.getuid(), expected_sha256=expected
            )
            self.assertEqual(value, catalog())
            self.assertEqual(observed, raw)
            path.write_bytes(json.dumps(catalog()).encode())
            with self.assertRaises(PROMOTE.CatalogPromotionError):
                PROMOTE.read_operator_catalog(
                    path,
                    expected_uid=os.getuid(),
                    expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            path.write_bytes(raw)
            path.chmod(0o644)
            with self.assertRaisesRegex(PROMOTE.CatalogPromotionError, "source_untrusted"):
                PROMOTE.read_operator_catalog(
                    path, expected_uid=os.getuid(), expected_sha256=expected
                )

    def test_active_or_untrusted_transaction_blocks_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = root / "action.json"
            record.write_bytes(PROMOTE.canonical({"phase": "provider-action-pending"}))
            record.chmod(0o600)
            with self.assertRaisesRegex(PROMOTE.CatalogPromotionError, "transaction_active"):
                PROMOTE.require_idle_transactions(root, trusted_uid=os.getuid())

    def test_receipt_is_durable_before_atomic_publication(self) -> None:
        source = (ROOT / "scripts/native-stack-catalog-promote.py").read_text()
        receipt_write = source.index("receipt_path,\n                    canonical(receipt)")
        publication = source.index(
            "_atomic_root_file(\n                target", receipt_write
        )
        self.assertLess(receipt_write, publication)
        self.assertIn(
            "require_idle_transactions(transactions, trusted_uid=trusted_uid)",
            source,
        )
        self.assertIn('current_catalog_digest(target) != plan["catalog_sha256"]', source)
        self.assertIn("verify_pending_authorization_receipt(", source)
        self.assertNotIn('subparsers.add_parser("promote")', source)

    def test_plan_and_authorization_are_exact_self_digested_and_touchid_only(self) -> None:
        plan = promotion_authority.make_plan(
            source_uid=os.getuid(),
            source_sha256="a" * 64,
            previous_catalog_sha256="b" * 64,
            host_release_id="c" * 64,
            now=2_000_000_000,
            promotion_id="11111111-1111-4111-8111-111111111111",
        )
        authorization = {
            "schema": promotion_authority.AUTHORIZATION_SCHEMA,
            "authorization_id": "22222222-2222-4222-8222-222222222222",
            "request_sha256": "d" * 64,
            "pending_receipt_sha256": "e" * 64,
            "promotion_id": plan["promotion_id"],
            "plan_sha256": plan["plan_sha256"],
            "method": "touch-id",
            "password_fallback": False,
            "authorized_at": 2_000_000_001,
            "expires_at": 2_000_000_121,
            "host_release_id": "c" * 64,
            "requesting_agent_sha256": "f" * 64,
            "requesting_session_sha256": "0" * 64,
        }
        authorization["authorization_sha256"] = promotion_authority.sha256(
            authorization
        )
        request = promotion_authority.make_request(plan, authorization)
        self.assertEqual(
            promotion_authority.validate_request(
                request,
                now=2_000_000_002,
                expected_host_release_id="c" * 64,
            ),
            (plan, authorization),
        )
        changed = json.loads(json.dumps(request))
        changed["plan"]["source_sha256"] = "9" * 64
        with self.assertRaises(promotion_authority.NativeStackCatalogPromotionError):
            promotion_authority.validate_request(changed, now=2_000_000_002)
        fallback = dict(authorization)
        fallback["password_fallback"] = True
        fallback["authorization_sha256"] = promotion_authority.sha256(
            {key: item for key, item in fallback.items() if key != "authorization_sha256"}
        )
        with self.assertRaises(promotion_authority.NativeStackCatalogPromotionError):
            promotion_authority.validate_authorization(
                fallback, plan, now=2_000_000_002
            )
        mismatched_release = dict(authorization)
        mismatched_release["host_release_id"] = "8" * 64
        mismatched_release["authorization_sha256"] = promotion_authority.sha256(
            {
                key: item
                for key, item in mismatched_release.items()
                if key != "authorization_sha256"
            }
        )
        with self.assertRaisesRegex(
            promotion_authority.NativeStackCatalogPromotionError,
            "authorization_mismatch",
        ):
            promotion_authority.validate_authorization(
                mismatched_release, plan, now=2_000_000_002
            )
        with self.assertRaisesRegex(
            promotion_authority.NativeStackCatalogPromotionError,
            "plan_release_mismatch",
        ):
            promotion_authority.validate_request(
                request,
                now=2_000_000_002,
                expected_host_release_id="8" * 64,
            )

    def test_promotion_rejects_root_owned_operator_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            raw = native_vendor_stack.canonical_bytes(catalog())
            path.write_bytes(raw)
            path.chmod(0o600)
            with self.assertRaisesRegex(PROMOTE.CatalogPromotionError, "authority_invalid"):
                PROMOTE.read_operator_catalog(
                    path,
                    expected_uid=0,
                    expected_sha256=hashlib.sha256(raw).hexdigest(),
                )

    def test_receipted_crash_replays_exact_staging_after_authority_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operator = root / "operator"
            protected = root / "protected"
            transactions = root / "transactions"
            authorization_receipts = root / "authorization-receipts"
            public_status = root / "public" / "status.json"
            for directory in (
                operator, protected, transactions, authorization_receipts
            ):
                directory.mkdir(mode=0o700)
            source = operator / "catalog.json"
            raw = native_vendor_stack.canonical_bytes(catalog())
            source.write_bytes(raw)
            source.chmod(0o600)
            release = "a" * 64
            created = 2_000_000_000
            plan = promotion_authority.make_plan(
                source_uid=os.getuid(),
                source_sha256=hashlib.sha256(raw).hexdigest(),
                previous_catalog_sha256=None,
                host_release_id=release,
                now=created,
                promotion_id="11111111-1111-4111-8111-111111111111",
            )
            pending = {
                "schema": "secure-sandbox-operator-authorization-receipt-v1",
                "request_id": "22222222-2222-4222-8222-222222222222",
                "request_sha256": "b" * 64,
                "status": "executing",
                "started_at": created + 1,
                "completed_at": None,
                "operation": promotion_authority.OPERATION,
                "declared_agent": "Control Center",
                "declared_session": "promotion-test",
                "identity_evidence": "operator-declared",
                "authorization_method": "touch-id",
                "ceremony": "approve",
                "purpose": "Promote exact catalog",
                "resource": promotion_authority.RESOURCE,
                "exit_status": None,
                "stdout_sha256": None,
                "stderr_sha256": None,
                "native_catalog_promotion_id": plan["promotion_id"],
                "native_catalog_plan_sha256": plan["plan_sha256"],
                "host_release_id": release,
            }
            authorization = {
                "schema": promotion_authority.AUTHORIZATION_SCHEMA,
                "authorization_id": pending["request_id"],
                "request_sha256": pending["request_sha256"],
                "pending_receipt_sha256": hashlib.sha256(
                    PROMOTE.canonical(pending)
                ).hexdigest(),
                "promotion_id": plan["promotion_id"],
                "plan_sha256": plan["plan_sha256"],
                "method": "touch-id",
                "password_fallback": False,
                "authorized_at": created + 1,
                "expires_at": created + 121,
                "host_release_id": release,
                "requesting_agent_sha256": "c" * 64,
                "requesting_session_sha256": "d" * 64,
            }
            authorization["authorization_sha256"] = promotion_authority.sha256(
                authorization
            )
            request = promotion_authority.make_request(plan, authorization)
            receipt_path = authorization_receipts / f"{pending['request_id']}.json"
            receipt_path.write_bytes(PROMOTE.canonical(pending))
            receipt_path.chmod(0o600)

            lifecycle_events = []

            def acquire(candidate: dict) -> str:
                lifecycle_events.append(("acquire", candidate["promotion_id"]))
                return "e" * 64

            def release_fence(candidate: dict) -> str:
                lifecycle_events.append(("release", candidate["promotion_id"]))
                return "f" * 64

            def crash(phase: str) -> None:
                if phase == "after-fence-acquire":
                    raise RuntimeError("simulated-crash")

            arguments = {
                "request": request,
                "target": protected / "catalog.json",
                "transactions": transactions,
                "authorization_receipts": authorization_receipts,
                "trusted_uid": os.getuid(),
                "trusted_gid": os.getgid(),
                "expected_euid": os.geteuid(),
                "expected_host_release_id": release,
                "public_status": public_status,
                "idle_verifier": acquire,
                "lifecycle_releaser": release_fence,
            }
            with self.assertRaisesRegex(RuntimeError, "simulated-crash"):
                PROMOTE.promote(source, now=created + 2, crash_hook=crash, **arguments)
            self.assertFalse((protected / "catalog.json").exists())
            self.assertTrue(
                (protected / "promotion-receipts" / f"{plan['promotion_id']}.json").is_file()
            )
            self.assertFalse(public_status.exists())
            self.assertEqual(lifecycle_events, [("acquire", plan["promotion_id"])])
            receipt = PROMOTE.promote(source, now=created + 500, **arguments)
            self.assertEqual(PROMOTE.current_catalog_digest(protected / "catalog.json"), plan["catalog_sha256"])
            projection = json.loads(public_status.read_bytes())
            self.assertEqual(projection["catalog_sha256"], plan["catalog_sha256"])
            self.assertEqual(projection["promotion_receipt_sha256"], receipt["receipt_sha256"])
            self.assertEqual(
                lifecycle_events,
                [
                    ("acquire", plan["promotion_id"]),
                    ("acquire", plan["promotion_id"]),
                    ("release", plan["promotion_id"]),
                ],
            )


if __name__ == "__main__":
    unittest.main()
