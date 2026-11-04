#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
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
        candidate = catalog()
        candidate_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(candidate)).hexdigest()
        plan = promotion_authority.make_plan(
            source_uid=os.getuid(),
            source_sha256=candidate_sha256,
            previous_catalog_sha256=None,
            host_release_id="b" * 64,
            now=2_000_000_000,
            promotion_id="11111111-1111-4111-8111-111111111111",
        )
        acquire_reply = {
            "schema": "secure-sandbox-native-stack-lifecycle-idle-reply-v1",
            "state": "idle",
            "live_run_count": 0,
            "observed_catalog_sha256": PROMOTE.EMPTY_CATALOG_SHA256,
            "fence_sha256": "c" * 64,
            "evidence_sha256": "d" * 64,
        }
        publish_reply = {
            "schema": "secure-sandbox-native-stack-catalog-publish-reply-v1",
            "state": "published",
            "catalog_sha256": plan["catalog_sha256"],
            "fence_sha256": "c" * 64,
            "publication_phase": "published",
            "publication_evidence_sha256": "e" * 64,
        }
        readback_reply = {
            "schema": "secure-sandbox-native-stack-catalog-readback-reply-v1",
            "state": "verified",
            "catalog_sha256": plan["catalog_sha256"],
            "fence_sha256": "c" * 64,
            "publication_phase": "published",
            "publication_evidence_sha256": "e" * 64,
            "evidence_sha256": "f" * 64,
        }
        release_reply = {
            "schema": "secure-sandbox-native-stack-lifecycle-release-reply-v1",
            "state": "released",
            "catalog_sha256": plan["catalog_sha256"],
            "evidence_sha256": "0" * 64,
            "publication_evidence_sha256": "1" * 64,
        }
        responses = [
            subprocess.CompletedProcess([], 0, PROMOTE.canonical(acquire_reply), b""),
            subprocess.CompletedProcess([], 0, PROMOTE.canonical(publish_reply), b""),
            subprocess.CompletedProcess([], 0, PROMOTE.canonical(readback_reply), b""),
            subprocess.CompletedProcess([], 0, PROMOTE.canonical(release_reply), b""),
        ]
        with mock.patch.object(PROMOTE.subprocess, "run", side_effect=responses) as run:
            self.assertEqual(
                PROMOTE.require_guest_idle(
                    plan, control_client=Path("/control"), ssh_config=Path("/ssh")
                ),
                acquire_reply,
            )
            self.assertEqual(
                PROMOTE.publish_guest_catalog(
                    plan, candidate, control_client=Path("/control"),
                    ssh_config=Path("/ssh")
                ),
                publish_reply,
            )
            self.assertEqual(
                PROMOTE.readback_guest_catalog(
                    plan, control_client=Path("/control"),
                    ssh_config=Path("/ssh")
                ),
                readback_reply,
            )
            self.assertEqual(
                PROMOTE.release_guest_lifecycle(
                    plan, control_client=Path("/control"), ssh_config=Path("/ssh")
                ),
                release_reply,
            )
        for call, schema in zip(
            run.call_args_list,
            (
                "secure-sandbox-native-stack-lifecycle-idle-request-v1",
                "secure-sandbox-native-stack-catalog-publish-request-v1",
                "secure-sandbox-native-stack-catalog-readback-request-v1",
                "secure-sandbox-native-stack-lifecycle-release-request-v1",
            ),
            strict=True,
        ):
            request = json.loads(call.kwargs["input"])
            self.assertEqual(request["schema"], schema)
            body = {
                "promotion_id": plan["promotion_id"],
                "plan_sha256": plan["plan_sha256"],
                "host_previous_catalog_sha256": None,
                "previous_catalog_sha256": PROMOTE.EMPTY_CATALOG_SHA256,
                "catalog_sha256": plan["catalog_sha256"],
            }
            if "catalog" in request:
                body["catalog"] = candidate
            self.assertEqual(
                {key: request[key] for key in body}, body)
            self.assertEqual(request["request_sha256"], PROMOTE.digest(body))

    def test_installed_promoter_plans_under_isolated_support_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / ("a" * 64)
            release.mkdir(mode=0o700)
            promoter = release / "native_stack_catalog_promoter"
            shutil.copyfile(
                ROOT / "scripts/native-stack-catalog-promote.py", promoter)
            promoter.chmod(0o755)
            support = release / "native_stack_support"
            with zipfile.ZipFile(support, "w", zipfile.ZIP_STORED) as archive:
                for name in (
                    "shared/__init__.py",
                    "shared/native_stack_catalog_promotion.py",
                    "shared/native_vendor_stack.py",
                ):
                    archive.writestr(name, (ROOT / name).read_bytes())
            support.chmod(0o444)
            source = Path(temporary) / "catalog.json"
            source.write_bytes(native_vendor_stack.canonical_bytes(catalog()))
            source.chmod(0o600)
            completed = subprocess.run(
                [
                    os.sys.executable, "-I", str(promoter), "plan",
                    "--source", str(source), "--source-uid", str(os.getuid()),
                    "--host-release-id", "a" * 64,
                ],
                cwd=release,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            planned = json.loads(completed.stdout)
            self.assertEqual(
                promotion_authority.validate_plan(planned), planned)

    def test_mixed_host_candidate_research_predecessor_fails_closed(self) -> None:
        plan = promotion_authority.make_plan(
            source_uid=os.getuid(), source_sha256="a" * 64,
            previous_catalog_sha256=None, host_release_id="b" * 64,
            now=2_000_000_000,
            promotion_id="11111111-1111-4111-8111-111111111111",
        )
        with self.assertRaisesRegex(
            PROMOTE.CatalogPromotionError, "cross_plane_generation_mismatch"
        ):
            PROMOTE.require_cross_plane_generation(
                plan,
                host_observed=plan["catalog_sha256"],
                research_observed=PROMOTE.EMPTY_CATALOG_SHA256,
            )

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
        self.assertIn('host_observed != plan["catalog_sha256"]', source)
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
            research_generation = {"sha256": PROMOTE.EMPTY_CATALOG_SHA256}
            research_released = {"value": False}

            def acquire(candidate: dict) -> dict:
                lifecycle_events.append(("acquire", candidate["promotion_id"]))
                return {
                    "schema": "secure-sandbox-native-stack-lifecycle-idle-reply-v1",
                    "state": "idle", "live_run_count": 0,
                    "observed_catalog_sha256": research_generation["sha256"],
                    "fence_sha256": "e" * 64,
                    "evidence_sha256": "1" * 64,
                }

            def publish_research(candidate: dict, admitted: dict) -> dict:
                self.assertEqual(admitted, catalog())
                lifecycle_events.append(("publish", candidate["promotion_id"]))
                research_generation["sha256"] = candidate["catalog_sha256"]
                publication_phase = (
                    "released" if research_released["value"] else "published")
                publication_evidence = (
                    "4" * 64 if research_released["value"] else "2" * 64)
                return {
                    "schema": "secure-sandbox-native-stack-catalog-publish-reply-v1",
                    "state": "published",
                    "catalog_sha256": candidate["catalog_sha256"],
                    "fence_sha256": "e" * 64,
                    "publication_phase": publication_phase,
                    "publication_evidence_sha256": publication_evidence,
                }

            def readback_research(candidate: dict) -> dict:
                lifecycle_events.append(("readback", candidate["promotion_id"]))
                publication_phase = (
                    "released" if research_released["value"] else "published")
                publication_evidence = (
                    "4" * 64 if research_released["value"] else "2" * 64)
                return {
                    "schema": "secure-sandbox-native-stack-catalog-readback-reply-v1",
                    "state": "verified",
                    "catalog_sha256": candidate["catalog_sha256"],
                    "fence_sha256": "e" * 64,
                    "publication_phase": publication_phase,
                    "publication_evidence_sha256": publication_evidence,
                    "evidence_sha256": "f" * 64,
                }

            def release_fence(candidate: dict) -> dict:
                lifecycle_events.append(("release", candidate["promotion_id"]))
                research_released["value"] = True
                return {
                    "schema": "secure-sandbox-native-stack-lifecycle-release-reply-v1",
                    "state": "released",
                    "catalog_sha256": candidate["catalog_sha256"],
                    "evidence_sha256": "3" * 64,
                    "publication_evidence_sha256": "4" * 64,
                }

            def crash(phase: str) -> None:
                if phase == "after-host-catalog-publication":
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
                "guest_publisher": publish_research,
                "guest_readback": readback_research,
                "lifecycle_releaser": release_fence,
            }
            with self.assertRaisesRegex(RuntimeError, "simulated-crash"):
                PROMOTE.promote(source, now=created + 2, crash_hook=crash, **arguments)
            self.assertEqual(
                PROMOTE.current_catalog_digest(protected / "catalog.json"),
                plan["catalog_sha256"],
            )
            self.assertTrue(
                (protected / "promotion-receipts" / f"{plan['promotion_id']}.json").is_file()
            )
            self.assertFalse(public_status.exists())
            self.assertEqual(lifecycle_events, [
                ("acquire", plan["promotion_id"]),
                ("publish", plan["promotion_id"]),
            ])
            def crash_after_release(phase: str) -> None:
                if phase == "after-fence-release":
                    raise RuntimeError("lost-release-reply")

            with self.assertRaisesRegex(RuntimeError, "lost-release-reply"):
                PROMOTE.promote(
                    source, now=created + 500,
                    crash_hook=crash_after_release, **arguments)
            self.assertFalse(public_status.exists())
            interrupted = json.loads((
                protected / "promotion-journals"
                / f"{plan['promotion_id']}.json").read_bytes())
            self.assertEqual(interrupted["phase"], "cross-plane-verified")

            receipt = PROMOTE.promote(source, now=created + 600, **arguments)
            self.assertEqual(PROMOTE.current_catalog_digest(protected / "catalog.json"), plan["catalog_sha256"])
            projection = json.loads(public_status.read_bytes())
            self.assertEqual(projection["catalog_sha256"], plan["catalog_sha256"])
            self.assertEqual(projection["promotion_receipt_sha256"], receipt["receipt_sha256"])
            self.assertEqual(
                lifecycle_events,
                [
                    ("acquire", plan["promotion_id"]),
                    ("publish", plan["promotion_id"]),
                    ("acquire", plan["promotion_id"]),
                    ("publish", plan["promotion_id"]),
                    ("readback", plan["promotion_id"]),
                    ("release", plan["promotion_id"]),
                    ("acquire", plan["promotion_id"]),
                    ("publish", plan["promotion_id"]),
                    ("readback", plan["promotion_id"]),
                    ("release", plan["promotion_id"]),
                ],
            )
            durable = json.loads((
                protected / "promotion-journals"
                / f"{plan['promotion_id']}.json").read_bytes())
            self.assertEqual(durable["phase"], "committed")
            self.assertEqual(
                durable["research_publication_evidence_sha256"], "2" * 64)


if __name__ == "__main__":
    unittest.main()
