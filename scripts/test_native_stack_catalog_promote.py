#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import fcntl
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


COORDINATION_CONTRACT = (
    ROOT / "config/native-stack-coordination-contract.json"
).read_bytes()


def make_host_release(
    install: Path, *, generation: bytes = b"first",
) -> tuple[str, Path]:
    releases = install / "releases"
    releases.mkdir(mode=0o755, exist_ok=True)
    values = {
        PROMOTE.COORDINATION_CONTRACT_NAME: COORDINATION_CONTRACT,
        "test_generation": generation,
    }
    payloads = {
        name: hashlib.sha256(raw).hexdigest()
        for name, raw in values.items()
    }
    release_id = PROMOTE._release_identity(payloads)
    release = releases / release_id
    release.mkdir(mode=0o755)
    for name, raw in values.items():
        (release / name).write_bytes(raw)
        (release / name).chmod(0o444)
    manifest = {
        "schema": "secure-sandbox-host-controller-release-v1",
        "release_id": release_id,
        "payloads": payloads,
    }
    (release / "manifest.json").write_bytes(PROMOTE.canonical(manifest))
    (release / "manifest.json").chmod(0o444)
    release.chmod(0o555)
    floor_path = install / PROMOTE.COORDINATION_FLOOR_NAME
    if not floor_path.exists():
        floor_raw = PROMOTE.canonical({
            "schema": PROMOTE.COORDINATION_FLOOR_SCHEMA,
            "minimum_epoch": 1,
            "established_from_release_id": release_id,
            "established_from_contract_sha256": hashlib.sha256(
                COORDINATION_CONTRACT).hexdigest(),
        })
        floor_path.write_bytes(floor_raw)
        floor_path.chmod(0o600)
        contract = json.loads(COORDINATION_CONTRACT)
        enforcement_path = install / PROMOTE.COORDINATION_ENFORCEMENT_NAME
        enforcement_path.write_bytes(PROMOTE.canonical({
            "schema": PROMOTE.COORDINATION_ENFORCEMENT_SCHEMA,
            "minimum_epoch": contract["epoch"],
            "minimum_features": contract["features"],
            "authoritative_floor_sha256": hashlib.sha256(
                floor_raw).hexdigest(),
        }))
        enforcement_path.chmod(0o444)
    return release_id, release


class NativeStackCatalogPromotionTests(unittest.TestCase):
    def test_deployment_admission_does_not_create_absent_promotion_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "host"
            install.mkdir(mode=0o755)
            release_id, _release = make_host_release(install)
            (install / "current").symlink_to(f"releases/{release_id}")
            catalog_root = root / "catalog"
            catalog_root.mkdir(mode=0o700)
            (catalog_root / "catalog.json").write_bytes(
                native_vendor_stack.canonical_bytes(PROMOTE.EMPTY_CATALOG))
            transactions = root / "transactions"
            public_status = root / "public/status.json"
            descriptor = os.open(install, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            before = sorted(path.name for path in catalog_root.iterdir())
            gate = PROMOTE.promotion_gate_state(
                descriptor, catalog_root=catalog_root,
                transactions=transactions, public_status=public_status,
                host_install_root=install, trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
                expected_host_release_id=release_id)
            self.assertEqual(gate["state"], "ready")
            with PROMOTE.promotion_admission(
                descriptor, catalog_root=catalog_root,
                transactions=transactions, public_status=public_status,
                host_install_root=install, trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
                expected_host_release_id=release_id,
            ) as (_authority, body):
                self.assertEqual(body["state"], "ready")
            self.assertEqual(
                sorted(path.name for path in catalog_root.iterdir()), before)
            self.assertFalse(transactions.exists())
            self.assertFalse(public_status.exists())

    def test_host_authority_rejects_install_transition_and_unlocked_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "host"
            install.mkdir(mode=0o755)
            install.chmod(0o755)
            release_id, _release = make_host_release(install)
            releases = install / "releases"
            releases.chmod(0o755)
            (install / "current").symlink_to(f"releases/{release_id}")
            descriptor = os.open(install, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, descriptor)
            with PROMOTE.inherited_host_authority(
                descriptor, host_install_root=install,
                trusted_uid=os.getuid(),
                expected_host_release_id=release_id,
            ):
                pass
            contender = os.open(install, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, contender)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with self.assertRaisesRegex(
                PROMOTE.CatalogPromotionError, "host_lock_not_held",
            ):
                with PROMOTE.inherited_host_authority(
                    contender, host_install_root=install,
                    trusted_uid=os.getuid(),
                    expected_host_release_id=release_id,
                ):
                    pass
            (install / PROMOTE.INSTALL_TRANSITION_PENDING_NAME).write_text(
                "{}\n", encoding="ascii")
            with self.assertRaisesRegex(
                PROMOTE.CatalogPromotionError,
                "host_install_transition_active",
            ):
                with PROMOTE.inherited_host_authority(
                    descriptor, host_install_root=install,
                    trusted_uid=os.getuid(),
                    expected_host_release_id=release_id,
                ):
                    pass
            with PROMOTE.inherited_host_authority(
                descriptor, host_install_root=install,
                trusted_uid=os.getuid(),
                expected_host_release_id=release_id,
                allow_install_transition=True,
            ):
                pass

    def test_promotion_rejects_active_and_invalid_deployment_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for state in ("active", "invalid"):
                with self.subTest(state=state):
                    active = "a" * 64 if state == "active" else None
                    body = {
                        "state": state,
                        "active_journal_sha256": active,
                    }
                    gate = {
                        "schema": PROMOTE.DEPLOYMENT_GATE_SCHEMA, **body,
                        "gate_sha256": PROMOTE.digest(body),
                    }
                    source = (
                        "def deployment_gate_state(*args, **kwargs):\n"
                        f"    return {gate!r}\n"
                    ).encode("ascii")
                    payloads = {
                        "native_stack_deployer": hashlib.sha256(
                            source).hexdigest()
                    }
                    release_id = PROMOTE._release_identity(payloads)
                    release = root / release_id
                    release.mkdir(mode=0o755)
                    deployer = release / "native_stack_deployer"
                    deployer.write_bytes(source)
                    deployer.chmod(0o755)
                    manifest = {
                        "schema": "secure-sandbox-host-controller-release-v1",
                        "release_id": release_id, "payloads": payloads,
                    }
                    (release / "manifest.json").write_bytes(
                        PROMOTE.canonical(manifest))
                    (release / "manifest.json").chmod(0o444)
                    release.chmod(0o555)
                    expected = (
                        "native_catalog_deployment_active"
                        if state == "active"
                        else "native_catalog_deployment_gate_invalid"
                    )
                    with self.assertRaisesRegex(
                        PROMOTE.CatalogPromotionError, expected,
                    ):
                        PROMOTE.require_deployment_gate_ready(
                            release, -1, state_root=root / "state",
                            host_install_root=root / "host",
                            trusted_uid=os.getuid(), trusted_gid=os.getgid())

    def test_finalized_history_requires_one_linear_chain(self) -> None:
        def record(candidate: str, previous: str | None) -> dict:
            return {
                "catalog_sha256": candidate,
                "previous_catalog_sha256": previous,
            }

        first = record("a" * 64, None)
        second = record("b" * 64, "a" * 64)
        self.assertIs(
            PROMOTE._finalized_chain_head({"first": first, "second": second}),
            second,
        )
        with self.assertRaisesRegex(
            PROMOTE.CatalogPromotionError, "history_disconnected",
        ):
            PROMOTE._require_active_extends_finalized_head(
                first["catalog_sha256"], second)
        with self.assertRaisesRegex(
            PROMOTE.CatalogPromotionError, "history_forked",
        ):
            PROMOTE._finalized_chain_head({
                "first": first,
                "second": second,
                "fork": record("c" * 64, "a" * 64),
            })
        with self.assertRaisesRegex(
            PROMOTE.CatalogPromotionError, "history_cycle",
        ):
            PROMOTE._finalized_chain_head({
                "left": record("a" * 64, "b" * 64),
                "right": record("b" * 64, "a" * 64),
            })
        with self.assertRaisesRegex(
            PROMOTE.CatalogPromotionError, "history_invalid",
        ):
            PROMOTE._finalized_chain_head({
                "left": record("a" * 64, None),
                "orphan": record("b" * 64, "c" * 64),
            })

    def test_exclusive_publication_residues_are_reconciled_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            promotion_id = "11111111-1111-4111-8111-111111111111"
            final = directory / f"{promotion_id}.json"
            raw = PROMOTE.canonical({"value": 1})
            PROMOTE._create_root_file_exclusive(
                final, raw, trusted_uid=os.getuid(), trusted_gid=os.getgid())
            temporary_path = directory / f".{final.name}.residue"
            os.link(final, temporary_path)
            self.assertEqual(final.stat().st_nlink, 2)
            PROMOTE._reconcile_exclusive_residues(
                directory, trusted_uid=os.getuid(), trusted_gid=os.getgid())
            self.assertFalse(temporary_path.exists())
            self.assertEqual(final.stat().st_nlink, 1)

    def test_exact_v1_journals_dual_validate_without_redefining_fields(self) -> None:
        plan = promotion_authority.make_plan(
            source_uid=os.getuid(), source_sha256="a" * 64,
            previous_catalog_sha256=None, host_release_id="b" * 64,
            now=2_000_000_000,
            promotion_id="11111111-1111-4111-8111-111111111111")
        authorization = {
            "authorization_sha256": "c" * 64,
            "pending_receipt_sha256": "d" * 64,
        }
        receipt = {
            "receipt_sha256": "e" * 64,
        }
        replay_sha256 = "f" * 64
        base = PROMOTE._new_promotion_journal(
            plan, authorization, receipt, replay_sha256,
            updated_at=2_000_000_001)
        evidence = {
            "research_observed_catalog_sha256": PROMOTE.EMPTY_CATALOG_SHA256,
            "research_fence_sha256": "1" * 64,
            "research_idle_evidence_sha256": "2" * 64,
            "research_publication_evidence_sha256": "3" * 64,
            "host_observed_catalog_sha256": "a" * 64,
            "research_readback_evidence_sha256": "4" * 64,
            "research_release_evidence_sha256": "5" * 64,
            "research_terminal_evidence_sha256": "6" * 64,
        }
        for phase in ("research-fenced", "committed"):
            with self.subTest(phase=phase):
                value = dict(base)
                value["schema"] = PROMOTE.LEGACY_PROMOTION_JOURNAL_SCHEMA
                value.pop("public_status_sha256")
                value.pop("replay_authority_sha256")
                phase_index = PROMOTE.PROMOTION_PHASES.index(phase)
                required = {
                    "research-fenced": 3, "research-published": 4,
                    "host-published": 5, "cross-plane-verified": 6,
                    "committed": 8,
                }[phase]
                for name in list(evidence)[:required]:
                    value[name] = evidence[name]
                value["phase"] = phase
                body = {
                    key: item for key, item in value.items()
                    if key not in {"schema", "journal_sha256"}
                }
                value["journal_sha256"] = PROMOTE.digest(body)
                normalized = PROMOTE._validate_promotion_journal_record(value)
                self.assertEqual(
                    normalized["schema"],
                    PROMOTE.LEGACY_PROMOTION_JOURNAL_SCHEMA)
                self.assertIsNone(normalized["replay_authority_sha256"])
                bound = PROMOTE._validate_promotion_journal(
                    value, plan, authorization, receipt, replay_sha256)
                self.assertEqual(
                    bound["replay_authority_sha256"], replay_sha256)

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
            no_op = subprocess.run(
                [
                    os.sys.executable, "-I", str(promoter), "plan",
                    "--source", str(source), "--source-uid", str(os.getuid()),
                    "--previous-catalog-sha256",
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                    "--host-release-id", "a" * 64,
                ],
                cwd=release,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(no_op.returncode, 0)
            self.assertIn("native_catalog_noop_forbidden", no_op.stderr)

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
            host_install_root = root / "host"
            for directory in (
                operator, protected, transactions, authorization_receipts
            ):
                directory.mkdir(mode=0o700)
            source = operator / "catalog.json"
            raw = native_vendor_stack.canonical_bytes(catalog())
            source.write_bytes(raw)
            source.chmod(0o600)
            host_install_root.mkdir(mode=0o755)
            release, release_path = make_host_release(host_install_root)
            releases = host_install_root / "releases"
            (host_install_root / "current").symlink_to(
                f"releases/{release}")
            host_install_fd = os.open(
                host_install_root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, host_install_fd)
            fcntl.flock(host_install_fd, fcntl.LOCK_EX)
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
            expected_admitted_catalog = {"value": catalog()}

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
                self.assertEqual(admitted, expected_admitted_catalog["value"])
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
                "host_install_fd": host_install_fd,
                "host_install_root": host_install_root,
                "deployment_state_root": root / "deployment",
                "deployment_gate_verifier": lambda *_args, **_kwargs: {
                    "state": "ready"
                },
                "public_status": public_status,
                "idle_verifier": acquire,
                "guest_publisher": publish_research,
                "guest_readback": readback_research,
                "lifecycle_releaser": release_fence,
            }

            def authority_mismatch(
                *, include_status: bool,
            ) -> list[tuple[Path, bytes]]:
                receipt_path = (
                    protected / "promotion-receipts"
                    / f"{plan['promotion_id']}.json")
                journal_path = (
                    protected / "promotion-journals"
                    / f"{plan['promotion_id']}.json")
                paths = [receipt_path, journal_path]
                if include_status:
                    paths.append(public_status)
                originals = [(path, path.read_bytes()) for path in paths]
                receipt = json.loads(receipt_path.read_bytes())
                receipt["plan_sha256"] = "d" * 64
                receipt_body = {
                    key: value for key, value in receipt.items()
                    if key not in {"schema", "receipt_sha256"}
                }
                receipt["receipt_sha256"] = PROMOTE.digest(receipt_body)
                receipt_path.write_bytes(PROMOTE.canonical(receipt))
                journal = json.loads(journal_path.read_bytes())
                journal["plan_sha256"] = receipt["plan_sha256"]
                journal["promotion_receipt_sha256"] = receipt[
                    "receipt_sha256"]
                journal_body = {
                    key: value for key, value in journal.items()
                    if key not in {"schema", "journal_sha256"}
                }
                journal["journal_sha256"] = PROMOTE.digest(journal_body)
                journal_path.write_bytes(PROMOTE.canonical(journal))
                if include_status:
                    status = json.loads(public_status.read_bytes())
                    status["promotion_receipt_sha256"] = receipt[
                        "receipt_sha256"]
                    status_body = {
                        key: value for key, value in status.items()
                        if key not in {"schema", "status_sha256"}
                    }
                    status["status_sha256"] = PROMOTE.digest(status_body)
                    public_status.write_bytes(PROMOTE.canonical(status))
                return originals
            def before_authority(phase: str) -> None:
                if phase == "before-replay-authority-publication":
                    raise RuntimeError("before-authority")

            with self.assertRaisesRegex(RuntimeError, "before-authority"):
                PROMOTE.promote(
                    source, now=created + 2,
                    crash_hook=before_authority, **arguments)
            self.assertFalse((
                protected / "promotion-replay-authorities"
                / f"{plan['promotion_id']}.json").exists())
            self.assertEqual(lifecycle_events, [])

            def after_authority(phase: str) -> None:
                if phase == "replay-authority-published":
                    raise RuntimeError("after-authority")

            with self.assertRaisesRegex(RuntimeError, "after-authority"):
                PROMOTE.promote(
                    source, now=created + 2,
                    crash_hook=after_authority, **arguments)
            user_plan = operator / "promotion-plan.json"
            user_plan.write_bytes(PROMOTE.canonical(request))
            source.unlink()
            user_plan.unlink()
            initial_gate = PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=release)
            self.assertEqual(initial_gate["state"], "active")
            for index, phase in enumerate((
                "journal-authorized", "journal-research-fenced",
                "journal-research-published", "journal-host-published",
                "journal-cross-plane-verified", "journal-committed",
            )):
                def crash_at(observed: str, expected: str = phase) -> None:
                    if observed == expected:
                        raise RuntimeError(expected)

                with self.subTest(crash_phase=phase), self.assertRaisesRegex(
                    RuntimeError, phase,
                ):
                    PROMOTE.recover_active(
                        host_install_fd, now=created + 10 + index,
                        crash_hook=crash_at,
                        **{key: value for key, value in arguments.items()
                           if key not in {"request", "host_install_fd"}})
                retry_gate = PROMOTE.promotion_gate_state(
                    host_install_fd, catalog_root=protected,
                    transactions=transactions, public_status=public_status,
                    host_install_root=host_install_root,
                    trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                    expected_host_release_id=release)
                self.assertEqual(retry_gate["state"], "active")
                self.assertEqual(
                    retry_gate["gate_sha256"], initial_gate["gate_sha256"])
            self.assertEqual(
                PROMOTE.current_catalog_digest(protected / "catalog.json"),
                plan["catalog_sha256"],
            )
            self.assertTrue(
                (protected / "promotion-receipts" / f"{plan['promotion_id']}.json").is_file()
            )
            authority_path = (
                protected / "promotion-replay-authorities"
                / f"{plan['promotion_id']}.json"
            )
            self.assertTrue(authority_path.is_file())
            gate = PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=release)
            self.assertEqual(gate["state"], "active")
            self.assertEqual(gate["active_promotion_id"], plan["promotion_id"])
            self.assertEqual(gate["gate_sha256"], initial_gate["gate_sha256"])
            with self.assertRaisesRegex(
                PROMOTE.CatalogPromotionError,
                "native_catalog_recovery_required",
            ):
                PROMOTE.promote(
                    source, now=created + 3, **arguments)
            self.assertFalse(public_status.exists())
            self.assertFalse(public_status.exists())
            interrupted = json.loads((
                protected / "promotion-journals"
                / f"{plan['promotion_id']}.json").read_bytes())
            self.assertEqual(interrupted["phase"], "committed")
            self.assertEqual(PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=release)["gate_sha256"],
                initial_gate["gate_sha256"])
            mismatch_originals = authority_mismatch(include_status=False)
            self.assertEqual(PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=release)["state"], "invalid")
            for path, original in mismatch_originals:
                path.write_bytes(original)

            def lose_terminal_reply(phase: str) -> None:
                if phase == "before-recovery-terminal-publication":
                    raise RuntimeError("lost-terminal-reply")

            with self.assertRaisesRegex(
                RuntimeError, "lost-terminal-reply",
            ):
                PROMOTE.recover_active(
                    host_install_fd, now=created + 600,
                    crash_hook=lose_terminal_reply,
                    **{key: value for key, value in arguments.items()
                       if key not in {"request", "host_install_fd"}})
            terminal = PROMOTE.recover_active(
                host_install_fd, now=created + 700,
                **{key: value for key, value in arguments.items()
                   if key not in {"request", "host_install_fd"}})
            replayed_terminal = PROMOTE.recover_active(
                host_install_fd, now=created + 800,
                **{key: value for key, value in arguments.items()
                   if key not in {"request", "host_install_fd"}})
            self.assertEqual(replayed_terminal, terminal)
            intent = json.loads((
                protected / "promotion-recovery-intents"
                / f"{plan['promotion_id']}.json").read_bytes())
            self.assertEqual(
                terminal["expected_gate_sha256"],
                intent["expected_gate_sha256"])
            self.assertEqual(
                terminal["recovery_intent_sha256"],
                intent["intent_sha256"])
            events_before_finalized_consume = list(lifecycle_events)
            with self.assertRaisesRegex(
                PROMOTE.CatalogPromotionError,
                "native_catalog_promotion_already_finalized",
            ):
                PROMOTE.promote(
                    source, now=created + 900, **arguments)
            self.assertEqual(lifecycle_events, events_before_finalized_consume)
            self.assertEqual(PROMOTE.current_catalog_digest(protected / "catalog.json"), plan["catalog_sha256"])
            projection = json.loads(public_status.read_bytes())
            self.assertEqual(projection["catalog_sha256"], plan["catalog_sha256"])
            self.assertEqual(
                projection["promotion_receipt_sha256"],
                terminal["promotion_receipt_sha256"])
            self.assertTrue(any(
                event[0] == "release" for event in lifecycle_events))
            durable = json.loads((
                protected / "promotion-journals"
                / f"{plan['promotion_id']}.json").read_bytes())
            self.assertEqual(durable["phase"], "finalized")
            mismatch_originals = authority_mismatch(include_status=True)
            self.assertEqual(PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=release)["state"], "invalid")
            for path, original in mismatch_originals:
                path.write_bytes(original)
            journal_path = (
                protected / "promotion-journals"
                / f"{plan['promotion_id']}.json")
            v2_journal_raw = journal_path.read_bytes()
            legacy = json.loads(v2_journal_raw)
            legacy["schema"] = PROMOTE.LEGACY_PROMOTION_JOURNAL_SCHEMA
            legacy["phase"] = "committed"
            legacy.pop("public_status_sha256")
            legacy.pop("replay_authority_sha256")
            legacy_body = {
                key: value for key, value in legacy.items()
                if key not in {"schema", "journal_sha256"}
            }
            legacy["journal_sha256"] = PROMOTE.digest(legacy_body)
            journal_path.write_bytes(PROMOTE.canonical(legacy))
            events_before_legacy_consume = list(lifecycle_events)
            with self.assertRaisesRegex(
                PROMOTE.CatalogPromotionError,
                "native_catalog_promotion_already_finalized",
            ):
                PROMOTE.promote(
                    source, now=created + 901, **arguments)
            self.assertEqual(lifecycle_events, events_before_legacy_consume)
            journal_path.write_bytes(v2_journal_raw)
            self.assertEqual(
                durable["research_publication_evidence_sha256"], "2" * 64)
            self.assertEqual(PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=release)["state"], "ready")
            newer_release, newer_path = make_host_release(
                host_install_root, generation=b"newer")
            (host_install_root / "current").unlink()
            (host_install_root / "current").symlink_to(
                f"releases/{newer_release}")
            self.assertEqual(PROMOTE.promotion_gate_state(
                host_install_fd, catalog_root=protected,
                transactions=transactions, public_status=public_status,
                host_install_root=host_install_root,
                trusted_uid=os.getuid(), trusted_gid=os.getgid(),
                expected_host_release_id=newer_release)["state"], "ready")
            self.assertEqual(
                json.loads(public_status.read_bytes())["host_release_id"],
                release)
            fresh_catalog = {
                "schema": native_vendor_stack.CATALOG_SCHEMA,
                "stacks": [anthropic_stack()],
            }
            fresh_raw = native_vendor_stack.canonical_bytes(fresh_catalog)
            source.write_bytes(fresh_raw)
            source.chmod(0o600)
            fresh_plan = promotion_authority.make_plan(
                source_uid=os.getuid(),
                source_sha256=hashlib.sha256(fresh_raw).hexdigest(),
                previous_catalog_sha256=plan["catalog_sha256"],
                host_release_id=newer_release,
                now=created + 2_000,
                promotion_id="33333333-3333-4333-8333-333333333333",
            )
            fresh_pending = dict(pending)
            fresh_pending.update({
                "request_id": "44444444-4444-4444-8444-444444444444",
                "request_sha256": "5" * 64,
                "started_at": created + 2_001,
                "native_catalog_promotion_id": fresh_plan["promotion_id"],
                "native_catalog_plan_sha256": fresh_plan["plan_sha256"],
                "host_release_id": newer_release,
            })
            fresh_authorization = dict(authorization)
            fresh_authorization.update({
                "authorization_id": fresh_pending["request_id"],
                "request_sha256": fresh_pending["request_sha256"],
                "pending_receipt_sha256": hashlib.sha256(
                    PROMOTE.canonical(fresh_pending)).hexdigest(),
                "promotion_id": fresh_plan["promotion_id"],
                "plan_sha256": fresh_plan["plan_sha256"],
                "authorized_at": created + 2_001,
                "expires_at": created + 2_121,
                "host_release_id": newer_release,
            })
            fresh_authorization["authorization_sha256"] = (
                promotion_authority.sha256({
                    key: value for key, value in fresh_authorization.items()
                    if key != "authorization_sha256"
                })
            )
            fresh_request = promotion_authority.make_request(
                fresh_plan, fresh_authorization)
            fresh_receipt_path = (
                authorization_receipts
                / f"{fresh_pending['request_id']}.json"
            )
            fresh_receipt_path.write_bytes(PROMOTE.canonical(fresh_pending))
            fresh_receipt_path.chmod(0o600)
            fresh_arguments = dict(arguments)
            fresh_arguments.update({
                "request": fresh_request,
                "expected_host_release_id": newer_release,
            })
            expected_admitted_catalog["value"] = fresh_catalog
            research_released["value"] = False
            PROMOTE.promote(
                source, now=created + 2_002, **fresh_arguments)
            fresh_status = json.loads(public_status.read_bytes())
            self.assertEqual(
                fresh_status["catalog_sha256"],
                fresh_plan["catalog_sha256"])
            self.assertEqual(
                fresh_status["host_release_id"], newer_release)


if __name__ == "__main__":
    unittest.main()
