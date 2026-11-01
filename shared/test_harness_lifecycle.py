#!/usr/bin/env python3
from __future__ import annotations

import base64
import errno
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("harness_lifecycle.py")
SPEC = importlib.util.spec_from_file_location("harness_lifecycle", MODULE_PATH)
LIFECYCLE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(LIFECYCLE)


class Response(io.BytesIO):
    def __init__(self, value: bytes, url: str, declared: int | None = None) -> None:
        super().__init__(value)
        self.url = url
        self.headers = {} if declared is None else {"Content-Length": str(declared)}

    def geturl(self) -> str:
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class HarnessLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = self.root / "private.key"
        self.public = self.root / "public.key"
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "genpkey", "-algorithm", "ED25519", "-out", str(self.private)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.public_text = self.public.read_text(encoding="ascii")
        self.key_id = hashlib.sha256(LIFECYCLE.ed25519_spki_der(self.public_text)).hexdigest()
        self.policy = {
            "artifact_origins": ["https://downloads.example.com"],
            "keys": [{"algorithm": "ed25519", "key_id": self.key_id,
                      "public_key_pem": self.public_text}],
            "mandatory_evidence_kinds": ["vendor-signature", "vendor-checksum-manifest"],
            "max_artifact_bytes": 1024 * 1024,
            "max_metadata_bytes": 256 * 1024,
            "metadata_url": "https://updates.example.com/harnesses.json",
            "schema": LIFECYCLE.POLICY_SCHEMA,
            "threshold": 1,
        }
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_bytes(LIFECYCLE.canonical_bytes(self.policy))
        self.policy_path.chmod(0o600)
        self.state = self.root / "state"
        self.now = 2_000_000_000
        self.artifact = b"inert candidate bytes\n"
        self.manifest = self.make_manifest()
        self.store = LIFECYCLE.HarnessStore(
            self.state, self.policy_path, now=lambda: self.now,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_manifest(self, **changes):
        artifact_sha = hashlib.sha256(self.artifact).hexdigest()
        value = {
            "adapter_id": "claude-core-v1",
            "artifact": {
                "filename": "claude-linux-arm64", "media_type": "application/octet-stream",
                "sha256": artifact_sha, "size": len(self.artifact),
                "url": "https://downloads.example.com/claude-linux-arm64",
            },
            "compatibility": {
                "adapter_sha256": "a" * 64, "controller_schema": "harness-controller-v1",
            },
            "evidence": [
                {"kind": "vendor-signature", "media_type": "application/octet-stream",
                 "required": True, "sha256": "b" * 64, "subject_sha256": artifact_sha},
                {"kind": "vendor-checksum-manifest", "media_type": "application/json",
                 "required": True, "sha256": "c" * 64, "subject_sha256": artifact_sha},
            ],
            "generation_id": "0" * 64,
            "harness_id": "claude-code", "platform": "linux-arm64",
            "release_sequence": 1, "schema": LIFECYCLE.MANIFEST_SCHEMA,
            "vendor_id": "anthropic", "version": "2.1.300",
        }
        value.update(changes)
        value["generation_id"] = LIFECYCLE.generation_identity(value)
        return value

    def envelope(self, *, sequence: int = 1, expires_at: int | None = None,
                 manifest=None) -> bytes:
        signed = {
            "expires_at": self.now + 3600 if expires_at is None else expires_at,
            "published_at": self.now - 10,
            "releases": [self.manifest if manifest is None else manifest],
            "schema": LIFECYCLE.METADATA_SCHEMA, "sequence": sequence,
        }
        payload_path = self.root / "payload"
        signature_path = self.root / "signature"
        payload_path.write_bytes(LIFECYCLE.canonical_bytes(signed))
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "pkeyutl", "-sign", "-inkey", str(self.private), "-rawin",
             "-in", str(payload_path), "-out", str(signature_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        value = {
            "schema": LIFECYCLE.ENVELOPE_SCHEMA,
            "signatures": [{
                "algorithm": "ed25519", "key_id": self.key_id,
                "signature": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
            }],
            "signed": signed,
        }
        return LIFECYCLE.canonical_bytes(value)

    def delegated_envelope(self, *, not_before: int | None = None,
                           not_after: int | None = None,
                           revoked_at: int | None = None,
                           issuer_key_id: str | None = None,
                           corrupt_certificate: bool = False,
                           corrupt_signature: bool = False) -> bytes:
        leaf_private = self.root / "leaf-private.key"
        leaf_public = self.root / "leaf-public.key"
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "genpkey", "-algorithm", "ED25519",
             "-out", str(leaf_private)], check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "pkey", "-in", str(leaf_private),
             "-pubout", "-out", str(leaf_public)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        leaf_pem = leaf_public.read_text(encoding="ascii")
        leaf_id = hashlib.sha256(LIFECYCLE.ed25519_spki_der(leaf_pem)).hexdigest()
        certificate = {
            "algorithm": "ed25519",
            "issuer_key_id": self.key_id if issuer_key_id is None else issuer_key_id,
            "not_after": self.now + 3600 if not_after is None else not_after,
            "not_before": self.now - 3600 if not_before is None else not_before,
            "revoked_at": revoked_at,
            "schema": LIFECYCLE.SIGNER_CERTIFICATE_SCHEMA,
            "subject_key_id": leaf_id,
            "subject_public_key_pem": leaf_pem,
        }
        certificate_payload = self.root / "certificate-payload"
        certificate_signature = self.root / "certificate-signature"
        certificate_payload.write_bytes(LIFECYCLE.canonical_bytes(certificate))
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "pkeyutl", "-sign", "-inkey",
             str(self.private), "-rawin", "-in", str(certificate_payload), "-out",
             str(certificate_signature)], check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        certificate_bytes = bytearray(certificate_signature.read_bytes())
        if corrupt_certificate:
            certificate_bytes[0] ^= 1
        certificate["signature"] = base64.b64encode(certificate_bytes).decode("ascii")
        signed = {
            "expires_at": self.now + 3600,
            "published_at": self.now - 10,
            "releases": [self.manifest],
            "schema": LIFECYCLE.METADATA_SCHEMA,
            "sequence": 1,
        }
        payload = self.root / "delegated-payload"
        signature = self.root / "delegated-signature"
        payload.write_bytes(LIFECYCLE.canonical_bytes(signed))
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "pkeyutl", "-sign", "-inkey",
             str(leaf_private), "-rawin", "-in", str(payload), "-out", str(signature)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        signature_bytes = bytearray(signature.read_bytes())
        if corrupt_signature:
            signature_bytes[0] ^= 1
        return LIFECYCLE.canonical_bytes({
            "schema": LIFECYCLE.ENVELOPE_V2_SCHEMA,
            "signatures": [{
                "algorithm": "ed25519", "certificates": [certificate],
                "key_id": leaf_id,
                "signature": base64.b64encode(signature_bytes).decode("ascii"),
            }],
            "signed": signed,
        })

    def checked(self) -> None:
        result = self.store.check_bytes(self.envelope())
        self.assertEqual(result["status"], "metadata_verified")

    def acquired(self) -> None:
        self.checked()
        result = self.store.acquire(
            self.manifest["generation_id"],
            opener=lambda _url: Response(self.artifact, self.manifest["artifact"]["url"],
                                         len(self.artifact)),
        )
        self.assertEqual(result["status"], "artifact_quarantined")

    def test_canonical_json_rejects_duplicates_and_noncanonical_bytes(self) -> None:
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "json_duplicate_key"):
            LIFECYCLE.parse_json(b'{"a":1,"a":2}\n')
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "json_noncanonical"):
            LIFECYCLE.parse_json(b'{ "a": 1 }\n')

    def test_manifest_identity_origin_and_evidence_are_bound(self) -> None:
        policy = LIFECYCLE.validate_policy(self.policy)
        self.assertEqual(LIFECYCLE.validate_manifest(self.manifest, policy), self.manifest)
        broken = json.loads(json.dumps(self.manifest)); broken["generation_id"] = "f" * 64
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "generation_id_mismatch"):
            LIFECYCLE.validate_manifest(broken, policy)
        broken = self.make_manifest()
        broken["evidence"][0]["subject_sha256"] = "f" * 64
        broken["generation_id"] = LIFECYCLE.generation_identity(broken)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "evidence_subject_mismatch"):
            LIFECYCLE.validate_manifest(broken, policy)

    def test_signed_metadata_and_signature_tampering(self) -> None:
        raw = self.envelope()
        envelope, _digest = LIFECYCLE.validate_envelope(
            raw, LIFECYCLE.validate_policy(self.policy), self.now,
        )
        self.assertEqual(envelope["signed"]["sequence"], 1)
        changed = json.loads(raw); changed["signed"]["sequence"] = 2
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "signature_invalid"):
            LIFECYCLE.validate_envelope(
                LIFECYCLE.canonical_bytes(changed), LIFECYCLE.validate_policy(self.policy), self.now,
            )

    def test_delegated_signer_chain_accepts_only_valid_current_leaf(self) -> None:
        policy = LIFECYCLE.validate_policy(self.policy)
        envelope, _ = LIFECYCLE.validate_envelope(
            self.delegated_envelope(), policy, self.now,
        )
        self.assertEqual(envelope["schema"], LIFECYCLE.ENVELOPE_V2_SCHEMA)
        for changes, reason in (
            ({"corrupt_signature": True}, "metadata_signature_invalid"),
            ({"corrupt_certificate": True}, "metadata_signer_chain_invalid"),
            ({"not_after": self.now}, "metadata_signer_certificate_expired"),
            ({"not_before": self.now + 1}, "metadata_signer_certificate_expired"),
            ({"revoked_at": self.now}, "metadata_signer_certificate_revoked"),
            ({"issuer_key_id": "f" * 64}, "metadata_signer_chain_invalid"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, reason):
                    LIFECYCLE.validate_envelope(
                        self.delegated_envelope(**changes), policy, self.now,
                    )

    def test_policy_revocation_cascades_through_intermediate_signer(self) -> None:
        def keypair(name: str) -> tuple[Path, str, str]:
            private = self.root / f"{name}-private.key"
            public = self.root / f"{name}-public.key"
            subprocess.run(
                [str(LIFECYCLE.DEFAULT_OPENSSL), "genpkey", "-algorithm", "ED25519",
                 "-out", str(private)], check=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [str(LIFECYCLE.DEFAULT_OPENSSL), "pkey", "-in", str(private),
                 "-pubout", "-out", str(public)], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            pem = public.read_text(encoding="ascii")
            return private, pem, hashlib.sha256(
                LIFECYCLE.ed25519_spki_der(pem),
            ).hexdigest()

        def certificate(name: str, subject_pem: str, subject_id: str,
                        issuer_id: str, issuer_private: Path) -> dict:
            value = {
                "algorithm": "ed25519", "issuer_key_id": issuer_id,
                "not_after": self.now + 3600, "not_before": self.now - 3600,
                "revoked_at": None,
                "schema": LIFECYCLE.SIGNER_CERTIFICATE_SCHEMA,
                "subject_key_id": subject_id,
                "subject_public_key_pem": subject_pem,
            }
            payload = self.root / f"{name}-certificate-payload"
            signature = self.root / f"{name}-certificate-signature"
            payload.write_bytes(LIFECYCLE.canonical_bytes(value))
            subprocess.run(
                [str(LIFECYCLE.DEFAULT_OPENSSL), "pkeyutl", "-sign", "-inkey",
                 str(issuer_private), "-rawin", "-in", str(payload), "-out",
                 str(signature)], check=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            value["signature"] = base64.b64encode(signature.read_bytes()).decode("ascii")
            return value

        intermediate_private, intermediate_pem, intermediate_id = keypair("intermediate")
        _leaf_private, leaf_pem, leaf_id = keypair("descendant-leaf")
        chain = [
            certificate(
                "intermediate", intermediate_pem, intermediate_id,
                self.key_id, self.private,
            ),
            certificate(
                "descendant-leaf", leaf_pem, leaf_id,
                intermediate_id, intermediate_private,
            ),
        ]
        roots = {self.key_id: {"public_key_pem": self.public.read_text(encoding="ascii")}}
        trusted_leaf, authority = LIFECYCLE.validate_signer_chain(
            chain, leaf_id, roots, set(), self.now, LIFECYCLE.verify_ed25519,
        )
        self.assertEqual(trusted_leaf, leaf_pem)
        self.assertEqual(authority, self.key_id)
        with self.assertRaisesRegex(
            LIFECYCLE.HarnessLifecycleError, "metadata_signer_certificate_revoked",
        ):
            LIFECYCLE.validate_signer_chain(
                chain, leaf_id, roots, {intermediate_id}, self.now,
                LIFECYCLE.verify_ed25519,
            )

    def test_release_catalog_is_reverified_metadata_only_and_floor_bound(self) -> None:
        self.checked()
        catalog = self.store.releases()
        self.assertEqual(catalog["authority"], "signed-metadata-only")
        self.assertEqual(catalog["releases"], [self.manifest])
        self.assertEqual(catalog["sequence"], 1)
        floor = json.loads((self.state / "metadata/floor.json").read_bytes())
        floor["envelope_sha256"] = "f" * 64
        (self.state / "metadata/floor.json").write_bytes(LIFECYCLE.canonical_bytes(floor))
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "metadata_floor_mismatch"):
            self.store.releases()

    def test_signature_verifier_ignores_hostile_path_and_enforces_threshold(self) -> None:
        hostile = self.root / "hostile-bin"; hostile.mkdir()
        fake = hostile / "openssl"; fake.write_text("#!/bin/sh\nexit 0\n", encoding="ascii"); fake.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(hostile)}):
            LIFECYCLE.validate_envelope(
                self.envelope(), LIFECYCLE.validate_policy(self.policy), self.now,
            )
        second_private = self.root / "second-private.key"
        second_public = self.root / "second-public.key"
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "genpkey", "-algorithm", "ED25519",
             "-out", str(second_private)], check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(LIFECYCLE.DEFAULT_OPENSSL), "pkey", "-in", str(second_private),
             "-pubout", "-out", str(second_public)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        second_pem = second_public.read_text(encoding="ascii")
        policy = json.loads(json.dumps(self.policy))
        policy["keys"].append({
            "algorithm": "ed25519",
            "key_id": hashlib.sha256(LIFECYCLE.ed25519_spki_der(second_pem)).hexdigest(),
            "public_key_pem": second_pem,
        })
        policy["threshold"] = 2
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "threshold_unmet"):
            LIFECYCLE.validate_envelope(
                self.envelope(), LIFECYCLE.validate_policy(policy), self.now,
            )

    def test_expiry_rollback_and_equivocation_fail_closed(self) -> None:
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "metadata_expired"):
            self.store.check_bytes(self.envelope(expires_at=self.now))
        self.store.check_bytes(self.envelope(sequence=2))
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "rollback_or_equivocation"):
            self.store.check_bytes(self.envelope(sequence=1))
        alternate = self.make_manifest(version="2.1.301", release_sequence=2)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "rollback_or_equivocation"):
            self.store.check_bytes(self.envelope(sequence=2, manifest=alternate))

    def test_metadata_floor_pins_exact_policy(self) -> None:
        self.checked()
        changed = json.loads(json.dumps(self.policy))
        changed["max_artifact_bytes"] += 1
        self.policy_path.write_bytes(LIFECYCLE.canonical_bytes(changed))
        self.policy_path.chmod(0o600)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "metadata_policy_changed"):
            self.store.check_bytes(self.envelope(sequence=2))

    def test_acquire_is_exact_inert_and_idempotent(self) -> None:
        self.acquired()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        self.assertEqual((generation / "artifact").read_bytes(), self.artifact)
        self.assertEqual((generation / "artifact").stat().st_mode & 0o777, 0o600)
        result = self.store.acquire(
            self.manifest["generation_id"], opener=lambda _url: self.fail("network reused"),
        )
        self.assertEqual(result["status"], "already_acquired")
        self.assertFalse(os.access(generation / "artifact", os.X_OK))

    def test_acquire_rejects_length_and_digest_substitution(self) -> None:
        self.checked()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "length_mismatch"):
            self.store.acquire(
                self.manifest["generation_id"],
                opener=lambda _url: Response(self.artifact, self.manifest["artifact"]["url"], 1),
            )
        self.assertFalse(generation.exists())
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "digest_mismatch"):
            self.store.acquire(
                self.manifest["generation_id"],
                opener=lambda _url: Response(b"x" * len(self.artifact),
                                             self.manifest["artifact"]["url"]),
            )
        self.assertFalse(generation.exists())

    def test_rejected_acquisition_preserves_concurrent_empty_generation(self) -> None:
        self.checked()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        observed: dict[str, int] = {}

        def carrier(_url):
            generation.mkdir(mode=0o700)
            info = generation.stat()
            observed.update(dev=info.st_dev, ino=info.st_ino)
            return Response(b"x" * len(self.artifact), self.manifest["artifact"]["url"])

        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "digest_mismatch"):
            self.store.acquire(self.manifest["generation_id"], opener=carrier)
        after = generation.stat()
        self.assertEqual((after.st_dev, after.st_ino), (observed["dev"], observed["ino"]))
        self.assertEqual(list(generation.iterdir()), [])

    def test_acquisition_refuses_and_preserves_concurrent_partial_generation(self) -> None:
        self.checked()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        sentinel = b"pre-existing partial manifest\n"

        def carrier(_url):
            generation.mkdir(mode=0o700)
            manifest = generation / "manifest.json"
            manifest.write_bytes(sentinel)
            manifest.chmod(0o600)
            return Response(self.artifact, self.manifest["artifact"]["url"])

        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "partial_state"):
            self.store.acquire(self.manifest["generation_id"], opener=carrier)
        self.assertEqual((generation / "manifest.json").read_bytes(), sentinel)
        self.assertFalse((generation / "artifact").exists())

    def test_acquire_has_total_deadline(self) -> None:
        self.checked()
        ticks = iter((0.0, 301.0))
        self.store.monotonic = lambda: next(ticks)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "deadline_exceeded"):
            self.store.acquire(
                self.manifest["generation_id"],
                opener=lambda _url: Response(self.artifact, self.manifest["artifact"]["url"]),
            )

    def test_acquire_deadline_includes_slow_eof(self) -> None:
        self.checked()
        ticks = iter((0.0, 1.0, 2.0, 3.0, 301.0))
        self.store.monotonic = lambda: next(ticks)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "deadline_exceeded"):
            self.store.acquire(
                self.manifest["generation_id"],
                opener=lambda _url: Response(
                    self.artifact, self.manifest["artifact"]["url"],
                ),
            )
        self.assertFalse(
            (self.state / "quarantine" / self.manifest["generation_id"]).exists(),
        )

    def test_metadata_check_has_total_deadline(self) -> None:
        ticks = iter((0.0, 61.0))
        self.store.monotonic = lambda: next(ticks)
        with mock.patch.object(
            LIFECYCLE, "open_https",
            return_value=Response(self.envelope(), self.policy["metadata_url"]),
        ):
            with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "deadline_exceeded"):
                self.store.check()

    def test_verify_receipt_is_explicitly_non_admitting(self) -> None:
        self.acquired()
        result = self.store.verify(self.manifest["generation_id"])
        self.assertEqual(result["status"], "artifact_and_evidence_bindings_verified")
        self.assertEqual(result["note"], "not_admitted_not_executable")
        status = self.store.status()
        self.assertEqual(status["authority"], "none")
        self.assertFalse(status["automatic_download"])
        self.assertFalse(status["automatic_install"])
        self.assertTrue(status["policy_configured"])
        self.assertRegex(status["policy_sha256"], r"^[0-9a-f]{64}$")

    def test_verify_rejects_byte_identical_substitution_before_receipt(self) -> None:
        self.acquired()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        artifact = generation / "artifact"
        receipts_before = set((self.state / "receipts").iterdir())
        original_receipt = self.store._receipt

        def substitute_then_receipt(*args, **kwargs):
            value = artifact.read_bytes()
            artifact.unlink()
            artifact.write_bytes(value)
            artifact.chmod(0o600)
            return original_receipt(*args, **kwargs)

        with mock.patch.object(
            self.store, "_receipt", side_effect=substitute_then_receipt,
        ):
            with self.assertRaisesRegex(
                LIFECYCLE.HarnessLifecycleError, "quarantine_generation_changed",
            ):
                self.store.verify(self.manifest["generation_id"])
        self.assertEqual(set((self.state / "receipts").iterdir()), receipts_before)

    def test_acquire_rejects_unexpected_child_before_receipt(self) -> None:
        self.checked()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        receipts_before = set((self.state / "receipts").iterdir())
        original_receipt = self.store._receipt

        def add_child_then_receipt(*args, **kwargs):
            extra = generation / "unexpected"
            extra.write_bytes(b"substituted evidence\n")
            extra.chmod(0o600)
            return original_receipt(*args, **kwargs)

        with mock.patch.object(
            self.store, "_receipt", side_effect=add_child_then_receipt,
        ):
            with self.assertRaisesRegex(
                LIFECYCLE.HarnessLifecycleError, "quarantine_generation_changed",
            ):
                self.store.acquire(
                    self.manifest["generation_id"],
                    opener=lambda _url: Response(
                        self.artifact, self.manifest["artifact"]["url"],
                    ),
                )
        self.assertEqual(set((self.state / "receipts").iterdir()), receipts_before)

    def test_quarantine_tampering_and_symlink_fail_closed(self) -> None:
        self.acquired()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        (generation / "artifact").write_bytes(b"x" * len(self.artifact))
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "digest_mismatch"):
            self.store.verify(self.manifest["generation_id"])
        (generation / "artifact").unlink()
        (generation / "artifact").symlink_to(self.root / "policy.json")
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "state_file_untrusted"):
            self.store.verify(self.manifest["generation_id"])

    def test_untrusted_state_directory_and_partial_generation_fail_closed(self) -> None:
        unsafe = self.root / "unsafe-state"
        unsafe.mkdir(mode=0o755); unsafe.chmod(0o755)
        store = LIFECYCLE.HarnessStore(unsafe, self.policy_path, now=lambda: self.now)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "state_directory_untrusted"):
            store.status()
        self.checked()
        generation = self.state / "quarantine" / self.manifest["generation_id"]
        generation.mkdir(mode=0o700)
        (generation / ".artifact.new-abandoned").write_bytes(b"partial")
        (generation / ".artifact.new-abandoned").chmod(0o600)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "partial_state"):
            self.store.acquire(
                self.manifest["generation_id"], opener=lambda _url: self.fail("network used"),
            )

    def test_policy_rejects_wrong_key_identity_and_http_origins(self) -> None:
        broken = json.loads(json.dumps(self.policy)); broken["keys"][0]["key_id"] = "f" * 64
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "key_id_mismatch"):
            LIFECYCLE.validate_policy(broken)
        broken = json.loads(json.dumps(self.policy)); broken["metadata_url"] = "http://updates.example.com/x"
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "metadata_url_invalid"):
            LIFECYCLE.validate_policy(broken)
        for invalid in ("https://127.0.0.1/x", "https://singlelabel/x", "https://EXAMPLE.com/x"):
            broken = json.loads(json.dumps(self.policy)); broken["metadata_url"] = invalid
            with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "metadata_url_invalid"):
                LIFECYCLE.validate_policy(broken)

    def test_redirected_final_url_is_rejected(self) -> None:
        fake_opener = mock.Mock()
        fake_opener.open.return_value = Response(b"metadata", "https://evil.example.net/file")
        with mock.patch.object(LIFECYCLE.urllib.request, "build_opener", return_value=fake_opener):
            with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "response_rejected"):
                LIFECYCLE.open_https("https://updates.example.com/file")

    def test_receipt_capacity_preflights_metadata_and_artifact_mutation(self) -> None:
        self.checked()
        floor_before = (self.state / "metadata/floor.json").read_bytes()
        for index in range(LIFECYCLE.MAX_RECEIPTS - 1):
            receipt = self.state / "receipts" / f"capacity-{index:03d}.json"
            receipt.write_bytes(b"{}\n"); receipt.chmod(0o600)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "receipt_capacity_exceeded"):
            self.store.check_bytes(self.envelope(sequence=2))
        self.assertEqual((self.state / "metadata/floor.json").read_bytes(), floor_before)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "receipt_capacity_exceeded"):
            self.store.acquire(
                self.manifest["generation_id"], opener=lambda _url: self.fail("network used"),
            )
        self.assertFalse((self.state / "quarantine" / self.manifest["generation_id"]).exists())

    def test_receipt_capacity_race_cannot_leave_unreceipted_acquisition(self) -> None:
        self.checked()
        receipts = self.state / "receipts"

        def fill_after_preflight(_url):
            for index in range(LIFECYCLE.MAX_RECEIPTS - len(list(receipts.iterdir()))):
                receipt = receipts / f"concurrent-{index:03d}.json"
                receipt.write_bytes(b"{}\n")
                receipt.chmod(0o600)
            return Response(self.artifact, self.manifest["artifact"]["url"])

        result = self.store.acquire(
            self.manifest["generation_id"], opener=fill_after_preflight,
        )
        self.assertEqual(result["status"], "artifact_quarantined")
        recorded = [
            json.loads(path.read_text()) for path in receipts.iterdir()
            if path.read_bytes() != b"{}\n"
        ]
        self.assertTrue(any(
            item.get("generation_id") == self.manifest["generation_id"]
            and item.get("status") == "artifact_quarantined"
            for item in recorded
        ))

    def test_write_new_at_distinguishes_collision_from_io_failure(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(
                LIFECYCLE.os, "open", side_effect=OSError(errno.ENOSPC, "full"),
            ):
                with self.assertRaisesRegex(
                    LIFECYCLE.HarnessLifecycleError, "state_write_failed",
                ):
                    LIFECYCLE.write_new_at(descriptor, "manifest.json", b"{}\n")
        finally:
            os.close(descriptor)

    def test_policy_file_mode_and_symlink_are_rejected(self) -> None:
        self.policy_path.chmod(0o644)
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "state_file_untrusted"):
            self.store.status()
        self.policy_path.chmod(0o600)
        linked = self.root / "linked-policy.json"
        linked.symlink_to(self.policy_path)
        linked_store = LIFECYCLE.HarnessStore(
            self.root / "linked-state", linked, now=lambda: self.now,
        )
        with self.assertRaisesRegex(LIFECYCLE.HarnessLifecycleError, "state_file_untrusted"):
            linked_store.status()


if __name__ == "__main__":
    unittest.main()
