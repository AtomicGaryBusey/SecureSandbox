#!/usr/bin/env python3
"""Synthetic, non-admitting provenance cases for disposable-Mac acceptance."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable

import harness_lifecycle as lifecycle
from harness_lifecycle_acceptance import CASE_BY_ID, digest


SCHEMA = "secure-sandbox-harness-lifecycle-provenance-fixture-v1"
PROVENANCE_CASES = frozenset(
    case.case_id for case in CASE_BY_ID.values() if case.category == "provenance"
)

EXPECTED_ERRORS = {
    "reject-redirect": "artifact_response_rejected",
    "reject-oversized-artifact": "artifact_size_mismatch",
    "reject-artifact-substitution": "artifact_digest_mismatch",
    "reject-bad-signature": "metadata_signature_invalid",
    "reject-unknown-signer": "metadata_signature_identity_invalid",
    "reject-revoked-signer": "metadata_signer_certificate_revoked",
    "reject-expired-signer": "metadata_signer_certificate_expired",
    "reject-broken-chain": "metadata_signer_chain_invalid",
    "reject-stale-metadata": "metadata_expired",
    "reject-future-metadata": "metadata_from_future",
    "reject-release-rollback": "metadata_rollback_or_equivocation",
    "reject-release-freeze": "metadata_expired",
    "reject-release-equivocation": "metadata_rollback_or_equivocation",
    "reject-inconsistent-provenance": "manifest_evidence_subject_mismatch",
}


class ProvenanceFixtureError(RuntimeError):
    """Stable failure for the synthetic provenance fixture."""


class Response(io.BytesIO):
    def __init__(self, value: bytes, url: str, *, final_url: str | None = None,
                 declared: int | None = None) -> None:
        super().__init__(value)
        self.url = final_url or url
        self.headers = {} if declared is None else {"Content-Length": str(declared)}

    def geturl(self) -> str:
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _trusted_root(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ProvenanceFixtureError("provenance_fixture_root_untrusted")


def _state_digest(path: Path) -> str:
    inventory = []
    if path.exists():
        for item in sorted(path.rglob("*"), key=lambda value: value.relative_to(path).as_posix()):
            info = item.lstat()
            relative = item.relative_to(path).as_posix()
            if stat.S_ISDIR(info.st_mode):
                inventory.append({"path": relative, "type": "directory",
                                  "mode": stat.S_IMODE(info.st_mode)})
            elif stat.S_ISREG(info.st_mode):
                inventory.append({"path": relative, "type": "file",
                                  "mode": stat.S_IMODE(info.st_mode),
                                  "sha256": hashlib.sha256(item.read_bytes()).hexdigest()})
            else:
                raise ProvenanceFixtureError("provenance_fixture_state_untrusted")
    return digest(inventory)


class ProvenanceFixture:
    def __init__(self, root: Path, *, now: int) -> None:
        _trusted_root(root)
        self.root = root
        self.current_time = now
        self.artifact = b"inert disposable provenance carrier\n"
        self.root_private = root / "root-private.pem"
        self.root_public = root / "root-public.pem"
        self.leaf_private = root / "leaf-private.pem"
        self.leaf_public = root / "leaf-public.pem"
        self._keypair(self.root_private, self.root_public)
        self._keypair(self.leaf_private, self.leaf_public)
        self.root_pem = self.root_public.read_text(encoding="ascii")
        self.leaf_pem = self.leaf_public.read_text(encoding="ascii")
        self.root_key_id = hashlib.sha256(
            lifecycle.ed25519_spki_der(self.root_pem),
        ).hexdigest()
        self.leaf_key_id = hashlib.sha256(
            lifecycle.ed25519_spki_der(self.leaf_pem),
        ).hexdigest()
        self.policy_path = root / "policy.json"
        self.state = root / "state"
        self.policy = {
            "artifact_origins": ["https://downloads.example.com"],
            "keys": [{"algorithm": "ed25519", "key_id": self.root_key_id,
                      "public_key_pem": self.root_pem}],
            "mandatory_evidence_kinds": [
                "vendor-signature", "vendor-checksum-manifest",
            ],
            "max_artifact_bytes": 1024 * 1024,
            "max_metadata_bytes": 256 * 1024,
            "metadata_url": "https://updates.example.com/harnesses.json",
            "revoked_signer_key_ids": [],
            "schema": lifecycle.POLICY_V2_SCHEMA,
            "threshold": 1,
        }
        self.policy_path.write_bytes(lifecycle.canonical_bytes(self.policy))
        self.policy_path.chmod(0o600)
        self.store = lifecycle.HarnessStore(
            self.state, self.policy_path, now=lambda: self.current_time,
        )

    def _revoke_leaf(self) -> None:
        self.policy["revoked_signer_key_ids"] = [self.leaf_key_id]
        self.policy_path.write_bytes(lifecycle.canonical_bytes(self.policy))
        self.policy_path.chmod(0o600)

    @staticmethod
    def _keypair(private: Path, public: Path) -> None:
        subprocess.run(
            [str(lifecycle.DEFAULT_OPENSSL), "genpkey", "-algorithm", "ED25519",
             "-out", str(private)], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
        subprocess.run(
            [str(lifecycle.DEFAULT_OPENSSL), "pkey", "-in", str(private),
             "-pubout", "-out", str(public)], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
        private.chmod(0o600); public.chmod(0o600)

    def _sign(self, private: Path, payload: bytes, name: str) -> str:
        payload_path = self.root / f".{name}.payload"
        signature_path = self.root / f".{name}.signature"
        payload_path.write_bytes(payload); payload_path.chmod(0o600)
        try:
            subprocess.run(
                [str(lifecycle.DEFAULT_OPENSSL), "pkeyutl", "-sign", "-inkey",
                 str(private), "-rawin", "-in", str(payload_path), "-out",
                 str(signature_path)], check=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
            return base64.b64encode(signature_path.read_bytes()).decode("ascii")
        finally:
            payload_path.unlink(missing_ok=True); signature_path.unlink(missing_ok=True)

    def manifest(self, *, sequence: int = 1, version: str = "1.0.0",
                 inconsistent: bool = False) -> dict[str, Any]:
        artifact_sha = hashlib.sha256(self.artifact).hexdigest()
        subject = "f" * 64 if inconsistent else artifact_sha
        value = {
            "adapter_id": "claude-core-v1",
            "artifact": {
                "filename": "fixture-linux-arm64", "media_type": "application/octet-stream",
                "sha256": artifact_sha, "size": len(self.artifact),
                "url": "https://downloads.example.com/fixture-linux-arm64",
            },
            "compatibility": {
                "adapter_sha256": "a" * 64,
                "controller_schema": "harness-controller-v1",
            },
            "evidence": [
                {"kind": "vendor-signature", "media_type": "application/octet-stream",
                 "required": True, "sha256": "b" * 64, "subject_sha256": subject},
                {"kind": "vendor-checksum-manifest", "media_type": "application/json",
                 "required": True, "sha256": "c" * 64, "subject_sha256": artifact_sha},
            ],
            "generation_id": "0" * 64,
            "harness_id": "disposable-provenance-fixture",
            "platform": "linux-arm64", "release_sequence": sequence,
            "schema": lifecycle.MANIFEST_SCHEMA,
            "vendor_id": "secure-sandbox-fixture", "version": version,
        }
        value["generation_id"] = lifecycle.generation_identity(value)
        return value

    def certificate(self, *, revoked_at: int | None = None,
                    not_before: int | None = None, not_after: int | None = None,
                    broken: bool = False) -> dict[str, Any]:
        value = {
            "algorithm": "ed25519", "issuer_key_id": self.root_key_id,
            "not_after": self.current_time + 3600 if not_after is None else not_after,
            "not_before": self.current_time - 3600 if not_before is None else not_before,
            "revoked_at": revoked_at,
            "schema": lifecycle.SIGNER_CERTIFICATE_SCHEMA,
            "subject_key_id": self.leaf_key_id,
            "subject_public_key_pem": self.leaf_pem,
        }
        signature = bytearray(base64.b64decode(self._sign(
            self.root_private, lifecycle.canonical_bytes(value), "certificate",
        )))
        if broken:
            signature[0] ^= 1
        value["signature"] = base64.b64encode(signature).decode("ascii")
        return value

    def envelope(self, *, sequence: int = 1, manifest: dict[str, Any] | None = None,
                 expires_at: int | None = None, published_at: int | None = None,
                 certificate: dict[str, Any] | None = None,
                 bad_signature: bool = False, unknown_signer: bool = False) -> bytes:
        signed = {
            "expires_at": self.current_time + 3600 if expires_at is None else expires_at,
            "published_at": self.current_time - 10 if published_at is None else published_at,
            "releases": [self.manifest() if manifest is None else manifest],
            "schema": lifecycle.METADATA_SCHEMA, "sequence": sequence,
        }
        if unknown_signer:
            signature = self._sign(
                self.leaf_private, lifecycle.canonical_bytes(signed), "unknown-envelope",
            )
            return lifecycle.canonical_bytes({
                "schema": lifecycle.ENVELOPE_SCHEMA,
                "signatures": [{"algorithm": "ed25519", "key_id": self.leaf_key_id,
                                "signature": signature}],
                "signed": signed,
            })
        signature_bytes = bytearray(base64.b64decode(self._sign(
            self.leaf_private, lifecycle.canonical_bytes(signed), "delegated-envelope",
        )))
        if bad_signature:
            signature_bytes[0] ^= 1
        return lifecycle.canonical_bytes({
            "schema": lifecycle.ENVELOPE_V2_SCHEMA,
            "signatures": [{
                "algorithm": "ed25519",
                "certificates": [self.certificate() if certificate is None else certificate],
                "key_id": self.leaf_key_id,
                "signature": base64.b64encode(signature_bytes).decode("ascii"),
            }],
            "signed": signed,
        })

    def _acquire(self, manifest: dict[str, Any], carrier: bytes | None = None,
                 *, final_url: str | None = None) -> dict[str, Any]:
        value = self.artifact if carrier is None else carrier
        return self.store.acquire(
            manifest["generation_id"],
            opener=lambda url: Response(value, url, final_url=final_url,
                                        declared=manifest["artifact"]["size"]),
        )

    def _run_case(self, case_id: str) -> dict[str, Any]:
        manifest = self.manifest()
        if case_id == "acquire-clean-carrier":
            self.store.check_bytes(self.envelope(manifest=manifest))
            receipt = self._acquire(manifest)
            return {"result": receipt, "generation_id": manifest["generation_id"]}
        if case_id in {"reject-redirect", "reject-oversized-artifact",
                       "reject-artifact-substitution"}:
            self.store.check_bytes(self.envelope(manifest=manifest))
            before = _state_digest(self.state)
            try:
                if case_id == "reject-redirect":
                    self._acquire(manifest, final_url="https://evil.example/fixture")
                elif case_id == "reject-oversized-artifact":
                    self._acquire(manifest, self.artifact + b"x")
                else:
                    self._acquire(manifest, b"x" * len(self.artifact))
            except lifecycle.HarnessLifecycleError as error:
                return {"error": str(error), "protected_state_before_sha256": before}
        elif case_id == "reject-bad-signature":
            self.store.check_bytes(self.envelope(bad_signature=True))
        elif case_id == "reject-unknown-signer":
            self.store.check_bytes(self.envelope(unknown_signer=True))
        elif case_id == "reject-revoked-signer":
            self._revoke_leaf()
            self.store.check_bytes(self.envelope())
        elif case_id == "reject-expired-signer":
            self.store.check_bytes(self.envelope(
                certificate=self.certificate(not_after=self.current_time),
            ))
        elif case_id == "reject-broken-chain":
            self.store.check_bytes(self.envelope(certificate=self.certificate(broken=True)))
        elif case_id == "reject-stale-metadata":
            self.store.check_bytes(self.envelope(expires_at=self.current_time))
        elif case_id == "reject-future-metadata":
            self.store.check_bytes(self.envelope(
                published_at=self.current_time + lifecycle.FUTURE_SKEW_SECONDS + 1,
            ))
        elif case_id == "reject-release-rollback":
            self.store.check_bytes(self.envelope(sequence=2))
            before = _state_digest(self.state)
            try:
                self.store.check_bytes(self.envelope(sequence=1))
            except lifecycle.HarnessLifecycleError as error:
                return {"error": str(error), "protected_state_before_sha256": before}
        elif case_id == "reject-release-freeze":
            frozen = self.envelope(expires_at=self.current_time + 10)
            self.store.check_bytes(frozen)
            self.current_time += 11
            before = _state_digest(self.state)
            try:
                self.store.check_bytes(frozen)
            except lifecycle.HarnessLifecycleError as error:
                return {"error": str(error), "protected_state_before_sha256": before}
        elif case_id == "accept-release-fast-forward":
            self.store.check_bytes(self.envelope(sequence=1))
            receipt = self.store.check_bytes(self.envelope(
                sequence=2, manifest=self.manifest(sequence=2, version="1.0.1"),
            ))
            return {"result": receipt, "generation_id": None}
        elif case_id == "reject-release-equivocation":
            self.store.check_bytes(self.envelope(sequence=1))
            before = _state_digest(self.state)
            try:
                self.store.check_bytes(self.envelope(
                    sequence=1, manifest=self.manifest(sequence=2, version="1.0.1"),
                ))
            except lifecycle.HarnessLifecycleError as error:
                return {"error": str(error), "protected_state_before_sha256": before}
        elif case_id == "reject-inconsistent-provenance":
            self.store.check_bytes(self.envelope(manifest=self.manifest(inconsistent=True)))
        else:
            raise ProvenanceFixtureError("provenance_fixture_case_invalid")
        raise ProvenanceFixtureError("provenance_fixture_case_did_not_reject")

    def run(self, case_id: str) -> dict[str, Any]:
        if case_id not in PROVENANCE_CASES:
            raise ProvenanceFixtureError("provenance_fixture_case_invalid")
        self.store.prepare()
        before = _state_digest(self.state)
        try:
            outcome = self._run_case(case_id)
        except lifecycle.HarnessLifecycleError as error:
            outcome = {"error": str(error)}
        after = _state_digest(self.state)
        expected = CASE_BY_ID[case_id].expected
        if expected == "rejected":
            error = outcome.get("error")
            if error != EXPECTED_ERRORS[case_id]:
                raise ProvenanceFixtureError("provenance_fixture_rejection_mismatch")
            protected_before = outcome.get("protected_state_before_sha256", before)
            if protected_before != after:
                raise ProvenanceFixtureError("provenance_fixture_state_changed")
            status = "rejected"
        else:
            if "result" not in outcome:
                raise ProvenanceFixtureError("provenance_fixture_success_missing")
            status = "verified"
        return {
            "schema": SCHEMA, "status": status, "case_id": case_id,
            "expected": expected, "observed_error": outcome.get("error"),
            "result": outcome.get("result"),
            "generation_id": outcome.get("generation_id"),
            "protected_state_before_sha256": outcome.get(
                "protected_state_before_sha256", before,
            ),
            "protected_state_after_sha256": after,
            "state": self.store.status(),
            "candidate_authority": "none", "production_material_used": False,
        }
