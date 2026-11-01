#!/usr/bin/env python3
"""Disposable-only synthetic activation fixture for physical recovery testing.

This module reuses the production generation-store implementation against an
isolated campaign workspace.  It has no production store path, admission API,
network client, credential input, or authorization broker integration.
"""

from __future__ import annotations

import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Callable

import harness_generation_store as store_module
import harness_lifecycle as lifecycle
from harness_lifecycle_acceptance import CASE_BY_ID, digest, validate_campaign


FIXTURE_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-recovery-fixture-v1"
CHECKPOINT_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-checkpoint-v1"
RECOVERY_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-recovery-v1"
RECOVERY_CASES = frozenset(
    case.case_id for case in CASE_BY_ID.values() if case.category == "recovery"
)


class AcceptanceFixtureError(RuntimeError):
    """Stable failure for the disposable recovery fixture."""


def canonical(value: object) -> bytes:
    return store_module.canonical_bytes(value)


def _write_new(path: Path, value: dict) -> None:
    payload = canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AcceptanceFixtureError("fixture_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _trusted_root(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise AcceptanceFixtureError("fixture_root_untrusted")


def _trusted_json(path: Path) -> dict:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 64 * 1024):
        raise AcceptanceFixtureError("fixture_metadata_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= 64 * 1024:
            chunk = os.read(descriptor, min(65536, 64 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > 64 * 1024):
        raise AcceptanceFixtureError("fixture_metadata_changed")
    raw = bytes(data)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceFixtureError("fixture_metadata_invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AcceptanceFixtureError("fixture_metadata_noncanonical")
    return value


class PassingProbe:
    def probe(self, plan: dict, executable: Path) -> dict:
        if executable.name != "harness":
            raise AcceptanceFixtureError("fixture_executable_invalid")
        value = {
            "schema": store_module.HEALTH_SCHEMA,
            "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "generation_id": plan["candidate"]["generation_id"],
            "artifact_sha256": plan["candidate"]["artifact_sha256"],
            "adapter_sha256": plan["candidate"]["adapter_sha256"],
            "health_probe_sha256": plan["candidate"]["health_probe_sha256"],
            "observer": "secure-sandbox-fixed-health-supervisor-v1",
            "synthetic": True,
            "production_credential_present": False,
            "network_attempts": [],
            "status": "passed",
        }
        value["health_sha256"] = store_module.sha256_value(value)
        return value


class RecoveryFixture:
    def __init__(self, root: Path, campaign: dict, case_id: str,
                 *, now: Callable[[], int] | None = None) -> None:
        if case_id not in RECOVERY_CASES:
            raise AcceptanceFixtureError("fixture_case_invalid")
        self.root = root
        self.case_id = case_id
        self.checkpoint = case_id.split("-loss-", 1)[1]
        self.now = now or (lambda: int(time.time()))
        self.campaign = validate_campaign(campaign, self.now())
        self.sources = root / "sources"
        self.metadata_path = root / "fixture.json"
        self.checkpoint_path = root / "checkpoint.json"
        self.store = store_module.GenerationStore(
            root / "release-root", root / "state", now=self.now,
        )

    @staticmethod
    def _uuid() -> str:
        return str(uuid.uuid4())

    def _write_json(self, path: Path, value: dict) -> None:
        _write_new(path, value)

    def _candidate(self, sequence: int, version: str) -> dict[str, Path]:
        directory = self.sources / f"candidate-{sequence}"
        directory.mkdir(mode=0o700)
        artifact = f"#!/bin/sh\necho disposable-harness-{version}\n".encode("ascii")
        artifact_sha = store_module.sha256_bytes(artifact)
        adapter_sha = store_module.sha256_bytes(f"adapter-{version}".encode("ascii"))
        policy_sha = store_module.sha256_bytes(b"disposable-policy-v1")
        evidence_sha = store_module.sha256_bytes(f"evidence-{version}".encode("ascii"))
        manifest = {
            "schema": lifecycle.MANIFEST_SCHEMA,
            "adapter_id": "claude-core-v1",
            "harness_id": "disposable-synthetic-harness",
            "vendor_id": "secure-sandbox-fixture",
            "version": version,
            "platform": "linux-arm64",
            "release_sequence": sequence,
            "artifact": {
                "filename": "fixture", "media_type": "application/octet-stream",
                "sha256": artifact_sha, "size": len(artifact),
                "url": f"https://invalid.example/disposable-{version}",
            },
            "compatibility": {
                "adapter_sha256": adapter_sha,
                "controller_schema": "harness-controller-v1",
            },
            "evidence": [{
                "kind": "fixture-signature", "media_type": "application/json",
                "required": True, "sha256": evidence_sha,
                "subject_sha256": artifact_sha,
            }],
        }
        manifest["generation_id"] = lifecycle.generation_identity(manifest)
        manifest_raw = canonical(manifest)
        manifest_sha = store_module.sha256_bytes(manifest_raw)
        observed_at = self.now()
        verification = {
            "action": "verify", "observed_at": observed_at,
            "receipt_id": self._uuid(), "schema": lifecycle.RECEIPT_SCHEMA,
            "status": "artifact_and_evidence_bindings_verified",
            "artifact_sha256": artifact_sha, "envelope_sha256": "e" * 64,
            "evidence_sha256": [evidence_sha],
            "generation_id": manifest["generation_id"],
            "manifest_sha256": manifest_sha,
            "note": "not_admitted_not_executable", "policy_sha256": policy_sha,
        }
        adapter = {
            "schema": store_module.ADAPTER_SCHEMA, "adapter_id": "claude-core-v1",
            "adapter_sha256": adapter_sha,
            "harness_id": "disposable-synthetic-harness",
            "executable_name": "harness",
            "protocol": "secure-sandbox-neutral-harness-v1",
            "policy_sha256": policy_sha, "authority": "none",
            "health_probe_sha256": "9" * 64,
        }
        adapter["projection_sha256"] = store_module.sha256_value(adapter)
        qualification = {
            "schema": store_module.QUALIFICATION_SCHEMA,
            "qualification_id": self._uuid(),
            "generation_id": manifest["generation_id"],
            "artifact_sha256": artifact_sha, "manifest_sha256": manifest_sha,
            "adapter_id": "claude-core-v1", "adapter_sha256": adapter_sha,
            "suite_sha256": "a" * 64, "policy_sha256": policy_sha,
            "observer": "secure-sandbox-disposable-supervisor-v1",
            "observation_set_sha256": "b" * 64,
            "qualified_at": observed_at, "expires_at": observed_at + 86400,
            "synthetic": False, "status": "qualified",
            "authority": "qualification-evidence-only",
        }
        qualification["qualification_sha256"] = store_module.sha256_value(qualification)
        paths = {name: directory / name for name in (
            "artifact", "manifest.json", "verification.json", "qualification.json",
            "adapter.json",
        )}
        paths["artifact"].write_bytes(artifact)
        paths["artifact"].chmod(0o600)
        paths["manifest.json"].write_bytes(manifest_raw)
        paths["manifest.json"].chmod(0o600)
        for name, value in (("verification.json", verification),
                            ("qualification.json", qualification),
                            ("adapter.json", adapter)):
            self._write_json(paths[name], value)
        return paths

    def _plan(self, paths: dict[str, Path]) -> dict:
        return self.store.create_plan(
            paths["manifest.json"], paths["artifact"], paths["verification.json"],
            paths["qualification.json"], paths["adapter.json"], now=self.now(),
        )

    def _authorization(self, plan: dict) -> dict:
        current = self.now()
        value = {
            "schema": store_module.AUTHORIZATION_SCHEMA,
            "authorization_id": self._uuid(), "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"], "operation": plan["operation"],
            "method": "touch-id", "password_fallback": False,
            "authorized_at": current, "expires_at": current + 120,
            "requesting_agent_sha256": "c" * 64,
            "requesting_session_sha256": "d" * 64,
        }
        value["authorization_sha256"] = store_module.sha256_value(value)
        return value

    def _activate(self, paths: dict[str, Path], plan: dict, authorization: dict) -> dict:
        return self.store.activate(
            plan, authorization, paths["manifest.json"], paths["artifact"],
            paths["verification.json"], paths["qualification.json"], paths["adapter.json"],
            PassingProbe(), runtime_idle=lambda: True, now=self.now(),
        )

    def _metadata(self, phase: str, **fields: object) -> dict:
        value = {
            "schema": FIXTURE_SCHEMA, "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "source_commit": self.campaign["source_commit"], "case_id": self.case_id,
            "checkpoint": self.checkpoint, "phase": phase,
            "candidate_authority": "none", "production_material_used": False,
            **fields,
        }
        value["fixture_sha256"] = digest(value)
        return value

    def _replace_metadata(self, value: dict) -> None:
        temporary = self.root / f".fixture-{self._uuid()}.json"
        _write_new(temporary, value)
        os.replace(temporary, self.metadata_path)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def run(self, reached: Callable[[str], None]) -> None:
        _trusted_root(self.root, create=True)
        self.sources.mkdir(mode=0o700)
        baseline = self._candidate(1, "1.0.0")
        baseline_plan = self._plan(baseline)
        self._activate(baseline, baseline_plan, self._authorization(baseline_plan))
        baseline_id = self.store.status()["active_generation_id"]
        target = self._candidate(2, "2.0.0")
        metadata = self._metadata("stage-created", baseline_generation_id=baseline_id,
                                  target_generation_id=json.loads(
                                      target["manifest.json"].read_text())["generation_id"])
        self._write_json(self.metadata_path, metadata)
        if self.checkpoint == "stage-created":
            reached("stage-created")
            raise AcceptanceFixtureError("checkpoint_callback_returned")
        plan = self._plan(target)
        authorization = self._authorization(plan)
        self._write_json(self.root / "plan.json", plan)
        self._write_json(self.root / "authorization.json", authorization)
        self._replace_metadata(self._metadata(
            "plan-written", baseline_generation_id=baseline_id,
            target_generation_id=plan["candidate"]["generation_id"],
            plan_sha256=plan["plan_sha256"],
        ))
        if self.checkpoint == "plan-written":
            reached("plan-written")
            raise AcceptanceFixtureError("checkpoint_callback_returned")

        def store_checkpoint(name: str) -> None:
            if name == self.checkpoint:
                self._replace_metadata(self._metadata(
                    "checkpoint-reached", baseline_generation_id=baseline_id,
                    target_generation_id=plan["candidate"]["generation_id"],
                    plan_sha256=plan["plan_sha256"],
                ))
                reached(name)
                raise AcceptanceFixtureError("checkpoint_callback_returned")

        self.store.checkpoint = store_checkpoint
        self._activate(target, plan, authorization)
        raise AcceptanceFixtureError("fixture_checkpoint_not_reached")

    def recover(self) -> dict:
        _trusted_root(self.root)
        if not self.metadata_path.is_file():
            raise AcceptanceFixtureError("fixture_metadata_missing")
        metadata = _trusted_json(self.metadata_path)
        if (not isinstance(metadata, dict) or metadata.get("schema") != FIXTURE_SCHEMA
                or metadata.get("campaign_id") != self.campaign["campaign_id"]
                or metadata.get("campaign_sha256") != self.campaign["campaign_sha256"]
                or metadata.get("case_id") != self.case_id
                or metadata.get("checkpoint") != self.checkpoint
                or metadata.get("candidate_authority") != "none"
                or metadata.get("production_material_used") is not False
                or metadata.get("fixture_sha256") != digest({
                    key: value for key, value in metadata.items() if key != "fixture_sha256"
                })):
            raise AcceptanceFixtureError("fixture_metadata_invalid")
        journals = list(self.store.journals.iterdir()) if self.store.journals.exists() else []
        if journals:
            recovery = self.store.recover(now=self.now())
            recovery_result = recovery["status"]
        elif self.checkpoint in {"stage-created", "plan-written"}:
            recovery_result = "pre-transaction-loss-safe"
        elif self.checkpoint == "journal-removed":
            recovery_result = "committed-readback"
        else:
            raise AcceptanceFixtureError("fixture_recovery_state_invalid")
        status = self.store.status()
        boundary = self.store.verify_boundary()
        if (status["admission"] != "open" or status["recovery_pending"] is not False
                or boundary.get("status") != "verified"):
            raise AcceptanceFixtureError("fixture_recovery_postcondition_invalid")
        value = {
            "schema": RECOVERY_SCHEMA, "status": "recovered",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "case_id": self.case_id, "checkpoint": self.checkpoint,
            "recovery_result": recovery_result,
            "active_generation_id": status["active_generation_id"],
            "boundary_sha256": store_module.sha256_value(boundary),
            "boundary": boundary,
            "candidate_authority": "none", "production_material_used": False,
        }
        value["recovery_sha256"] = digest(value)
        return value
