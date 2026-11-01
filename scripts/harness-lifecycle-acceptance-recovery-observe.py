#!/usr/bin/env python3
"""Project one verified recovery-supervisor artifact set into observations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
    validate_observation,
)


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-recovery-projection-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-recovery-projection-error-v1"
MEDIA_TYPE = "application/json"
RAW_FILES = {
    "fault-injection-receipt": "fault-injection-receipt.json",
    "cold-boot-readback": "cold-boot-readback.json",
    "recovery-receipt": "recovery-receipt.json",
    "boundary-readback": "boundary-readback.json",
}
AUTHORITIES = {
    "fault-injection-receipt": "disposable-supervisor",
    "cold-boot-readback": "cold-boot-supervisor",
    "recovery-receipt": "protected-research",
    "boundary-readback": "privileged-control",
}
SUPPORT = {
    "fault-injection-receipt": (),
    "cold-boot-readback": ("fault-injection-receipt",),
    "recovery-receipt": ("fault-injection-receipt",),
    "boundary-readback": ("recovery-receipt",),
}


class ProjectionError(RuntimeError):
    """Stable, content-free projection failure."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ProjectionError("recovery_projection_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_supervisor_projection",
    ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
)
OBSERVER = load_script(
    "harness_lifecycle_acceptance_observer_projection",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)


def private_directory(path: Path, label: str) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ProjectionError(f"{label}_untrusted")


def raw_artifacts(path: Path, expected_kinds: list[str]) -> dict[str, Path]:
    private_directory(path, "recovery_raw_directory")
    expected = {RAW_FILES[kind] for kind in expected_kinds}
    entries = {item.name: item for item in path.iterdir()}
    if set(entries) != expected:
        raise ProjectionError("recovery_raw_inventory_invalid")
    return {kind: entries[RAW_FILES[kind]] for kind in expected_kinds}


def trusted_json(path: Path) -> dict[str, Any]:
    try:
        return SUPERVISOR.trusted_json(path)
    except SUPERVISOR.SupervisorError as error:
        raise ProjectionError("recovery_raw_artifact_untrusted") from error


def validate_raw_set(campaign: dict[str, Any], case: dict[str, Any],
                     paths: dict[str, Path]) -> dict[str, bytes]:
    try:
        fault = trusted_json(paths["fault-injection-receipt"])
        checkpoint = SUPERVISOR.validate_fault(campaign, case, fault)
        recovery_result = trusted_json(paths["recovery-receipt"])
        _, boundary = SUPERVISOR.validate_recovery(
            campaign, case, checkpoint, recovery_result,
        )
        boundary_readback = trusted_json(paths["boundary-readback"])
    except SUPERVISOR.SupervisorError as error:
        raise ProjectionError("recovery_raw_binding_invalid") from error
    if boundary_readback != boundary:
        raise ProjectionError("recovery_boundary_readback_mismatch")
    values = {
        "fault-injection-receipt": fault,
        "recovery-receipt": recovery_result,
        "boundary-readback": boundary_readback,
    }
    if "cold-boot-readback" in paths:
        cold_boot = trusted_json(paths["cold-boot-readback"])
        try:
            SUPERVISOR.validate_cold_boot(
                campaign, case, checkpoint, cold_boot,
            )
        except SUPERVISOR.SupervisorError as error:
            raise ProjectionError("recovery_raw_binding_invalid") from error
        if (cold_boot["vm_stopped"] != fault["vm_stopped"]
                or cold_boot["vm_restarted"] != fault["vm_restarted"]):
            raise ProjectionError("recovery_cold_boot_fault_mismatch")
        values["cold-boot-readback"] = cold_boot
    return {kind: canonical(values[kind]) for kind in paths}


def existing_observation(path: Path, campaign: dict[str, Any], case: dict[str, Any],
                         kind: str, raw_values: dict[str, bytes]) -> str:
    try:
        raw = OBSERVER.trusted_read(path)
        value = json.loads(raw)
    except (AcceptanceError, OSError, UnicodeDecodeError,
            json.JSONDecodeError) as error:
        raise ProjectionError("recovery_existing_observation_invalid") from error
    expected_artifacts = [kind, *SUPPORT[kind]]
    evidence = value.get("evidence") if isinstance(value, dict) else None
    artifacts = evidence.get("artifacts") if isinstance(evidence, dict) else None
    if (not isinstance(value, dict) or canonical(value) != raw
            or value.get("kind") != kind
            or value.get("source_commit") != campaign["source_commit"]
            or not isinstance(artifacts, list)
            or [item.get("name") for item in artifacts
                if isinstance(item, dict)] != expected_artifacts
            or any(
                not isinstance(item, dict)
                or item.get("authority") != AUTHORITIES[item_kind]
                or item.get("sha256")
                   != hashlib.sha256(raw_values[item_kind]).hexdigest()
                for item, item_kind in zip(artifacts, expected_artifacts)
            )):
        raise ProjectionError("recovery_existing_observation_mismatch")
    try:
        validate_observation(value, campaign, CASE_BY_ID[case["case_id"]])
    except AcceptanceError as error:
        raise ProjectionError("recovery_existing_observation_invalid") from error
    return value["observation_sha256"]


def artifact_arguments(kind: str, paths: dict[str, Path]) -> list[list[str]]:
    kinds = (kind, *SUPPORT[kind])
    return [
        [item, AUTHORITIES[item], str(paths[item]), MEDIA_TYPE]
        for item in kinds
    ]


def write_snapshot(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProjectionError("recovery_snapshot_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_staged(staged: Path, destination: Path) -> None:
    value = trusted_json(staged)
    try:
        OBSERVER.write_new(destination, value)
    except (AcceptanceError, OSError) as error:
        raise ProjectionError("recovery_observation_publication_failed") from error


def project(campaign_path: Path, observations: Path, case_id: str,
            raw_directory: Path, now: int) -> dict[str, Any]:
    try:
        campaign = validate_campaign(trusted_json(campaign_path), now)
    except (AcceptanceError, ProjectionError) as error:
        raise ProjectionError("recovery_campaign_invalid") from error
    try:
        SUPERVISOR.verify_source_checkout(campaign)
        machine_identity = SUPERVISOR.current_machine_identity()
        case = SUPERVISOR.next_recovery_case(campaign_path, observations, case_id)
    except SUPERVISOR.SupervisorError as error:
        raise ProjectionError("recovery_projection_preflight_failed") from error
    if machine_identity != campaign["machine_identity_sha256"]:
        raise ProjectionError("recovery_machine_identity_mismatch")
    expected_kinds = list(case["evidence_kinds"])
    if set(expected_kinds) != set(RAW_FILES) - (
            set() if case["procedure"]["interaction"]
            == "supervisor-research-vm-hard-power" else {"cold-boot-readback"}
    ):
        raise ProjectionError("recovery_case_evidence_inventory_invalid")
    paths = raw_artifacts(raw_directory, expected_kinds)
    primary_bytes = validate_raw_set(campaign, case, paths)
    private_directory(observations, "recovery_observation_directory")

    existing: dict[str, str] = {}
    missing: list[str] = []
    for kind in expected_kinds:
        destination = observations / f"{case_id}.{kind}.json"
        if os.path.lexists(destination):
            existing[kind] = existing_observation(
                destination, campaign, case, kind, primary_bytes,
            )
        else:
            missing.append(kind)

    projected: dict[str, str] = dict(existing)
    with tempfile.TemporaryDirectory(
            prefix="secure-sandbox-recovery-projection.") as temporary:
        stage = Path(temporary)
        stage.chmod(0o700)
        snapshot_directory = stage / "raw"
        staged_observations = stage / "observations"
        snapshot_directory.mkdir(mode=0o700)
        staged_observations.mkdir(mode=0o700)
        snapshot_paths: dict[str, Path] = {}
        for kind, raw in primary_bytes.items():
            snapshot = snapshot_directory / RAW_FILES[kind]
            write_snapshot(snapshot, raw)
            snapshot_paths[kind] = snapshot
        for kind in missing:
            result = OBSERVER.observe(
                campaign=campaign, case_id=case_id, kind=kind,
                artifact_arguments=artifact_arguments(kind, snapshot_paths),
                output_directory=staged_observations, now=now,
            )
            projected[kind] = result["observation_sha256"]
        for kind in missing:
            name = f"{case_id}.{kind}.json"
            publish_staged(staged_observations / name, observations / name)

    directory = os.open(observations, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    value = {
        "schema": SCHEMA, "status": "recorded",
        "campaign_id": campaign["campaign_id"], "case_id": case_id,
        "procedure_sha256": case["procedure"]["procedure_sha256"],
        "observation_sha256": {kind: projected[kind] for kind in expected_kinds},
        "resumed_observation_kinds": [kind for kind in expected_kinds if kind in existing],
        "recorded_observation_kinds": missing,
        "candidate_authority": "none", "production_material_used": False,
    }
    value["projection_sha256"] = digest(value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Project one verified recovery artifact set into observations",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--observations", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--raw-directory", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    result = project(
        args.campaign, args.observations, args.case, args.raw_directory,
        int(time.time()),
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProjectionError, AcceptanceError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ProjectionError) \
            else "recovery_projection_failed"
        sys.stderr.buffer.write(canonical({
            "schema": ERROR_SCHEMA, "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
