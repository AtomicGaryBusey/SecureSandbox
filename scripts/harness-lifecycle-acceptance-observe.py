#!/usr/bin/env python3
"""Project bounded protected readbacks into one acceptance observation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    ARTIFACT_AUTHORITIES,
    CASE_BY_ID,
    COLLECTOR_PRIMARY_AUTHORITY,
    EVIDENCE_KIND_COLLECTOR,
    EVIDENCE_SCHEMA,
    MAX_DETAIL_BYTES,
    OBSERVATION_SCHEMA,
    TOKEN,
    canonical,
    digest,
    validate_campaign,
    validate_observation,
)


MAX_ARTIFACTS = 16


def trusted_read(path: Path) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.geteuid() or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < before.st_size <= MAX_DETAIL_BYTES):
        raise AcceptanceError("observation_artifact_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= MAX_DETAIL_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_DETAIL_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > MAX_DETAIL_BYTES):
        raise AcceptanceError("observation_artifact_changed")
    return bytes(data)


def trusted_campaign(path: Path, now: int) -> dict:
    raw = trusted_read(path)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("campaign_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AcceptanceError("campaign_json_noncanonical")
    return validate_campaign(value, now)


def trusted_output_directory(path: Path, expected_uid: int | None = None) -> None:
    info = path.lstat()
    owner = os.geteuid() if expected_uid is None else expected_uid
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700):
        raise AcceptanceError("observation_directory_untrusted")


def write_new(path: Path, value: dict, mode: int = 0o600) -> None:
    if mode not in {0o444, 0o600}:
        raise AcceptanceError("observation_mode_invalid")
    payload = canonical(value)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AcceptanceError("observation_write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode); os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def observe(*, campaign: dict, case_id: str, kind: str,
            artifact_arguments: list[list[str]], output_directory: Path, now: int,
            output_directory_uid: int | None = None,
            output_mode: int = 0o600) -> dict:
    case = CASE_BY_ID.get(case_id)
    if case is None or kind not in case.evidence_kinds:
        raise AcceptanceError("observation_case_or_kind_invalid")
    collector = EVIDENCE_KIND_COLLECTOR[kind]
    if not 1 <= len(artifact_arguments) <= MAX_ARTIFACTS:
        raise AcceptanceError("observation_artifact_inventory_invalid")
    artifacts = []
    raw_values: list[bytes] = []
    names: set[str] = set()
    for name, authority, raw_path, media_type in artifact_arguments:
        if (name in names or authority not in ARTIFACT_AUTHORITIES
                or TOKEN.fullmatch(media_type) is None):
            raise AcceptanceError("observation_artifact_argument_invalid")
        raw = trusted_read(Path(raw_path))
        names.add(name); raw_values.append(raw)
        artifacts.append({
            "name": name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            "media_type": media_type, "authority": authority,
            "content_base64": base64.b64encode(raw).decode("ascii"),
        })
    if artifacts[0]["authority"] != COLLECTOR_PRIMARY_AUTHORITY[collector]:
        raise AcceptanceError("observation_primary_authority_mismatch")
    try:
        primary = json.loads(raw_values[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("observation_primary_json_invalid") from error
    source_schema = primary.get("schema") if isinstance(primary, dict) else None
    source_status = primary.get("status") if isinstance(primary, dict) else None
    if not isinstance(source_schema, str) or TOKEN.fullmatch(source_schema) is None:
        raise AcceptanceError("observation_primary_schema_invalid")
    if not isinstance(source_status, str) or TOKEN.fullmatch(source_status) is None:
        raise AcceptanceError("observation_primary_status_invalid")
    source_sha256 = artifacts[0]["sha256"]
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "evidence_id": str(uuid.uuid4()),
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "case_id": case.case_id,
        "kind": kind,
        "collector": collector,
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"],
        "observed_at": now,
        "outcome": case.expected,
        "subject_sha256": source_sha256,
        "source_schema": source_schema,
        "source_status": source_status,
        "source_sha256": source_sha256,
        "artifacts": artifacts,
        "candidate_statement_used": False,
    }
    evidence["evidence_sha256"] = digest(evidence)
    observation = {
        "schema": OBSERVATION_SCHEMA,
        "observation_id": str(uuid.uuid4()),
        "campaign_id": campaign["campaign_id"],
        "campaign_sha256": campaign["campaign_sha256"],
        "case_id": case.case_id,
        "kind": kind,
        "collector": collector,
        "machine_identity_sha256": campaign["machine_identity_sha256"],
        "source_commit": campaign["source_commit"],
        "started_at": now,
        "completed_at": now,
        "outcome": case.expected,
        "subject_sha256": source_sha256,
        "evidence": evidence,
        "evidence_sha256": evidence["evidence_sha256"],
        "candidate_statement_used": False,
    }
    observation["observation_sha256"] = digest(observation)
    validate_observation(observation, campaign, case)
    trusted_output_directory(output_directory, output_directory_uid)
    write_new(
        output_directory / f"{case.case_id}.{kind}.json", observation,
        output_mode,
    )
    return observation


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Capture a protected acceptance readback")
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--kind", required=True)
    value.add_argument("--artifact", nargs=4, action="append", metavar=("NAME", "AUTHORITY", "PATH", "MEDIA_TYPE"), required=True)
    value.add_argument("--output-directory", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    now = int(time.time())
    campaign = trusted_campaign(args.campaign, now)
    result = observe(
        campaign=campaign, case_id=args.case, kind=args.kind,
        artifact_arguments=args.artifact, output_directory=args.output_directory, now=now,
    )
    print(json.dumps({
        "schema": "secure-sandbox-harness-lifecycle-acceptance-observation-result-v1",
        "status": "recorded", "case_id": result["case_id"], "kind": result["kind"],
        "observation_sha256": result["observation_sha256"],
    }, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, AcceptanceError) else "observation_io_failed"
        print(json.dumps({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-observation-error-v1",
            "status": "rejected", "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
