#!/usr/bin/env python3
"""Immutable, content-free receipts minted by trusted instrument identities."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import syslog
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "secure-sandbox-evidence-receipt-v3"
V2_SCHEMA = "secure-sandbox-evidence-receipt-v2"
LEGACY_SCHEMA = "secure-sandbox-evidence-receipt-v1"
REGISTRY = Path("/var/lib/secure-sandbox/evidence-receipts")
RUN_ID_FILE = Path("/run/secure-sandbox/run-id")
LIFECYCLE_FILE = Path("/var/lib/secure-sandbox/run-lifecycle/active.json")
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TEMP_RE = re.compile(r"^\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([1-9][0-9]*)\.new$")
FINAL_RE = re.compile(r"^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json$")
MAX_RECEIPTS = 4096
MAX_RECEIPTS_PER_RUN = 256
MAX_RECEIPT_BYTES = 4096
PRODUCERS = {
    "corpus-broker": ("corpus", "exhaustive_corpus_search"),
    "execution-broker": ("execution", "measured_execution"),
}


class ReceiptError(ValueError): pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def active_run(path: Path = RUN_ID_FILE, trusted_uid: int = 0,
               lifecycle_path: Path | None = None) -> str:
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != trusted_uid or info.st_mode & 0o022):
            raise ReceiptError("active_run_untrusted")
        value = path.read_text(encoding="utf-8").strip()
    except OSError as error: raise ReceiptError("active_run_required") from error
    if not UUID4_RE.fullmatch(value): raise ReceiptError("active_run_required")
    lifecycle_path = LIFECYCLE_FILE if lifecycle_path is None and path == RUN_ID_FILE else lifecycle_path
    if lifecycle_path is not None:
        try:
            info = lifecycle_path.lstat()
            lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != trusted_uid
                    or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1
                    or lifecycle.get("schema") != "secure-sandbox-run-lifecycle-v2"
                    or lifecycle.get("phase") != "active" or lifecycle.get("run_id") != value):
                raise ReceiptError("active_run_required")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise ReceiptError("active_run_required") from error
    return value


def request_hash(instrument: str, arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({"instrument": instrument, "arguments": arguments})).hexdigest()


def _validate_projection(evidence_class: str, value: dict[str, Any], schema: str = SCHEMA) -> None:
    if evidence_class == "exhaustive_corpus_search":
        expected = {"source_id", "instrument", "run_id", "request_sha256", "result_set_sha256", "exhaustive"}
        instruments = {"search_corpus", "scan_corpus"}
        if set(value) != expected or value.get("instrument") not in instruments or value.get("exhaustive") is not True:
            raise ReceiptError("receipt_projection_invalid")
        hashes = (value.get("request_sha256"), value.get("result_set_sha256"))
    elif evidence_class == "measured_execution":
        expected = {"source_id", "request_id", "run_id", "code_sha256", "stdout_sha256", "fixture_manifest_sha256", "image_digest"}
        if schema in {SCHEMA, V2_SCHEMA}:
            expected |= {"stderr_sha256", "exit_code", "timed_out", "output_limit_exceeded", "stdout_truncated", "stderr_truncated"}
        if schema == SCHEMA:
            expected |= {"timeout_seconds", "duration_ms"}
        if set(value) != expected or not str(value.get("image_digest", "")).startswith("sha256:"):
            raise ReceiptError("receipt_projection_invalid")
        hashes = [value.get("code_sha256"), value.get("stdout_sha256"), value.get("fixture_manifest_sha256"), str(value.get("image_digest"))[7:]]
        if schema in {SCHEMA, V2_SCHEMA}:
            hashes.append(value.get("stderr_sha256"))
            if (not isinstance(value.get("exit_code"), int) or isinstance(value.get("exit_code"), bool)
                    or not -255 <= value["exit_code"] <= 255
                    or any(not isinstance(value.get(name), bool) for name in
                           ("timed_out", "output_limit_exceeded", "stdout_truncated", "stderr_truncated"))):
                raise ReceiptError("receipt_projection_invalid")
        if schema == SCHEMA and (not isinstance(value.get("timeout_seconds"), int)
                or isinstance(value.get("timeout_seconds"), bool) or not 1 <= value["timeout_seconds"] <= 10
                or not isinstance(value.get("duration_ms"), int) or isinstance(value.get("duration_ms"), bool)
                or not 0 <= value["duration_ms"] <= 120_000):
            raise ReceiptError("receipt_projection_invalid")
        if not UUID4_RE.fullmatch(str(value.get("request_id", ""))): raise ReceiptError("receipt_projection_invalid")
    else: raise ReceiptError("receipt_class_invalid")
    if not UUID4_RE.fullmatch(str(value.get("source_id", ""))) or not UUID4_RE.fullmatch(str(value.get("run_id", ""))):
        raise ReceiptError("receipt_projection_invalid")
    if any(not SHA256_RE.fullmatch(str(item)) for item in hashes): raise ReceiptError("receipt_projection_invalid")


def _receipt_gid() -> int:
    import grp
    try: return grp.getgrnam("evidence-receipts").gr_gid
    except KeyError as error: raise ReceiptError("receipt_group_unavailable") from error


def _safe_directory(path: Path, owner_uid: int, group_gid: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner_uid or info.st_gid != group_gid or info.st_mode & 0o027):
        raise ReceiptError("receipt_state_untrusted")


def _validate_record_value(record: object, receipt_id: str, producer: str, expected_hash: str | None = None) -> dict[str, Any]:
    if (not isinstance(record,dict) or record.get("schema") not in {SCHEMA, V2_SCHEMA, LEGACY_SCHEMA} or record.get("receipt_id") != receipt_id
            or record.get("producer") != producer or record.get("evidence_class") != PRODUCERS[producer][1]):
        raise ReceiptError("receipt_invalid")
    recorded=record.get("content_sha256"); unsigned=dict(record); unsigned.pop("content_sha256",None)
    if (expected_hash is not None and recorded != expected_hash) or recorded != hashlib.sha256(canonical(unsigned)).hexdigest():
        raise ReceiptError("receipt_invalid")
    evidence=record.get("evidence")
    if not isinstance(evidence,dict): raise ReceiptError("receipt_invalid")
    _validate_projection(record["evidence_class"],evidence,record["schema"])
    if ((record["evidence_class"] == "exhaustive_corpus_search" and record.get("instrument") != evidence["instrument"])
            or (record["evidence_class"] == "measured_execution" and record.get("instrument") != "run_python_fixture")):
        raise ReceiptError("receipt_invalid")
    return record


def publish(
    producer: str, instrument: str, projection: dict[str, Any], registry: Path = REGISTRY,
    owner_uid: int | None = None, group_gid: int | None = None, root_uid: int = 0,
) -> dict[str, Any]:
    if producer not in PRODUCERS or PRODUCERS[producer][1] != projection.get("class"):
        raise ReceiptError("receipt_producer_invalid")
    evidence_class = projection["class"]
    evidence = {key: value for key, value in projection.items() if key != "class"}
    _validate_projection(evidence_class, evidence)
    if ((evidence_class == "exhaustive_corpus_search" and evidence["instrument"] != instrument)
            or (evidence_class == "measured_execution" and instrument != "run_python_fixture")):
        raise ReceiptError("receipt_instrument_invalid")
    directory = registry / PRODUCERS[producer][0]
    owner = os.geteuid() if owner_uid is None else owner_uid
    group = _receipt_gid() if group_gid is None else group_gid
    _safe_directory(registry, root_uid, group)
    _safe_directory(directory, owner, group)
    changed=False
    for entry in list(directory.iterdir()):
        info=entry.lstat()
        if TEMP_RE.fullmatch(entry.name):
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != owner or info.st_gid != group or info.st_mode & 0o027):
                raise ReceiptError("receipt_state_untrusted")
            entry.unlink(); changed=True
    if changed:
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
    finals = 0; run_receipts = 0; duplicate = None
    for entry in directory.iterdir():
        info=entry.lstat()
        if (not FINAL_RE.fullmatch(entry.name) or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1 or info.st_uid != owner or info.st_gid != group
                or info.st_mode & 0o027 or info.st_size > MAX_RECEIPT_BYTES):
            raise ReceiptError("receipt_state_untrusted")
        try: existing=json.loads(entry.read_text(encoding="utf-8"))
        except (OSError,ValueError,json.JSONDecodeError) as error: raise ReceiptError("receipt_state_untrusted") from error
        try: existing = _validate_record_value(existing,entry.stem,producer)
        except ReceiptError as error: raise ReceiptError("receipt_state_untrusted") from error
        finals += 1
        if existing["evidence"].get("run_id") == evidence.get("run_id"): run_receipts += 1
        if (existing.get("instrument") == instrument and existing.get("evidence_class") == evidence_class
                and existing.get("evidence") == evidence): duplicate = existing
    if duplicate is not None:
        try:
            syslog.openlog("secure-sandbox-evidence-receipts",syslog.LOG_PID,syslog.LOG_AUTHPRIV)
            syslog.syslog(syslog.LOG_INFO,canonical({"event":"receipt_reused","instrument":instrument,
                "receipt_id":duplicate["receipt_id"],"status":"ok"}).decode())
        except Exception: pass
        return {"class":evidence_class,"receipt_id":duplicate["receipt_id"],
                "receipt_sha256":duplicate["content_sha256"],**evidence}
    if run_receipts >= MAX_RECEIPTS_PER_RUN: raise ReceiptError("receipt_run_limit_exceeded")
    if finals >= MAX_RECEIPTS: raise ReceiptError("receipt_state_limit_exceeded")
    receipt_id = str(uuid.uuid4())
    record = {"schema":SCHEMA,"receipt_id":receipt_id,"producer":producer,
              "instrument":instrument,"evidence_class":evidence_class,"produced_at":now(),"evidence":evidence}
    record["content_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    final = directory / f"{receipt_id}.json"; temporary = directory / f".{receipt_id}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(descriptor,"wb") as handle:
            handle.write(canonical(record)+b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.link(temporary, final, follow_symlinks=False)
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
        temporary.unlink(); fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)
    except Exception:
        try: temporary.unlink()
        except OSError: pass
        raise
    try:
        syslog.openlog("secure-sandbox-evidence-receipts",syslog.LOG_PID,syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO,canonical({"event":"receipt_published","instrument":instrument,
            "receipt_id":receipt_id,"status":"ok"}).decode())
    except Exception: pass
    return {"class":evidence_class,"receipt_id":receipt_id,"receipt_sha256":record["content_sha256"],**evidence}


def load_projection(
    receipt_id: str, receipt_sha256: str, producer: str, registry: Path = REGISTRY,
    root_uid: int = 0, producer_uid: int | None = None, group_gid: int | None = None,
) -> dict[str, Any]:
    if not UUID4_RE.fullmatch(str(receipt_id)) or not SHA256_RE.fullmatch(str(receipt_sha256)) or producer not in PRODUCERS:
        raise ReceiptError("receipt_invalid")
    group = _receipt_gid() if group_gid is None else group_gid
    _safe_directory(registry, root_uid, group)
    directory = registry / PRODUCERS[producer][0]
    if producer_uid is None:
        import pwd
        producer_uid = pwd.getpwnam(producer).pw_uid
    _safe_directory(directory, producer_uid, group)
    path = directory / f"{receipt_id}.json"
    try:
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1
                or info.st_uid != producer_uid or info.st_gid != group or info.st_mode & 0o027
                or info.st_size > MAX_RECEIPT_BYTES):
            raise ReceiptError("receipt_untrusted")
        record=json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error: raise ReceiptError("receipt_unavailable") from error
    record=_validate_record_value(record,receipt_id,producer,receipt_sha256)
    recorded=record["content_sha256"]; evidence=record["evidence"]
    return {"class":record["evidence_class"],"receipt_id":receipt_id,"receipt_sha256":recorded,**evidence}
