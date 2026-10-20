#!/usr/bin/env python3
"""Bounded candidate-finding submission broker for the Research VM."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import syslog
import time

from bounded_unix_server import serve as serve_bounded
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from evidence_receipts import REGISTRY as RECEIPT_REGISTRY, ReceiptError, load_projection

STATE_DIR = Path("/var/lib/secure-sandbox/findings")
SOCKET_PATH = Path("/run/secure-sandbox-findings/findings.sock")
RUN_ID_FILE = Path("/run/secure-sandbox/run-id")
POLICY_HASH_FILE = Path("/etc/secure-sandbox/policy.sha256")
SOURCE_INDEX = Path("/home/agent/research-workspace/repos/INDEX.json")
WORKSPACE = Path("/home/agent/research-workspace")
CODEGRAPH_INDEXES = WORKSPACE / "codegraph-indexes"

MAX_REQUEST_BYTES = 64 * 1024
MAX_CANDIDATES = 256
MAX_PER_RUN = 16
MAX_AMENDMENTS = 1024
MAX_AMENDMENTS_PER_FINDING = 16
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TEMP_RECORD_RE = re.compile(r"^\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([1-9][0-9]*)\.new$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
EVIDENCE_CLASSES = {
    "static_source_review", "exhaustive_corpus_search", "static_graph_reachability",
    "measured_execution", "report_reference", "operator_reported",
}
EXECUTION_VERBS = re.compile(r"\b(executes?|returns?|writes?|prints?|sends?|creates?|deletes?|modifies?)\b", re.I)


class FindingError(ValueError):
    """A fixed, safe-to-return rejection."""


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clean_text(value: object, field: str, maximum: int, *, multiline: bool = True) -> str:
    if not isinstance(value, str):
        raise FindingError(f"{field}_invalid")
    value = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n").strip()
    if not value or len(value.encode()) > maximum:
        raise FindingError(f"{field}_invalid")
    if not multiline and ("\n" in value or "\t" in value):
        raise FindingError(f"{field}_invalid")
    if any(unicodedata.category(character).startswith("C") and character not in {"\n", "\t"} for character in value):
        raise FindingError(f"{field}_invalid")
    return value


def canonical_uuid4(value: object, field: str) -> str:
    if not isinstance(value, str) or not UUID4_RE.fullmatch(value):
        raise FindingError(f"{field}_invalid")
    return value


def sha256_value(value: object, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise FindingError(f"{field}_invalid")
    return value


def safe_relative(value: object, field: str, *, prefix: str | None = None) -> str:
    value = clean_text(value, field, 512, multiline=False)
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise FindingError(f"{field}_invalid")
    if prefix is not None and path.parts[0] != prefix:
        raise FindingError(f"{field}_invalid")
    return str(path)


def trusted_file(path: Path, *, uid: int = 0, allow_group_read: bool = True) -> os.stat_result:
    info = path.lstat()
    forbidden = 0o022 if allow_group_read else 0o077
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_mode & forbidden:
        raise FindingError("trusted_state_invalid")
    return info


def active_run(path: Path = RUN_ID_FILE, trusted_uid: int = 0) -> str:
    try:
        parent = path.parent.lstat(); marker = path.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
                or parent.st_uid != trusted_uid or parent.st_mode & 0o022
                or not stat.S_ISREG(marker.st_mode) or stat.S_ISLNK(marker.st_mode)
                or marker.st_uid != trusted_uid or marker.st_mode & 0o022):
            raise FindingError("active_run_required")
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError, FindingError) as error:
        raise FindingError("active_run_required") from error
    return canonical_uuid4(value, "active_run")


def policy_generation(path: Path = POLICY_HASH_FILE, trusted_uid: int = 0) -> str:
    try:
        trusted_file(path, uid=trusted_uid)
        return sha256_value(path.read_text(encoding="ascii").strip(), "policy_generation")
    except (OSError, UnicodeError, FindingError) as error:
        raise FindingError("policy_generation_unavailable") from error


def load_sources(path: Path = SOURCE_INDEX) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        sources = value["sources"]
        if value.get("schema") != "secure-sandbox-source-registry-v1" or not isinstance(sources, list):
            raise ValueError
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise FindingError("source_registry_unavailable") from error
    result: dict[str, dict[str, Any]] = {}
    for item in sources:
        if not isinstance(item, dict):
            raise FindingError("source_registry_unavailable")
        source_id = canonical_uuid4(item.get("source_id"), "source_id")
        if source_id in result:
            raise FindingError("source_registry_ambiguous")
        sha256_value(item.get("tree_manifest_sha256"), "tree_manifest_sha256")
        result[source_id] = item
    return result


def validate_source_path(source: dict[str, Any], source_id: str, relative: str, workspace: Path) -> None:
    try:
        baseline = safe_relative(source.get("baseline_path"), "baseline_path", prefix="baselines")
        if baseline != f"baselines/{source_id}":
            raise FindingError("source_anchor_unsupported")
        parts = PurePosixPath(baseline, relative).parts
        descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for offset, part in enumerate(parts):
                flags = os.O_RDONLY | os.O_NOFOLLOW
                if offset < len(parts) - 1:
                    flags |= os.O_DIRECTORY
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor); descriptor = next_descriptor
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise FindingError("source_path_invalid")
        finally:
            os.close(descriptor)
    except FindingError:
        raise
    except OSError as error:
        raise FindingError("source_path_invalid") from error


def validate_affected(
    value: object, sources: dict[str, dict[str, Any]], workspace: Path = WORKSPACE,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise FindingError("affected_invalid")
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"source_id", "path", "symbol", "line"}:
            raise FindingError("affected_invalid")
        source_id = canonical_uuid4(item["source_id"], "source_id")
        source = sources.get(source_id)
        if source is None:
            raise FindingError("source_not_registered")
        resolved = source.get("resolved_commit")
        if not isinstance(resolved, str) or not COMMIT_RE.fullmatch(resolved):
            raise FindingError("source_anchor_unsupported")
        path = safe_relative(item["path"], "affected_path")
        validate_source_path(source, source_id, path, workspace)
        symbol = clean_text(item["symbol"], "affected_symbol", 256, multiline=False)
        line = item["line"]
        if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= 10_000_000:
            raise FindingError("affected_line_invalid")
        result.append({
            "source_id": source_id, "path": path, "symbol": symbol, "line": line,
            "tree_manifest_sha256": source["tree_manifest_sha256"],
            "resolved_commit": resolved,
        })
    return result


def validate_report_reference(item: dict[str, Any], workspace: Path) -> dict[str, Any]:
    if set(item) != {"class", "path"}:
        raise FindingError("evidence_schema_invalid")
    relative = safe_relative(item["path"], "evidence_path", prefix="reports")
    path = workspace / relative
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > 1024 * 1024:
            raise FindingError("evidence_report_invalid")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            digest = hashlib.sha256()
            while chunk := handle.read(65536): digest.update(chunk)
    except OSError as error:
        raise FindingError("evidence_report_invalid") from error
    return {"class": "report_reference", "path": relative, "content_sha256": digest.hexdigest(), "size": info.st_size}


def validate_evidence_item(
    item: object, sources: dict[str, dict[str, Any]], workspace: Path = WORKSPACE,
    codegraph_indexes: Path = CODEGRAPH_INDEXES, receipt_registry: Path = RECEIPT_REGISTRY,
    receipt_root_uid: int = 0, receipt_producer_uids: dict[str, int] | None = None,
    receipt_group_gid: int | None = None,
) -> dict[str, Any]:
    if not isinstance(item, dict) or item.get("class") not in EVIDENCE_CLASSES:
        raise FindingError("evidence_schema_invalid")
    kind = item["class"]
    if kind == "report_reference":
        return validate_report_reference(item, workspace)
    if kind == "operator_reported":
        if set(item) != {"class", "reference"}:
            raise FindingError("evidence_schema_invalid")
        return {"class": kind, "reference": clean_text(item["reference"], "operator_reference", 256, multiline=False)}
    source_id = canonical_uuid4(item.get("source_id"), "source_id")
    source = sources.get(source_id)
    if source is None:
        raise FindingError("source_not_registered")
    anchor = {"class": kind, "source_id": source_id, "tree_manifest_sha256": source["tree_manifest_sha256"]}
    if kind == "static_source_review":
        if set(item) != {"class", "source_id", "path", "line"}:
            raise FindingError("evidence_schema_invalid")
        path = safe_relative(item["path"], "evidence_path")
        validate_source_path(source, source_id, path, workspace)
        anchor.update(path=path, line=item["line"])
        if not isinstance(item["line"], int) or isinstance(item["line"], bool) or item["line"] < 1:
            raise FindingError("evidence_line_invalid")
    elif kind == "exhaustive_corpus_search":
        producer="corpus-broker"
        try:
            projection=load_projection(item.get("receipt_id"),item.get("receipt_sha256"),producer,
                receipt_registry,receipt_root_uid,
                None if receipt_producer_uids is None else receipt_producer_uids.get(producer),receipt_group_gid)
        except ReceiptError as error: raise FindingError(str(error)) from error
        if item != projection: raise FindingError("receipt_projection_mismatch")
        anchor.update({key:value for key,value in projection.items() if key not in {"class","source_id"}})
    elif kind == "static_graph_reachability":
        expected = {"class", "source_id", "analysis_id", "codegraph_index_sha256", "measured_execution", "exhaustive", "caller_selected_entrypoint"}
        if set(item) != expected or item["measured_execution"] is not False or item["exhaustive"] is not False or item["caller_selected_entrypoint"] is not True:
            raise FindingError("evidence_schema_invalid")
        analysis_id = sha256_value(item["analysis_id"], "analysis_id")
        index_hash = sha256_value(item["codegraph_index_sha256"], "codegraph_index_sha256")
        try:
            manifest = json.loads((codegraph_indexes / f"{source_id}.json").read_text())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise FindingError("codegraph_anchor_unavailable") from error
        if manifest.get("source_id") != source_id or manifest.get("codegraph_index_sha256") != index_hash:
            raise FindingError("codegraph_anchor_mismatch")
        anchor.update(analysis_id=analysis_id, codegraph_index_sha256=index_hash,
                      measured_execution=False, exhaustive=False, caller_selected_entrypoint=True)
    elif kind == "measured_execution":
        producer="execution-broker"
        try:
            projection=load_projection(item.get("receipt_id"),item.get("receipt_sha256"),producer,
                receipt_registry,receipt_root_uid,
                None if receipt_producer_uids is None else receipt_producer_uids.get(producer),receipt_group_gid)
        except ReceiptError as error: raise FindingError(str(error)) from error
        if item != projection: raise FindingError("receipt_projection_mismatch")
        anchor.update({key:value for key,value in projection.items() if key not in {"class","source_id"}})
    return anchor


def validate_evidence(value: object, sources: dict[str, dict[str, Any]], **paths: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise FindingError("evidence_invalid")
    cleaned = [validate_evidence_item(item, sources, **paths) for item in value]
    if len({hashlib.sha256(canonical(item)).hexdigest() for item in cleaned}) != len(cleaned):
        raise FindingError("evidence_duplicate")
    return cleaned


def validate_candidate(request: object, sources: dict[str, dict[str, Any]], **paths: Any) -> dict[str, Any]:
    expected = {"claim", "affected", "evidence", "reproduction_conditions", "limitations", "counterargument", "proposed_severity", "severity_rationale"}
    if not isinstance(request, dict) or set(request) != expected:
        raise FindingError("candidate_schema_invalid")
    severity = request["proposed_severity"]
    if severity not in SEVERITIES:
        raise FindingError("proposed_severity_invalid")
    claim = clean_text(request["claim"], "claim", 512, multiline=False)
    evidence = validate_evidence(request["evidence"], sources, **paths)
    classes = sorted({item["class"] for item in evidence})
    execution_claim = bool(EXECUTION_VERBS.search(claim))
    support = "mismatch" if execution_claim and "measured_execution" not in classes else "supported"
    return {
        "claim": claim,
        "affected": validate_affected(request["affected"], sources, paths.get("workspace", WORKSPACE)),
        "evidence": evidence,
        "reproduction_conditions": clean_text(request["reproduction_conditions"], "reproduction_conditions", 2048),
        "limitations": clean_text(request["limitations"], "limitations", 2048),
        "counterargument": clean_text(request["counterargument"], "counterargument", 2048),
        "proposed_severity": severity,
        "severity_rationale": clean_text(request["severity_rationale"], "severity_rationale", 2048),
        "evidence_classes": classes,
        "claim_requires_execution": execution_claim,
        "claim_evidence_support": support,
    }


def validate_state(path: Path, owner_uid: int) -> tuple[Path, Path]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o077:
        raise FindingError("finding_state_untrusted")
    candidates, amendments = path / "candidates", path / "amendments"
    for directory in (candidates, amendments):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o077:
            raise FindingError("finding_state_untrusted")
    return candidates, amendments


def records(path: Path, maximum: int) -> list[tuple[Path, dict[str, Any]]]:
    result = []
    for entry in path.iterdir():
        if entry.is_symlink() or not entry.is_file() or not UUID4_RE.fullmatch(entry.stem) or entry.suffix != ".json":
            raise FindingError("finding_state_untrusted")
        try: value = json.loads(entry.read_text())
        except (OSError, ValueError, json.JSONDecodeError) as error: raise FindingError("finding_state_untrusted") from error
        if not isinstance(value, dict):
            raise FindingError("finding_state_untrusted")
        recorded = value.get("content_sha256"); unsigned = dict(value); unsigned.pop("content_sha256", None)
        if recorded != hashlib.sha256(canonical(unsigned)).hexdigest():
            raise FindingError("finding_state_untrusted")
        result.append((entry, value))
    if len(result) > maximum:
        raise FindingError("finding_state_limit_exceeded")
    return result


def cleanup_temporary_records(path: Path, owner_uid: int) -> None:
    changed = False
    for entry in path.iterdir():
        if not TEMP_RECORD_RE.fullmatch(entry.name):
            continue
        info = entry.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != owner_uid or info.st_mode & 0o077):
            raise FindingError("finding_state_untrusted")
        entry.unlink(); changed = True
    if changed:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def publish(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical(value) + b"\n"
    temporary = path.parent / f".{path.stem}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
        # A hard link gives us atomic no-overwrite publication: unlike rename(),
        # an unexpected final record can never be replaced between a pre-check
        # and publication.
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except Exception:
        try: temporary.unlink()
        except OSError: pass
        raise


def submit_candidate(
    request: object, state_dir: Path = STATE_DIR, run_id_file: Path = RUN_ID_FILE,
    policy_file: Path = POLICY_HASH_FILE, source_index: Path = SOURCE_INDEX,
    workspace: Path = WORKSPACE, codegraph_indexes: Path = CODEGRAPH_INDEXES,
    receipt_registry: Path = RECEIPT_REGISTRY, trusted_uid: int = 0,
    state_owner_uid: int | None = None, receipt_root_uid: int = 0,
    receipt_producer_uids: dict[str, int] | None = None, receipt_group_gid: int | None = None,
) -> dict[str, Any]:
    run_id = active_run(run_id_file, trusted_uid)
    policy = policy_generation(policy_file, trusted_uid)
    sources = load_sources(source_index)
    cleaned = validate_candidate(request, sources, workspace=workspace, codegraph_indexes=codegraph_indexes,
        receipt_registry=receipt_registry,receipt_root_uid=receipt_root_uid,
        receipt_producer_uids=receipt_producer_uids,receipt_group_gid=receipt_group_gid)
    owner = os.geteuid() if state_owner_uid is None else state_owner_uid
    candidates, _ = validate_state(state_dir, owner)
    cleanup_temporary_records(candidates, owner)
    existing = records(candidates, MAX_CANDIDATES)
    request_hash = hashlib.sha256(canonical(cleaned)).hexdigest()
    per_run = 0
    for _, record in existing:
        if record.get("run_id") == run_id: per_run += 1
        if record.get("run_id") == run_id and record.get("request_sha256") == request_hash:
            return {"status": "already_submitted", "finding_id": record["finding_id"],
                    "content_sha256": record["content_sha256"], "authority": "candidate_only"}
    if len(existing) >= MAX_CANDIDATES:
        raise FindingError("finding_state_limit_exceeded")
    if per_run >= MAX_PER_RUN:
        raise FindingError("finding_run_limit_exceeded")
    finding_id = str(uuid.uuid4())
    record = {
        "schema": "secure-sandbox-candidate-finding-v1", "finding_id": finding_id,
        "submitted_by": "researcher_agent", "run_id": run_id,
        "policy_generation": policy, "submitted_at": now(), "status": "candidate",
        "request_sha256": request_hash, **cleaned, "authority": "candidate_only",
    }
    record["content_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    publish(candidates / f"{finding_id}.json", record)
    return {"status": "submitted", "finding_id": finding_id,
            "content_sha256": record["content_sha256"], "claim_evidence_support": cleaned["claim_evidence_support"],
            "authority": "candidate_only"}


def submit_amendment(
    request: object, state_dir: Path = STATE_DIR, run_id_file: Path = RUN_ID_FILE,
    policy_file: Path = POLICY_HASH_FILE, source_index: Path = SOURCE_INDEX,
    workspace: Path = WORKSPACE, codegraph_indexes: Path = CODEGRAPH_INDEXES,
    receipt_registry: Path = RECEIPT_REGISTRY, trusted_uid: int = 0,
    state_owner_uid: int | None = None, receipt_root_uid: int = 0,
    receipt_producer_uids: dict[str, int] | None = None, receipt_group_gid: int | None = None,
) -> dict[str, Any]:
    expected = {"finding_id", "evidence", "limitations", "counterargument", "note"}
    if not isinstance(request, dict) or set(request) != expected:
        raise FindingError("amendment_schema_invalid")
    run_id = active_run(run_id_file, trusted_uid); policy = policy_generation(policy_file, trusted_uid)
    owner = os.geteuid() if state_owner_uid is None else state_owner_uid
    candidates, amendments = validate_state(state_dir, owner)
    cleanup_temporary_records(amendments, owner)
    finding_id = canonical_uuid4(request["finding_id"], "finding_id")
    try: candidate = json.loads((candidates / f"{finding_id}.json").read_text())
    except (OSError, ValueError, json.JSONDecodeError) as error: raise FindingError("finding_not_available") from error
    if candidate.get("schema") != "secure-sandbox-candidate-finding-v1" or candidate.get("submitted_by") != "researcher_agent":
        raise FindingError("finding_not_available")
    sources = load_sources(source_index)
    cleaned = {
        "finding_id": finding_id,
        "evidence": validate_evidence(request["evidence"], sources, workspace=workspace,
            codegraph_indexes=codegraph_indexes,receipt_registry=receipt_registry,
            receipt_root_uid=receipt_root_uid,receipt_producer_uids=receipt_producer_uids,
            receipt_group_gid=receipt_group_gid),
        "limitations": clean_text(request["limitations"], "limitations", 2048),
        "counterargument": clean_text(request["counterargument"], "counterargument", 2048),
        "note": clean_text(request["note"], "note", 1024),
    }
    existing = records(amendments, MAX_AMENDMENTS)
    request_hash = hashlib.sha256(canonical(cleaned)).hexdigest()
    related = [record for _, record in existing if record.get("finding_id") == finding_id]
    for record in related:
        if record.get("run_id") == run_id and record.get("request_sha256") == request_hash:
            return {"status": "already_submitted", "amendment_id": record["amendment_id"],
                    "content_sha256": record["content_sha256"], "authority": "candidate_only"}
    if len(existing) >= MAX_AMENDMENTS:
        raise FindingError("finding_state_limit_exceeded")
    if len(related) >= MAX_AMENDMENTS_PER_FINDING:
        raise FindingError("amendment_finding_limit_exceeded")
    amendment_id = str(uuid.uuid4())
    record = {"schema": "secure-sandbox-finding-amendment-v1", "amendment_id": amendment_id,
              "relation": "amends", "submitted_by": "researcher_agent", "run_id": run_id,
              "policy_generation": policy, "submitted_at": now(), "request_sha256": request_hash,
              **cleaned, "authority": "candidate_only"}
    record["content_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    publish(amendments / f"{amendment_id}.json", record)
    return {"status": "amended", "finding_id": finding_id, "amendment_id": amendment_id,
            "content_sha256": record["content_sha256"], "authority": "candidate_only"}


def audit(result: dict[str, Any], operation: str) -> None:
    event = {
        "event": "finding_" + ("rejected" if result.get("status") == "rejected" else str(result.get("status", "rejected"))),
        "operation": operation if operation in {"submit", "amend"} else "invalid",
        "finding_id": str(result.get("finding_id", ""))[:64],
        "amendment_id": str(result.get("amendment_id", ""))[:64],
        "content_sha256": str(result.get("content_sha256", ""))[:64],
        "claim_evidence_support": str(result.get("claim_evidence_support", ""))[:16],
        "error": str(result.get("error", ""))[:64],
    }
    try:
        syslog.openlog("secure-sandbox-findings", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING if event["error"] else syslog.LOG_INFO, canonical(event).decode())
    except Exception: pass


def rejected_response(error: str, operation: str = "invalid") -> bytes:
    result = {"status":"rejected","error":error}
    audit(result, operation)
    return canonical(result) + b"\n"


def handle(raw: bytes) -> bytes:
    operation = "invalid"
    try:
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or set(envelope) != {"operation", "arguments"}:
            raise FindingError("request_schema_invalid")
        operation = envelope["operation"]
        if operation == "submit": result = submit_candidate(envelope["arguments"])
        elif operation == "amend": result = submit_amendment(envelope["arguments"])
        elif operation == "transport_reject":
            arguments = envelope["arguments"]
            if (not isinstance(arguments, dict) or set(arguments) != {"error"}
                    or arguments["error"] not in {"request_too_large", "request_incomplete", "finding_invalid"}):
                raise FindingError("request_schema_invalid")
            return rejected_response(arguments["error"])
        else: raise FindingError("operation_invalid")
        audit(result, operation)
    except FindingError as error:
        result = {"status": "rejected", "error": str(error) or "finding_invalid"}; audit(result, operation)
    except (json.JSONDecodeError, UnicodeDecodeError):
        result = {"status": "rejected", "error": "finding_invalid"}; audit(result, operation)
    except Exception:
        result = {"status": "rejected", "error": "internal_error"}; audit(result, operation)
    return canonical(result) + b"\n"


def receive_request(connection: socket.socket) -> bytes:
    deadline = time.monotonic() + 5; chunks = bytearray()
    while len(chunks) <= MAX_REQUEST_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError("request_deadline_exceeded")
        connection.settimeout(min(1.0, remaining))
        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(chunks)))
        if not chunk: break
        chunks.extend(chunk)
    if len(chunks) > MAX_REQUEST_BYTES: return rejected_response("request_too_large")
    return handle(bytes(chunks))


def serve(socket_path: Path = SOCKET_PATH) -> None:
    def bounded_handle(raw: bytes) -> bytes:
        if len(raw) > MAX_REQUEST_BYTES: return rejected_response("request_too_large")
        return handle(raw)
    serve_bounded(socket_path, MAX_REQUEST_BYTES, 5, bounded_handle,
                  lambda: rejected_response("request_incomplete"))


if __name__ == "__main__":
    serve()
