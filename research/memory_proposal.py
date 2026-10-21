#!/usr/bin/env python3
"""Bounded, append-only memory proposal broker for the Research VM."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import syslog
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path("/var/lib/secure-sandbox/memory-proposals")
SOCKET_PATH = Path("/run/secure-sandbox-memory/memory-proposal.sock")
RUN_ID_FILE = Path("/run/secure-sandbox/run-id")
LIFECYCLE_FILE = Path("/var/lib/secure-sandbox/run-lifecycle/active.json")
MAX_REQUEST_BYTES = 16 * 1024
MAX_PROPOSALS = 128
MAX_EVIDENCE_REFS = 8
CATEGORIES = {"identity", "working_principle", "project_context", "operator_preference"}
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class ProposalError(ValueError):
    """A structured, safe-to-return rejection."""


def clean_text(value: object, field: str, maximum: int, *, multiline: bool = True) -> str:
    if not isinstance(value, str):
        raise ProposalError(f"{field}_invalid")
    value = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n").strip()
    if not value or len(value.encode("utf-8")) > maximum:
        raise ProposalError(f"{field}_invalid")
    if not multiline and ("\n" in value or "\t" in value):
        raise ProposalError(f"{field}_invalid")
    for character in value:
        if unicodedata.category(character).startswith("C") and character not in {"\n", "\t"}:
            raise ProposalError(f"{field}_invalid")
    return value


def canonical_run_id(path: Path = RUN_ID_FILE, trusted_uid: int = 0,
                     lifecycle_path: Path | None = None) -> str:
    try:
        directory = path.parent.lstat()
        marker = path.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or stat.S_ISLNK(directory.st_mode)
            or directory.st_uid != trusted_uid
            or directory.st_mode & 0o022
            or not stat.S_ISREG(marker.st_mode)
            or stat.S_ISLNK(marker.st_mode)
            or marker.st_uid != trusted_uid
            or marker.st_mode & 0o022
        ):
            raise ProposalError("active_run_required")
        value = path.read_text(encoding="ascii").strip()
        parsed = uuid.UUID(value)
    except (OSError, UnicodeError, ValueError) as error:
        raise ProposalError("active_run_required") from error
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ProposalError("active_run_required")
    lifecycle_path = LIFECYCLE_FILE if lifecycle_path is None and path == RUN_ID_FILE else lifecycle_path
    if lifecycle_path is not None:
        try:
            info = lifecycle_path.lstat()
            lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != trusted_uid
                    or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1
                    or lifecycle.get("schema") != "secure-sandbox-run-lifecycle-v2"
                    or lifecycle.get("phase") != "active" or lifecycle.get("run_id") != value):
                raise ProposalError("active_run_required")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise ProposalError("active_run_required") from error
    return value


def validate_request(request: object) -> dict:
    if not isinstance(request, dict) or set(request) != {
        "category", "title", "proposal", "rationale", "evidence_refs"
    }:
        raise ProposalError("proposal_schema_invalid")
    category = request.get("category")
    if category not in CATEGORIES:
        raise ProposalError("category_invalid")
    references = request.get("evidence_refs")
    if not isinstance(references, list) or len(references) > MAX_EVIDENCE_REFS:
        raise ProposalError("evidence_refs_invalid")
    cleaned_refs = [clean_text(item, "evidence_ref", 256, multiline=False) for item in references]
    if len(set(cleaned_refs)) != len(cleaned_refs):
        raise ProposalError("evidence_refs_invalid")
    return {
        "category": category,
        "title": clean_text(request.get("title"), "title", 96, multiline=False),
        "proposal": clean_text(request.get("proposal"), "proposal", 4096),
        "rationale": clean_text(request.get("rationale"), "rationale", 2048),
        "evidence_refs": cleaned_refs,
    }


def validate_state_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ProposalError("proposal_state_unavailable")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ProposalError("proposal_state_untrusted")


def existing_proposals(path: Path) -> list[Path]:
    entries = list(path.iterdir())
    proposals: list[Path] = []
    for entry in entries:
        if not UUID4_RE.fullmatch(entry.stem) or entry.suffix != ".json" or entry.is_symlink() or not entry.is_file():
            raise ProposalError("proposal_state_untrusted")
        proposals.append(entry)
    if len(proposals) >= MAX_PROPOSALS:
        raise ProposalError("proposal_state_limit_exceeded")
    return proposals


def submit(
    request: object,
    state_dir: Path = STATE_DIR,
    run_id_file: Path = RUN_ID_FILE,
    run_id_owner_uid: int = 0,
) -> dict:
    cleaned = validate_request(request)
    run_id = canonical_run_id(run_id_file, run_id_owner_uid)
    validate_state_directory(state_dir)
    existing_proposals(state_dir)
    content_hash = hashlib.sha256(json.dumps(cleaned, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    proposal_id = str(uuid.uuid4())
    record = {
        "schema": "secure-sandbox-memory-proposal-v1",
        "proposal_id": proposal_id,
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "content_sha256": content_hash,
        **cleaned,
        "authority": "untrusted_proposal",
        "status": "pending_operator_review",
    }
    encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()
    destination = state_dir / f"{proposal_id}.json"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return {
        "status": "queued_for_operator_review",
        "proposal_id": proposal_id,
        "content_sha256": content_hash,
        "authority": "untrusted_proposal",
    }


def audit(result: dict, category: str = "invalid") -> None:
    event = {
        "event": "memory_proposal_queued" if result.get("status") == "queued_for_operator_review" else "memory_proposal_rejected",
        "proposal_id": str(result.get("proposal_id", ""))[:64],
        "content_sha256": str(result.get("content_sha256", ""))[:64],
        "category": category if category in CATEGORIES else "invalid",
        "error": str(result.get("error", ""))[:64],
    }
    try:
        syslog.openlog("secure-sandbox-memory-proposal", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO if not event["error"] else syslog.LOG_WARNING,
                      json.dumps(event, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass


def handle(raw: bytes) -> bytes:
    try:
        request = json.loads(raw)
        result = submit(request)
        audit(result, request.get("category", "invalid") if isinstance(request, dict) else "invalid")
    except ProposalError as error:
        result = {"status": "rejected", "error": str(error) or "proposal_invalid"}
        audit(result)
    except (json.JSONDecodeError, UnicodeDecodeError):
        result = {"status": "rejected", "error": "proposal_invalid"}
        audit(result)
    except Exception:
        result = {"status": "rejected", "error": "internal_error"}
        audit(result)
    return (json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n").encode()


def serve(socket_path: Path = SOCKET_PATH) -> None:
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o660)
    server.listen(8)
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(2)
            chunks = bytearray()
            try:
                while len(chunks) <= MAX_REQUEST_BYTES:
                    chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(chunks)))
                    if not chunk:
                        break
                    chunks.extend(chunk)
                response = handle(bytes(chunks)) if len(chunks) <= MAX_REQUEST_BYTES else b'{"error":"request_too_large","status":"rejected"}\n'
            except (OSError, TimeoutError):
                response = b'{"error":"request_incomplete","status":"rejected"}\n'
            try:
                connection.sendall(response)
            except OSError:
                pass


if __name__ == "__main__":
    serve()
