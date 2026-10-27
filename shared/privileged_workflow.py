#!/usr/bin/env python3
"""Bounded, append-only state for privileged multi-step workflows.

The engine records decisions and verified postconditions.  Callers retain all
authority to perform side effects and must supply their own authorization and
evidence digests.  A durable event may exist before the replaceable head
pointer after process loss; opening the transaction reconciles that case.
"""

from __future__ import annotations

import fcntl
import contextlib
import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Iterator


SCHEMA = "secure-sandbox-privileged-workflow-event-v1"
HEAD_SCHEMA = "secure-sandbox-privileged-workflow-head-v1"
PHASES = ("prepared", "authorized", "activated", "verified", "committed")
TERMINAL_PHASES = ("rolled_back", "expired")
TRANSITIONS = {
    "prepared": {"authorized", "rolled_back", "expired"},
    "authorized": {"activated", "rolled_back", "expired"},
    "activated": {"verified"},
    "verified": {"committed"},
    "committed": set(),
    "rolled_back": set(),
    "expired": set(),
}
UUID4_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,62}")
IDENTITY_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,62}")
IDENTITY_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
EVENT_NAME_RE = re.compile(r"([0-9]{8})-([0-9a-f]{64})\.json")
TRANSACTION_TEMP_RE = re.compile(r"\.new-([0-9a-f-]{36})-([0-9a-f-]{36})")
EVENT_TEMP_RE = re.compile(r"\.event-new-([0-9a-f-]{36})\.tmp")
HEAD_TEMP_RE = re.compile(r"\.head\.json\.new-[0-9]+-([0-9a-f-]{36})")
MAX_JSON_BYTES = 32 * 1024
MAX_TRANSACTIONS = 32
MAX_EVENTS = 16
MAX_IDENTITIES = 16
MAX_LIFETIME_SECONDS = 7 * 86400


class WorkflowError(RuntimeError):
    """A stable, content-free workflow failure."""


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4_RE.fullmatch(value) is None:
        raise WorkflowError(f"{label}_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise WorkflowError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise WorkflowError(f"{label}_invalid")
    return value


def _digest(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise WorkflowError(f"{label}_invalid")
    return value


def validate_identities(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_IDENTITIES:
        raise WorkflowError("component_identities_invalid")
    normalized: dict[str, str] = {}
    for name, identity in value.items():
        if (not isinstance(name, str) or IDENTITY_NAME_RE.fullmatch(name) is None
                or not isinstance(identity, str) or IDENTITY_VALUE_RE.fullmatch(identity) is None):
            raise WorkflowError("component_identities_invalid")
        normalized[name] = identity
    return dict(sorted(normalized.items()))


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.new-{os.getpid()}-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise WorkflowError("state_write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def append_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.parent / f".event-new-{uuid.uuid4()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise WorkflowError("state_write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
        fsync_directory(path.parent)


def _trusted_directory(path: Path, owner_uid: int, mode: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise WorkflowError("state_directory_missing") from error
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != mode):
        raise WorkflowError("state_directory_untrusted")


def _read_regular(path: Path, owner_uid: int, mode: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise WorkflowError("state_invalid") from error
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != owner_uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= MAX_JSON_BYTES):
        raise WorkflowError("state_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise WorkflowError("state_changed")
        chunks = bytearray()
        while len(chunks) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_JSON_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (len(chunks) > MAX_JSON_BYTES
            or (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size)):
        raise WorkflowError("state_changed")
    return bytes(chunks)


def _read_json(path: Path, owner_uid: int, mode: int) -> dict[str, Any]:
    raw = _read_regular(path, owner_uid, mode)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkflowError("state_invalid") from error
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise WorkflowError("state_invalid")
    return value


class WorkflowStore:
    """A bounded store for one named workflow family."""

    def __init__(self, root: Path, workflow: str, *, owner_uid: int | None = None) -> None:
        if NAME_RE.fullmatch(workflow) is None:
            raise WorkflowError("workflow_invalid")
        self.root = root
        self.workflow = workflow
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
        self.transactions = root / "transactions"
        self.lock_path = root / ".lock"
        self._lock_depth = 0

    def prepare(self) -> None:
        old_umask = os.umask(0o077)
        try:
            self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
            self.transactions.mkdir(mode=0o700, exist_ok=True)
            _trusted_directory(self.root, self.owner_uid, 0o700)
            _trusted_directory(self.transactions, self.owner_uid, 0o700)
            entries = list(self.transactions.iterdir())
            if len(entries) > MAX_TRANSACTIONS * 2:
                raise WorkflowError("transaction_store_untrusted")
            transactions = 0
            for entry in entries:
                if entry.is_symlink() or not entry.is_dir():
                    raise WorkflowError("transaction_store_untrusted")
                if UUID4_RE.fullmatch(entry.name):
                    _uuid4(entry.name, "transaction_id")
                    transactions += 1
                elif TRANSACTION_TEMP_RE.fullmatch(entry.name):
                    match = TRANSACTION_TEMP_RE.fullmatch(entry.name)
                    assert match is not None
                    _uuid4(match.group(1), "transaction_id")
                    _uuid4(match.group(2), "temporary_id")
                    _trusted_directory(entry, self.owner_uid, 0o700)
                    for child in entry.iterdir():
                        if child.is_symlink() or child.name not in {"events", "head.json"}:
                            raise WorkflowError("transaction_store_untrusted")
                else:
                    raise WorkflowError("transaction_store_untrusted")
            if transactions > MAX_TRANSACTIONS:
                raise WorkflowError("transaction_store_untrusted")
            descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise WorkflowError("state_lock_untrusted")
            finally:
                os.close(descriptor)
        finally:
            os.umask(old_umask)

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        if self._lock_depth:
            raise WorkflowError("workflow_lock_reentry")
        self.prepare()
        descriptor = os.open(self.lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        handle = os.fdopen(descriptor, "r+b", closefd=True)
        entered = False
        try:
            opened = os.fstat(handle.fileno())
            current = self.lock_path.lstat()
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != self.owner_uid
                    or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
                raise WorkflowError("state_lock_untrusted")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            current = self.lock_path.lstat()
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise WorkflowError("state_lock_changed")
            self._lock_depth += 1
            entered = True
            self._cleanup_temporaries()
            yield
        finally:
            if entered:
                self._lock_depth -= 1
            handle.close()

    def _cleanup_temporaries(self) -> None:
        for entry in self.transactions.iterdir():
            match = TRANSACTION_TEMP_RE.fullmatch(entry.name)
            if match is None:
                if UUID4_RE.fullmatch(entry.name):
                    self._cleanup_transaction_temporaries(entry)
                continue
            _uuid4(match.group(1), "transaction_id")
            _uuid4(match.group(2), "temporary_id")
            _trusted_directory(entry, self.owner_uid, 0o700)
            for child in entry.iterdir():
                if child.is_symlink() or child.name not in {"events", "head.json"}:
                    raise WorkflowError("transaction_store_untrusted")
            __import__("shutil").rmtree(entry)
            fsync_directory(self.transactions)

    def _cleanup_transaction_temporaries(self, transaction: Path) -> None:
        _trusted_directory(transaction, self.owner_uid, 0o700)
        for entry in transaction.iterdir():
            head_match = HEAD_TEMP_RE.fullmatch(entry.name)
            if head_match is not None:
                _uuid4(head_match.group(1), "temporary_id")
                self._remove_temporary_file(entry)
                continue
            if entry.name not in {"events", "head.json"}:
                raise WorkflowError("transaction_state_untrusted")
        events = transaction / "events"
        if not events.exists():
            return
        _trusted_directory(events, self.owner_uid, 0o700)
        for entry in events.iterdir():
            match = EVENT_TEMP_RE.fullmatch(entry.name)
            if match is not None:
                _uuid4(match.group(1), "temporary_id")
                self._remove_temporary_file(entry)

    def _remove_temporary_file(self, path: Path) -> None:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != self.owner_uid or info.st_nlink not in {1, 2}
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_JSON_BYTES):
            raise WorkflowError("transaction_state_untrusted")
        path.unlink()
        fsync_directory(path.parent)

    def _require_locked(self) -> None:
        if self._lock_depth != 1:
            raise WorkflowError("workflow_lock_required")

    def _transaction_path(self, transaction_id: str) -> Path:
        return self.transactions / _uuid4(transaction_id, "transaction_id")

    def _event_body(self, transaction_id: str, sequence: int, phase: str, action_id: str,
                    prior_hash: str | None, identities: dict[str, str], transaction_expires_at: int,
                    recorded_at: int, authorization_sha256: str | None,
                    authorization_expires_at: int | None, evidence_sha256: str | None) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "workflow": self.workflow,
            "transaction_id": transaction_id,
            "sequence": sequence,
            "phase": phase,
            "action_id": action_id,
            "prior_event_sha256": prior_hash,
            "component_identities": identities,
            "transaction_expires_at": transaction_expires_at,
            "recorded_at": recorded_at,
            "authorization_sha256": authorization_sha256,
            "authorization_expires_at": authorization_expires_at,
            "evidence_sha256": evidence_sha256,
        }

    def _validate_event(self, value: dict[str, Any], expected_name: str | None = None) -> dict[str, Any]:
        expected_fields = {
            "schema", "workflow", "transaction_id", "sequence", "phase", "action_id",
            "prior_event_sha256", "component_identities", "transaction_expires_at", "recorded_at",
            "authorization_sha256", "authorization_expires_at", "evidence_sha256", "event_sha256",
        }
        if set(value) != expected_fields or value.get("schema") != SCHEMA or value.get("workflow") != self.workflow:
            raise WorkflowError("event_invalid")
        _uuid4(value.get("transaction_id"), "transaction_id")
        _uuid4(value.get("action_id"), "action_id")
        if (not isinstance(value.get("sequence"), int) or isinstance(value.get("sequence"), bool)
                or not 0 <= value["sequence"] < MAX_EVENTS or value.get("phase") not in {*PHASES, *TERMINAL_PHASES}
                or not isinstance(value.get("recorded_at"), int) or isinstance(value.get("recorded_at"), bool)
                or not isinstance(value.get("transaction_expires_at"), int)
                or isinstance(value.get("transaction_expires_at"), bool)):
            raise WorkflowError("event_invalid")
        validate_identities(value.get("component_identities"))
        if value["sequence"] == 0:
            if value["phase"] != "prepared" or value["prior_event_sha256"] is not None:
                raise WorkflowError("event_invalid")
        else:
            _digest(value.get("prior_event_sha256"), "prior_event_sha256")
        _digest(value.get("authorization_sha256"), "authorization_sha256", optional=True)
        _digest(value.get("evidence_sha256"), "evidence_sha256", optional=True)
        authorization_expiry = value.get("authorization_expires_at")
        if authorization_expiry is not None and (not isinstance(authorization_expiry, int)
                or isinstance(authorization_expiry, bool)):
            raise WorkflowError("event_invalid")
        phase = value["phase"]
        if (phase == "prepared" and any(value[name] is not None for name in (
                "authorization_sha256", "authorization_expires_at", "evidence_sha256"))
                or phase == "authorized" and (value["authorization_sha256"] is None
                    or value["authorization_expires_at"] is None or value["evidence_sha256"] is not None)
                or phase in {"activated", "verified", "committed", "rolled_back"}
                    and (value["authorization_sha256"] is not None
                         or value["authorization_expires_at"] is not None
                         or value["evidence_sha256"] is None)
                or phase == "expired" and any(value[name] is not None for name in (
                    "authorization_sha256", "authorization_expires_at", "evidence_sha256"))):
            raise WorkflowError("event_invalid")
        supplied = _digest(value.get("event_sha256"), "event_sha256")
        body = dict(value); del body["event_sha256"]
        calculated = sha256_bytes(canonical_bytes(body))
        if not hmac.compare_digest(supplied or "", calculated):
            raise WorkflowError("event_hash_mismatch")
        if expected_name is not None and expected_name != f"{value['sequence']:08d}-{calculated}.json":
            raise WorkflowError("event_name_mismatch")
        return value

    def _events(self, transaction: Path) -> list[dict[str, Any]]:
        events_dir = transaction / "events"
        _trusted_directory(transaction, self.owner_uid, 0o700)
        _trusted_directory(events_dir, self.owner_uid, 0o700)
        entries = list(events_dir.iterdir())
        if not 1 <= len(entries) <= MAX_EVENTS:
            raise WorkflowError("event_count_invalid")
        parsed: list[dict[str, Any]] = []
        seen_sequences: set[int] = set()
        for entry in entries:
            match = EVENT_NAME_RE.fullmatch(entry.name)
            if match is None or int(match.group(1)) in seen_sequences:
                raise WorkflowError("event_chain_ambiguous")
            seen_sequences.add(int(match.group(1)))
            parsed.append(self._validate_event(_read_json(entry, self.owner_uid, 0o600), entry.name))
        parsed.sort(key=lambda item: item["sequence"])
        for index, event in enumerate(parsed):
            if event["sequence"] != index:
                raise WorkflowError("event_chain_incomplete")
            if index and event["prior_event_sha256"] != parsed[index - 1]["event_sha256"]:
                raise WorkflowError("event_chain_invalid")
            if index and (event["transaction_id"] != parsed[0]["transaction_id"]
                          or event["component_identities"] != parsed[0]["component_identities"]
                          or event["transaction_expires_at"] != parsed[0]["transaction_expires_at"]):
                raise WorkflowError("event_chain_identity_mismatch")
            if index and event["phase"] not in TRANSITIONS[parsed[index - 1]["phase"]]:
                raise WorkflowError("event_chain_transition_invalid")
        return parsed

    def _head_value(self, event: dict[str, Any]) -> dict[str, Any]:
        body = {
            "schema": HEAD_SCHEMA,
            "workflow": self.workflow,
            "transaction_id": event["transaction_id"],
            "sequence": event["sequence"],
            "phase": event["phase"],
            "event_sha256": event["event_sha256"],
        }
        body["head_sha256"] = sha256_bytes(canonical_bytes(body))
        return body

    def _read_head(self, transaction: Path) -> dict[str, Any] | None:
        path = transaction / "head.json"
        if not path.exists() and not path.is_symlink():
            return None
        value = _read_json(path, self.owner_uid, 0o600)
        if set(value) != {"schema", "workflow", "transaction_id", "sequence", "phase", "event_sha256", "head_sha256"}:
            raise WorkflowError("head_invalid")
        supplied = _digest(value.get("head_sha256"), "head_sha256")
        body = dict(value); del body["head_sha256"]
        if (value.get("schema") != HEAD_SCHEMA or value.get("workflow") != self.workflow
                or not isinstance(value.get("sequence"), int) or isinstance(value.get("sequence"), bool)
                or value["sequence"] < 0 or value.get("phase") not in {*PHASES, *TERMINAL_PHASES}
                or not isinstance(value.get("transaction_id"), str)
                or not isinstance(value.get("event_sha256"), str)
                or not hmac.compare_digest(supplied or "", sha256_bytes(canonical_bytes(body)))):
            raise WorkflowError("head_invalid")
        return value

    def _reconcile(self, transaction: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        events = self._events(transaction)
        last = events[-1]
        expected = self._head_value(last)
        head = self._read_head(transaction)
        if head is None or (0 <= head.get("sequence", -1) < last["sequence"]
                            and head == self._head_value(events[head["sequence"]])):
            atomic_write(transaction / "head.json", canonical_bytes(expected))
            head = expected
        if head != expected:
            raise WorkflowError("head_event_mismatch")
        return events, last

    def create(self, transaction_id: str, action_id: str, component_identities: dict[str, str],
               transaction_expires_at: int, *, now: int | None = None) -> dict[str, Any]:
        self._require_locked()
        transaction_id = _uuid4(transaction_id, "transaction_id")
        action_id = _uuid4(action_id, "action_id")
        identities = validate_identities(component_identities)
        current_time = int(time.time()) if now is None else now
        if (not isinstance(transaction_expires_at, int) or isinstance(transaction_expires_at, bool)
                or not current_time < transaction_expires_at <= current_time + MAX_LIFETIME_SECONDS):
            raise WorkflowError("transaction_expiry_invalid")
        transaction = self._transaction_path(transaction_id)
        if transaction.exists() or transaction.is_symlink():
            events, head = self._reconcile(transaction)
            first = events[0]
            if (first["action_id"] == action_id and first["component_identities"] == identities
                    and first["transaction_expires_at"] == transaction_expires_at):
                return head
            raise WorkflowError("transaction_conflict")
        if len(list(self.transactions.iterdir())) >= MAX_TRANSACTIONS:
            raise WorkflowError("transaction_limit_exceeded")
        temporary = self.transactions / f".new-{transaction_id}-{uuid.uuid4()}"
        temporary.mkdir(mode=0o700)
        events_dir = temporary / "events"; events_dir.mkdir(mode=0o700)
        fsync_directory(temporary)
        body = self._event_body(transaction_id, 0, "prepared", action_id, None, identities,
                                transaction_expires_at, current_time, None, None, None)
        body["event_sha256"] = sha256_bytes(canonical_bytes(body))
        append_exclusive(events_dir / f"00000000-{body['event_sha256']}.json", canonical_bytes(body))
        head = self._head_value(body)
        atomic_write(temporary / "head.json", canonical_bytes(head))
        fsync_directory(temporary)
        os.rename(temporary, transaction)
        fsync_directory(self.transactions)
        return head

    def inspect(self, transaction_id: str, component_identities: dict[str, str] | None = None) -> dict[str, Any]:
        self._require_locked()
        events, head = self._reconcile(self._transaction_path(transaction_id))
        if component_identities is not None and events[0]["component_identities"] != validate_identities(component_identities):
            raise WorkflowError("component_identity_mismatch")
        return head

    def advance(self, transaction_id: str, target_phase: str, action_id: str,
                component_identities: dict[str, str], *, authorization_sha256: str | None = None,
                authorization_expires_at: int | None = None, evidence_sha256: str | None = None,
                now: int | None = None) -> dict[str, Any]:
        self._require_locked()
        if target_phase not in {*PHASES, *TERMINAL_PHASES} or target_phase == "prepared":
            raise WorkflowError("target_phase_invalid")
        action_id = _uuid4(action_id, "action_id")
        identities = validate_identities(component_identities)
        auth_digest = _digest(authorization_sha256, "authorization_sha256", optional=True)
        evidence_digest = _digest(evidence_sha256, "evidence_sha256", optional=True)
        current_time = int(time.time()) if now is None else now
        transaction = self._transaction_path(transaction_id)
        events, head = self._reconcile(transaction)
        if events[0]["component_identities"] != identities:
            raise WorkflowError("component_identity_mismatch")
        for event in events:
            if event["action_id"] == action_id:
                if (event["phase"] == target_phase and event["authorization_sha256"] == auth_digest
                        and event["authorization_expires_at"] == authorization_expires_at
                        and event["evidence_sha256"] == evidence_digest):
                    return self._head_value(event)
                raise WorkflowError("action_id_conflict")
        current = events[-1]
        if target_phase not in TRANSITIONS[current["phase"]]:
            raise WorkflowError("phase_transition_invalid")
        transaction_expiry = current["transaction_expires_at"]
        if target_phase == "expired":
            if current_time <= transaction_expiry:
                raise WorkflowError("transaction_not_expired")
        elif current_time > transaction_expiry and current["phase"] in {"prepared", "authorized"}:
            raise WorkflowError("transaction_expired")
        if target_phase == "authorized":
            if auth_digest is None or not isinstance(authorization_expires_at, int) or isinstance(authorization_expires_at, bool):
                raise WorkflowError("authorization_required")
            if not current_time < authorization_expires_at <= transaction_expiry:
                raise WorkflowError("authorization_expiry_invalid")
        else:
            if auth_digest is not None or authorization_expires_at is not None:
                raise WorkflowError("authorization_fields_unexpected")
        if target_phase in {"activated", "verified", "committed", "rolled_back"} and evidence_digest is None:
            raise WorkflowError("evidence_required")
        if target_phase == "expired" and evidence_digest is not None:
            raise WorkflowError("evidence_unexpected")
        if target_phase == "activated":
            authorized = current
            if authorized["phase"] != "authorized" or current_time > authorized["authorization_expires_at"]:
                raise WorkflowError("authorization_expired")
        body = self._event_body(transaction_id, len(events), target_phase, action_id,
                                current["event_sha256"], identities, transaction_expiry,
                                current_time, auth_digest, authorization_expires_at, evidence_digest)
        body["event_sha256"] = sha256_bytes(canonical_bytes(body))
        append_exclusive(transaction / "events" / f"{body['sequence']:08d}-{body['event_sha256']}.json",
                         canonical_bytes(body))
        new_head = self._head_value(body)
        atomic_write(transaction / "head.json", canonical_bytes(new_head))
        return new_head

    def event_history(self, transaction_id: str, component_identities: dict[str, str]) -> list[dict[str, Any]]:
        self._require_locked()
        events, _ = self._reconcile(self._transaction_path(transaction_id))
        if events[0]["component_identities"] != validate_identities(component_identities):
            raise WorkflowError("component_identity_mismatch")
        return events
