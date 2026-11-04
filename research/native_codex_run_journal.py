#!/usr/bin/env python3
"""Immutable native run events and independent process absence proof.

The historical module name is retained for installed-path compatibility; the
event contract is provider-neutral and is used by both admitted native stacks.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping

from shared import runtime_authority


EVENT_SCHEMA = "secure-sandbox-native-run-event-v1"
ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller/native-runs")
SESSION_STATE_ROOT = Path("/run/secure-sandbox/native-codex/session-state")
CGROUP_ROOT = Path("/sys/fs/cgroup")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SYSTEMCTL = Path("/usr/bin/systemctl")
LOCK_NAME = ".journal.lock"
MAX_SESSIONS = 4096
MAX_EVENTS = 16
MAX_EVENT_BYTES = 128 * 1024
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
EVENT_NAME = re.compile(r"([0-9]{8})-(prepared|active|terminal|ambiguous)\.json")
PHASES = {"prepared", "active", "terminal", "ambiguous"}
FIELDS = {
    "schema", "sequence", "phase", "transition_operation_id", "session_id",
    "runtime_authority", "runtime_authority_sha256", "scope_unit",
    "process_id", "process_start_time_ticks", "boot_id_sha256",
    "executable_sha256", "lease_started_at", "lease_expires_at",
    "observed_at", "exit_code", "absence_evidence_sha256",
    "prior_event_sha256", "event_sha256",
}


class NativeCodexRunJournalError(RuntimeError):
    """Stable fail-closed journal error."""


def canonical(value: object) -> bytes:
    try:
        raw = (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeCodexRunJournalError("native_codex_journal_value_invalid") from error
    if len(raw) > MAX_EVENT_BYTES:
        raise NativeCodexRunJournalError("native_codex_journal_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise NativeCodexRunJournalError("native_codex_journal_write_failed")
        view = view[count:]


def _open_root(root: Path, *, uid: int, gid: int) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        current = root.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_uid != uid or opened.st_gid != gid
                or stat.S_IMODE(opened.st_mode) != 0o700):
            raise NativeCodexRunJournalError("native_codex_journal_root_untrusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _lock(root_descriptor: int, *, uid: int, gid: int) -> int:
    descriptor = os.open(
        LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=root_descriptor)
    try:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise NativeCodexRunJournalError("native_codex_journal_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_file(directory: int, name: str, *, uid: int, gid: int) -> dict[str, Any]:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= MAX_EVENT_BYTES):
            raise NativeCodexRunJournalError("native_codex_journal_event_untrusted")
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeCodexRunJournalError("native_codex_journal_event_changed")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCodexRunJournalError("native_codex_journal_event_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeCodexRunJournalError("native_codex_journal_event_invalid")
    return validate_event(value)


def validate_event(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise NativeCodexRunJournalError("native_codex_journal_event_fields_invalid")
    if (value["schema"] != EVENT_SCHEMA or value["phase"] not in PHASES
            or not isinstance(value["sequence"], int)
            or not 0 <= value["sequence"] < MAX_EVENTS
            or not isinstance(value["transition_operation_id"], str)
            or UUID4.fullmatch(value["transition_operation_id"]) is None
            or not isinstance(value["session_id"], str)
            or UUID4.fullmatch(value["session_id"]) is None):
        raise NativeCodexRunJournalError("native_codex_journal_event_invalid")
    try:
        authority = runtime_authority.validate_binding(value["runtime_authority"])
    except runtime_authority.RuntimeAuthorityError as error:
        raise NativeCodexRunJournalError(
            "native_codex_journal_authority_invalid") from error
    if (authority["binding_sha256"] != value["runtime_authority_sha256"]
            or authority["session_context_binding"]["session_id"]
               != value["session_id"]):
        raise NativeCodexRunJournalError("native_codex_journal_authority_mismatch")
    if (not isinstance(value["scope_unit"], str)
            or re.fullmatch(
                r"secure-sandbox-native-run-[0-9a-f]{32}\.scope",
                value["scope_unit"]) is None
            or not isinstance(value["boot_id_sha256"], str)
            or SHA256.fullmatch(value["boot_id_sha256"]) is None
            or not isinstance(value["executable_sha256"], str)
            or SHA256.fullmatch(value["executable_sha256"]) is None
            or not isinstance(value["lease_started_at"], int)
            or not isinstance(value["lease_expires_at"], int)
            or not 0 < value["lease_started_at"] < value["lease_expires_at"]
            or not isinstance(value["observed_at"], int)
            or value["observed_at"] < value["lease_started_at"]):
        raise NativeCodexRunJournalError("native_codex_journal_event_invalid")
    process_values = (value["process_id"], value["process_start_time_ticks"])
    if (process_values[0] is None) != (process_values[1] is None):
        raise NativeCodexRunJournalError("native_codex_journal_process_partial")
    if process_values[0] is not None and (
        not isinstance(process_values[0], int) or process_values[0] <= 1
        or not isinstance(process_values[1], int) or process_values[1] < 1
    ):
        raise NativeCodexRunJournalError("native_codex_journal_process_invalid")
    if value["phase"] == "prepared" and process_values[0] is not None:
        raise NativeCodexRunJournalError("native_codex_journal_phase_invalid")
    if value["phase"] == "active" and process_values[0] is None:
        raise NativeCodexRunJournalError("native_codex_journal_phase_invalid")
    if value["phase"] == "terminal":
        if (not isinstance(value["exit_code"], int)
                or value["absence_evidence_sha256"] is None):
            raise NativeCodexRunJournalError("native_codex_journal_phase_invalid")
    elif value["exit_code"] is not None or value["absence_evidence_sha256"] is not None:
        raise NativeCodexRunJournalError("native_codex_journal_phase_invalid")
    for field in ("runtime_authority_sha256", "absence_evidence_sha256",
                  "prior_event_sha256", "event_sha256"):
        if value[field] is not None and (
            not isinstance(value[field], str) or SHA256.fullmatch(value[field]) is None
        ):
            raise NativeCodexRunJournalError("native_codex_journal_digest_invalid")
    if (value["sequence"] == 0) != (value["prior_event_sha256"] is None):
        raise NativeCodexRunJournalError("native_codex_journal_chain_invalid")
    body = {key: value[key] for key in FIELDS - {"schema", "event_sha256"}}
    if value["event_sha256"] != digest(body):
        raise NativeCodexRunJournalError("native_codex_journal_digest_invalid")
    return value


def _session_descriptor(root_descriptor: int, session_id: str, *, uid: int,
                        gid: int, create: bool) -> int:
    if UUID4.fullmatch(session_id) is None:
        raise NativeCodexRunJournalError("native_codex_journal_session_invalid")
    try:
        descriptor = os.open(
            session_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_CLOEXEC, dir_fd=root_descriptor)
    except FileNotFoundError:
        if not create:
            raise
        names = [name for name in os.listdir(root_descriptor) if name != LOCK_NAME]
        if len(names) >= MAX_SESSIONS or any(UUID4.fullmatch(name) is None for name in names):
            raise NativeCodexRunJournalError("native_codex_journal_retention_limit")
        os.mkdir(session_id, 0o700, dir_fd=root_descriptor)
        descriptor = os.open(
            session_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_CLOEXEC, dir_fd=root_descriptor)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o700)
        os.fsync(root_descriptor)
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(descriptor)
        raise NativeCodexRunJournalError("native_codex_journal_session_untrusted")
    return descriptor


def _events(session_descriptor: int, *, uid: int, gid: int) -> list[dict[str, Any]]:
    names = sorted(os.listdir(session_descriptor))
    if len(names) > MAX_EVENTS or any(EVENT_NAME.fullmatch(name) is None for name in names):
        raise NativeCodexRunJournalError("native_codex_journal_inventory_invalid")
    values = [_read_file(session_descriptor, name, uid=uid, gid=gid)
              for name in names]
    prior = None
    for index, value in enumerate(values):
        if (value["sequence"] != index or value["prior_event_sha256"] != prior
                or not names[index].startswith(f"{index:08d}-{value['phase']}.")):
            raise NativeCodexRunJournalError("native_codex_journal_chain_invalid")
        prior = value["event_sha256"]
    return values


def append_event(*, phase: str, transition_operation_id: str,
                 authority: Mapping[str, Any], scope_unit: str,
                 process_id: int | None, process_start_time_ticks: int | None,
                 boot_id_sha256: str, executable_sha256: str,
                 lease_started_at: int, lease_expires_at: int, observed_at: int,
                 exit_code: int | None, absence_evidence_sha256: str | None,
                 root: Path = ROOT, trusted_uid: int = 0,
                 trusted_gid: int = 0) -> dict[str, Any]:
    validated_authority = runtime_authority.validate_binding(authority)
    session_id = validated_authority["session_context_binding"]["session_id"]
    root_descriptor = _open_root(root, uid=trusted_uid, gid=trusted_gid)
    lock = -1
    session = -1
    try:
        lock = _lock(root_descriptor, uid=trusted_uid, gid=trusted_gid)
        session = _session_descriptor(
            root_descriptor, session_id, uid=trusted_uid, gid=trusted_gid,
            create=phase == "prepared")
        values = _events(session, uid=trusted_uid, gid=trusted_gid)
        if len(values) >= MAX_EVENTS:
            raise NativeCodexRunJournalError("native_codex_journal_event_limit")
        requested = {
            "phase": phase,
            "transition_operation_id": transition_operation_id,
            "session_id": session_id,
            "runtime_authority": dict(validated_authority),
            "runtime_authority_sha256": validated_authority["binding_sha256"],
            "scope_unit": scope_unit,
            "process_id": process_id,
            "process_start_time_ticks": process_start_time_ticks,
            "boot_id_sha256": boot_id_sha256,
            "executable_sha256": executable_sha256,
            "lease_started_at": lease_started_at,
            "lease_expires_at": lease_expires_at,
            "observed_at": observed_at,
            "exit_code": exit_code,
            "absence_evidence_sha256": absence_evidence_sha256,
        }
        allowed = ({None: {"prepared"}, "prepared": {"active", "terminal", "ambiguous"},
                    "active": {"terminal", "ambiguous"},
                    "ambiguous": {"terminal", "ambiguous"},
                    "terminal": set()})
        prior_phase = values[-1]["phase"] if values else None
        if phase not in allowed[prior_phase]:
            if values and values[-1]["phase"] == phase:
                observed = {name: values[-1][name] for name in requested}
                if observed == requested:
                    return values[-1]
                raise NativeCodexRunJournalError(
                    "native_codex_journal_replay_conflict")
            raise NativeCodexRunJournalError("native_codex_journal_transition_invalid")
        sequence = len(values)
        body = {
            "sequence": sequence, **requested,
            "prior_event_sha256": values[-1]["event_sha256"] if values else None,
        }
        value = {"schema": EVENT_SCHEMA, **body, "event_sha256": digest(body)}
        validate_event(value)
        name = f"{sequence:08d}-{phase}.json"
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=session)
        try:
            os.fchown(descriptor, trusted_uid, trusted_gid)
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, canonical(value))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(session)
        if _read_file(session, name, uid=trusted_uid, gid=trusted_gid) != value:
            raise NativeCodexRunJournalError("native_codex_journal_readback_failed")
        return value
    finally:
        if session >= 0:
            os.close(session)
        if lock >= 0:
            os.close(lock)
        os.close(root_descriptor)


def latest(session_id: str, *, root: Path = ROOT, trusted_uid: int = 0,
           trusted_gid: int = 0) -> dict[str, Any]:
    root_descriptor = _open_root(root, uid=trusted_uid, gid=trusted_gid)
    lock = session = -1
    try:
        lock = _lock(root_descriptor, uid=trusted_uid, gid=trusted_gid)
        session = _session_descriptor(
            root_descriptor, session_id, uid=trusted_uid, gid=trusted_gid,
            create=False)
        values = _events(session, uid=trusted_uid, gid=trusted_gid)
        if not values:
            raise NativeCodexRunJournalError("native_codex_journal_empty")
        return values[-1]
    finally:
        if session >= 0:
            os.close(session)
        if lock >= 0:
            os.close(lock)
        os.close(root_descriptor)


def boot_id_sha256(path: Path = BOOT_ID) -> str:
    raw = path.read_bytes()
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise NativeCodexRunJournalError("native_codex_journal_boot_invalid") from error
    if UUID4.fullmatch(value) is None or raw != (value + "\n").encode("ascii"):
        raise NativeCodexRunJournalError("native_codex_journal_boot_invalid")
    return hashlib.sha256(raw).hexdigest()


def process_start_time(pid: int, *, proc_root: Path = Path("/proc")) -> int:
    raw = (proc_root / str(pid) / "stat").read_text(encoding="ascii")
    close = raw.rfind(") ")
    fields = raw[close + 2:].split() if close >= 1 else []
    if len(fields) < 20:
        raise NativeCodexRunJournalError("native_codex_journal_process_invalid")
    try:
        value = int(fields[19])
    except ValueError as error:
        raise NativeCodexRunJournalError("native_codex_journal_process_invalid") from error
    if value < 1:
        raise NativeCodexRunJournalError("native_codex_journal_process_invalid")
    return value


def prove_absence(*, session_id: str, scope_unit: str,
                  process_id: int | None, process_start_time_ticks: int | None,
                  egress_evidence_sha256: str,
                  session_state_root: Path = SESSION_STATE_ROOT,
                  proc_root: Path = Path("/proc"), systemctl: Path = SYSTEMCTL,
                  cgroup_root: Path = CGROUP_ROOT,
                  runner: Any = subprocess.run) -> str:
    if (UUID4.fullmatch(session_id) is None
            or SHA256.fullmatch(egress_evidence_sha256) is None):
        raise NativeCodexRunJournalError("native_codex_absence_request_invalid")
    result = runner(
        [str(systemctl), "show", scope_unit,
         "--property=LoadState,ActiveState,SubState,ControlGroup"], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    if result.returncode not in {0, 4} or len(result.stdout) > 16 * 1024:
        raise NativeCodexRunJournalError("native_codex_absence_scope_ambiguous")
    fields: dict[str, str] = {}
    try:
        for raw_line in result.stdout.decode("ascii").splitlines():
            if "=" not in raw_line:
                raise NativeCodexRunJournalError(
                    "native_codex_absence_scope_ambiguous")
            name, content = raw_line.split("=", 1)
            if name in fields:
                raise NativeCodexRunJournalError(
                    "native_codex_absence_scope_ambiguous")
            fields[name] = content
    except UnicodeDecodeError as error:
        raise NativeCodexRunJournalError(
            "native_codex_absence_scope_ambiguous") from error
    if result.returncode == 4:
        if fields:
            raise NativeCodexRunJournalError(
                "native_codex_absence_scope_ambiguous")
        scope_observation = "not-found"
    else:
        if set(fields) != {"LoadState", "ActiveState", "SubState", "ControlGroup"}:
            raise NativeCodexRunJournalError(
                "native_codex_absence_scope_ambiguous")
        if fields["ActiveState"] not in {"inactive", "failed"}:
            raise NativeCodexRunJournalError(
                "native_codex_absence_scope_ambiguous")
        control_group = fields["ControlGroup"]
        if control_group:
            if (not control_group.startswith("/")
                    or ".." in Path(control_group).parts
                    or not control_group.endswith("/" + scope_unit)):
                raise NativeCodexRunJournalError(
                    "native_codex_absence_scope_ambiguous")
            processes = cgroup_root / control_group.lstrip("/") / "cgroup.procs"
            try:
                raw_processes = processes.read_bytes()
            except FileNotFoundError:
                raw_processes = b""
            if raw_processes.strip():
                raise NativeCodexRunJournalError(
                    "native_codex_absence_scope_processes_live")
        scope_observation = hashlib.sha256(result.stdout).hexdigest()
    if process_id is not None:
        try:
            observed_start = process_start_time(process_id, proc_root=proc_root)
        except FileNotFoundError:
            observed_start = None
        if observed_start == process_start_time_ticks:
            raise NativeCodexRunJournalError("native_codex_absence_process_live")
    session_root_descriptor = -1
    try:
        session_root_descriptor = os.open(
            session_state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            session_info = os.stat(
                session_id, dir_fd=session_root_descriptor,
                follow_symlinks=False)
        except FileNotFoundError:
            session_info = None
    except FileNotFoundError:
        session_info = None
    finally:
        if session_root_descriptor >= 0:
            os.close(session_root_descriptor)
    if session_info is not None:
        raise NativeCodexRunJournalError("native_codex_absence_session_state_live")
    return digest({
        "session_id": session_id, "scope_unit": scope_unit,
        "process_id": process_id,
        "process_start_time_ticks": process_start_time_ticks,
        "egress_evidence_sha256": egress_evidence_sha256,
        "scope_observation": scope_observation,
        "state": "absent",
    })
