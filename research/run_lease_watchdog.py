#!/usr/bin/env python3
"""Terminate the exact tagged Claude process group when a run lease expires."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import pwd
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

RUN_DIRECTORY = Path("/run/secure-sandbox")
LIFECYCLE_DIRECTORY = Path("/var/lib/secure-sandbox/run-lifecycle")
LIFECYCLE_FILE = LIFECYCLE_DIRECTORY / "active.json"
FAILURE_FILE = LIFECYCLE_DIRECTORY / "failure-latched.json"
EXECUTION_APPROVAL_MIGRATION_FENCE = (
    LIFECYCLE_DIRECTORY / "execution-approval-migration-fence.json"
)
EXECUTION_APPROVAL_ACCEPTANCE_PERMIT = (
    LIFECYCLE_DIRECTORY / "execution-approval-acceptance-permit.json"
)
COMPLETED_DIRECTORY = LIFECYCLE_DIRECTORY / "completed"
CAPTURE_RECEIPTS = LIFECYCLE_DIRECTORY / "capture-receipts"
CAPTURE = "/usr/local/libexec/secure-sandbox/conversation_capture.py"
CAPTURE_RECIPIENT = "/etc/secure-sandbox/conversation-recipient.txt"
SYSTEMCTL = "/usr/bin/systemctl"
CGROUP_ROOT = Path("/sys/fs/cgroup")
RUN_ID_FILE = RUN_DIRECTORY / "run-id"
EVIDENCE_RUN_ID_FILE = RUN_DIRECTORY / "evidence-run-id"
LEASE_FILE = RUN_DIRECTORY / "run-lease.json"
PROCESS_FILE = RUN_DIRECTORY / "run-process.json"
LOCK_FILE = RUN_DIRECTORY / "run-lease.lock"
CLOSE_LOCK_FILE = RUN_DIRECTORY / "run-close.lock"
PROC = Path("/proc")
SCHEMA = "secure-sandbox-research-run-lease-v1"
LIFECYCLE_SCHEMA = "secure-sandbox-run-lifecycle-v2"
TRUSTED_UID = 0
INSTALL_PENDING = Path("/var/lib/secure-sandbox/policy-backups/run-leases-research-install.pending")


def canonical_uuid4(value: str, name: str) -> str:
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return str(parsed)


def atomic_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o755 if path.parent == LIFECYCLE_DIRECTORY else 0o700,
                      parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chown(temporary, 0, 0); os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def atomic_text(path: Path, value: str, mode: int = 0o644) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, value.encode("ascii")); os.fsync(descriptor)
        os.fchmod(descriptor, mode); os.fchown(descriptor, 0, 0)
    finally:
        os.close(descriptor)
    os.replace(temporary, path); fsync_directory(path.parent)


def load_root_json(path: Path, schema: str, mode: int = 0o600) -> dict[str, Any]:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != TRUSTED_UID
            or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_nlink != 1):
        raise PermissionError(f"invalid {path.name} ownership or mode")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError(f"invalid {path.name} schema")
    return value


def lifecycle() -> dict[str, Any]:
    value = load_root_json(LIFECYCLE_FILE, LIFECYCLE_SCHEMA, 0o644)
    canonical_uuid4(str(value.get("run_id", "")), "run ID")
    canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    if value.get("phase") not in {"preparing", "active", "closing", "local_closed", "failure_latched"}:
        raise ValueError("invalid lifecycle phase")
    return value


def process_ids_for_uid_strict(uid: int) -> set[int]:
    result: set[int] = set()
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status_text = (entry / "status").read_text(encoding="ascii")
            state_line = next(line for line in status_text.splitlines() if line.startswith("State:"))
            uid_line = next(line for line in status_text.splitlines() if line.startswith("Uid:"))
            real_uid = int(uid_line.split()[1])
            if real_uid == uid and "Z" not in state_line.split()[1]:
                result.add(int(entry.name))
        except FileNotFoundError:
            continue
        except (OSError, StopIteration, ValueError, IndexError) as error:
            raise RuntimeError("cannot prove agent process inventory") from error
    return result


def unit_name(run_id: str) -> str:
    return "secure-sandbox-run-" + canonical_uuid4(run_id, "run ID") + ".scope"


def unit_cgroup(unit: str) -> Path:
    result = subprocess.run([SYSTEMCTL, "show", "--property=ControlGroup", "--value", unit],
                            capture_output=True, text=True, check=False, timeout=10)
    value = result.stdout.strip()
    if (result.returncode != 0 or value == "/" or not value.startswith("/")
            or ".." in value.split("/") or not unit.startswith("secure-sandbox-run-")
            or not unit.endswith(".scope")):
        raise RuntimeError("cannot resolve run cgroup")
    return CGROUP_ROOT / value.lstrip("/")


def cgroup_populated(path: Path) -> bool:
    values = dict(line.split(maxsplit=1) for line in (path / "cgroup.events").read_text().splitlines())
    if values.get("populated") not in {"0", "1"}:
        raise RuntimeError("invalid cgroup events")
    return values["populated"] == "1"


def kill_run_cgroup(unit: str) -> None:
    path = unit_cgroup(unit)
    if (path / "cgroup.freeze").exists():
        (path / "cgroup.freeze").write_text("1\n", encoding="ascii")
    (path / "cgroup.kill").write_text("1\n", encoding="ascii")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not cgroup_populated(path):
            return
        time.sleep(0.05)
    raise RuntimeError("run cgroup remains populated")


def kill_agent_uid(uid: int) -> None:
    deadline = time.monotonic() + 10
    while True:
        processes = process_ids_for_uid_strict(uid)
        if not processes:
            return
        for pid in processes:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        if time.monotonic() >= deadline:
            raise RuntimeError("agent processes remain after emergency kill")
        time.sleep(0.05)


def stop_agent_user_manager(uid: int) -> None:
    unit = f"user@{uid}.service"
    stopped = subprocess.run([SYSTEMCTL, "stop", unit], capture_output=True, text=True,
                             check=False, timeout=10)
    if stopped.returncode != 0:
        raise RuntimeError("agent user manager did not stop cleanly")
    active = subprocess.run([SYSTEMCTL, "is-active", "--quiet", unit], capture_output=True,
                            text=True, check=False, timeout=5)
    if active.returncode == 0:
        raise RuntimeError("agent user manager remains active")
    subprocess.run([SYSTEMCTL, "reset-failed", unit], capture_output=True, text=True,
                   check=False, timeout=5)
    failed = subprocess.run([SYSTEMCTL, "is-failed", "--quiet", unit], capture_output=True,
                            text=True, check=False, timeout=5)
    if failed.returncode == 0:
        raise RuntimeError("agent user manager failure state could not be cleared")


def capture_operation(command: str, run_id: str) -> dict[str, Any]:
    result = subprocess.run([CAPTURE, "--recipient-file", CAPTURE_RECIPIENT,
                             f"--{command}", run_id], capture_output=True, text=True,
                            check=False, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"conversation capture {command} failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("run_id") != run_id:
        raise RuntimeError(f"invalid conversation capture {command} receipt")
    return value


def recorded_scope_empty(state: dict[str, Any]) -> bool:
    registration = load_root_json(PROCESS_FILE, "secure-sandbox-run-process-v1")
    if (registration.get("run_id") != state.get("run_id")
            or registration.get("lease_id") != state.get("lease_id")
            or registration.get("unit") != state.get("unit")):
        return False
    if registration.get("ready") is False:
        return ("supervisor_pid" not in registration
                or registration.get("scope_empty") is True)
    return (registration.get("ready") is True and registration.get("scope_empty") is True
            and isinstance(registration.get("exit_status"), int)
            and isinstance(registration.get("exited_at"), int))


def await_scope_empty_receipt(state: dict[str, Any], seconds: float = 2.0) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        try:
            if recorded_scope_empty(state):
                return True
        except (FileNotFoundError, PermissionError, ValueError, json.JSONDecodeError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def scope_is_empty(state: dict[str, Any]) -> bool:
    try:
        return not cgroup_populated(unit_cgroup(str(state["unit"])))
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return recorded_scope_empty(state)


def validate_capture_receipt(receipt: dict[str, Any], run_id: str) -> None:
    if receipt.get("run_id") != run_id:
        raise RuntimeError("capture receipt run mismatch")
    sequence = receipt.get("final_sequence")
    chunks = receipt.get("chunks")
    journals = receipt.get("journals")
    prepared = receipt.get("prepared_offsets")
    if (isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0
            or not isinstance(chunks, list) or len(chunks) != sequence
            or not isinstance(journals, list) or not isinstance(prepared, dict)):
        raise RuntimeError("invalid capture receipt structure")
    previous = ""
    for expected, chunk in enumerate(chunks):
        if (not isinstance(chunk, dict) or chunk.get("sequence") != expected
                or not isinstance(chunk.get("journal_identity"), str)
                or isinstance(chunk.get("start_offset"), bool)
                or not isinstance(chunk.get("start_offset"), int)
                or isinstance(chunk.get("end_offset"), bool)
                or not isinstance(chunk.get("end_offset"), int)
                or chunk["start_offset"] < 0 or chunk["end_offset"] <= chunk["start_offset"]
                or len(str(chunk.get("cipher_sha256", ""))) != 64
                or any(character not in "0123456789abcdef"
                       for character in str(chunk.get("cipher_sha256", "")))):
            raise RuntimeError("invalid capture receipt chunk")
        previous = str(chunk["cipher_sha256"])
    if receipt.get("final_cipher_sha256") != previous:
        raise RuntimeError("capture receipt chain head mismatch")
    for identity, offset in prepared.items():
        if not isinstance(identity, str) or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise RuntimeError("invalid prepared capture offset")
    final_identities: set[str] = set()
    for journal in journals:
        if (not isinstance(journal, dict) or not isinstance(journal.get("identity"), str)
                or isinstance(journal.get("snapshot_size"), bool)
                or not isinstance(journal.get("snapshot_size"), int)
                or journal.get("final_offset") != journal.get("snapshot_size")
                or journal["snapshot_size"] < 0):
            raise RuntimeError("capture receipt does not prove terminal offsets")
        if journal["identity"] in final_identities:
            raise RuntimeError("duplicate journal in capture receipt")
        final_identities.add(journal["identity"])
    if not set(prepared).issubset(final_identities):
        raise RuntimeError("prepared journal missing from capture receipt")
    if any(str(chunk["journal_identity"]) not in final_identities for chunk in chunks):
        raise RuntimeError("capture chunk lacks a terminal journal proof")


def validated_snapshot(lease: dict[str, Any]) -> dict[str, Any]:
    state = lifecycle()
    if (state.get("run_id") != lease.get("run_id")
            or state.get("lease_id") != lease.get("lease_id")):
        raise RuntimeError("lease and lifecycle identity mismatch")
    phase = state.get("phase")
    if phase not in {"active", "closing", "local_closed"}:
        raise RuntimeError("lease has invalid lifecycle phase")
    if phase == "active":
        try:
            metadata = RUN_ID_FILE.lstat()
            marker = RUN_ID_FILE.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise RuntimeError("active admission marker mismatch") from error
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != TRUSTED_UID
                or stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_nlink != 1
                or marker != lease.get("run_id")):
            raise RuntimeError("active admission marker mismatch")
    return state


def latch_failure(run_id: str, operation: str, error: BaseException) -> None:
    value = {"schema":LIFECYCLE_SCHEMA,"phase":"failure_latched","run_id":run_id,
             "operation":operation,"error":type(error).__name__,"latched_at":int(time.time())}
    atomic_json(FAILURE_FILE, value)
    try:
        current = lifecycle(); current.update(value); atomic_json(LIFECYCLE_FILE, current, 0o644)
    except Exception:
        pass


@contextlib.contextmanager
def lease_lock():
    descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextlib.contextmanager
def close_lock():
    descriptor = os.open(CLOSE_LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def arm(run_id: str, lease_id: str, expires_at: int,
        session_id: str | None = None) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    lease_id = canonical_uuid4(lease_id, "lease ID")
    session_id = canonical_uuid4(session_id or run_id, "session ID")
    if expires_at <= int(time.time()):
        raise ValueError("lease expiry must be in the future")
    with lease_lock():
        acceptance = None
        if EXECUTION_APPROVAL_MIGRATION_FENCE.exists():
            try:
                permit = load_root_json(
                    EXECUTION_APPROVAL_ACCEPTANCE_PERMIT,
                    "secure-sandbox-execution-approval-acceptance-permit-v1",
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                raise PermissionError(
                    "execution approval migration has closed Research admission"
                ) from error
            required = {
                "schema", "status", "transaction_id", "generation_id", "generation_epoch",
                "run_id", "session_id", "source_id", "code_sha256",
                "fixture_manifest_sha256", "timeout_seconds", "runtime_image_id", "expires_at",
                "acceptance_attempt_id", "acceptance_attempt_number",
                "previous_acceptance_binding_sha256", "acceptance_binding_sha256",
            }
            now = int(time.time())
            if (set(permit) != required or permit.get("status") != "ready"
                    or permit.get("run_id") != run_id or permit.get("session_id") != session_id
                    or not isinstance(permit.get("expires_at"), int)
                    or permit["expires_at"] < now or expires_at > permit["expires_at"]):
                raise PermissionError("execution approval migration has closed Research admission")
            acceptance = {name:permit[name] for name in permit if name not in {"schema", "status"}}
        if (INSTALL_PENDING.exists() or LEASE_FILE.exists() or LIFECYCLE_FILE.exists() or FAILURE_FILE.exists()
                or RUN_ID_FILE.exists() or EVIDENCE_RUN_ID_FILE.exists()):
            raise FileExistsError("a Research run lease is already armed")
        agent_uid = pwd.getpwnam("agent").pw_uid
        if process_ids_for_uid_strict(agent_uid):
            raise RuntimeError("agent processes exist before run arm")
        value = {"schema": SCHEMA, "run_id": run_id, "lease_id": lease_id, "expires_at": expires_at}
        state = {"schema":LIFECYCLE_SCHEMA,"phase":"preparing","run_id":run_id,
                 "session_id":session_id,
                 "lease_id":lease_id,"expires_at":expires_at,"unit":unit_name(run_id),
                 "preparing_at":int(time.time())}
        if acceptance is not None:
            state["execution_approval_acceptance"] = acceptance
        atomic_json(LIFECYCLE_FILE, state, 0o644)
        try:
            capture_operation("prepare", run_id)
            atomic_json(LEASE_FILE, value)
            process = {"schema": "secure-sandbox-run-process-v1", "run_id": run_id,
                       "lease_id": lease_id, "ready": False, "unit":unit_name(run_id)}
            atomic_json(PROCESS_FILE, process)
            state["phase"] = "active"; state["armed_at"] = int(time.time())
            atomic_json(LIFECYCLE_FILE, state, 0o644)
            atomic_text(RUN_ID_FILE, run_id + "\n")
            if acceptance is not None:
                atomic_json(
                    EXECUTION_APPROVAL_ACCEPTANCE_PERMIT,
                    {**permit, "status":"consumed", "consumed_at":int(time.time())},
                )
        except Exception as error:
            try: LEASE_FILE.unlink()
            except FileNotFoundError: pass
            try: PROCESS_FILE.unlink()
            except FileNotFoundError: pass
            latch_failure(run_id, "arm", error)
            raise
        return value


def _close(run_id: str, require_expired: bool = False) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    state: dict[str, Any]
    with lease_lock():
        state = lifecycle()
        if state["run_id"] != run_id:
            raise PermissionError("lifecycle belongs to another run")
        if require_expired and int(time.time()) < int(load_lease()["expires_at"]):
            return state
        if state["phase"] == "local_closed":
            return state
        try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
        except FileNotFoundError: pass
        state["phase"] = "closing"; state["admission_revoked_at"] = int(time.time())
        atomic_json(LIFECYCLE_FILE, state, 0o644)
    # Do not hold the lifecycle lock while the scope supervisor records its
    # terminal receipt or while capture takes its independent lock.
    try:
        cgroup_error = None
        try: kill_run_cgroup(str(state["unit"]))
        except Exception as error: cgroup_error = error
        agent_uid = pwd.getpwnam("agent").pw_uid
        user_manager_error = None
        try: stop_agent_user_manager(agent_uid)
        except Exception as error: user_manager_error = error
        # A clean systemd stop is the normal path.  The strict UID sweep remains
        # the fail-closed backstop and runs even when the manager stop fails.
        kill_agent_uid(agent_uid)
        if user_manager_error is not None:
            raise RuntimeError("agent user manager cleanup failed") from user_manager_error
        if cgroup_error is not None and not await_scope_empty_receipt(state):
            raise RuntimeError("run cgroup closure was not proven") from cgroup_error
        receipt = capture_operation("finalize", run_id)
        with lease_lock():
            current = lifecycle()
            if (current.get("run_id") != run_id or current.get("lease_id") != state.get("lease_id")
                    or current.get("phase") not in {"closing", "local_closed"}):
                raise RuntimeError("lifecycle changed during close")
            current["phase"] = "local_closed"; current["local_closed_at"] = int(time.time())
            current["capture_receipt"] = str(CAPTURE_RECEIPTS / f"{run_id}.json")
            current["capture_final_sequence"] = receipt.get("final_sequence")
            atomic_json(LIFECYCLE_FILE, current, 0o644)
            return current
    except Exception as error:
        latch_failure(run_id, "close", error)
        raise


def close(run_id: str, require_expired: bool = False) -> dict[str, Any]:
    with close_lock():
        return _close(run_id, require_expired)


def disarm(run_id: str) -> None:
    close(run_id)


def _commit(run_id: str, gateway_summary_sha256: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    if len(gateway_summary_sha256) != 64 or any(c not in "0123456789abcdef" for c in gateway_summary_sha256):
        raise ValueError("invalid Gateway summary digest")
    with lease_lock():
        state = lifecycle()
        if state["run_id"] != run_id or state["phase"] != "local_closed":
            raise RuntimeError("run is not locally closed")
        if not scope_is_empty(state):
            raise RuntimeError("run cgroup is not proven empty during commit")
        if process_ids_for_uid_strict(pwd.getpwnam("agent").pw_uid):
            raise RuntimeError("agent processes remain during commit")
        receipt = load_root_json(CAPTURE_RECEIPTS / f"{run_id}.json",
                                 "secure-sandbox-capture-final-v1")
        validate_capture_receipt(receipt, run_id)
        if FAILURE_FILE.exists():
            failure = load_root_json(FAILURE_FILE, LIFECYCLE_SCHEMA)
            if failure.get("run_id") != run_id:
                raise RuntimeError("failure latch belongs to another run")
        completed = {**state,"phase":"committed","committed_at":int(time.time()),
                     "gateway_summary_sha256":gateway_summary_sha256}
        atomic_json(COMPLETED_DIRECTORY / f"{run_id}.json", completed)
        for path in (LEASE_FILE, PROCESS_FILE, LIFECYCLE_FILE, FAILURE_FILE):
            try: path.unlink()
            except FileNotFoundError: pass
        fsync_directory(LIFECYCLE_DIRECTORY)
        return completed


def commit(run_id: str, gateway_summary_sha256: str) -> dict[str, Any]:
    with close_lock():
        return _commit(run_id, gateway_summary_sha256)


def status(run_id: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        state = lifecycle()
        if state["run_id"] != run_id:
            raise PermissionError("lifecycle belongs to another run")
        return state


def emergency() -> dict[str, Any]:
    agent_uid = pwd.getpwnam("agent").pw_uid
    state: dict[str, Any] | None = None
    try:
        state = lifecycle()
        return close(str(state["run_id"]))
    except Exception as error:
        try: kill_agent_uid(agent_uid)
        finally: latch_failure(str(state["run_id"]) if state is not None else "unknown",
                               "emergency", error)
        raise


def renew(run_id: str, lease_id: str, expires_at: int) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    lease_id = canonical_uuid4(lease_id, "lease ID")
    with lease_lock():
        value = load_lease()
        if value["run_id"] != run_id or value["lease_id"] != lease_id:
            raise PermissionError("armed lease identity mismatch")
        if expires_at <= int(value["expires_at"]):
            raise ValueError("renewed expiry must increase")
        state = lifecycle()
        if (state["run_id"] != run_id or state["lease_id"] != lease_id
                or state["phase"] != "active"):
            raise PermissionError("active lifecycle identity mismatch")
        state["expires_at"] = expires_at
        atomic_json(LIFECYCLE_FILE, state, 0o644)
        value["expires_at"] = expires_at
        atomic_json(LEASE_FILE, value)
        return value


def expire(run_id: str) -> dict[str, Any]:
    run_id = canonical_uuid4(run_id, "run ID")
    with lease_lock():
        value = load_lease()
        if value["run_id"] != run_id:
            raise PermissionError("armed lease belongs to another run")
        value["expires_at"] = int(time.time()) + 1
        atomic_json(LEASE_FILE, value)
        return value


def load_lease() -> dict[str, Any]:
    metadata = LEASE_FILE.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("invalid Research lease ownership or mode")
    descriptor = os.open(LEASE_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle: value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("invalid Research lease schema")
    canonical_uuid4(str(value.get("run_id", "")), "run ID")
    canonical_uuid4(str(value.get("lease_id", "")), "lease ID")
    if not isinstance(value.get("expires_at"), int):
        raise ValueError("invalid Research lease expiry")
    return value


def watch() -> None:
    agent_uid = pwd.getpwnam("agent").pw_uid
    while True:
        lease = None
        state = None
        recovery_close = False
        state_error: BaseException | None = None
        with lease_lock():
            try:
                state = lifecycle()
            except FileNotFoundError:
                if RUN_ID_FILE.exists() or process_ids_for_uid_strict(agent_uid):
                    error = RuntimeError("durable lifecycle disappeared while admission or agent processes remained")
                    try:
                        try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
                        except FileNotFoundError: pass
                        kill_agent_uid(agent_uid)
                    finally: latch_failure("unknown", "watch", error)
                    raise error
            except Exception as error:
                print(json.dumps({"event":"lease_watchdog_failed","error":type(error).__name__}, separators=(",", ":")), flush=True)
                run_id = "unknown"
                try: run_id = lifecycle()["run_id"]
                except Exception: pass
                try:
                    try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
                    except FileNotFoundError: pass
                    kill_agent_uid(agent_uid)
                finally: latch_failure(run_id, "watch", error)
                raise
            if state is not None:
                phase = str(state["phase"])
                try:
                    lease = load_lease()
                    if (lease.get("run_id") != state.get("run_id")
                            or lease.get("lease_id") != state.get("lease_id")):
                        raise RuntimeError("lease and lifecycle identity mismatch")
                    if phase in {"active", "closing", "local_closed"}:
                        validated_snapshot(lease)
                except FileNotFoundError:
                    if phase in {"preparing", "active", "closing"}:
                        recovery_close = True
                    elif phase not in {"local_closed", "failure_latched"}:
                        raise
                except Exception as error:
                    try: RUN_ID_FILE.unlink(); fsync_directory(RUN_ID_FILE.parent)
                    except FileNotFoundError: pass
                    recovery_close = True
                    lease = None
                    state_error = error
        if lease is None:
            if recovery_close and state is not None:
                close(str(state["run_id"]))
                if state_error is not None:
                    latch_failure(str(state["run_id"]), "watch_state", state_error)
                    print(json.dumps({"event":"lease_watchdog_state_latched",
                                      "run_id":state["run_id"],
                                      "error":type(state_error).__name__},
                                     separators=(",", ":"), sort_keys=True), flush=True)
            time.sleep(0.5)
            continue
        assert state is not None
        if state["phase"] == "failure_latched":
            time.sleep(0.5)
            continue
        if state["phase"] in {"closing", "local_closed"}:
            if state["phase"] == "closing":
                state = close(str(lease["run_id"]))
            while LIFECYCLE_FILE.exists():
                time.sleep(0.5)
            continue
        now = int(time.time())
        if now < lease["expires_at"]:
            time.sleep(min(1, lease["expires_at"] - now)); continue
        state = close(lease["run_id"], require_expired=True)
        if state.get("phase") == "local_closed":
            print(json.dumps({"event":"lease_watchdog_expired","run_id":lease["run_id"],
                              "lease_id":lease["lease_id"]}, separators=(",", ":"), sort_keys=True), flush=True)
            while LIFECYCLE_FILE.exists():
                time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command")
    arm_parser = sub.add_parser("arm"); arm_parser.add_argument("run_id"); arm_parser.add_argument("lease_id"); arm_parser.add_argument("expires_at", type=int); arm_parser.add_argument("session_id", nargs="?")
    disarm_parser = sub.add_parser("disarm"); disarm_parser.add_argument("run_id")
    close_parser = sub.add_parser("close"); close_parser.add_argument("run_id")
    commit_parser = sub.add_parser("commit"); commit_parser.add_argument("run_id"); commit_parser.add_argument("gateway_summary_sha256")
    status_parser = sub.add_parser("status"); status_parser.add_argument("run_id")
    sub.add_parser("emergency")
    renew_parser = sub.add_parser("renew"); renew_parser.add_argument("run_id"); renew_parser.add_argument("lease_id"); renew_parser.add_argument("expires_at", type=int)
    expire_parser = sub.add_parser("expire"); expire_parser.add_argument("run_id")
    args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit("run lease watchdog requires root")
    if args.command == "arm": print(json.dumps(arm(args.run_id, args.lease_id, args.expires_at, args.session_id), separators=(",", ":"), sort_keys=True))
    elif args.command == "disarm": disarm(args.run_id)
    elif args.command == "close": print(json.dumps(close(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command == "commit": print(json.dumps(commit(args.run_id, args.gateway_summary_sha256), separators=(",", ":"), sort_keys=True))
    elif args.command == "status": print(json.dumps(status(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command == "emergency": print(json.dumps(emergency(), separators=(",", ":"), sort_keys=True))
    elif args.command == "renew": print(json.dumps(renew(args.run_id, args.lease_id, args.expires_at), separators=(",", ":"), sort_keys=True))
    elif args.command == "expire": print(json.dumps(expire(args.run_id), separators=(",", ":"), sort_keys=True))
    elif args.command is None: watch()
    else: raise SystemExit(2)


if __name__ == "__main__": main()

