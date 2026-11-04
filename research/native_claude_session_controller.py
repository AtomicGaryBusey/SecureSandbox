#!/usr/bin/env python3
"""Root-only no-capture native Claude session supervisor.

The controller rebuilds runtime authority from protected state, resolves effort
from the canonical catalog, and relays the unmodified Claude terminal through
an opaque PTY. Production admission stays closed until an exact live isolation
qualification is available; requests cannot select or bypass that gate.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import pty
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import termios
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from research import native_claude_adapter as adapter
from research import native_codex_run_journal as run_journal
from research import native_codex_session_controller as lifecycle
from research import native_lifecycle_fence
from research import native_provider_controller as provider
from shared import native_vendor_stack


STATE_ROOT = Path("/run/secure-sandbox/native-claude/session-state")
PREPARATION_ROOT = Path("/run/secure-sandbox/native-claude/preparations")
JOURNAL_ROOT = Path(
    "/var/lib/secure-sandbox/native-vendor/controller/native-claude-runs")
WORKSPACE = Path("/home/agent/research-workspace")
PREPARE_REQUEST_SCHEMA = "secure-sandbox-native-claude-session-prepare-request-v1"
PREPARE_REPLY_SCHEMA = "secure-sandbox-native-claude-session-prepare-reply-v1"
PREPARE_STATE_SCHEMA = "secure-sandbox-native-claude-session-prepare-state-v1"
STOP_REQUEST_SCHEMA = "secure-sandbox-native-claude-session-stop-request-v1"
STOP_REPLY_SCHEMA = "secure-sandbox-native-claude-session-stop-reply-v1"
STATUS_REQUEST_SCHEMA = "secure-sandbox-native-claude-session-status-request-v1"
STATUS_REPLY_SCHEMA = "secure-sandbox-native-claude-session-status-reply-v1"
MAX_REQUEST_BYTES = 128 * 1024
MAX_PREPARATIONS = 4096
MAXIMUM_SESSION_SECONDS = 4 * 60 * 60
UUID4 = provider.UUID4
SHA256 = provider.SHA256


class NativeClaudeSessionError(RuntimeError):
    """Stable fail-closed native Claude session error."""


def canonical(value: object) -> bytes:
    try:
        raw = adapter.canonical_bytes(value)
    except adapter.NativeClaudeAdapterError as error:
        raise NativeClaudeSessionError(
            "native_claude_session_value_invalid") from error
    if len(raw) > MAX_REQUEST_BYTES:
        raise NativeClaudeSessionError("native_claude_session_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def deny_unqualified(_authority: Mapping[str, Any]) -> str:
    raise NativeClaudeSessionError(
        "native_claude_live_isolation_qualification_required")


def validate_prepare_request(value: object) -> dict[str, Any]:
    fields = {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "session_id", "runtime_authority", "resume_session_id",
        "request_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeClaudeSessionError(
            "native_claude_session_prepare_fields_invalid")
    if value["schema"] != PREPARE_REQUEST_SCHEMA:
        raise NativeClaudeSessionError(
            "native_claude_session_prepare_schema_invalid")
    for name in ("operation_id", "session_id"):
        if not isinstance(value[name], str) or UUID4.fullmatch(value[name]) is None:
            raise NativeClaudeSessionError(
                f"native_claude_session_prepare_{name}_invalid")
    resume = value["resume_session_id"]
    if resume is not None and (
        not isinstance(resume, str) or UUID4.fullmatch(resume) is None
    ):
        raise NativeClaudeSessionError(
            "native_claude_session_prepare_resume_session_id_invalid")
    if resume is not None and resume == value["session_id"]:
        raise NativeClaudeSessionError(
            "native_claude_session_prepare_resume_binding_mismatch")
    for name in ("plan_sha256", "authorization_sha256", "request_sha256"):
        if not isinstance(value[name], str) or SHA256.fullmatch(value[name]) is None:
            raise NativeClaudeSessionError(
                f"native_claude_session_prepare_{name}_invalid")
    authority = adapter.require_claude_authority(value["runtime_authority"])
    if authority["session_context_binding"]["session_id"] != value["session_id"]:
        raise NativeClaudeSessionError(
            "native_claude_session_prepare_authority_mismatch")
    body = {name: value[name] for name in fields - {"schema", "request_sha256"}}
    if value["request_sha256"] != digest(body):
        raise NativeClaudeSessionError(
            "native_claude_session_prepare_digest_mismatch")
    return value


def _resume_authority_matches(
    prior: Mapping[str, Any], current: Mapping[str, Any],
) -> bool:
    """Require the same authority except for the newly allocated session ID."""
    if (prior.get("model_stack_binding") != current.get("model_stack_binding")
            or prior.get("harness_binding") != current.get("harness_binding")):
        return False
    prior_context = prior.get("session_context_binding")
    current_context = current.get("session_context_binding")
    if not isinstance(prior_context, Mapping) or not isinstance(
        current_context, Mapping
    ):
        return False
    fields = {
        "source_id", "source_manifest_sha256", "persona_sha256",
        "tool_catalog_sha256", "extension_set_sha256",
    }
    return all(prior_context.get(field) == current_context.get(field)
               for field in fields)


def validate_control_request(value: object, *, status: bool) -> dict[str, Any]:
    fields = ({"schema", "operation_id", "session_id",
               "runtime_authority_sha256", "request_sha256"} if status else {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "session_id", "runtime_authority_sha256", "request_sha256",
    })
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeClaudeSessionError(
            "native_claude_session_control_fields_invalid")
    if value["schema"] != (STATUS_REQUEST_SCHEMA if status else STOP_REQUEST_SCHEMA):
        raise NativeClaudeSessionError(
            "native_claude_session_control_schema_invalid")
    for name in ("operation_id", "session_id"):
        if not isinstance(value[name], str) or UUID4.fullmatch(value[name]) is None:
            raise NativeClaudeSessionError(
                f"native_claude_session_control_{name}_invalid")
    digests = {"runtime_authority_sha256", "request_sha256"}
    if not status:
        digests.update({"plan_sha256", "authorization_sha256"})
    for name in digests:
        if not isinstance(value[name], str) or SHA256.fullmatch(value[name]) is None:
            raise NativeClaudeSessionError(
                f"native_claude_session_control_{name}_invalid")
    body = {name: value[name] for name in fields - {"schema", "request_sha256"}}
    if value["request_sha256"] != digest(body):
        raise NativeClaudeSessionError(
            "native_claude_session_control_digest_mismatch")
    return value


def admitted_runtime(
    authority_value: object, *, catalog_path: Path = provider.CATALOG_PATH,
    runtime_loader: Callable[[str], dict[str, str]] = provider.generation_runtime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], str]:
    """Rebuild authority and resolve exact effort from protected catalog."""
    authority = adapter.require_claude_authority(authority_value)
    native = authority["model_stack_binding"]["authority"]
    stack, _ = provider.load_stack(
        native["stack_sha256"], catalog_path=catalog_path)
    generation = stack["harness"]["generation_id"]
    if generation is None:
        raise NativeClaudeSessionError(
            "native_claude_session_harness_not_selected")
    harness = runtime_loader(generation)
    context = authority["session_context_binding"]
    expected = provider.make_authority(
        stack, harness, session_id=context["session_id"],
        source_id=context["source_id"],
        source_manifest_sha256=context["source_manifest_sha256"],
        persona_sha256=context["persona_sha256"],
        tool_catalog_sha256=context["tool_catalog_sha256"],
        extension_set_sha256=context["extension_set_sha256"])
    if expected != authority:
        raise NativeClaudeSessionError(
            "native_claude_session_authority_readback_mismatch")
    settings = stack["model"]["settings"]
    if native_vendor_stack.sha256(settings) != native["model_settings_sha256"]:
        raise NativeClaudeSessionError(
            "native_claude_session_settings_digest_mismatch")
    effort = settings.get("effort")
    if effort not in {"low", "medium", "high"}:
        raise NativeClaudeSessionError(
            "native_claude_session_effort_invalid")
    return authority, stack, harness, effort


def _open_preparation_root(root: Path, *, uid: int, gid: int) -> int:
    descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        current = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(current.st_mode)
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise NativeClaudeSessionError(
                "native_claude_session_preparation_root_untrusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_preparation(root_fd: int, name: str, *, uid: int,
                      gid: int) -> dict[str, Any]:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= MAX_REQUEST_BYTES):
            raise NativeClaudeSessionError(
                "native_claude_session_preparation_untrusted")
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or os.read(descriptor, 1):
            raise NativeClaudeSessionError(
                "native_claude_session_preparation_changed")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeClaudeSessionError(
            "native_claude_session_preparation_invalid") from error
    expected = {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "session_id", "runtime_authority", "resume_session_id",
        "request_sha256", "prepare_sha256", "qualification_evidence_sha256",
    }
    if (not isinstance(value, dict) or set(value) != expected
            or raw != canonical(value)
            or value.get("schema") != PREPARE_STATE_SCHEMA):
        raise NativeClaudeSessionError(
            "native_claude_session_preparation_invalid")
    body = {key: value[key] for key in expected - {"schema", "prepare_sha256"}}
    if value["prepare_sha256"] != digest(body):
        raise NativeClaudeSessionError(
            "native_claude_session_preparation_digest_mismatch")
    validate_prepare_request({
        "schema": PREPARE_REQUEST_SCHEMA,
        **{key: value[key] for key in (
            "operation_id", "plan_sha256", "authorization_sha256",
            "session_id", "runtime_authority", "resume_session_id",
            "request_sha256")},
    })
    if (not isinstance(value["qualification_evidence_sha256"], str)
            or SHA256.fullmatch(value["qualification_evidence_sha256"]) is None):
        raise NativeClaudeSessionError(
            "native_claude_session_qualification_evidence_invalid")
    return value


def _write_all(descriptor: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        count = os.write(descriptor, remaining)
        if count <= 0:
            raise NativeClaudeSessionError(
                "native_claude_session_preparation_write_failed")
        remaining = remaining[count:]


def prepare_session(
    value: object, *, preparation_root: Path = PREPARATION_ROOT,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    catalog_path: Path = provider.CATALOG_PATH,
    runtime_loader: Callable[[str], dict[str, str]] = provider.generation_runtime,
    qualification_gate: Callable[[Mapping[str, Any]], str] = deny_unqualified,
    journal_root: Path = JOURNAL_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    request = validate_prepare_request(value)
    authority, _stack, _harness, _effort = admitted_runtime(
        request["runtime_authority"], catalog_path=catalog_path,
        runtime_loader=runtime_loader)
    evidence = qualification_gate(authority)
    if not isinstance(evidence, str) or SHA256.fullmatch(evidence) is None:
        raise NativeClaudeSessionError(
            "native_claude_session_qualification_evidence_invalid")
    if request["resume_session_id"] is not None:
        try:
            prior = run_journal.latest(
                request["resume_session_id"], root=journal_root,
                trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        except (FileNotFoundError,
                run_journal.NativeCodexRunJournalError) as error:
            raise NativeClaudeSessionError(
                "native_claude_session_resume_evidence_missing") from error
        if (prior["phase"] != "terminal"
                or not _resume_authority_matches(
                    prior["runtime_authority"], authority)):
            raise NativeClaudeSessionError(
                "native_claude_session_resume_binding_mismatch")
    request_body = {key: request[key] for key in request if key != "schema"}
    state_body = {**request_body, "qualification_evidence_sha256": evidence}
    state = {"schema": PREPARE_STATE_SCHEMA, **state_body,
             "prepare_sha256": digest(state_body)}
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid):
            root_fd = _open_preparation_root(
                preparation_root, uid=trusted_uid, gid=trusted_gid)
            try:
                names = os.listdir(root_fd)
                if (len(names) >= MAX_PREPARATIONS
                        or any(re.fullmatch(
                            r"[0-9a-f-]{36}(?:\.consumed)?\.json", name
                        ) is None for name in names)):
                    raise NativeClaudeSessionError(
                        "native_claude_session_preparation_retention_limit")
                name = f"{request['operation_id']}.json"
                try:
                    descriptor = os.open(
                        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
                except FileExistsError:
                    if _read_preparation(
                        root_fd, name, uid=trusted_uid, gid=trusted_gid
                    ) != state:
                        raise NativeClaudeSessionError(
                            "native_claude_session_prepare_replay_conflict")
                else:
                    try:
                        os.fchown(descriptor, trusted_uid, trusted_gid)
                        os.fchmod(descriptor, 0o600)
                        _write_all(descriptor, canonical(state))
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.fsync(root_fd)
                    if _read_preparation(
                        root_fd, name, uid=trusted_uid, gid=trusted_gid
                    ) != state:
                        raise NativeClaudeSessionError(
                            "native_claude_session_prepare_readback_failed")
            finally:
                os.close(root_fd)
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeClaudeSessionError(str(error)) from error
    return {
        "schema": PREPARE_REPLY_SCHEMA,
        "operation_id": request["operation_id"],
        "prepare_sha256": state["prepare_sha256"],
        "evidence_sha256": digest({
            "operation_id": request["operation_id"],
            "prepare_sha256": state["prepare_sha256"],
            "qualification_evidence_sha256": evidence,
        }),
    }


def _claim_preparation(
    operation_id: str, prepare_sha256: str, *, root: Path,
    uid: int, gid: int,
) -> dict[str, Any]:
    if UUID4.fullmatch(operation_id) is None or SHA256.fullmatch(prepare_sha256) is None:
        raise NativeClaudeSessionError(
            "native_claude_session_launch_identity_invalid")
    root_fd = _open_preparation_root(root, uid=uid, gid=gid)
    try:
        source = f"{operation_id}.json"
        consumed = f"{operation_id}.consumed.json"
        try:
            os.stat(consumed, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise NativeClaudeSessionError(
                "native_claude_session_launch_replay_denied")
        value = _read_preparation(root_fd, source, uid=uid, gid=gid)
        if value["prepare_sha256"] != prepare_sha256:
            raise NativeClaudeSessionError(
                "native_claude_session_launch_preparation_invalid")
        before = os.stat(source, dir_fd=root_fd, follow_symlinks=False)
        os.replace(source, consumed, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
        after = os.stat(consumed, dir_fd=root_fd, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise NativeClaudeSessionError(
                "native_claude_session_launch_claim_ambiguous")
        if _read_preparation(root_fd, consumed, uid=uid, gid=gid) != value:
            raise NativeClaudeSessionError(
                "native_claude_session_launch_claim_ambiguous")
        return value
    finally:
        os.close(root_fd)


def _read_control_file(path: Path, *, mode: int, uid: int = 0) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 1 <= before.st_size <= 1024 * 1024):
        raise NativeClaudeSessionError(
            "native_claude_session_control_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
               != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
            or len(raw) != before.st_size):
        raise NativeClaudeSessionError(
            "native_claude_session_control_file_changed")
    return raw


def _make_session_layout(session_id: str, *, root: Path, uid: int,
                         gid: int, trusted_uid: int, trusted_gid: int) -> Path:
    lifecycle._require_directory(
        root, uid=trusted_uid, gid=trusted_gid, mode=0o700)
    session = root / session_id
    session.mkdir(mode=0o700)
    os.chown(session, trusted_uid, trusted_gid)
    os.chmod(session, 0o700)
    for name in ("home", "cache", "tmp"):
        item = session / name
        item.mkdir(mode=0o700)
        os.chown(item, uid, gid)
        os.chmod(item, 0o700)
    return session


def _copy_terminal_size(source: int, target: int) -> None:
    try:
        size = fcntl.ioctl(source, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(target, termios.TIOCSWINSZ, size)
    except OSError:
        pass


def relay_opaque_pty(
    pid: int, master: int, *, input_fd: int = 0, output_fd: int = 1,
    maximum_seconds: int = MAXIMUM_SESSION_SECONDS,
) -> int:
    """Move bounded byte chunks without parsing or retaining their contents."""
    selector = selectors.DefaultSelector()
    selector.register(master, selectors.EVENT_READ, "vendor")
    selector.register(input_fd, selectors.EVENT_READ, "operator")
    deadline = time.monotonic() + maximum_seconds
    status: int | None = None
    try:
        while time.monotonic() < deadline:
            _copy_terminal_size(input_fd, master)
            if status is None:
                waited, observed = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = observed
            events = selector.select(
                0 if status is not None else min(0.1, deadline - time.monotonic()))
            if not events and status is not None:
                break
            for key, _mask in events:
                try:
                    block = os.read(key.fd, 16 * 1024)
                except OSError as error:
                    if error.errno == errno.EIO and key.data == "vendor":
                        selector.unregister(key.fd)
                        continue
                    raise
                if not block:
                    selector.unregister(key.fd)
                    if key.data == "operator":
                        raise NativeClaudeSessionError(
                            "native_claude_session_operator_eof")
                    continue
                destination = output_fd if key.data == "vendor" else master
                remaining = memoryview(block)
                while remaining:
                    count = os.write(destination, remaining)
                    if count <= 0:
                        raise NativeClaudeSessionError(
                            "native_claude_session_transport_failed")
                    remaining = remaining[count:]
        if status is None:
            raise NativeClaudeSessionError(
                "native_claude_session_run_lease_expired")
        return os.waitstatus_to_exitcode(status)
    finally:
        selector.close()


def _absence(
    latest: Mapping[str, Any], *, egress_sha256: str,
    session_state_root: Path, proc_root: Path,
    prover: Callable[..., str],
) -> str:
    process_id = latest["process_id"]
    start = latest["process_start_time_ticks"]
    try:
        current_boot = run_journal.boot_id_sha256()
    except (OSError, run_journal.NativeCodexRunJournalError):
        current_boot = None
    if current_boot != latest["boot_id_sha256"]:
        process_id = start = None
    return prover(
        session_id=latest["session_id"], scope_unit=latest["scope_unit"],
        process_id=process_id, process_start_time_ticks=start,
        egress_evidence_sha256=egress_sha256,
        session_state_root=session_state_root, proc_root=proc_root)


def _record_ambiguous(
    *, operation_id: str, authority: Mapping[str, Any], unit: str,
    process_id: int | None, process_start: int | None, boot_sha256: str,
    executable_sha256: str, lease_started_at: int, lease_expires_at: int,
    journal_root: Path, trusted_uid: int, trusted_gid: int,
) -> None:
    try:
        latest = run_journal.latest(
            authority["session_context_binding"]["session_id"],
            root=journal_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        if latest["phase"] == "terminal":
            return
        run_journal.append_event(
            phase="ambiguous", transition_operation_id=operation_id,
            authority=authority, scope_unit=unit,
            process_id=process_id, process_start_time_ticks=process_start,
            boot_id_sha256=boot_sha256,
            executable_sha256=executable_sha256,
            lease_started_at=lease_started_at,
            lease_expires_at=lease_expires_at,
            observed_at=max(lease_started_at, int(time.time())),
            exit_code=None, absence_evidence_sha256=None,
            root=journal_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    except Exception:
        pass


def launch_prepared(
    operation_id: str, prepare_sha256: str, *, input_fd: int = 0,
    output_fd: int = 1, preparation_root: Path = PREPARATION_ROOT,
    state_root: Path = STATE_ROOT, journal_root: Path = JOURNAL_ROOT,
    lifecycle_root: Path = native_lifecycle_fence.ROOT,
    catalog_path: Path = provider.CATALOG_PATH,
    runtime_loader: Callable[[str], dict[str, str]] = provider.generation_runtime,
    qualification_gate: Callable[[Mapping[str, Any]], str] = deny_unqualified,
    trusted_uid: int = 0, trusted_gid: int = 0,
    boot_id_path: Path = run_journal.BOOT_ID,
    proc_root: Path = Path("/proc"),
    systemctl: Path = lifecycle.SYSTEMCTL,
    busctl: Path = lifecycle.BUSCTL,
    cgroup_root: Path = lifecycle.CGROUP_ROOT,
    scope_starter: Callable[..., None] = lifecycle.start_transient_scope,
    scope_verifier: Callable[..., dict[str, object]] = lifecycle.verify_transient_scope,
    egress_closer: Callable[[], str] = lifecycle.close_native_egress,
    absence_prover: Callable[..., str] = run_journal.prove_absence,
    relay: Callable[..., int] = relay_opaque_pty,
    now: int | None = None,
) -> int:
    """Consume one preparation and run one scope-bound opaque Claude PTY."""
    if os.geteuid() != trusted_uid:
        raise NativeClaudeSessionError("native_claude_session_root_required")
    timestamp = int(time.time()) if now is None else now
    try:
        with native_lifecycle_fence.admission_open(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid):
            prepared = _claim_preparation(
                operation_id, prepare_sha256, root=preparation_root,
                uid=trusted_uid, gid=trusted_gid)
            authority, _stack, harness, effort = admitted_runtime(
                prepared["runtime_authority"], catalog_path=catalog_path,
                runtime_loader=runtime_loader)
            if qualification_gate(authority) != prepared[
                "qualification_evidence_sha256"]:
                raise NativeClaudeSessionError(
                    "native_claude_session_qualification_changed")
            service = provider._identity(provider.CLAUDE_IDENTITY)
            executable = adapter.executable_for_harness(harness)
            session_id = prepared["session_id"]
            unit = "secure-sandbox-native-run-" + session_id.replace("-", "") + ".scope"
            boot_sha256 = run_journal.boot_id_sha256(boot_id_path)
            executable_sha256 = harness["harness_executable_sha256"]
            lease_expires_at = timestamp + MAXIMUM_SESSION_SECONDS
            persona = _read_control_file(
                adapter.PERSONA, mode=0o444, uid=trusted_uid)
            if hashlib.sha256(persona).hexdigest() != authority[
                "session_context_binding"]["persona_sha256"]:
                raise NativeClaudeSessionError(
                    "native_claude_session_persona_mismatch")
            _read_control_file(
                adapter.MANAGED_SETTINGS, mode=0o444, uid=trusted_uid)
            session = _make_session_layout(
                session_id, root=state_root, uid=service.pw_uid,
                gid=service.pw_gid, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            environment = adapter.child_environment(
                authority, home=session / "home", cache=session / "cache",
                temporary=session / "tmp",
                config_root=provider.CLAUDE_CONFIG_ROOT)
            command = adapter.session_command(
                executable,
                session_id=prepared["resume_session_id"] or session_id,
                effort=effort,
                resume=prepared["resume_session_id"] is not None)
            run_journal.append_event(
                phase="prepared", transition_operation_id=operation_id,
                authority=authority, scope_unit=unit, process_id=None,
                process_start_time_ticks=None, boot_id_sha256=boot_sha256,
                executable_sha256=executable_sha256,
                lease_started_at=timestamp,
                lease_expires_at=lease_expires_at, observed_at=timestamp,
                exit_code=None, absence_evidence_sha256=None,
                root=journal_root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            master, slave = pty.openpty()
            _copy_terminal_size(input_fd, slave)
            child = -1
            process_start: int | None = None
            result = 1
            transport_failure: BaseException | None = None
            try:
                child = os.fork()
                if child == 0:  # pragma: no cover - stopped exec-only child
                    try:
                        lifecycle._child_hardening()
                        os.setsid()
                        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                        os.setgroups([])
                        os.setgid(service.pw_gid)
                        os.setuid(service.pw_uid)
                        os.chdir(WORKSPACE)
                        for descriptor in (0, 1, 2):
                            if slave != descriptor:
                                os.dup2(slave, descriptor)
                        maximum = os.sysconf("SC_OPEN_MAX")
                        os.closerange(3, maximum if maximum > 3 else 1024)
                        os.kill(os.getpid(), signal.SIGSTOP)
                        os.execve(executable, command, environment)
                    except BaseException:
                        os._exit(126)
                os.close(slave)
                slave = -1
                waited, status = os.waitpid(child, os.WUNTRACED)
                if (waited != child or not os.WIFSTOPPED(status)
                        or os.WSTOPSIG(status) != signal.SIGSTOP):
                    raise NativeClaudeSessionError(
                        "native_claude_session_child_gate_failed")
                scope_starter(unit, child, busctl=busctl)
                scope_verifier(
                    unit, launcher_uid=service.pw_uid, systemctl=systemctl,
                    cgroup_root=cgroup_root)
                process_start = run_journal.process_start_time(
                    child, proc_root=proc_root)
                run_journal.append_event(
                    phase="active", transition_operation_id=operation_id,
                    authority=authority, scope_unit=unit, process_id=child,
                    process_start_time_ticks=process_start,
                    boot_id_sha256=boot_sha256,
                    executable_sha256=executable_sha256,
                    lease_started_at=timestamp,
                    lease_expires_at=lease_expires_at,
                    observed_at=max(timestamp, int(time.time())),
                    exit_code=None, absence_evidence_sha256=None,
                    root=journal_root, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid)
                os.kill(child, signal.SIGCONT)
                result = relay(
                    child, master, input_fd=input_fd, output_fd=output_fd,
                    maximum_seconds=MAXIMUM_SESSION_SECONDS)
                child = -1
            except BaseException as error:
                subprocess.run(
                    [str(systemctl), "stop", unit], check=False,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=10,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                if child > 0:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child, 0)
                    except ChildProcessError:
                        pass
                transport_failure = error
            finally:
                if slave >= 0:
                    os.close(slave)
                os.close(master)
                if session.exists() and not session.is_symlink():
                    shutil.rmtree(session)
            latest = run_journal.latest(
                session_id, root=journal_root, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
            try:
                egress = egress_closer()
                absence = _absence(
                    latest, egress_sha256=egress,
                    session_state_root=state_root, proc_root=proc_root,
                    prover=absence_prover)
                run_journal.append_event(
                    phase="terminal", transition_operation_id=operation_id,
                    authority=authority, scope_unit=unit,
                    process_id=latest["process_id"],
                    process_start_time_ticks=latest["process_start_time_ticks"],
                    boot_id_sha256=boot_sha256,
                    executable_sha256=executable_sha256,
                    lease_started_at=timestamp,
                    lease_expires_at=lease_expires_at,
                    observed_at=max(timestamp, int(time.time())),
                    exit_code=result if transport_failure is None else 143,
                    absence_evidence_sha256=absence,
                    root=journal_root, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid)
            except BaseException:
                _record_ambiguous(
                    operation_id=operation_id, authority=authority, unit=unit,
                    process_id=latest["process_id"],
                    process_start=latest["process_start_time_ticks"],
                    boot_sha256=boot_sha256,
                    executable_sha256=executable_sha256,
                    lease_started_at=timestamp,
                    lease_expires_at=lease_expires_at,
                    journal_root=journal_root, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid)
                raise
            if transport_failure is not None:
                raise transport_failure
            return result
    except native_lifecycle_fence.NativeLifecycleFenceError as error:
        raise NativeClaudeSessionError(str(error)) from error


def session_control(
    value: object, *, status: bool, journal_root: Path = JOURNAL_ROOT,
    state_root: Path = STATE_ROOT, trusted_uid: int = 0, trusted_gid: int = 0,
    proc_root: Path = Path("/proc"), systemctl: Path = lifecycle.SYSTEMCTL,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    egress_closer: Callable[[], str] = lifecycle.close_native_egress,
    egress_observer: Callable[[], str] = lifecycle.observe_closed_native_egress,
    absence_prover: Callable[..., str] = run_journal.prove_absence,
) -> dict[str, Any]:
    request = validate_control_request(value, status=status)
    latest = run_journal.latest(
        request["session_id"], root=journal_root,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if latest["runtime_authority_sha256"] != request["runtime_authority_sha256"]:
        raise NativeClaudeSessionError(
            "native_claude_session_control_authority_mismatch")
    if status:
        if latest["phase"] != "terminal":
            raise NativeClaudeSessionError(
                "native_claude_session_not_absent")
        egress = egress_observer()
    else:
        stopped = runner(
            [str(systemctl), "stop", latest["scope_unit"]], check=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if stopped.returncode not in {0, 3, 4, 5}:
            raise NativeClaudeSessionError(
                "native_claude_session_stop_failed")
        egress = egress_closer()
    absence = _absence(
        latest, egress_sha256=egress, session_state_root=state_root,
        proc_root=proc_root, prover=absence_prover)
    if not status and latest["phase"] != "terminal":
        latest = run_journal.append_event(
            phase="terminal", transition_operation_id=request["operation_id"],
            authority=latest["runtime_authority"],
            scope_unit=latest["scope_unit"],
            process_id=latest["process_id"],
            process_start_time_ticks=latest["process_start_time_ticks"],
            boot_id_sha256=latest["boot_id_sha256"],
            executable_sha256=latest["executable_sha256"],
            lease_started_at=latest["lease_started_at"],
            lease_expires_at=latest["lease_expires_at"],
            observed_at=max(latest["observed_at"], int(time.time())),
            exit_code=143, absence_evidence_sha256=absence,
            root=journal_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
    evidence = digest({
        "operation_id": request["operation_id"],
        "session_id": request["session_id"], "state": "absent",
        "runtime_authority_sha256": request["runtime_authority_sha256"],
        "final_summary_sha256": latest["event_sha256"],
        "absence_evidence_sha256": absence,
    })
    return {
        "schema": STATUS_REPLY_SCHEMA if status else STOP_REPLY_SCHEMA,
        "operation_id": request["operation_id"],
        "session_id": request["session_id"], "state": "absent",
        "final_summary_sha256": latest["event_sha256"],
        "evidence_sha256": evidence,
    }


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    try:
        if values in (["prepare"], ["stop"], ["status"]):
            raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
            if not 1 <= len(raw) <= MAX_REQUEST_BYTES:
                raise NativeClaudeSessionError(
                    "native_claude_session_request_size_invalid")
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise NativeClaudeSessionError(
                    "native_claude_session_request_invalid") from error
            if raw != canonical(value):
                raise NativeClaudeSessionError(
                    "native_claude_session_request_not_canonical")
            reply = (prepare_session(value) if values == ["prepare"] else
                     session_control(value, status=values == ["status"]))
            sys.stdout.buffer.write(canonical(reply))
            sys.stdout.buffer.flush()
            return 0
        if (len(values) == 3 and values[0] == "launch"
                and UUID4.fullmatch(values[1]) is not None
                and SHA256.fullmatch(values[2]) is not None):
            return launch_prepared(values[1], values[2])
        return 64
    except (NativeClaudeSessionError, adapter.NativeClaudeAdapterError,
            provider.NativeProviderControllerError,
            run_journal.NativeCodexRunJournalError, OSError, ValueError):
        if values and values[0] == "launch":
            os.write(1, b"\r\nSecureSandbox Claude session failed closed.\r\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
