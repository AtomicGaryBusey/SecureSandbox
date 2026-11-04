#!/usr/bin/env python3
"""Crash-fenced Host controller for native interactive sessions.

Touch ID authorizes one exact session plan.  Preparation obtains a bounded
runtime grant and a one-shot Research handle but keeps egress closed.  The
authenticated terminal claim is the only path that may publish that grant.
Every stream exit, error, or explicit stop first proves the Research process
absent, then closes both guest policy domains, deletes conntrack state, and
independently reads the operational status before terminalizing custody.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping


HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "native_stack_support"
if SUPPORT.is_file():
    sys.path.insert(0, str(SUPPORT))
elif (HERE.parent / "shared/native_stack_session.py").is_file():
    sys.path.insert(0, str(HERE.parent))

try:
    import native_stack_manager as stack_manager
except ModuleNotFoundError:
    from scripts import native_stack_manager as stack_manager

from shared import native_egress
from shared import native_stack_operations
from shared import native_stack_runtime_binding
from shared import native_stack_session
from shared import native_terminal_handle
from shared import native_vendor_stack
from shared import runtime_authority


JOURNAL_SCHEMA = "secure-sandbox-native-stack-session-transaction-v1"
BEGIN_SCHEMA = "secure-sandbox-native-stack-session-stream-begin-v1"
COMPLETION_SCHEMA = "secure-sandbox-native-stack-session-completion-v1"
SESSION_HOST_TICKET_SCHEMA = "secure-sandbox-native-stack-session-host-ticket-v1"
SESSION_CONTINUATION_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-continuation-ticket-v1"
)
SESSION_PREPARE_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-prepare-ticket-v1"
)
SESSION_RECOVERY_TICKET_SCHEMA = (
    "secure-sandbox-native-stack-session-recovery-ticket-v1"
)
STATE_ROOT = Path("/usr/local/var/lib/secure-sandbox/native-stack-sessions")
AUTHORIZATION_RECEIPT_ROOT = Path(
    "/usr/local/var/log/secure-sandbox/authorization-receipts"
)
CATALOG_PATH = Path(
    "/usr/local/var/lib/secure-sandbox/native-stack-catalog/catalog.json"
)
TERMINAL_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-terminal-handles"
)
HOST_BACKEND = HERE / "native_stack_backend"
CONTROL_CLIENT = HERE / "control_client"
SSH_CONFIG = HERE / "ssh_config"
MAX_RECORDS = 256
TERMINAL_PHASES = {"completed", "stopped", "fenced"}


class NativeStackSessionManagerError(RuntimeError):
    """Stable fail-closed session-controller error."""


def canonical(value: object) -> bytes:
    return stack_manager.canonical(value)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "journal_sha256"}


def _safe_error(error: BaseException | str) -> str:
    return stack_manager._safe_error(error)


def session_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    body = {
        "schema": SESSION_HOST_TICKET_SCHEMA,
        "plan": plan, "authorization": authorization,
    }
    return {**body, "ticket_sha256": digest(body)}


def continuation_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any], handle_id: str,
) -> dict[str, Any]:
    body = {
        "schema": SESSION_CONTINUATION_TICKET_SCHEMA,
        "plan": plan, "authorization": authorization,
        "handle_id": handle_id,
    }
    return {**body, "ticket_sha256": digest(body)}


def prepare_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    grant: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": SESSION_PREPARE_TICKET_SCHEMA,
        "plan": plan, "authorization": authorization, "grant": grant,
    }
    return {**body, "ticket_sha256": digest(body)}


def recovery_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    journal_sha256: str,
) -> dict[str, Any]:
    body = {
        "schema": SESSION_RECOVERY_TICKET_SCHEMA,
        "plan": plan, "authorization": authorization,
        "journal_sha256": journal_sha256,
    }
    return {**body, "ticket_sha256": digest(body)}


def _validate_grant(value: object, plan: Mapping[str, Any]) -> dict[str, Any]:
    try:
        grant = native_egress.validate_grant(value)
        authority = runtime_authority.validate_binding(plan["runtime_authority"])
    except (
        native_egress.NativeEgressError,
        runtime_authority.RuntimeAuthorityError,
    ) as error:
        raise NativeStackSessionManagerError(
            "native_stack_session_grant_invalid"
        ) from error
    binding = grant["binding"]
    if (grant["phase"] != native_egress.PHASE_INFERENCE
            or binding["kind"] != "runtime-authority"
            or binding["value"] != authority):
        raise NativeStackSessionManagerError(
            "native_stack_session_grant_mismatch"
        )
    return grant


def validate_journal(value: object) -> dict[str, Any]:
    fields = {
        "schema", "action_id", "session_id", "plan", "authorization",
        "catalog_sha256", "grant", "session_lease", "public_handle", "phase",
        "network_open", "completed_steps", "stop_reply", "error_code",
        "created_at", "updated_at", "journal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_fields_invalid"
        )
    if value["schema"] != JOURNAL_SCHEMA:
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_schema_invalid"
        )
    try:
        plan = native_stack_session.validate_plan(value["plan"])
        authorization = native_stack_session.validate_authorization(
            value["authorization"], plan, now=value["created_at"],
            expected_host_release_id=value["authorization"]["host_release_id"],
            require_fresh=False,
        )
    except native_stack_session.NativeStackSessionError as error:
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_authority_invalid"
        ) from error
    if (plan["action"] != "session-start"
            or value["action_id"] != plan["action_id"]
            or value["session_id"] != plan["session_id"]
            or value["catalog_sha256"] != plan["catalog_sha256"]
            or authorization["plan_sha256"] != plan["plan_sha256"]):
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_authority_mismatch"
        )
    grant = value["grant"]
    if grant is not None:
        _validate_grant(grant, plan)
    lease = value["session_lease"]
    if lease is not None:
        try:
            lease = native_stack_session.validate_session_lease(lease)
        except native_stack_session.NativeStackSessionError as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_lease_invalid"
            ) from error
        if (grant is None
                or lease["lease_profile_id"] != plan["lease_profile_id"]
                or lease["session_id"] != plan["session_id"]
                or lease["runtime_authority_sha256"]
                    != plan["runtime_authority_sha256"]
                or lease["grant_id"] != grant["grant_id"]
                or lease["grant_sha256"] != grant["grant_sha256"]
                or lease["issued_at"] != grant["issued_at"]
                or lease["expires_at"] != grant["expires_at"]):
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_lease_mismatch"
            )
    public = value["public_handle"]
    if public is not None:
        try:
            public = native_terminal_handle.validate_public(public)
        except native_terminal_handle.NativeTerminalHandleError as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_handle_invalid"
            ) from error
        if (public["kind"] != "claude-session"
                or public["operation_id"] != plan["action_id"]
                or public["session_id"] != plan["session_id"]):
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_handle_mismatch"
            )
    if (not isinstance(value["phase"], str)
            or not 1 <= len(value["phase"]) <= 96
            or not isinstance(value["network_open"], bool)
            or (value["network_open"] and (grant is None or lease is None))
            or value["phase"] == "prepared" and public is None):
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_phase_invalid"
        )
    steps = value["completed_steps"]
    if (not isinstance(steps, list) or len(steps) > 96
            or any(not isinstance(item, str) or not 1 <= len(item) <= 96
                   for item in steps)):
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_steps_invalid"
        )
    stop_reply = value["stop_reply"]
    if stop_reply is not None:
        if (not isinstance(stop_reply, dict)
                or stop_reply.get("state") != "absent"
                or stop_reply.get("session_id") != plan["session_id"]
                or native_stack_operations.SHA256.fullmatch(
                    str(stop_reply.get("evidence_sha256", ""))
                ) is None):
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_stop_invalid"
            )
    error = value["error_code"]
    if error is not None and stack_manager.ERROR_CODE.fullmatch(str(error)) is None:
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_error_invalid"
        )
    for field in ("created_at", "updated_at"):
        if (not isinstance(value[field], int) or isinstance(value[field], bool)
                or value[field] < 1):
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_time_invalid"
            )
    supplied = value["journal_sha256"]
    if (not isinstance(supplied, str)
            or native_stack_operations.SHA256.fullmatch(supplied) is None
            or not hmac.compare_digest(supplied, digest(_body(value)))):
        raise NativeStackSessionManagerError(
            "native_stack_session_journal_digest_invalid"
        )
    canonical(value)
    return value


class SessionBackend:
    def __init__(
        self, *, host_backend: Path = HOST_BACKEND,
        control_client: Path = CONTROL_CLIENT, ssh_config: Path = SSH_CONFIG,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> None:
        self.host_backend = host_backend
        self.transport = stack_manager.SubprocessBackend(
            control_client=control_client, ssh_config=ssh_config,
            host_backend=host_backend, runner=runner,
        )

    def _host(
        self, operation: str, plan: Mapping[str, Any],
        authorization: Mapping[str, Any], *, handle_id: str | None = None,
    ) -> dict[str, Any]:
        ticket = (
            session_ticket(plan, authorization)
            if handle_id is None else
            continuation_ticket(plan, authorization, handle_id)
        )
        return self.transport._run(
            [str(self.host_backend), operation], ticket, timeout=300
        )

    def status(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any], *,
        handle_id: str | None = None,
    ) -> dict[str, Any]:
        return self._host(
            "session-status" if handle_id is None
            else "session-status-continuation",
            plan, authorization, handle_id=handle_id,
        )

    def prepare_grant(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._host("session-prepare-grant", plan, authorization)

    def prepare(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        grant: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self.transport._run(
            [str(self.host_backend), "session-prepare"],
            prepare_ticket(plan, authorization, grant), timeout=300,
        )

    def stop_continuation(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        handle_id: str,
    ) -> dict[str, Any]:
        return self._host(
            "session-stop-continuation", plan, authorization,
            handle_id=handle_id,
        )

    def stop(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._host("session-operation", plan, authorization)

    def recover_stop(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        journal_sha256: str,
    ) -> dict[str, Any]:
        return self.transport._run(
            [str(self.host_backend), "session-recover-stop"],
            recovery_ticket(plan, authorization, journal_sha256),
            timeout=300,
        )

    def recover_status(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        journal_sha256: str,
    ) -> dict[str, Any]:
        return self.transport._run(
            [str(self.host_backend), "session-recover-status"],
            recovery_ticket(plan, authorization, journal_sha256),
            timeout=300,
        )

    def rotation_step(
        self, step: str, plan: Mapping[str, Any],
        authorization: Mapping[str, Any], grant: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        try:
            host, operation = self.transport.STEP_OPERATIONS[step]
        except KeyError as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_rotation_step_invalid"
            ) from error
        native = plan["runtime_authority"]["model_stack_binding"]["authority"]
        closed_body = {
            "action_id": plan["action_id"],
            "plan_sha256": plan["plan_sha256"],
            "stack_id": plan["stack_id"], "stack_sha256": plan["stack_sha256"],
            "state": "closed",
        }
        successor: object = (
            grant
            if grant is not None and step in {
                "apply-gateway-successor-policy",
                "apply-research-successor-policy",
            }
            else {
                "schema": stack_manager.CLOSED_POLICY_SCHEMA, **closed_body,
                "policy_sha256": digest(closed_body),
            }
        )
        payload = {
            "schema": "secure-sandbox-native-stack-step-request-v1",
            "action_id": plan["action_id"],
            "plan_sha256": plan["plan_sha256"],
            "authorization_sha256": authorization["authorization_sha256"],
            "step": step, "successor": successor,
        }
        command = [
            str(self.transport.control_client), "client", "--ssh-config",
            str(self.transport.ssh_config), "--timeout-seconds", "180",
            host, "pipe", operation,
        ]
        result = self.transport._run(command, payload)
        expected = {
            "schema", "action_id", "plan_sha256", "authorization_sha256",
            "step", "status", "evidence_sha256",
        }
        if (not isinstance(result, dict) or set(result) != expected
                or result.get("schema") != stack_manager.STEP_RESULT_SCHEMA
                or result.get("action_id") != plan["action_id"]
                or result.get("plan_sha256") != plan["plan_sha256"]
                or result.get("authorization_sha256")
                    != authorization["authorization_sha256"]
                or result.get("step") != step
                or result.get("status") != "verified"
                or native_stack_operations.SHA256.fullmatch(
                    str(result.get("evidence_sha256", ""))
                ) is None
                or native.get("stack_sha256") != plan["stack_sha256"]):
            raise NativeStackSessionManagerError(
                "native_stack_session_rotation_result_invalid"
            )
        return result


class NativeStackSessionManager:
    def __init__(
        self, backend: SessionBackend, *, state_root: Path = STATE_ROOT,
        authorization_receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
        catalog_path: Path = CATALOG_PATH, terminal_root: Path = TERMINAL_ROOT,
        trusted_uid: int = 0, host_release_id: str | None = None,
        now: Callable[[], int] = lambda: int(time.time()),
        crash_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.backend = backend
        self.state_root = state_root
        self.authorization_receipt_root = authorization_receipt_root
        self.catalog_path = catalog_path
        self.terminal_root = terminal_root
        self.trusted_uid = trusted_uid
        self.host_release_id = host_release_id
        self.now = now
        self.crash_hook = (lambda _phase: None) if crash_hook is None else crash_hook

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        stack_manager.ensure_state_directory(self.state_root, self.trusted_uid)
        path = self.state_root / ".lock"
        descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != self.trusted_uid
                    or opened.st_nlink != 1):
                raise NativeStackSessionManagerError(
                    "native_stack_session_lock_untrusted"
                )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _records(self) -> list[tuple[Path, dict[str, Any]]]:
        records: list[tuple[Path, dict[str, Any]]] = []
        for path in sorted(self.state_root.glob("*.json")):
            value = stack_manager.trusted_canonical_document(
                path, self.trusted_uid
            )
            records.append((path, validate_journal(value)))
        if len(records) > MAX_RECORDS:
            raise NativeStackSessionManagerError(
                "native_stack_session_record_capacity_exceeded"
            )
        return records

    def _write(
        self, path: Path, journal: dict[str, Any], phase: str, **values: object,
    ) -> None:
        journal.update(values)
        journal["phase"] = phase
        journal["updated_at"] = self.now()
        journal["journal_sha256"] = digest(_body(journal))
        stack_manager.atomic_json(
            path, validate_journal(journal), self.trusted_uid
        )
        self.crash_hook(phase)

    def _validate_authority(
        self, plan_value: object, authorization_value: object, *,
        action: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            plan = native_stack_session.validate_plan(
                plan_value, now=self.now(), require_fresh=True
            )
            authorization = native_stack_session.validate_authorization(
                authorization_value, plan, now=self.now(),
                expected_host_release_id=str(self.host_release_id),
            )
        except native_stack_session.NativeStackSessionError as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_authority_invalid"
            ) from error
        if plan["action"] != action:
            raise NativeStackSessionManagerError(
                "native_stack_session_action_mismatch"
            )
        self._verify_pending_receipt(plan, authorization)
        self._verify_catalog(plan)
        return plan, authorization

    def _verify_pending_receipt(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> None:
        receipt = stack_manager.trusted_canonical_document(
            self.authorization_receipt_root
            / f"{authorization['authorization_id']}.json",
            self.trusted_uid,
        )
        expected = {
            "schema", "request_id", "request_sha256", "status",
            "started_at", "completed_at", "operation", "declared_agent",
            "declared_session", "identity_evidence", "authorization_method",
            "ceremony", "purpose", "resource", "exit_status",
            "stdout_sha256", "stderr_sha256", "native_session_action_id",
            "native_session_id", "native_session_plan_sha256",
            "host_release_id",
        }
        if (set(receipt) != expected
                or digest(receipt) != authorization["pending_receipt_sha256"]
                or receipt["schema"]
                    != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt["request_id"] != authorization["authorization_id"]
                or receipt["request_sha256"] != authorization["request_sha256"]
                or receipt["status"] != "executing"
                or receipt["started_at"] != authorization["authorized_at"]
                or receipt["completed_at"] is not None
                or receipt["operation"] != f"native-{plan['action']}"
                or receipt["authorization_method"] != "touch-id"
                or receipt["ceremony"] != "approve"
                or receipt["exit_status"] is not None
                or receipt["stdout_sha256"] is not None
                or receipt["stderr_sha256"] is not None
                or receipt["native_session_action_id"] != plan["action_id"]
                or receipt["native_session_id"] != plan["session_id"]
                or receipt["native_session_plan_sha256"] != plan["plan_sha256"]
                or receipt["host_release_id"]
                    != authorization["host_release_id"]
                or hashlib.sha256(
                    receipt["declared_agent"].encode("utf-8")
                ).hexdigest() != authorization["requesting_agent_sha256"]
                or hashlib.sha256(
                    receipt["declared_session"].encode("utf-8")
                ).hexdigest() != authorization["requesting_session_sha256"]):
            raise NativeStackSessionManagerError(
                "native_stack_session_authorization_receipt_invalid"
            )

    def _verify_catalog(self, plan: Mapping[str, Any]) -> None:
        try:
            stack_manager._trusted_directory(
                self.catalog_path.parent, self.trusted_uid
            )
            catalog = native_vendor_stack.load_catalog(
                self.catalog_path, private=True
            )
            stack = native_vendor_stack.stack_by_id(catalog, plan["stack_id"])
            native = native_stack_runtime_binding.make_binding(stack)
            authority = runtime_authority.validate_binding(
                plan["runtime_authority"]
            )
        except Exception as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_catalog_untrusted"
            ) from error
        if (hashlib.sha256(
                native_vendor_stack.canonical_bytes(catalog)
            ).hexdigest() != plan["catalog_sha256"]
                or native_vendor_stack.stack_revision(stack)
                    != plan["stack_sha256"]
                or authority["model_stack_binding"]["authority"] != native):
            raise NativeStackSessionManagerError(
                "native_stack_session_catalog_mismatch"
            )

    def _verify_completed_receipt(
        self, journal: Mapping[str, Any]
    ) -> None:
        plan = journal["plan"]
        authorization = journal["authorization"]
        public = journal["public_handle"]
        receipt = stack_manager.trusted_canonical_document(
            self.authorization_receipt_root
            / f"{authorization['authorization_id']}.json",
            self.trusted_uid,
        )
        pending = dict(receipt)
        pending.update({
            "status": "executing", "completed_at": None,
            "exit_status": None, "stdout_sha256": None,
            "stderr_sha256": None,
        })
        try:
            record, consumption = native_terminal_handle.read_consumed_by_id(
                root=self.terminal_root, handle_id=public["handle_id"],
                trusted_uid=self.trusted_uid, trusted_gid=0,
            )
        except (OSError, native_terminal_handle.NativeTerminalHandleError) as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_handle_unavailable"
            ) from error
        if (record["record_sha256"] != public["handle_sha256"]
                or record["operation_id"] != plan["action_id"]
                or record["session_id"] != plan["session_id"]
                or consumption["claimed_at"] >= record["expires_at"]
                or receipt.get("status") != "succeeded"
                or receipt.get("exit_status") != 0
                or receipt.get("stdout_sha256")
                    != hashlib.sha256(canonical(public)).hexdigest()
                or receipt.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
                or digest(pending) != authorization["pending_receipt_sha256"]):
            raise NativeStackSessionManagerError(
                "native_stack_session_completed_receipt_invalid"
            )

    def _rotate(
        self, path: Path, journal: dict[str, Any], *, opening: bool,
    ) -> list[dict[str, Any]]:
        protocol = (
            tuple(native_egress.ROTATION_PROTOCOL)
            if opening else stack_manager.validate_close_only_protocol()
        )
        evidence: list[dict[str, Any]] = []
        for index, step in enumerate(protocol):
            label = "open" if opening else "close"
            self._write(path, journal, f"{label}-{index:02d}-{step}-pending")
            result = self.backend.rotation_step(
                step, journal["plan"], journal["authorization"],
                journal["grant"] if opening else None,
            )
            evidence.append(result)
            journal["completed_steps"].append(f"{label}:{step}")
            self._write(path, journal, f"{label}-{index:02d}-{step}-verified")
        self._write(path, journal, "running" if opening else "closed",
                    network_open=opening)
        return evidence

    @staticmethod
    def _requires_close(journal: Mapping[str, Any]) -> bool:
        return (
            journal["network_open"]
            or str(journal["phase"]).startswith("open-")
            or any(str(step).startswith("open:")
                   for step in journal["completed_steps"])
        )

    def _recover_one(
        self, path: Path, journal: dict[str, Any], *, reason: str,
    ) -> None:
        if journal["phase"] in TERMINAL_PHASES:
            return
        must_close = self._requires_close(journal)
        try:
            stop = self.backend.recover_stop(
                journal["plan"], journal["authorization"],
                journal["journal_sha256"],
            )
            self._write(
                path, journal, "recovery-stop-verified", stop_reply=stop,
                error_code=reason,
            )
            if must_close:
                self._rotate(path, journal, opening=False)
            status = native_stack_operations.validate_status(
                self.backend.recover_status(
                    journal["plan"], journal["authorization"],
                    journal["journal_sha256"],
                )
            )
            if (status["network"]["phase"] != "closed"
                    or status["live_run_count"] != 0
                    or stop.get("state") != "absent"):
                raise NativeStackSessionManagerError(
                    "native_stack_session_recovery_readback_ambiguous"
                )
            self._write(
                path, journal, "fenced", network_open=False,
                error_code=reason,
            )
        except Exception as error:
            code = _safe_error(error)
            self._write(
                path, journal, "recovery-required",
                error_code=code,
            )
            raise NativeStackSessionManagerError(
                "native_stack_session_recovery_required"
            ) from error

    def _recover_all_locked(self, *, exclude_session_id: str | None = None) -> None:
        for path, journal in self._records():
            if (journal["phase"] not in TERMINAL_PHASES
                    and journal["session_id"] != exclude_session_id):
                self._recover_one(
                    path, journal, reason="native_stack_session_startup_recovery"
                )

    def recover(self) -> dict[str, Any]:
        with self.locked():
            self._recover_all_locked()
            remaining = [
                value for _path, value in self._records()
                if value["phase"] not in TERMINAL_PHASES
            ]
            if remaining:
                raise NativeStackSessionManagerError(
                    "native_stack_session_recovery_required"
                )
            body = {
                "state": "closed", "active_session_count": 0,
                "reconciled_at": self.now(),
            }
            return {
                "schema": "secure-sandbox-native-stack-session-recovery-v1",
                **body, "evidence_sha256": digest(body),
            }

    def prepare(
        self, plan_value: object, authorization_value: object,
    ) -> dict[str, Any]:
        with self.locked():
            self._recover_all_locked()
            plan, authorization = self._validate_authority(
                plan_value, authorization_value, action="session-start"
            )
            records = self._records()
            if any(value["action_id"] == plan["action_id"] for _, value in records):
                raise NativeStackSessionManagerError(
                    "native_stack_session_action_replay"
                )
            if any(value["phase"] not in TERMINAL_PHASES for _, value in records):
                raise NativeStackSessionManagerError(
                    "native_stack_session_recovery_required"
                )
            status = native_stack_operations.validate_status(
                self.backend.status(plan, authorization)
            )
            if status["status_sha256"] != plan["status_sha256"]:
                raise NativeStackSessionManagerError(
                    "native_stack_session_status_changed"
                )
            native_stack_session.require_start_status(
                status, stack_sha256=plan["stack_sha256"]
            )
            grant = _validate_grant(
                self.backend.prepare_grant(plan, authorization), plan
            )
            lease = native_stack_session.make_session_lease(
                lease_profile_id=plan["lease_profile_id"],
                session_id=plan["session_id"],
                runtime_authority_sha256=plan["runtime_authority_sha256"],
                grant_id=grant["grant_id"], grant_sha256=grant["grant_sha256"],
                issued_at=grant["issued_at"], expires_at=grant["expires_at"],
            )
            now = self.now()
            journal = {
                "schema": JOURNAL_SCHEMA, "action_id": plan["action_id"],
                "session_id": plan["session_id"], "plan": plan,
                "authorization": authorization,
                "catalog_sha256": plan["catalog_sha256"], "grant": grant,
                "session_lease": lease,
                "public_handle": None, "phase": "preparing",
                "network_open": False, "completed_steps": [],
                "stop_reply": None, "error_code": None,
                "created_at": now, "updated_at": now,
                "journal_sha256": "0" * 64,
            }
            journal["journal_sha256"] = digest(_body(journal))
            path = self.state_root / f"{plan['action_id']}.json"
            stack_manager.atomic_json(
                path, validate_journal(journal), self.trusted_uid
            )
            self.crash_hook("preparing")
            try:
                public = native_terminal_handle.validate_public(
                    self.backend.prepare(plan, authorization, grant)
                )
                if (public["kind"] != "claude-session"
                        or public["operation_id"] != plan["action_id"]
                        or public["session_id"] != plan["session_id"]
                        or public["expires_at"] > authorization["expires_at"]):
                    raise NativeStackSessionManagerError(
                        "native_stack_session_handle_mismatch"
                    )
                self._write(
                    path, journal, "prepared", public_handle=public
                )
                return public
            except Exception as error:
                self._write(
                    path, journal, "recovery-required",
                    error_code=_safe_error(error),
                )
                raise

    def begin(self, action_id: str) -> dict[str, Any]:
        with self.locked():
            path, journal = self._record(action_id, None)
            if journal["phase"] != "prepared":
                self._recover_one(
                    path, journal,
                    reason="native_stack_session_interrupted_begin",
                )
                raise NativeStackSessionManagerError(
                    "native_stack_session_recovery_required"
                )
            self._verify_completed_receipt(journal)
            status = native_stack_operations.validate_status(
                self.backend.status(
                    journal["plan"], journal["authorization"],
                    handle_id=journal["public_handle"]["handle_id"],
                )
            )
            native_stack_session.require_start_status(
                status, stack_sha256=journal["plan"]["stack_sha256"]
            )
            try:
                evidence = self._rotate(path, journal, opening=True)
                status = native_stack_operations.validate_status(
                    self.backend.status(
                        journal["plan"], journal["authorization"],
                        handle_id=journal["public_handle"]["handle_id"],
                    )
                )
                network = status["network"]
                if (network["phase"] != native_egress.PHASE_INFERENCE
                        or network["grant_sha256"]
                            != journal["session_lease"]["grant_sha256"]
                        or network["expires_at"]
                            != journal["session_lease"]["expires_at"]
                        or self.now() >= journal["session_lease"]["expires_at"]):
                    raise NativeStackSessionManagerError(
                        "native_stack_session_grant_readback_mismatch"
                    )
                self._write(path, journal, "running-readback-verified",
                            network_open=True)
                self._write(path, journal, "running", network_open=True)
            except Exception as error:
                self._close_or_fence(path, journal, error)
                raise
            body = {
                "action_id": action_id, "session_id": journal["session_id"],
                "runtime_authority_sha256": journal["plan"][
                    "runtime_authority_sha256"
                ],
                "session_lease_sha256": journal["session_lease"][
                    "lease_sha256"
                ],
                "session_expires_at": journal["session_lease"]["expires_at"],
                "evidence_sha256": digest(evidence),
            }
            return {"schema": BEGIN_SCHEMA, **body, "begin_sha256": digest(body)}

    def complete(self, action_id: str) -> dict[str, Any]:
        with self.locked():
            path, journal = self._record(action_id, "running")
            try:
                stop = self.backend.stop_continuation(
                    journal["plan"], journal["authorization"],
                    journal["public_handle"]["handle_id"],
                )
                self._write(path, journal, "stop-verified", stop_reply=stop)
                evidence = self._rotate(path, journal, opening=False)
                self._verify_closed(journal)
                body = {
                    "action_id": action_id,
                    "session_id": journal["session_id"],
                    "state": "absent",
                    "final_summary_sha256": stop["final_summary_sha256"],
                    "evidence_sha256": digest([stop, *evidence]),
                }
                self._write(path, journal, "completed")
                return {
                    "schema": COMPLETION_SCHEMA, **body,
                    "completion_sha256": digest(body),
                }
            except Exception as error:
                self._close_or_fence(path, journal, error)
                raise

    def abort(self, action_id: str) -> dict[str, Any]:
        with self.locked():
            path, journal = self._record(action_id, None)
            if journal["phase"] in TERMINAL_PHASES:
                raise NativeStackSessionManagerError(
                    "native_stack_session_not_active"
                )
            try:
                stop = self.backend.stop_continuation(
                    journal["plan"], journal["authorization"],
                    journal["public_handle"]["handle_id"],
                )
                self._write(path, journal, "abort-stop-verified", stop_reply=stop)
                if self._requires_close(journal):
                    self._rotate(path, journal, opening=False)
                self._verify_closed(journal)
                self._write(
                    path, journal, "fenced",
                    error_code="native_stack_session_stream_aborted",
                )
                body = {
                    "action_id": action_id,
                    "session_id": journal["session_id"], "state": "fenced",
                    "journal_sha256": journal["journal_sha256"],
                }
                return {
                    "schema": "secure-sandbox-native-stack-session-abort-v1",
                    **body, "evidence_sha256": digest(body),
                }
            except Exception as error:
                self._close_or_fence(path, journal, error)
                raise

    def stop(
        self, plan_value: object, authorization_value: object,
    ) -> dict[str, Any]:
        with self.locked():
            plan, authorization = self._validate_authority(
                plan_value, authorization_value, action="session-stop"
            )
            self._recover_all_locked(exclude_session_id=plan["session_id"])
            matches = [
                (path, value) for path, value in self._records()
                if value["session_id"] == plan["session_id"]
                and value["phase"] not in TERMINAL_PHASES
            ]
            if len(matches) > 1:
                raise NativeStackSessionManagerError(
                    "native_stack_session_state_ambiguous"
                )
            stop = self.backend.stop(plan, authorization)
            if not matches:
                status = native_stack_operations.validate_status(
                    self.backend.status(plan, authorization)
                )
                if status["network"]["phase"] != "closed":
                    raise NativeStackSessionManagerError(
                        "native_stack_session_close_readback_ambiguous"
                    )
                return stop
            path, journal = matches[0]
            try:
                self._write(path, journal, "explicit-stop-verified",
                            stop_reply=stop)
                if self._requires_close(journal):
                    self._rotate(path, journal, opening=False)
                status = native_stack_operations.validate_status(
                    self.backend.status(plan, authorization)
                )
                if (status["network"]["phase"] != "closed"
                        or status["live_run_count"] != 0):
                    raise NativeStackSessionManagerError(
                        "native_stack_session_close_readback_ambiguous"
                    )
                self._write(path, journal, "stopped")
                return stop
            except Exception as error:
                self._close_or_fence(path, journal, error)
                raise

    def _record(
        self, action_id: str, expected_phase: str | None,
    ) -> tuple[Path, dict[str, Any]]:
        if native_stack_operations.UUID4.fullmatch(action_id) is None:
            raise NativeStackSessionManagerError(
                "native_stack_session_action_id_invalid"
            )
        path = self.state_root / f"{action_id}.json"
        journal = validate_journal(
            stack_manager.trusted_canonical_document(path, self.trusted_uid)
        )
        if expected_phase is not None and journal["phase"] != expected_phase:
            raise NativeStackSessionManagerError(
                "native_stack_session_phase_mismatch"
            )
        return path, journal

    def _verify_closed(self, journal: Mapping[str, Any]) -> None:
        status = native_stack_operations.validate_status(
            self.backend.status(
                journal["plan"], journal["authorization"],
                handle_id=journal["public_handle"]["handle_id"],
            )
        )
        if (status["network"]["phase"] != "closed"
                or status["live_run_count"] != 0
                or journal["stop_reply"] is None
                or journal["stop_reply"]["state"] != "absent"):
            raise NativeStackSessionManagerError(
                "native_stack_session_close_readback_ambiguous"
            )

    def _close_or_fence(
        self, path: Path, journal: dict[str, Any], error: BaseException,
    ) -> None:
        code = _safe_error(error)
        try:
            if self._requires_close(journal):
                self._rotate(path, journal, opening=False)
            # Closing egress is necessary but not sufficient: the Research
            # scope may still own a process or credential. Only recovery,
            # which obtains an exact stop reply and independent status
            # readback, may terminalize this journal.
            self._write(
                path, journal, "recovery-required", error_code=code,
                network_open=False,
            )
        except Exception:
            self._write(
                path, journal, "recovery-required", error_code=code,
                network_open=journal["network_open"],
            )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    for name in ("prepare", "stop"):
        command = sub.add_parser(name)
        command.add_argument("--plan-json", required=True)
        command.add_argument("--authorization-json", required=True)
    for name in ("begin", "complete", "abort"):
        command = sub.add_parser(name)
        command.add_argument("--action-id", required=True)
    sub.add_parser("recover")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        release_id = HERE.name
        if native_stack_operations.SHA256.fullmatch(release_id) is None:
            raise NativeStackSessionManagerError(
                "native_stack_session_protected_release_invalid"
            )
        manager = NativeStackSessionManager(
            SessionBackend(), host_release_id=release_id
        )
        if args.command in {"prepare", "stop"}:
            plan = json.loads(args.plan_json.encode("ascii"))
            authorization = json.loads(args.authorization_json.encode("ascii"))
            result = (
                manager.prepare(plan, authorization)
                if args.command == "prepare"
                else manager.stop(plan, authorization)
            )
        elif args.command == "begin":
            result = manager.begin(args.action_id)
        elif args.command == "complete":
            result = manager.complete(args.action_id)
        elif args.command == "abort":
            result = manager.abort(args.action_id)
        else:
            result = manager.recover()
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (
        NativeStackSessionManagerError,
        native_stack_session.NativeStackSessionError,
        native_stack_operations.NativeStackOperationError,
        native_egress.NativeEgressError,
        native_terminal_handle.NativeTerminalHandleError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        output = {
            "schema": "secure-sandbox-native-stack-session-manager-error-v1",
            "status": "rejected", "error": _safe_error(error),
        }
        sys.stderr.buffer.write(canonical(output))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
