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
import select
import signal
import socket
import stat
import struct
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
from shared import native_codex_projection
from shared import native_codex_ui_handle
from shared import native_projection_identity_recovery
from shared import native_projection_reconciliation
from shared import native_stack_operations
from shared import native_stack_runtime_binding
from shared import native_stack_session
from shared import native_terminal_handle
from shared import native_vendor_stack
from shared import runtime_authority


JOURNAL_SCHEMA = "secure-sandbox-native-stack-session-transaction-v3"
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
CODEX_UI_ROOT = Path(
    "/usr/local/var/lib/secure-sandbox/native-codex-ui-handles"
)
HOST_BACKEND = HERE / "native_stack_backend"
PROJECTION_CONSUMER = HERE / "native_projection_consumer"
CONTROL_CLIENT = HERE / "control_client"
SSH_CONFIG = HERE / "ssh_config"
MAX_RECORDS = 256
TERMINAL_PHASES = {"completed", "stopped", "fenced"}
PROJECTION_TERMINATION_MAGIC = b"SSEND01\n"
PROJECTION_TERMINALIZATION_SCHEMA = (
    "secure-sandbox-native-projection-terminalization-v1"
)


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


def codex_prepare_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    handle_id: str, session_lease: Mapping[str, Any],
    projection_claim: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": "secure-sandbox-native-stack-codex-prepare-ticket-v1",
        "plan": plan, "authorization": authorization,
        "handle_id": handle_id, "session_lease": session_lease,
        "projection_claim": projection_claim,
    }
    return {**body, "ticket_sha256": digest(body)}


def validate_codex_prepare_reply(
    value: object, *, plan: Mapping[str, Any],
    lease: Mapping[str, Any], projection_claim: Mapping[str, Any], now: int,
) -> dict[str, Any]:
    """Independently validate the Host/Research one-shot prepare boundary."""
    fields = {
        "schema", "operation_id", "prepare_sha256", "expires_at",
        "session_lease_sha256", "session_expires_at", "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeStackSessionManagerError(
            "native_codex_prepare_reply_fields_invalid"
        )
    expires_at = value.get("expires_at")
    if (value.get("schema")
            != "secure-sandbox-native-codex-session-prepare-reply-v1"
            or value.get("operation_id") != plan["action_id"]
            or native_stack_operations.SHA256.fullmatch(
                str(value.get("prepare_sha256", ""))
            ) is None
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or not now < expires_at <= min(
                now + 120, lease["expires_at"],
                projection_claim["access_expires_at_ms"] // 1000,
            )
            or value.get("session_lease_sha256") != lease["lease_sha256"]
            or value.get("session_expires_at") != lease["expires_at"]
            or native_stack_operations.SHA256.fullmatch(
                str(value.get("evidence_sha256", ""))
            ) is None):
        raise NativeStackSessionManagerError(
            "native_codex_prepare_reply_invalid"
        )
    evidence_body = {
        "operation_id": plan["action_id"],
        "prepare_sha256": value["prepare_sha256"],
        "expires_at": expires_at,
        "runtime_authority_sha256": plan["runtime_authority_sha256"],
        "session_lease_sha256": lease["lease_sha256"],
        "session_expires_at": lease["expires_at"],
    }
    if not hmac.compare_digest(
        str(value["evidence_sha256"]), digest(evidence_body)
    ):
        raise NativeStackSessionManagerError(
            "native_codex_prepare_reply_evidence_mismatch"
        )
    return dict(value)


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


def projection_reconciliation_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    original_plan: Mapping[str, Any],
    original_authorization: Mapping[str, Any], journal_sha256: str,
) -> dict[str, Any]:
    body = {
        "schema": (
            "secure-sandbox-native-projection-reconciliation-host-ticket-v1"
        ),
        "plan": plan, "authorization": authorization,
        "original_plan": original_plan,
        "original_authorization": original_authorization,
        "journal_sha256": journal_sha256,
    }
    return {**body, "ticket_sha256": digest(body)}


def projection_identity_recovery_ticket(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    original_plan: Mapping[str, Any],
    original_authorization: Mapping[str, Any], journal_sha256: str,
) -> dict[str, Any]:
    body = {
        "schema": (
            "secure-sandbox-native-projection-identity-recovery-host-ticket-v1"
        ),
        "plan": plan, "authorization": authorization,
        "original_plan": original_plan,
        "original_authorization": original_authorization,
        "journal_sha256": journal_sha256,
    }
    return {**body, "ticket_sha256": digest(body)}


def _validate_projection_terminalization(
    value: object, *, original_operation_id: str,
) -> dict[str, Any]:
    fields = {
        "schema", "original_operation_id", "state", "observed_at",
        "custody_evidence_sha256", "status_sha256", "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeStackSessionManagerError(
            "native_projection_terminalization_fields_invalid"
        )
    body = {key: value[key] for key in fields - {"schema", "evidence_sha256"}}
    if (value.get("schema") != PROJECTION_TERMINALIZATION_SCHEMA
            or value.get("original_operation_id") != original_operation_id
            or value.get("state") != "helper-cleared"
            or not isinstance(value.get("observed_at"), int)
            or isinstance(value.get("observed_at"), bool)
            or value["observed_at"] < 1
            or any(native_stack_operations.SHA256.fullmatch(
                str(value.get(field, ""))
            ) is None for field in (
                "custody_evidence_sha256", "status_sha256", "evidence_sha256",
            ))
            or value["evidence_sha256"] != digest(body)):
        raise NativeStackSessionManagerError(
            "native_projection_terminalization_invalid"
        )
    return {"schema": PROJECTION_TERMINALIZATION_SCHEMA, **body,
            "evidence_sha256": value["evidence_sha256"]}


def make_projection_terminalization(
    *, original_operation_id: str, status: Mapping[str, Any], observed_at: int,
) -> dict[str, Any]:
    custody = status["credential_custody"]
    if (status["network"]["phase"] != "closed"
            or status["live_run_count"] != 0
            or custody["state"] not in {"retained", "absent"}
            or custody["projection_count"] != 0):
        raise NativeStackSessionManagerError(
            "native_projection_terminalization_not_observed"
        )
    body = {
        "original_operation_id": original_operation_id,
        "state": "helper-cleared", "observed_at": observed_at,
        "custody_evidence_sha256": custody["evidence_sha256"],
        "status_sha256": status["status_sha256"],
    }
    return _validate_projection_terminalization({
        "schema": PROJECTION_TERMINALIZATION_SCHEMA, **body,
        "evidence_sha256": digest(body),
    }, original_operation_id=original_operation_id)


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
        "projection_identity", "projection_closure",
        "projection_identity_recovery_plan",
        "projection_identity_recovery_reply",
        "projection_recovery_plan", "projection_reconciliation",
        "projection_terminalization",
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
            if public.get("schema") == native_terminal_handle.PUBLIC_SCHEMA:
                public = native_terminal_handle.validate_public(public)
                expected_kind = "claude-session"
            elif public.get("schema") == native_codex_ui_handle.PUBLIC_SCHEMA:
                public = native_codex_ui_handle.validate_public(public)
                expected_kind = native_codex_ui_handle.KIND
            else:
                raise NativeStackSessionManagerError(
                    "native_stack_session_handle_schema_invalid"
                )
        except (
            AttributeError,
            native_terminal_handle.NativeTerminalHandleError,
            native_codex_ui_handle.NativeCodexUIHandleError,
        ) as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_journal_handle_invalid"
            ) from error
        if (public["kind"] != expected_kind
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
    projection_identity = value["projection_identity"]
    projection_identity_plan = value["projection_identity_recovery_plan"]
    projection_identity_reply = value["projection_identity_recovery_reply"]
    projection_closure = value["projection_closure"]
    projection_plan = value["projection_recovery_plan"]
    projection_reply = value["projection_reconciliation"]
    projection_terminalization = value["projection_terminalization"]
    try:
        if projection_identity_plan is not None:
            projection_identity_plan = (
                native_projection_identity_recovery.validate_plan(
                    projection_identity_plan
                )
            )
            if (projection_identity_plan["original_operation_id"]
                    != plan["action_id"]
                    or projection_identity_plan["session_id"]
                        != plan["session_id"]
                    or projection_identity_plan["stack_id"]
                        != plan["stack_id"]
                    or projection_identity_plan["stack_sha256"]
                        != plan["stack_sha256"]
                    or projection_identity_plan["session_authority_sha256"]
                        != plan["runtime_authority_sha256"]
                    or projection_identity_plan["host_release_id"]
                        != authorization["host_release_id"]):
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_identity_plan_mismatch"
                )
        if projection_identity_reply is not None:
            if projection_identity_plan is None:
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_identity_reply_without_plan"
                )
            projection_identity_reply = (
                native_projection_identity_recovery.validate_reply(
                    projection_identity_reply,
                    plan_value=projection_identity_plan,
                )
            )
        if projection_identity is not None:
            projection_identity = (
                native_projection_reconciliation.validate_identity(
                    projection_identity
                )
            )
            if (projection_identity["original_operation_id"]
                    != plan["action_id"]
                    or projection_identity["session_authority_sha256"]
                        != plan["runtime_authority_sha256"]
                    or public is None
                    or public.get("schema")
                        != native_codex_ui_handle.PUBLIC_SCHEMA):
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_identity_mismatch"
                )
            if (projection_identity_reply is not None
                    and (projection_identity["process_identifier"]
                        != projection_identity_reply["process_identifier"]
                    or projection_identity["process_start_time_us"]
                        != projection_identity_reply["process_start_time_us"]
                    or projection_identity["consumer_executable_sha256"]
                        != projection_identity_reply[
                            "consumer_executable_sha256"
                        ]
                    or projection_identity["session_authority_sha256"]
                        != projection_identity_reply[
                            "session_authority_sha256"
                        ])):
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_identity_reply_mismatch"
                )
        elif projection_identity_reply is not None:
            raise NativeStackSessionManagerError(
                "native_stack_session_projection_identity_reply_unbound"
            )
        if projection_closure is not None:
            projection_closure = (
                native_projection_reconciliation.validate_closure_evidence(
                    projection_closure
                )
            )
            if (projection_identity is None
                    or projection_closure["original_operation_id"]
                        != plan["action_id"]):
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_closure_mismatch"
                )
        if projection_plan is not None:
            projection_plan = native_projection_reconciliation.validate_plan(
                projection_plan
            )
            if (projection_identity is None or projection_closure is None
                    or projection_plan["original_operation_id"]
                        != plan["action_id"]
                    or projection_plan["session_id"] != plan["session_id"]
                    or projection_plan["stack_id"] != plan["stack_id"]
                    or projection_plan["stack_sha256"] != plan["stack_sha256"]
                    or projection_plan["session_authority_sha256"]
                        != plan["runtime_authority_sha256"]
                    or projection_plan["process_identifier"]
                        != projection_identity["process_identifier"]
                    or projection_plan["process_start_time_us"]
                        != projection_identity["process_start_time_us"]
                    or projection_plan["consumer_executable_sha256"]
                        != projection_identity[
                            "consumer_executable_sha256"
                        ]
                    or projection_plan["guest_absence_evidence_sha256"]
                        != projection_closure[
                            "guest_absence_evidence_sha256"
                        ]
                    or projection_plan["egress_closed_evidence_sha256"]
                        != projection_closure[
                            "egress_closed_evidence_sha256"
                        ]):
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_plan_mismatch"
                )
        if projection_reply is not None:
            if projection_plan is None:
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_reply_without_plan"
                )
            projection_reply = native_projection_reconciliation.validate_reply(
                projection_reply, plan_value=projection_plan
            )
        if projection_terminalization is not None:
            if projection_identity is None:
                raise NativeStackSessionManagerError(
                    "native_stack_session_projection_terminalization_unbound"
                )
            projection_terminalization = _validate_projection_terminalization(
                projection_terminalization,
                original_operation_id=plan["action_id"],
            )
    except (
        native_projection_identity_recovery.NativeProjectionIdentityRecoveryError,
        native_projection_reconciliation.NativeProjectionReconciliationError,
    ) as error:
        raise NativeStackSessionManagerError(
            "native_stack_session_projection_state_invalid"
        ) from error
    if (projection_identity is not None
            and value["phase"] in TERMINAL_PHASES
            and projection_terminalization is None):
        raise NativeStackSessionManagerError(
            "native_stack_session_projection_terminalization_missing"
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
        self.runner = runner
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

    def project_codex(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        handle_id: str, projection_fd: int,
    ) -> dict[str, Any]:
        ticket = continuation_ticket(plan, authorization, handle_id)
        command = [
            str(self.host_backend), "session-codex-project",
            "--projection-fd", str(projection_fd),
        ]
        result = self.runner(
            command, input=canonical(ticket), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=300,
            pass_fds=(projection_fd,), start_new_session=True, close_fds=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
        if result.returncode != 0 or not 2 <= len(result.stdout) <= 1024 * 1024:
            raise NativeStackSessionManagerError(
                "native_codex_projection_operation_failed"
            )
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeStackSessionManagerError(
                "native_codex_projection_reply_invalid"
            ) from error
        if not isinstance(value, dict) or result.stdout != canonical(value):
            raise NativeStackSessionManagerError(
                "native_codex_projection_reply_invalid"
            )
        return value

    def prepare_codex(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        handle_id: str, session_lease: Mapping[str, Any],
        projection_claim: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self.transport._run(
            [str(self.host_backend), "session-codex-prepare"],
            codex_prepare_ticket(
                plan, authorization, handle_id, session_lease,
                projection_claim,
            ), timeout=300,
        )

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

    def reconcile_projection(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        original_plan: Mapping[str, Any],
        original_authorization: Mapping[str, Any], journal_sha256: str,
    ) -> dict[str, Any]:
        return self.transport._run(
            [str(self.host_backend), "projection-reconcile"],
            projection_reconciliation_ticket(
                plan, authorization, original_plan,
                original_authorization, journal_sha256,
            ),
            timeout=300,
        )

    def recover_projection_identity(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any],
        original_plan: Mapping[str, Any],
        original_authorization: Mapping[str, Any], journal_sha256: str,
    ) -> dict[str, Any]:
        return self.transport._run(
            [str(self.host_backend), "projection-identity-recover"],
            projection_identity_recovery_ticket(
                plan, authorization, original_plan,
                original_authorization, journal_sha256,
            ),
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
        codex_ui_root: Path = CODEX_UI_ROOT,
        projection_consumer: Path = PROJECTION_CONSUMER,
        trusted_uid: int = 0, trusted_gid: int = 0,
        host_release_id: str | None = None,
        now: Callable[[], int] = lambda: int(time.time()),
        crash_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.backend = backend
        self.state_root = state_root
        self.authorization_receipt_root = authorization_receipt_root
        self.catalog_path = catalog_path
        self.terminal_root = terminal_root
        self.codex_ui_root = codex_ui_root
        self.projection_consumer = projection_consumer
        self.trusted_uid = trusted_uid
        self.trusted_gid = trusted_gid
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

    def _verify_projection_reconciliation_receipt(
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
            "stdout_sha256", "stderr_sha256",
            "native_projection_recovery_operation_id",
            "native_projection_original_operation_id",
            "native_projection_reconciliation_plan_sha256",
            "host_release_id",
        }
        if (set(receipt) != expected
                or digest(receipt) != authorization[
                    "pending_receipt_sha256"
                ]
                or receipt["schema"]
                    != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt["request_id"]
                    != authorization["authorization_id"]
                or receipt["request_sha256"]
                    != authorization["request_sha256"]
                or receipt["status"] != "executing"
                or receipt["started_at"] != authorization["authorized_at"]
                or receipt["completed_at"] is not None
                or receipt["operation"]
                    != native_projection_reconciliation.OPERATION
                or receipt["authorization_method"] != "touch-id"
                or receipt["ceremony"] != "approve"
                or receipt["exit_status"] is not None
                or receipt["stdout_sha256"] is not None
                or receipt["stderr_sha256"] is not None
                or receipt["native_projection_recovery_operation_id"]
                    != plan["recovery_operation_id"]
                or receipt["native_projection_original_operation_id"]
                    != plan["original_operation_id"]
                or receipt["native_projection_reconciliation_plan_sha256"]
                    != plan["plan_sha256"]
                or receipt["host_release_id"] != plan["host_release_id"]
                or hashlib.sha256(
                    receipt["declared_agent"].encode("utf-8")
                ).hexdigest() != authorization["requesting_agent_sha256"]
                or hashlib.sha256(
                    receipt["declared_session"].encode("utf-8")
                ).hexdigest()
                    != authorization["requesting_session_sha256"]):
            raise NativeStackSessionManagerError(
                "native_projection_reconciliation_receipt_invalid"
            )

    def _verify_projection_identity_recovery_receipt(
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
            "stdout_sha256", "stderr_sha256",
            "native_projection_recovery_operation_id",
            "native_projection_original_operation_id",
            "native_projection_identity_recovery_plan_sha256",
            "host_release_id",
        }
        if (set(receipt) != expected
                or digest(receipt) != authorization[
                    "pending_receipt_sha256"
                ]
                or receipt["schema"]
                    != "secure-sandbox-operator-authorization-receipt-v1"
                or receipt["request_id"]
                    != authorization["authorization_id"]
                or receipt["request_sha256"]
                    != authorization["request_sha256"]
                or receipt["status"] != "executing"
                or receipt["started_at"] != authorization["authorized_at"]
                or receipt["completed_at"] is not None
                or receipt["operation"]
                    != native_projection_identity_recovery.OPERATION
                or receipt["authorization_method"] != "touch-id"
                or receipt["ceremony"] != "approve"
                or receipt["exit_status"] is not None
                or receipt["stdout_sha256"] is not None
                or receipt["stderr_sha256"] is not None
                or receipt["native_projection_recovery_operation_id"]
                    != plan["recovery_operation_id"]
                or receipt["native_projection_original_operation_id"]
                    != plan["original_operation_id"]
                or receipt[
                    "native_projection_identity_recovery_plan_sha256"
                ] != plan["plan_sha256"]
                or receipt["host_release_id"] != plan["host_release_id"]
                or hashlib.sha256(
                    receipt["declared_agent"].encode("utf-8")
                ).hexdigest() != authorization["requesting_agent_sha256"]
                or hashlib.sha256(
                    receipt["declared_session"].encode("utf-8")
                ).hexdigest()
                    != authorization["requesting_session_sha256"]):
            raise NativeStackSessionManagerError(
                "native_projection_identity_recovery_receipt_invalid"
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
            if public["schema"] == native_terminal_handle.PUBLIC_SCHEMA:
                record, consumption = native_terminal_handle.read_consumed_by_id(
                    root=self.terminal_root, handle_id=public["handle_id"],
                    trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid,
                )
            else:
                record, consumption = native_codex_ui_handle.read_consumed_by_id(
                    root=self.codex_ui_root, handle_id=public["handle_id"],
                    trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid,
                )
        except (
            OSError,
            native_terminal_handle.NativeTerminalHandleError,
            native_codex_ui_handle.NativeCodexUIHandleError,
        ) as error:
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

    def _retire_handle(self, journal: Mapping[str, Any]) -> None:
        public = journal["public_handle"]
        try:
            if public.get("schema") == native_codex_ui_handle.PUBLIC_SCHEMA:
                native_codex_ui_handle.retire_handle(
                    root=self.codex_ui_root, handle_id=public["handle_id"],
                    handle_sha256=public["handle_sha256"], now=self.now(),
                    trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid,
                )
            elif public.get("schema") == native_terminal_handle.PUBLIC_SCHEMA:
                native_terminal_handle.retire_handle(
                    root=self.terminal_root, handle_id=public["handle_id"],
                    handle_sha256=public["handle_sha256"], now=self.now(),
                    trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid,
                )
            else:
                raise NativeStackSessionManagerError(
                    "native_stack_session_handle_schema_invalid"
                )
        except (
            OSError,
            native_codex_ui_handle.NativeCodexUIHandleError,
            native_terminal_handle.NativeTerminalHandleError,
        ) as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_handle_retirement_failed"
            ) from error

    def _finalize_handle_retirement(self, journal: Mapping[str, Any]) -> None:
        public = journal["public_handle"]
        try:
            if public.get("schema") == native_codex_ui_handle.PUBLIC_SCHEMA:
                native_codex_ui_handle.finalize_retirement(
                    root=self.codex_ui_root, handle_id=public["handle_id"],
                    handle_sha256=public["handle_sha256"], now=self.now(),
                    trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid,
                )
            elif public.get("schema") == native_terminal_handle.PUBLIC_SCHEMA:
                native_terminal_handle.finalize_retirement(
                    root=self.terminal_root, handle_id=public["handle_id"],
                    handle_sha256=public["handle_sha256"], now=self.now(),
                    trusted_uid=self.trusted_uid, trusted_gid=self.trusted_gid,
                )
        except (
            OSError,
            native_codex_ui_handle.NativeCodexUIHandleError,
            native_terminal_handle.NativeTerminalHandleError,
        ) as error:
            raise NativeStackSessionManagerError(
                "native_stack_session_handle_finalization_failed"
            ) from error

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

    def _bind_projection_identity(
        self, action_id: str, reply: Mapping[str, Any],
    ) -> dict[str, Any]:
        projection = reply["projection"]
        identity = native_projection_reconciliation.make_identity(
            original_operation_id=action_id,
            process_identifier=projection["process_identifier"],
            process_start_time_us=projection["process_start_time_us"],
            consumer_executable_sha256=projection["executable_sha256"],
            session_authority_sha256=projection[
                "session_authority_sha256"
            ],
            credential_response_sha256=reply["response_sha256"],
            credential_reply_sha256=reply["reply_sha256"],
            observed_at=self.now(),
        )
        with self.locked():
            path, journal = self._record(action_id, None)
            if journal["phase"] in TERMINAL_PHASES:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_session_terminal"
                )
            current = journal["projection_identity"]
            if current is not None and current != identity:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_conflict"
                )
            self._write(
                path, journal, "projection-bound",
                projection_identity=identity,
            )
        return identity

    def _projection_closure(
        self, journal: Mapping[str, Any], status: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if journal["projection_identity"] is None:
            return None
        stop = journal["stop_reply"]
        if (stop is None or stop.get("state") != "absent"
                or native_stack_operations.SHA256.fullmatch(
                    str(stop.get("evidence_sha256", ""))
                ) is None):
            raise NativeStackSessionManagerError(
                "native_projection_guest_absence_unverified"
            )
        try:
            egress = (
                native_projection_reconciliation
                .closed_egress_evidence_sha256(status)
            )
            return native_projection_reconciliation.make_closure_evidence(
                original_operation_id=journal["action_id"],
                guest_absence_evidence_sha256=stop["evidence_sha256"],
                egress_closed_evidence_sha256=egress,
                observed_at=self.now(),
            )
        except native_projection_reconciliation.NativeProjectionReconciliationError as error:
            raise NativeStackSessionManagerError(
                "native_projection_closure_unverified"
            ) from error

    def _projection_terminalization(
        self, journal: Mapping[str, Any], status: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if journal["projection_identity"] is None:
            return None
        custody = status["credential_custody"]
        if (status["network"]["phase"] != "closed"
                or status["live_run_count"] != 0
                or custody["state"] not in {"retained", "absent"}
                or custody["projection_count"] != 0):
            return None
        return make_projection_terminalization(
            original_operation_id=journal["action_id"], status=status,
            observed_at=self.now(),
        )

    def _record_projection_closure(
        self, path: Path, journal: dict[str, Any],
        status: Mapping[str, Any], *, phase: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if (journal["projection_identity"] is None
                and status["credential_custody"]["state"]
                    in {"ambiguous", "session-projected"}):
            # A helper projection can exist before the signed backend reply is
            # durably journaled (power loss at that exact boundary).  Never
            # infer that the absence of a Host identity means no projection.
            raise NativeStackSessionManagerError(
                "native_projection_identity_recovery_required"
            )
        closure = self._projection_closure(journal, status)
        terminalization = self._projection_terminalization(journal, status)
        self._write(
            path, journal, phase, projection_closure=closure,
            projection_terminalization=terminalization,
            network_open=False,
        )
        return closure, terminalization

    def _recover_one(
        self, path: Path, journal: dict[str, Any], *, reason: str,
    ) -> None:
        if journal["phase"] in TERMINAL_PHASES:
            return
        must_close = self._requires_close(journal)
        try:
            if (journal["projection_identity"] is not None
                    and journal["projection_closure"] is not None):
                status = native_stack_operations.validate_status(
                    self.backend.recover_status(
                        journal["plan"], journal["authorization"],
                        journal["journal_sha256"],
                    )
                )
                terminalization = self._projection_terminalization(
                    journal, status
                )
                if terminalization is None:
                    self._write(
                        path, journal, "projection-reconciliation-required",
                        error_code="native_projection_reconciliation_required",
                        network_open=False,
                    )
                    raise NativeStackSessionManagerError(
                        "native_projection_reconciliation_required"
                    )
                self._retire_handle(journal)
                self._write(
                    path, journal, "fenced", network_open=False,
                    projection_terminalization=terminalization,
                    error_code=reason,
                )
                self._finalize_handle_retirement(journal)
                return
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
            self._retire_handle(journal)
            _closure, terminalization = self._record_projection_closure(
                path, journal, status,
                phase="recovery-closure-verified",
            )
            if (journal["projection_identity"] is not None
                    and terminalization is None):
                self._write(
                    path, journal, "projection-reconciliation-required",
                    error_code="native_projection_reconciliation_required",
                    network_open=False,
                )
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_required"
                )
            self._write(
                path, journal, "fenced", network_open=False,
                error_code=reason,
            )
            self._finalize_handle_retirement(journal)
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
            elif journal["phase"] in TERMINAL_PHASES:
                self._retire_handle(journal)
                self._finalize_handle_retirement(journal)

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
                "projection_identity": None, "projection_closure": None,
                "projection_identity_recovery_plan": None,
                "projection_identity_recovery_reply": None,
                "projection_recovery_plan": None,
                "projection_reconciliation": None,
                "projection_terminalization": None,
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
                raw_public = self.backend.prepare(plan, authorization, grant)
                if raw_public.get("schema") == native_terminal_handle.PUBLIC_SCHEMA:
                    public = native_terminal_handle.validate_public(raw_public)
                    expected_kind = "claude-session"
                elif raw_public.get("schema") == native_codex_ui_handle.PUBLIC_SCHEMA:
                    public = native_codex_ui_handle.validate_public(raw_public)
                    expected_kind = native_codex_ui_handle.KIND
                else:
                    raise NativeStackSessionManagerError(
                        "native_stack_session_handle_schema_invalid"
                    )
                if (public["kind"] != expected_kind
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

    @staticmethod
    def _terminate_stream(process: subprocess.Popen[bytes] | None) -> None:
        if process is None:
            return
        if process.poll() is not None:
            process.wait()
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        process.wait(timeout=5)

    def _projection_consumer_sha256(self) -> str:
        try:
            before = self.projection_consumer.lstat()
            descriptor = os.open(
                self.projection_consumer,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as error:
            raise NativeStackSessionManagerError(
                "native_codex_projection_consumer_unavailable"
            ) from error
        try:
            opened = os.fstat(descriptor)
            digest_value = hashlib.sha256()
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest_value.update(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or before.st_uid != self.trusted_uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o555
                or before.st_size < 1
                or identity != (
                    opened.st_dev, opened.st_ino, opened.st_size,
                    opened.st_mtime_ns, opened.st_ctime_ns,
                )
                or identity != (
                    after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns,
                )):
            raise NativeStackSessionManagerError(
                "native_codex_projection_consumer_untrusted"
            )
        return digest_value.hexdigest()

    @staticmethod
    def _require_same_unix_stream(input_fd: int, output_fd: int) -> None:
        identities: list[tuple[object, ...]] = []
        for descriptor in (input_fd, output_fd):
            duplicate = socket.socket(fileno=os.dup(descriptor))
            try:
                info = os.fstat(descriptor)
                identities.append((
                    info.st_dev, info.st_ino, duplicate.family,
                    duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),
                    duplicate.getsockname(), duplicate.getpeername(),
                ))
            finally:
                duplicate.close()
        if (identities[0] != identities[1]
                or identities[0][2] != socket.AF_UNIX
                or identities[0][3] != socket.SOCK_STREAM):
            raise NativeStackSessionManagerError(
                "native_codex_ui_stream_invalid"
            )

    @staticmethod
    def _ack_projection_termination(
        connection: socket.socket, *, operation_id: str,
        session_authority_sha256: str,
    ) -> None:
        if (native_stack_operations.UUID4.fullmatch(operation_id) is None
                or native_stack_operations.SHA256.fullmatch(
                    session_authority_sha256
                ) is None):
            raise NativeStackSessionManagerError(
                "native_codex_projection_termination_authority_invalid"
            )
        payload = (
            PROJECTION_TERMINATION_MAGIC
            + operation_id.encode("ascii")
            + session_authority_sha256.encode("ascii")
        )
        if len(payload) != 108:
            raise NativeStackSessionManagerError(
                "native_codex_projection_termination_ack_invalid"
            )
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)

    def _codex_stream_command(
        self, operation: str, arguments: list[str], timeout: int,
    ) -> list[str]:
        if operation not in {"native-codex-launch", "native-codex-ui"}:
            raise NativeStackSessionManagerError(
                "native_codex_stream_operation_invalid"
            )
        return [
            str(self.backend.transport.control_client), "client",
            "--ssh-config", str(self.backend.transport.ssh_config),
            "--timeout-seconds", str(timeout), "sandbox-research-control",
            "stream", operation, *arguments,
        ]

    def run_codex(
        self, action_id: str, *, handle_fd: int = 3,
        input_fd: int = 0, output_fd: int = 1,
    ) -> int:
        """Own one typed UI run while keeping token and UI channels distinct."""
        self._require_same_unix_stream(input_fd, output_fd)
        record = native_codex_ui_handle.read_unlinked_fd(
            handle_fd, now=self.now(), trusted_uid=self.trusted_uid,
            trusted_gid=self.trusted_gid,
        )
        if record["operation_id"] != action_id:
            raise NativeStackSessionManagerError(
                "native_codex_ui_handle_action_mismatch"
            )
        control_root: socket.socket | None = None
        control_peer: socket.socket | None = None
        research_read: socket.socket | None = None
        consumer_write: socket.socket | None = None
        launch: subprocess.Popen[bytes] | None = None
        ui: subprocess.Popen[bytes] | None = None
        closure_verified = False
        projection_bound = False
        ack_attempted = False
        begin_attempted = False
        plan: dict[str, Any] | None = None
        try:
            begin_attempted = True
            begun = self.begin(action_id)
            if (begun["session_id"] != record["session_id"]
                    or begun["runtime_authority_sha256"]
                        != record["runtime_authority_sha256"]
                    or begun["session_lease_sha256"]
                        != record["session_lease"]["lease_sha256"]
                    or begun["session_expires_at"]
                        != record["session_lease"]["expires_at"]):
                raise NativeStackSessionManagerError(
                    "native_codex_ui_begin_mismatch"
                )
            with self.locked():
                _path, journal = self._record(action_id, "running")
                if (native_codex_ui_handle.public_record(record)
                        != journal["public_handle"]):
                    raise NativeStackSessionManagerError(
                        "native_codex_ui_handle_journal_mismatch"
                    )
                plan = journal["plan"]
                authorization = journal["authorization"]
                lease = journal["session_lease"]
            control_root, control_peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            projection_reply = self.backend.project_codex(
                plan, authorization, record["handle_id"], control_peer.fileno()
            )
            control_peer.close(); control_peer = None
            try:
                projection_reply = (
                    native_codex_projection.validate_client_projection_reply(
                        projection_reply,
                        expected_operation_id=plan["action_id"],
                        expected_session_authority_sha256=plan[
                            "runtime_authority_sha256"
                        ],
                        expected_executable_sha256=(
                            self._projection_consumer_sha256()
                        ),
                        now_ms=self.now() * 1000,
                    )
                )
            except native_codex_projection.NativeCodexProjectionError as error:
                raise NativeStackSessionManagerError(
                    "native_codex_projection_reply_mismatch"
                ) from error
            self._bind_projection_identity(action_id, projection_reply)
            projection_bound = True
            claim = native_codex_projection.read_claim(
                control_root.fileno(), now_ms=self.now() * 1000
            )
            if (claim["operation_id"] != plan["action_id"]
                    or claim["session_authority_sha256"]
                        != plan["runtime_authority_sha256"]
                    or claim["authorization_receipt_sha256"]
                        != authorization["pending_receipt_sha256"]):
                raise NativeStackSessionManagerError(
                    "native_codex_projection_claim_mismatch"
                )
            prepared = validate_codex_prepare_reply(
                self.backend.prepare_codex(
                    plan, authorization, record["handle_id"], lease, claim
                ),
                plan=plan, lease=lease, projection_claim=claim,
                now=self.now(),
            )
            remaining = lease["expires_at"] - self.now()
            if remaining <= 0:
                raise NativeStackSessionManagerError(
                    "native_codex_session_lease_expired"
                )
            research_read, consumer_write = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            launch = subprocess.Popen(
                self._codex_stream_command(
                    "native-codex-launch",
                    [plan["action_id"], prepared["prepare_sha256"]],
                    remaining,
                ), stdin=research_read, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
            )
            research_read.close(); research_read = None
            native_codex_projection.send_stream_fd(
                control_root.fileno(), consumer_write.fileno()
            )
            consumer_write.close(); consumer_write = None
            native_codex_projection.read_ready(
                control_root.fileno(),
                expected_operation_id=plan["action_id"],
                expected_access_token_sha256=claim["access_token_sha256"],
            )
            remaining = lease["expires_at"] - self.now()
            if remaining <= 0:
                raise NativeStackSessionManagerError(
                    "native_codex_session_lease_expired"
                )
            ui = subprocess.Popen(
                self._codex_stream_command(
                    "native-codex-ui", [
                        plan["session_id"], plan["runtime_authority_sha256"],
                        record["harness_generation_id"],
                        record["harness_executable_sha256"],
                        lease["lease_sha256"], str(lease["expires_at"]),
                    ], remaining,
                ), stdin=input_fd, stdout=output_fd,
                stderr=subprocess.DEVNULL, close_fds=True,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
            )
            ui_status = ui.wait(timeout=max(1, remaining))
            ui = None
            launch_status = launch.wait(timeout=30)
            launch = None
            if ui_status != 0 or launch_status != 0:
                raise NativeStackSessionManagerError(
                    "native_codex_session_stream_failed"
                )
            self.complete(action_id)
            closure_verified = True
            ack_attempted = True
            self._ack_projection_termination(
                control_root, operation_id=plan["action_id"],
                session_authority_sha256=plan["runtime_authority_sha256"],
            )
            self.finalize_projection(action_id)
            return 0
        except Exception:
            for process in (ui, launch):
                try:
                    self._terminate_stream(process)
                except Exception:
                    # Exact abort/readback below remains mandatory even if a
                    # local transport child cannot be synchronously reaped.
                    pass
            if not closure_verified and begin_attempted:
                try:
                    self.abort(action_id)
                    closure_verified = True
                except Exception:
                    pass
            if (closure_verified and projection_bound and not ack_attempted
                    and control_root is not None and plan is not None):
                ack_attempted = True
                try:
                    self._ack_projection_termination(
                        control_root, operation_id=plan["action_id"],
                        session_authority_sha256=plan[
                            "runtime_authority_sha256"
                        ],
                    )
                    self.finalize_projection(action_id)
                except Exception:
                    # Closing without the exact ack deliberately leaves the
                    # helper's durable custody state ambiguous.
                    pass
            raise
        finally:
            for connection in (
                consumer_write, research_read, control_peer, control_root,
            ):
                if connection is not None:
                    connection.close()

    def finalize_projection(self, action_id: str) -> dict[str, Any]:
        """Terminalize custody only after the helper independently clears it."""
        with self.locked():
            path, journal = self._record(action_id, None)
            if journal["projection_identity"] is None:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_missing"
                )
            if journal["projection_terminalization"] is not None:
                return journal["projection_terminalization"]
            if journal["projection_closure"] is None:
                raise NativeStackSessionManagerError(
                    "native_projection_closure_missing"
                )
            status = native_stack_operations.validate_status(
                self.backend.recover_status(
                    journal["plan"], journal["authorization"],
                    journal["journal_sha256"],
                )
            )
            terminalization = self._projection_terminalization(
                journal, status
            )
            if terminalization is None:
                self._write(
                    path, journal, "projection-reconciliation-required",
                    error_code="native_projection_reconciliation_required",
                    network_open=False,
                )
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_required"
                )
            terminal_phase = (
                "completed"
                if journal["phase"] == "projection-termination-pending"
                else "fenced"
            )
            self._write(
                path, journal, terminal_phase,
                projection_terminalization=terminalization,
                network_open=False,
            )
            self._finalize_handle_retirement(journal)
            return terminalization

    def projection_identity_recovery_plan(
        self, *, original_operation_id: str, recovery_operation_id: str,
    ) -> dict[str, Any]:
        """Authorize disclosure of one helper-committed process identity.

        This is intentionally read-only with respect to helper custody.  The
        independently observed guest/egress closure is still required before
        the separate projection-reconciliation ceremony may be planned.
        """
        with self.locked():
            path, journal = self._record(original_operation_id, None)
            if journal["projection_identity"] is not None:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_already_available"
                )
            if journal["projection_terminalization"] is not None:
                raise NativeStackSessionManagerError(
                    "native_projection_already_terminal"
                )
            if (journal["public_handle"] is None
                    or journal["public_handle"].get("schema")
                        != native_codex_ui_handle.PUBLIC_SCHEMA):
                raise NativeStackSessionManagerError(
                    "native_projection_identity_recovery_not_codex"
                )
            stop = self.backend.recover_stop(
                journal["plan"], journal["authorization"],
                journal["journal_sha256"],
            )
            self._write(
                path, journal, "projection-identity-plan-stop-verified",
                stop_reply=stop,
            )
            if self._requires_close(journal):
                self._rotate(path, journal, opening=False)
            status = native_stack_operations.validate_status(
                self.backend.recover_status(
                    journal["plan"], journal["authorization"],
                    journal["journal_sha256"],
                )
            )
            custody = status["credential_custody"]
            if (status["network"]["phase"] != "closed"
                    or status["live_run_count"] != 0
                    or stop.get("state") != "absent"
                    or custody["state"]
                        not in {"ambiguous", "session-projected"}):
                raise NativeStackSessionManagerError(
                    "native_projection_identity_recovery_not_required"
                )
            plan = native_projection_identity_recovery.make_plan(
                recovery_operation_id=recovery_operation_id,
                original_operation_id=original_operation_id,
                session_id=journal["session_id"],
                stack_id=journal["plan"]["stack_id"],
                stack_sha256=journal["plan"]["stack_sha256"],
                session_authority_sha256=journal["plan"][
                    "runtime_authority_sha256"
                ],
                host_release_id=str(self.host_release_id),
                created_at=self.now(),
            )
            self._write(
                path, journal,
                "projection-identity-recovery-awaiting-authorization",
                projection_identity_recovery_plan=plan,
                error_code="native_projection_identity_recovery_required",
                network_open=False,
            )
            return plan

    def recover_projection_identity(
        self, plan_value: object, authorization_value: object,
    ) -> dict[str, Any]:
        """Import a content-free committed identity; never clear custody."""
        with self.locked():
            try:
                plan = native_projection_identity_recovery.validate_plan(
                    plan_value, now=self.now(), require_fresh=True
                )
                authorization = (
                    native_projection_identity_recovery.validate_authorization(
                        authorization_value, plan, now=self.now(),
                        expected_host_release_id=str(self.host_release_id),
                    )
                )
            except native_projection_identity_recovery.NativeProjectionIdentityRecoveryError as error:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_recovery_authority_invalid"
                ) from error
            self._verify_projection_identity_recovery_receipt(
                plan, authorization
            )
            path, journal = self._record(plan["original_operation_id"], None)
            if (journal["projection_identity"] is not None
                    or journal["projection_terminalization"] is not None
                    or journal["projection_identity_recovery_plan"] != plan):
                raise NativeStackSessionManagerError(
                    "native_projection_identity_recovery_journal_mismatch"
                )
            status = native_stack_operations.validate_status(
                self.backend.recover_status(
                    journal["plan"], journal["authorization"],
                    journal["journal_sha256"],
                )
            )
            if (status["network"]["phase"] != "closed"
                    or status["live_run_count"] != 0
                    or status["credential_custody"]["state"]
                        not in {"ambiguous", "session-projected"}
                    or journal["stop_reply"] is None
                    or journal["stop_reply"].get("state") != "absent"):
                raise NativeStackSessionManagerError(
                    "native_projection_identity_recovery_state_changed"
                )
            raw_reply = self.backend.recover_projection_identity(
                plan, authorization, journal["plan"],
                journal["authorization"], journal["journal_sha256"],
            )
            try:
                reply = native_projection_identity_recovery.validate_reply(
                    raw_reply, plan_value=plan
                )
            except native_projection_identity_recovery.NativeProjectionIdentityRecoveryError as error:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_recovery_reply_invalid"
                ) from error
            identity = native_projection_reconciliation.make_identity(
                original_operation_id=plan["original_operation_id"],
                process_identifier=reply["process_identifier"],
                process_start_time_us=reply["process_start_time_us"],
                consumer_executable_sha256=reply[
                    "consumer_executable_sha256"
                ],
                session_authority_sha256=reply[
                    "session_authority_sha256"
                ],
                credential_response_sha256=reply[
                    "identity_evidence_sha256"
                ],
                credential_reply_sha256=reply["reply_sha256"],
                observed_at=self.now(),
            )
            self._write(
                path, journal, "projection-identity-recovered",
                projection_identity_recovery_reply=reply,
                projection_identity=identity,
                error_code="native_projection_reconciliation_required",
                network_open=False,
            )
            return reply

    def projection_recovery_plan(
        self, *, original_operation_id: str, recovery_operation_id: str,
    ) -> dict[str, Any]:
        """Create a fresh exact Touch ID plan from independently read closure."""
        with self.locked():
            path, journal = self._record(original_operation_id, None)
            identity = journal["projection_identity"]
            if identity is None:
                raise NativeStackSessionManagerError(
                    "native_projection_identity_missing"
                )
            if journal["projection_terminalization"] is not None:
                raise NativeStackSessionManagerError(
                    "native_projection_already_terminal"
                )
            if journal["projection_reconciliation"] is not None:
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_already_applied"
                )
            stop = self.backend.recover_stop(
                journal["plan"], journal["authorization"],
                journal["journal_sha256"],
            )
            self._write(
                path, journal, "projection-plan-stop-verified",
                stop_reply=stop,
            )
            if self._requires_close(journal):
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
                    "native_projection_recovery_closure_ambiguous"
                )
            closure = self._projection_closure(journal, status)
            if closure is None:
                raise NativeStackSessionManagerError(
                    "native_projection_closure_missing"
                )
            if self._projection_terminalization(journal, status) is not None:
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_no_longer_required"
                )
            now = self.now()
            plan = native_projection_reconciliation.make_plan(
                recovery_operation_id=recovery_operation_id,
                original_operation_id=original_operation_id,
                session_id=journal["session_id"],
                stack_id=journal["plan"]["stack_id"],
                stack_sha256=journal["plan"]["stack_sha256"],
                session_authority_sha256=journal["plan"][
                    "runtime_authority_sha256"
                ],
                process_identifier=identity["process_identifier"],
                process_start_time_us=identity["process_start_time_us"],
                consumer_executable_sha256=identity[
                    "consumer_executable_sha256"
                ],
                guest_absence_evidence_sha256=closure[
                    "guest_absence_evidence_sha256"
                ],
                egress_closed_evidence_sha256=closure[
                    "egress_closed_evidence_sha256"
                ],
                host_release_id=str(self.host_release_id),
                created_at=now,
            )
            self._write(
                path, journal,
                "projection-reconciliation-awaiting-authorization",
                projection_closure=closure,
                projection_recovery_plan=plan,
                error_code="native_projection_reconciliation_required",
                network_open=False,
            )
            return plan

    def reconcile_projection(
        self, plan_value: object, authorization_value: object,
    ) -> dict[str, Any]:
        with self.locked():
            try:
                plan = native_projection_reconciliation.validate_plan(
                    plan_value, now=self.now(), require_fresh=True
                )
                authorization = (
                    native_projection_reconciliation.validate_authorization(
                        authorization_value, plan, now=self.now(),
                        expected_host_release_id=str(self.host_release_id),
                    )
                )
            except native_projection_reconciliation.NativeProjectionReconciliationError as error:
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_authority_invalid"
                ) from error
            self._verify_projection_reconciliation_receipt(
                plan, authorization
            )
            path, journal = self._record(
                plan["original_operation_id"], None
            )
            if (journal["projection_identity"] is None
                    or journal["projection_closure"] is None
                    or journal["projection_terminalization"] is not None
                    or journal["projection_reconciliation"] is not None
                    or journal["projection_recovery_plan"] != plan):
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_journal_mismatch"
                )
            stop = self.backend.recover_stop(
                journal["plan"], journal["authorization"],
                journal["journal_sha256"],
            )
            status = native_stack_operations.validate_status(
                self.backend.recover_status(
                    journal["plan"], journal["authorization"],
                    journal["journal_sha256"],
                )
            )
            try:
                egress_evidence = (
                    native_projection_reconciliation
                    .closed_egress_evidence_sha256(status)
                )
            except native_projection_reconciliation.NativeProjectionReconciliationError as error:
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_closure_changed"
                ) from error
            if (stop.get("state") != "absent"
                    or stop.get("evidence_sha256")
                        != plan["guest_absence_evidence_sha256"]
                    or egress_evidence
                        != plan["egress_closed_evidence_sha256"]
                    or status["credential_custody"]["state"]
                        not in {"ambiguous", "session-projected"}):
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_closure_changed"
                )
            reply = self.backend.reconcile_projection(
                plan, authorization, journal["plan"],
                journal["authorization"], journal["journal_sha256"],
            )
            try:
                reply = native_projection_reconciliation.validate_reply(
                    reply, plan_value=plan
                )
            except native_projection_reconciliation.NativeProjectionReconciliationError as error:
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_reply_invalid"
                ) from error
            self._write(
                path, journal, "projection-reconciliation-applied",
                projection_reconciliation=reply,
                error_code="native_projection_reconciliation_readback_pending",
                network_open=False,
            )
            final_status = native_stack_operations.validate_status(
                self.backend.recover_status(
                    journal["plan"], journal["authorization"],
                    journal["journal_sha256"],
                )
            )
            terminalization = self._projection_terminalization(
                journal, final_status
            )
            if terminalization is None:
                self._write(
                    path, journal, "projection-reconciliation-readback-required",
                    error_code="native_projection_reconciliation_readback_required",
                )
                raise NativeStackSessionManagerError(
                    "native_projection_reconciliation_readback_required"
                )
            self._retire_handle(journal)
            self._write(
                path, journal, "fenced", network_open=False,
                projection_terminalization=terminalization,
                error_code="native_projection_reconciled",
            )
            self._finalize_handle_retirement(journal)
            return reply

    def complete(self, action_id: str) -> dict[str, Any]:
        with self.locked():
            path, journal = self._record(action_id, None)
            if (journal["phase"] in TERMINAL_PHASES
                    or not journal["network_open"]):
                raise NativeStackSessionManagerError(
                    "native_stack_session_not_running"
                )
            try:
                stop = self.backend.stop_continuation(
                    journal["plan"], journal["authorization"],
                    journal["public_handle"]["handle_id"],
                )
                self._write(path, journal, "stop-verified", stop_reply=stop)
                evidence = self._rotate(path, journal, opening=False)
                status = self._verify_closed(journal)
                self._retire_handle(journal)
                _closure, terminalization = self._record_projection_closure(
                    path, journal, status,
                    phase=(
                        "projection-termination-pending"
                        if journal["projection_identity"] is not None
                        else "closure-verified"
                    ),
                )
                body = {
                    "action_id": action_id,
                    "session_id": journal["session_id"],
                    "state": "absent",
                    "final_summary_sha256": stop["final_summary_sha256"],
                    "evidence_sha256": digest([stop, *evidence]),
                }
                if journal["projection_identity"] is None:
                    self._write(path, journal, "completed")
                    self._finalize_handle_retirement(journal)
                elif terminalization is not None:
                    self._write(path, journal, "completed")
                    self._finalize_handle_retirement(journal)
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
                status = self._verify_closed(journal)
                self._retire_handle(journal)
                _closure, terminalization = self._record_projection_closure(
                    path, journal, status,
                    phase=(
                        "projection-reconciliation-required"
                        if (journal["projection_identity"] is not None
                            and self._projection_terminalization(
                                journal, status
                            ) is None)
                        else "abort-closure-verified"
                    ),
                )
                if (journal["projection_identity"] is None
                        or terminalization is not None):
                    self._write(
                        path, journal, "fenced",
                        error_code="native_stack_session_stream_aborted",
                    )
                    self._finalize_handle_retirement(journal)
                body = {
                    "action_id": action_id,
                    "session_id": journal["session_id"],
                    "state": (
                        "fenced" if terminalization is not None
                        or journal["projection_identity"] is None
                        else "reconciliation-required"
                    ),
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
                self._retire_handle(journal)
                _closure, terminalization = self._record_projection_closure(
                    path, journal, status,
                    phase=(
                        "projection-reconciliation-required"
                        if journal["projection_identity"] is not None
                        else "explicit-stop-closure-verified"
                    ),
                )
                if (journal["projection_identity"] is None
                        or terminalization is not None):
                    self._write(path, journal, "stopped")
                    self._finalize_handle_retirement(journal)
                else:
                    # The guest process and egress are absent, but the signed
                    # helper still reports a live/ambiguous projection.  A
                    # plain guest `state: absent` must never finalize the
                    # operator receipt or be presented as credential absence.
                    raise NativeStackSessionManagerError(
                        "native_projection_reconciliation_required"
                    )
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

    def _verify_closed(
        self, journal: Mapping[str, Any]
    ) -> dict[str, Any]:
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
        return status

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
    codex = sub.add_parser("codex-run")
    codex.add_argument("--action-id", required=True)
    recovery_plan = sub.add_parser("projection-recovery-plan")
    recovery_plan.add_argument("--original-operation-id", required=True)
    recovery_plan.add_argument("--recovery-operation-id", required=True)
    identity_plan = sub.add_parser("projection-identity-recovery-plan")
    identity_plan.add_argument("--original-operation-id", required=True)
    identity_plan.add_argument("--recovery-operation-id", required=True)
    identity_recover = sub.add_parser("projection-identity-recover")
    identity_recover.add_argument("--plan-json", required=True)
    identity_recover.add_argument("--authorization-json", required=True)
    reconcile = sub.add_parser("projection-reconcile")
    reconcile.add_argument("--plan-json", required=True)
    reconcile.add_argument("--authorization-json", required=True)
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
        elif args.command == "codex-run":
            return manager.run_codex(args.action_id)
        elif args.command == "projection-recovery-plan":
            result = manager.projection_recovery_plan(
                original_operation_id=args.original_operation_id,
                recovery_operation_id=args.recovery_operation_id,
            )
        elif args.command == "projection-identity-recovery-plan":
            result = manager.projection_identity_recovery_plan(
                original_operation_id=args.original_operation_id,
                recovery_operation_id=args.recovery_operation_id,
            )
        elif args.command == "projection-identity-recover":
            result = manager.recover_projection_identity(
                json.loads(args.plan_json.encode("ascii")),
                json.loads(args.authorization_json.encode("ascii")),
            )
        elif args.command == "projection-reconcile":
            result = manager.reconcile_projection(
                json.loads(args.plan_json.encode("ascii")),
                json.loads(args.authorization_json.encode("ascii")),
            )
        else:
            result = manager.recover()
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (
        NativeStackSessionManagerError,
        native_stack_session.NativeStackSessionError,
        native_stack_operations.NativeStackOperationError,
        native_egress.NativeEgressError,
        native_codex_projection.NativeCodexProjectionError,
        native_codex_ui_handle.NativeCodexUIHandleError,
        native_projection_identity_recovery.NativeProjectionIdentityRecoveryError,
        native_projection_reconciliation.NativeProjectionReconciliationError,
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
