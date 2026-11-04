#!/usr/bin/env python3
"""Canonical authority for native-stack protected deployment.

The Host deployment coordinator, the Research lifecycle fence, and both guest
installers exchange only the values defined here.  A package identity covers
the complete ordered source inventory.  A deployment plan binds those two
package identities to the active protected Host release and the exact catalog
that must be installed on Research.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Mapping, Sequence


PACKAGE_SCHEMA = "secure-sandbox-native-deployment-package-v1"
PLAN_SCHEMA = "secure-sandbox-native-deployment-plan-v1"
STATUS_SCHEMA = "secure-sandbox-native-deployment-status-v1"
FENCE_REQUEST_SCHEMA = "secure-sandbox-native-deployment-fence-request-v1"
FENCE_REPLY_SCHEMA = "secure-sandbox-native-deployment-fence-reply-v1"
RELEASE_REQUEST_SCHEMA = "secure-sandbox-native-deployment-release-request-v1"
RELEASE_REPLY_SCHEMA = "secure-sandbox-native-deployment-release-reply-v1"
AUTHORIZATION_SCHEMA = (
    "secure-sandbox-native-deployment-touchid-authorization-v1"
)
REQUEST_SCHEMA = "secure-sandbox-native-deployment-authorized-request-v1"
APPLY_OPERATION = "native-deployment-apply"
RECOVER_OPERATION = "native-deployment-recover"
OPERATION = APPLY_OPERATION
OPERATIONS = {APPLY_OPERATION, RECOVER_OPERATION}
RESOURCE = "Protected native vendor harness and model stack deployment authority"
MAX_CANONICAL_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}"
)


class NativeDeploymentError(RuntimeError):
    """Stable fail-closed native deployment error."""


def canonical(value: object, *, maximum: int = MAX_CANONICAL_BYTES) -> bytes:
    try:
        raw = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeDeploymentError("native_deployment_value_invalid") from error
    if not 2 <= len(raw) <= maximum:
        raise NativeDeploymentError("native_deployment_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeDeploymentError(f"native_deployment_{label}_invalid")
    return value


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeDeploymentError(f"native_deployment_{label}_invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise NativeDeploymentError(
            f"native_deployment_{label}_invalid"
        ) from error
    if parsed.version != 4 or str(parsed) != value:
        raise NativeDeploymentError(f"native_deployment_{label}_invalid")
    return value


def _optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def make_package(role: str, files: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if role not in {"gateway", "research"}:
        raise NativeDeploymentError("native_deployment_package_role_invalid")
    admitted: list[dict[str, Any]] = []
    observed_names: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping) or set(item) != {
            "name", "size", "sha256", "mode"
        }:
            raise NativeDeploymentError("native_deployment_package_file_invalid")
        name = item["name"]
        size = item["size"]
        sha256 = item["sha256"]
        mode = item["mode"]
        if (
            not isinstance(name, str)
            or SAFE_NAME.fullmatch(name) is None
            or name in observed_names
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= 128 * 1024 * 1024
            or not isinstance(mode, int)
            or isinstance(mode, bool)
            or mode not in {0o600, 0o700}
        ):
            raise NativeDeploymentError("native_deployment_package_file_invalid")
        _sha256(sha256, "package_file_digest")
        observed_names.add(name)
        admitted.append({
            "name": name, "size": size, "sha256": sha256, "mode": mode,
        })
    admitted.sort(key=lambda value: value["name"])
    if not 1 <= len(admitted) <= 256:
        raise NativeDeploymentError("native_deployment_package_inventory_invalid")
    body = {"role": role, "files": admitted}
    return {"schema": PACKAGE_SCHEMA, **body, "package_sha256": digest(body)}


def validate_package(value: object, *, role: str | None = None) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "role", "files", "package_sha256"
    }:
        raise NativeDeploymentError("native_deployment_package_invalid")
    candidate_role = value.get("role")
    if role is not None and candidate_role != role:
        raise NativeDeploymentError("native_deployment_package_role_mismatch")
    admitted = make_package(str(candidate_role), value.get("files", []))
    if value.get("schema") != PACKAGE_SCHEMA or dict(value) != admitted:
        raise NativeDeploymentError("native_deployment_package_invalid")
    return admitted


def make_plan(
    *,
    deployment_id: str,
    host_release_id: str,
    catalog_sha256: str,
    gateway_package_sha256: str,
    research_package_sha256: str,
    previous_gateway_package_sha256: str | None,
    previous_research_package_sha256: str | None,
    previous_gateway_status_sha256: str,
    previous_research_status_sha256: str,
    created_at: int | None = None,
    expires_at: int | None = None,
) -> dict[str, Any]:
    _uuid4(deployment_id, "deployment_id")
    for value, label in (
        (host_release_id, "host_release_id"),
        (catalog_sha256, "catalog_digest"),
        (gateway_package_sha256, "gateway_package_digest"),
        (research_package_sha256, "research_package_digest"),
    ):
        _sha256(value, label)
    _optional_sha256(
        previous_gateway_package_sha256, "previous_gateway_package_digest"
    )
    _optional_sha256(
        previous_research_package_sha256, "previous_research_package_digest"
    )
    _sha256(previous_gateway_status_sha256, "previous_gateway_status_digest")
    _sha256(previous_research_status_sha256, "previous_research_status_digest")
    timestamp = int(time.time()) if created_at is None else created_at
    expiry = timestamp + 1800 if expires_at is None else expires_at
    if (
        not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or not isinstance(expiry, int)
        or isinstance(expiry, bool)
        or not 1 <= timestamp < expiry
        or expiry - timestamp > 3600
    ):
        raise NativeDeploymentError("native_deployment_plan_time_invalid")
    body = {
        "deployment_id": deployment_id,
        "host_release_id": host_release_id,
        "catalog_sha256": catalog_sha256,
        "gateway_package_sha256": gateway_package_sha256,
        "research_package_sha256": research_package_sha256,
        "previous_gateway_package_sha256": previous_gateway_package_sha256,
        "previous_research_package_sha256": previous_research_package_sha256,
        "previous_gateway_status_sha256": previous_gateway_status_sha256,
        "previous_research_status_sha256": previous_research_status_sha256,
        "created_at": timestamp,
        "expires_at": expiry,
    }
    return {"schema": PLAN_SCHEMA, **body, "plan_sha256": digest(body)}


def validate_plan(
    value: object, *, now: int | None = None, require_fresh: bool = True,
) -> dict[str, Any]:
    fields = {
        "schema", "deployment_id", "host_release_id", "catalog_sha256",
        "gateway_package_sha256", "research_package_sha256",
        "previous_gateway_package_sha256",
        "previous_research_package_sha256", "previous_gateway_status_sha256",
        "previous_research_status_sha256", "created_at", "expires_at",
        "plan_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeDeploymentError("native_deployment_plan_invalid")
    admitted = make_plan(
        deployment_id=value["deployment_id"],
        host_release_id=value["host_release_id"],
        catalog_sha256=value["catalog_sha256"],
        gateway_package_sha256=value["gateway_package_sha256"],
        research_package_sha256=value["research_package_sha256"],
        previous_gateway_package_sha256=value[
            "previous_gateway_package_sha256"
        ],
        previous_research_package_sha256=value[
            "previous_research_package_sha256"
        ],
        previous_gateway_status_sha256=value[
            "previous_gateway_status_sha256"
        ],
        previous_research_status_sha256=value[
            "previous_research_status_sha256"
        ],
        created_at=value["created_at"],
        expires_at=value["expires_at"],
    )
    if value.get("schema") != PLAN_SCHEMA or dict(value) != admitted:
        raise NativeDeploymentError("native_deployment_plan_invalid")
    timestamp = int(time.time()) if now is None else now
    if require_fresh and not admitted["created_at"] <= timestamp < admitted["expires_at"]:
        raise NativeDeploymentError("native_deployment_plan_expired")
    return admitted


def make_authorization(
    plan: Mapping[str, Any], *, authorization_id: str,
    request_sha256: str, pending_receipt_sha256: str,
    requesting_agent_sha256: str, requesting_session_sha256: str,
    authorized_at: int, expires_at: int,
    operation: str = APPLY_OPERATION,
    recovery_action: str = "apply",
    active_journal_sha256: str | None = None,
) -> dict[str, Any]:
    if operation not in OPERATIONS:
        raise NativeDeploymentError("native_deployment_operation_invalid")
    admitted = validate_plan(
        plan, now=authorized_at, require_fresh=operation == APPLY_OPERATION)
    _uuid4(authorization_id, "authorization_id")
    for value, label in (
        (request_sha256, "authorization_request_digest"),
        (pending_receipt_sha256, "authorization_receipt_digest"),
        (requesting_agent_sha256, "authorization_agent_digest"),
        (requesting_session_sha256, "authorization_session_digest"),
    ):
        _sha256(value, label)
    if operation == APPLY_OPERATION:
        if recovery_action != "apply" or active_journal_sha256 is not None:
            raise NativeDeploymentError(
                "native_deployment_authorization_action_invalid")
    elif (
        recovery_action not in {"resume", "rollback"}
        or active_journal_sha256 is None
    ):
        raise NativeDeploymentError(
            "native_deployment_authorization_action_invalid")
    if active_journal_sha256 is not None:
        _sha256(active_journal_sha256, "authorization_journal_digest")
    if (
        not isinstance(authorized_at, int)
        or isinstance(authorized_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not 0 < authorized_at < expires_at <= authorized_at + 120
        or (
            operation == APPLY_OPERATION
            and (
                authorized_at < admitted["created_at"]
                or expires_at > admitted["expires_at"]
            )
        )
    ):
        raise NativeDeploymentError(
            "native_deployment_authorization_time_invalid")
    body = {
        "authorization_id": authorization_id,
        "request_sha256": request_sha256,
        "pending_receipt_sha256": pending_receipt_sha256,
        "operation": operation,
        "recovery_action": recovery_action,
        "active_journal_sha256": active_journal_sha256,
        "deployment_id": admitted["deployment_id"],
        "plan_sha256": admitted["plan_sha256"],
        "method": "touch-id",
        "password_fallback": False,
        "authorized_at": authorized_at,
        "expires_at": expires_at,
        "host_release_id": admitted["host_release_id"],
        "requesting_agent_sha256": requesting_agent_sha256,
        "requesting_session_sha256": requesting_session_sha256,
    }
    unsigned = {"schema": AUTHORIZATION_SCHEMA, **body}
    return {**unsigned, "authorization_sha256": digest(unsigned)}


def validate_authorization(
    value: object, plan: Mapping[str, Any], *, now: int | None = None,
    require_fresh: bool = True, expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    operation = value.get("operation") if isinstance(value, Mapping) else None
    admitted_plan = validate_plan(
        plan, now=now,
        require_fresh=require_fresh and operation == APPLY_OPERATION,
    )
    fields = {
        "schema", "authorization_id", "request_sha256",
        "pending_receipt_sha256", "operation", "recovery_action",
        "active_journal_sha256", "deployment_id", "plan_sha256", "method",
        "password_fallback", "authorized_at", "expires_at", "host_release_id",
        "requesting_agent_sha256", "requesting_session_sha256",
        "authorization_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeDeploymentError("native_deployment_authorization_invalid")
    expected = make_authorization(
        admitted_plan,
        authorization_id=value["authorization_id"],
        request_sha256=value["request_sha256"],
        pending_receipt_sha256=value["pending_receipt_sha256"],
        requesting_agent_sha256=value["requesting_agent_sha256"],
        requesting_session_sha256=value["requesting_session_sha256"],
        authorized_at=value["authorized_at"], expires_at=value["expires_at"],
        operation=value["operation"], recovery_action=value["recovery_action"],
        active_journal_sha256=value["active_journal_sha256"],
    )
    timestamp = int(time.time()) if now is None else now
    if (
        dict(value) != expected
        or value["deployment_id"] != admitted_plan["deployment_id"]
        or value["plan_sha256"] != admitted_plan["plan_sha256"]
        or value["host_release_id"] != admitted_plan["host_release_id"]
        or value["method"] != "touch-id"
        or value["password_fallback"] is not False
        or (require_fresh and not value["authorized_at"] <= timestamp < value["expires_at"])
        or (
            expected_host_release_id is not None
            and value["host_release_id"] != expected_host_release_id
        )
    ):
        raise NativeDeploymentError("native_deployment_authorization_invalid")
    return expected


def make_authorized_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
) -> dict[str, Any]:
    admitted_plan = validate_plan(plan, require_fresh=False)
    admitted_authorization = validate_authorization(
        authorization, admitted_plan,
        now=authorization.get("authorized_at", 0), require_fresh=False,
    )
    body = {"plan": admitted_plan, "authorization": admitted_authorization}
    return {"schema": REQUEST_SCHEMA, **body, "request_sha256": digest(body)}


def validate_authorized_request(
    value: object, *, now: int | None = None, require_fresh: bool = True,
    expected_host_release_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "plan", "authorization", "request_sha256"
    }:
        raise NativeDeploymentError("native_deployment_request_invalid")
    operation = (
        value["authorization"].get("operation")
        if isinstance(value.get("authorization"), Mapping) else None
    )
    admitted_plan = validate_plan(
        value["plan"], now=now,
        require_fresh=require_fresh and operation == APPLY_OPERATION,
    )
    if (
        expected_host_release_id is not None
        and admitted_plan["host_release_id"] != expected_host_release_id
    ):
        raise NativeDeploymentError("native_deployment_request_release_mismatch")
    admitted_authorization = validate_authorization(
        value["authorization"], admitted_plan, now=now,
        require_fresh=require_fresh,
        expected_host_release_id=expected_host_release_id,
    )
    body = {"plan": admitted_plan, "authorization": admitted_authorization}
    if (
        value.get("schema") != REQUEST_SCHEMA
        or not isinstance(value.get("request_sha256"), str)
        or not hmac.compare_digest(value["request_sha256"], digest(body))
    ):
        raise NativeDeploymentError("native_deployment_request_invalid")
    return admitted_plan, admitted_authorization


def validate_predecessor(
    plan: Mapping[str, Any], *, role: str, generation_kind: str,
    package_sha256: str | None,
) -> tuple[str, str | None]:
    admitted = validate_plan(plan, require_fresh=False)
    if role not in {"gateway", "research"}:
        raise NativeDeploymentError(
            "native_deployment_predecessor_role_invalid")
    if generation_kind not in {"absent", "legacy", "protected"}:
        raise NativeDeploymentError(
            "native_deployment_predecessor_kind_invalid")
    if (generation_kind == "absent") != (package_sha256 is None):
        raise NativeDeploymentError(
            "native_deployment_predecessor_invalid")
    if package_sha256 is not None:
        _sha256(package_sha256, "predecessor_package_digest")
    expected = admitted[f"previous_{role}_package_sha256"]
    if package_sha256 != expected:
        raise NativeDeploymentError(
            "native_deployment_predecessor_mismatch")
    return generation_kind, package_sha256


def fence_identity(plan: Mapping[str, Any]) -> dict[str, str]:
    admitted = validate_plan(plan, now=int(plan["created_at"]))
    return {
        "promotion_id": admitted["deployment_id"],
        "plan_sha256": admitted["plan_sha256"],
        "previous_catalog_sha256": admitted["catalog_sha256"],
        "catalog_sha256": admitted["catalog_sha256"],
    }


def make_fence_request(plan: Mapping[str, Any]) -> dict[str, Any]:
    admitted = validate_plan(plan, now=int(plan["created_at"]))
    body = {"plan": admitted}
    return {"schema": FENCE_REQUEST_SCHEMA, **body,
            "request_sha256": digest(body)}


def validate_fence_request(value: object, *, now: int | None = None
                           ) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "plan", "request_sha256"
    }:
        raise NativeDeploymentError("native_deployment_fence_request_invalid")
    plan = validate_plan(value.get("plan"), now=now)
    body = {"plan": plan}
    if (
        value.get("schema") != FENCE_REQUEST_SCHEMA
        or value.get("request_sha256") != digest(body)
    ):
        raise NativeDeploymentError("native_deployment_fence_request_invalid")
    return {"schema": FENCE_REQUEST_SCHEMA, **body,
            "request_sha256": value["request_sha256"]}


def make_release_request(plan: Mapping[str, Any]) -> dict[str, Any]:
    admitted = validate_plan(plan, now=int(plan["created_at"]))
    body = {"plan": admitted}
    return {"schema": RELEASE_REQUEST_SCHEMA, **body,
            "request_sha256": digest(body)}


def validate_release_request(value: object, *, now: int | None = None
                             ) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "plan", "request_sha256"
    }:
        raise NativeDeploymentError("native_deployment_release_request_invalid")
    plan = validate_plan(value.get("plan"), now=now, require_fresh=False)
    body = {"plan": plan}
    if (
        value.get("schema") != RELEASE_REQUEST_SCHEMA
        or value.get("request_sha256") != digest(body)
    ):
        raise NativeDeploymentError("native_deployment_release_request_invalid")
    return {"schema": RELEASE_REQUEST_SCHEMA, **body,
            "request_sha256": value["request_sha256"]}


def make_status(
    *, role: str, package_sha256: str | None, release_id: str | None,
    catalog_sha256: str | None, closed_evidence_sha256: str | None,
    observed_at: int, state: str, generation_kind: str,
) -> dict[str, Any]:
    if role not in {"gateway", "research"} or state not in {"absent", "verified"}:
        raise NativeDeploymentError("native_deployment_status_invalid")
    if not isinstance(observed_at, int) or isinstance(observed_at, bool) or observed_at < 1:
        raise NativeDeploymentError("native_deployment_status_invalid")
    if state == "absent":
        if generation_kind != "absent":
            raise NativeDeploymentError("native_deployment_status_invalid")
        if any(value is not None for value in (
            package_sha256, release_id, catalog_sha256,
            closed_evidence_sha256,
        )):
            raise NativeDeploymentError("native_deployment_status_invalid")
    else:
        if generation_kind not in {"legacy", "protected"}:
            raise NativeDeploymentError("native_deployment_status_invalid")
        _sha256(package_sha256, "status_package_digest")
        _sha256(release_id, "status_release_id")
        _sha256(closed_evidence_sha256, "status_closed_evidence")
        if role == "research":
            _sha256(catalog_sha256, "status_catalog_digest")
        elif catalog_sha256 is not None:
            raise NativeDeploymentError("native_deployment_status_invalid")
    body = {
        "role": role,
        "state": state,
        "generation_kind": generation_kind,
        "package_sha256": package_sha256,
        "release_id": release_id,
        "catalog_sha256": catalog_sha256,
        "closed_evidence_sha256": closed_evidence_sha256,
        "pending": False,
        "observed_at": observed_at,
    }
    return {"schema": STATUS_SCHEMA, **body,
            "evidence_sha256": digest(body)}


def validate_status(value: object) -> dict[str, Any]:
    fields = {
        "schema", "role", "state", "package_sha256", "release_id",
        "catalog_sha256", "closed_evidence_sha256", "pending",
        "observed_at", "generation_kind", "evidence_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeDeploymentError("native_deployment_status_invalid")
    admitted = make_status(
        role=value["role"], state=value["state"],
        package_sha256=value["package_sha256"], release_id=value["release_id"],
        catalog_sha256=value["catalog_sha256"],
        closed_evidence_sha256=value["closed_evidence_sha256"],
        observed_at=value["observed_at"], generation_kind=value["generation_kind"],
    )
    if value.get("schema") != STATUS_SCHEMA or dict(value) != admitted:
        raise NativeDeploymentError("native_deployment_status_invalid")
    return admitted


def stable_status_projection(value: object) -> dict[str, Any]:
    """Return the time-independent guest identity bound into a Host plan."""
    admitted = validate_status(value)
    return {
        "role": admitted["role"],
        "state": admitted["state"],
        "generation_kind": admitted["generation_kind"],
        "package_sha256": admitted["package_sha256"],
        "release_id": admitted["release_id"],
        "catalog_sha256": admitted["catalog_sha256"],
        "closed_evidence_sha256": admitted["closed_evidence_sha256"],
    }


def stable_status_sha256(value: object) -> str:
    return digest(stable_status_projection(value))


def validate_plan_predecessor_statuses(
    plan: Mapping[str, Any], *, gateway_status: object,
    research_status: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    admitted = validate_plan(plan, require_fresh=False)
    gateway = validate_status(gateway_status)
    research = validate_status(research_status)
    if (
        gateway["role"] != "gateway"
        or research["role"] != "research"
        or gateway["package_sha256"]
        != admitted["previous_gateway_package_sha256"]
        or research["package_sha256"]
        != admitted["previous_research_package_sha256"]
        or stable_status_sha256(gateway)
        != admitted["previous_gateway_status_sha256"]
        or stable_status_sha256(research)
        != admitted["previous_research_status_sha256"]
    ):
        raise NativeDeploymentError(
            "native_deployment_predecessor_status_mismatch")
    return gateway, research


def validate_plan_predecessor_status(
    plan: Mapping[str, Any], *, role: str, status: object,
) -> dict[str, Any]:
    admitted = validate_plan(plan, require_fresh=False)
    observed = validate_status(status)
    if (
        role not in {"gateway", "research"}
        or observed["role"] != role
        or observed["package_sha256"]
        != admitted[f"previous_{role}_package_sha256"]
        or stable_status_sha256(observed)
        != admitted[f"previous_{role}_status_sha256"]
    ):
        raise NativeDeploymentError(
            "native_deployment_predecessor_status_mismatch")
    return observed
