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
            "name", "size", "sha256"
        }:
            raise NativeDeploymentError("native_deployment_package_file_invalid")
        name = item["name"]
        size = item["size"]
        sha256 = item["sha256"]
        if (
            not isinstance(name, str)
            or SAFE_NAME.fullmatch(name) is None
            or name in observed_names
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= 128 * 1024 * 1024
        ):
            raise NativeDeploymentError("native_deployment_package_file_invalid")
        _sha256(sha256, "package_file_digest")
        observed_names.add(name)
        admitted.append({"name": name, "size": size, "sha256": sha256})
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
        "previous_research_package_sha256", "created_at", "expires_at",
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
        created_at=value["created_at"],
        expires_at=value["expires_at"],
    )
    if value.get("schema") != PLAN_SCHEMA or dict(value) != admitted:
        raise NativeDeploymentError("native_deployment_plan_invalid")
    timestamp = int(time.time()) if now is None else now
    if require_fresh and not admitted["created_at"] <= timestamp < admitted["expires_at"]:
        raise NativeDeploymentError("native_deployment_plan_expired")
    return admitted


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
