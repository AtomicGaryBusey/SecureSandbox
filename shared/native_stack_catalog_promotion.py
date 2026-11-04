"""Exact, content-free authority objects for protected catalog promotion.

The operator catalog is inert until one short-lived Touch ID plan is consumed
by the root promoter.  These validators are deliberately shared by the
operator broker and root consumer so neither side can silently broaden the
other's accepted schema.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Mapping


PLAN_SCHEMA = "secure-sandbox-native-stack-catalog-promotion-plan-v1"
AUTHORIZATION_SCHEMA = (
    "secure-sandbox-native-stack-catalog-promotion-touchid-authorization-v1"
)
REQUEST_SCHEMA = "secure-sandbox-native-stack-catalog-promotion-request-v1"
RECEIPT_SCHEMA = "secure-sandbox-native-stack-catalog-promotion-receipt-v1"
OPERATION = "native-stack-catalog-promote"
RESOURCE = "Protected native vendor harness and model stack catalog authority"
MAX_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class NativeStackCatalogPromotionError(ValueError):
    """Stable fail-closed catalog-promotion schema rejection."""


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = (
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
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_not_canonicalizable"
        ) from error
    if len(encoded) > MAX_BYTES:
        raise NativeStackCatalogPromotionError("native_catalog_promotion_oversized")
    return encoded


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackCatalogPromotionError(
            f"native_catalog_promotion_{label}_fields_invalid"
        )
    return value


def _digest(value: object, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeStackCatalogPromotionError(
            f"native_catalog_promotion_{label}_invalid"
        )


def validate_plan(
    value: object, *, now: int | None = None, require_fresh: bool = False
) -> dict[str, Any]:
    plan = _exact(
        value,
        {
            "schema",
            "promotion_id",
            "source_uid",
            "source_sha256",
            "previous_catalog_sha256",
            "catalog_sha256",
            "created_at",
            "expires_at",
            "host_release_id",
            "plan_sha256",
        },
        "plan",
    )
    if plan["schema"] != PLAN_SCHEMA:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_schema_invalid"
        )
    if not isinstance(plan["promotion_id"], str) or UUID4.fullmatch(
        plan["promotion_id"]
    ) is None:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_id_invalid"
        )
    try:
        parsed = uuid.UUID(plan["promotion_id"])
    except ValueError as error:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_id_invalid"
        ) from error
    if parsed.version != 4 or str(parsed) != plan["promotion_id"]:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_id_invalid"
        )
    if (
        not isinstance(plan["source_uid"], int)
        or isinstance(plan["source_uid"], bool)
        or plan["source_uid"] <= 0
    ):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_source_uid_invalid"
        )
    _digest(plan["source_sha256"], "source_sha256")
    _digest(
        plan["previous_catalog_sha256"],
        "previous_catalog_sha256",
        optional=True,
    )
    _digest(plan["catalog_sha256"], "catalog_sha256")
    _digest(plan["host_release_id"], "host_release_id")
    _digest(plan["plan_sha256"], "plan_sha256")
    if not hmac.compare_digest(plan["source_sha256"], plan["catalog_sha256"]):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_source_catalog_mismatch"
        )
    created_at = plan["created_at"]
    expires_at = plan["expires_at"]
    if (
        not isinstance(created_at, int)
        or isinstance(created_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not 0 < created_at < expires_at <= created_at + 300
        or (require_fresh and (int(time.time()) if now is None else now) >= expires_at)
    ):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_expired"
        )
    body = {key: item for key, item in plan.items() if key not in {"schema", "plan_sha256"}}
    if not hmac.compare_digest(plan["plan_sha256"], sha256(body)):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_digest_mismatch"
        )
    canonical_bytes(plan)
    return plan


def make_plan(
    *,
    source_uid: int,
    source_sha256: str,
    previous_catalog_sha256: str | None,
    host_release_id: str,
    now: int | None = None,
    promotion_id: str | None = None,
    lifetime_seconds: int = 180,
) -> dict[str, Any]:
    created_at = int(time.time()) if now is None else now
    if not isinstance(lifetime_seconds, int) or not 1 <= lifetime_seconds <= 300:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_lifetime_invalid"
        )
    body = {
        "promotion_id": str(uuid.uuid4()) if promotion_id is None else promotion_id,
        "source_uid": source_uid,
        "source_sha256": source_sha256,
        "previous_catalog_sha256": previous_catalog_sha256,
        "catalog_sha256": source_sha256,
        "created_at": created_at,
        "expires_at": created_at + lifetime_seconds,
        "host_release_id": host_release_id,
    }
    return validate_plan(
        {"schema": PLAN_SCHEMA, **body, "plan_sha256": sha256(body)},
        now=created_at,
        require_fresh=True,
    )


def validate_authorization(
    value: object,
    plan_value: object,
    *,
    now: int,
    require_fresh: bool = True,
    expected_host_release_id: str | None = None,
) -> dict[str, Any]:
    plan = validate_plan(plan_value, now=now, require_fresh=require_fresh)
    authorization = _exact(
        value,
        {
            "schema",
            "authorization_id",
            "request_sha256",
            "pending_receipt_sha256",
            "promotion_id",
            "plan_sha256",
            "method",
            "password_fallback",
            "authorized_at",
            "expires_at",
            "host_release_id",
            "requesting_agent_sha256",
            "requesting_session_sha256",
            "authorization_sha256",
        },
        "authorization",
    )
    if authorization["schema"] != AUTHORIZATION_SCHEMA:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_authorization_schema_invalid"
        )
    if not isinstance(authorization["authorization_id"], str) or UUID4.fullmatch(
        authorization["authorization_id"]
    ) is None:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_authorization_id_invalid"
        )
    for field in (
        "request_sha256",
        "pending_receipt_sha256",
        "plan_sha256",
        "host_release_id",
        "requesting_agent_sha256",
        "requesting_session_sha256",
        "authorization_sha256",
    ):
        _digest(authorization[field], f"authorization_{field}")
    authorized_at = authorization["authorized_at"]
    expires_at = authorization["expires_at"]
    if (
        authorization["promotion_id"] != plan["promotion_id"]
        or authorization["plan_sha256"] != plan["plan_sha256"]
        or authorization["host_release_id"] != plan["host_release_id"]
        or authorization["method"] != "touch-id"
        or authorization["password_fallback"] is not False
        or not isinstance(authorized_at, int)
        or isinstance(authorized_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not plan["created_at"] <= authorized_at < expires_at
        or expires_at > min(plan["expires_at"], authorized_at + 120)
        or (require_fresh and not authorized_at <= now < expires_at)
        or (
            expected_host_release_id is not None
            and authorization["host_release_id"] != expected_host_release_id
        )
    ):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_authorization_mismatch"
        )
    body = {
        key: item
        for key, item in authorization.items()
        if key != "authorization_sha256"
    }
    if not hmac.compare_digest(authorization["authorization_sha256"], sha256(body)):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_authorization_digest_mismatch"
        )
    canonical_bytes(authorization)
    return authorization


def make_request(plan_value: object, authorization_value: object) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    authorization = validate_authorization(
        authorization_value,
        plan,
        now=authorization_value.get("authorized_at", 0)
        if isinstance(authorization_value, Mapping)
        else 0,
        require_fresh=False,
    )
    body = {"plan": plan, "authorization": authorization}
    return {"schema": REQUEST_SCHEMA, **body, "request_sha256": sha256(body)}


def validate_request(
    value: object,
    *,
    now: int,
    require_fresh: bool = True,
    expected_host_release_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = _exact(
        value,
        {"schema", "plan", "authorization", "request_sha256"},
        "request",
    )
    if request["schema"] != REQUEST_SCHEMA:
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_request_schema_invalid"
        )
    plan = validate_plan(request["plan"], now=now, require_fresh=require_fresh)
    if (
        expected_host_release_id is not None
        and plan["host_release_id"] != expected_host_release_id
    ):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_plan_release_mismatch"
        )
    authorization = validate_authorization(
        request["authorization"],
        plan,
        now=now,
        require_fresh=require_fresh,
        expected_host_release_id=expected_host_release_id,
    )
    body = {"plan": plan, "authorization": authorization}
    _digest(request["request_sha256"], "request_sha256")
    if not hmac.compare_digest(request["request_sha256"], sha256(body)):
        raise NativeStackCatalogPromotionError(
            "native_catalog_promotion_request_digest_mismatch"
        )
    canonical_bytes(request)
    return plan, authorization
