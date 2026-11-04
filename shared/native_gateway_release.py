#!/usr/bin/env python3
"""Name-bound release identity for the complete Gateway native runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "secure-sandbox-native-gateway-release-v1"
MANIFEST = Path("/etc/secure-sandbox/native-gateway-release.json")
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
ROOT = "/usr/local/libexec/secure-sandbox"
SHARED = ROOT + "/shared"


EXPECTED_ARTIFACTS: Mapping[str, int] = {
    f"{ROOT}/privileged_control.py": 0o755,
    f"{ROOT}/native_guest_control.py": 0o755,
    f"{ROOT}/native_opaque_tunnel.py": 0o755,
    f"{ROOT}/render_gateway_firewall.py": 0o755,
    f"{ROOT}/update-policy-hash.sh": 0o755,
    f"{SHARED}/__init__.py": 0o644,
    f"{SHARED}/harness_runtime_binding.py": 0o644,
    f"{SHARED}/model_stack_runtime_binding.py": 0o644,
    f"{SHARED}/native_deployment.py": 0o644,
    f"{SHARED}/native_egress.py": 0o644,
    f"{SHARED}/native_gateway_release.py": 0o644,
    f"{SHARED}/native_stack_runtime_binding.py": 0o644,
    f"{SHARED}/native_vendor_stack.py": 0o644,
    f"{SHARED}/runtime_authority.py": 0o644,
    f"{SHARED}/session_context_binding.py": 0o644,
    "/etc/secure-sandbox/gateway-admin-source-ipv4": 0o600,
    "/etc/secure-sandbox/native-egress-installed": 0o600,
    "/etc/secure-sandbox/native-egress-role": 0o600,
    "/etc/systemd/system/native-opaque-tunnel.service": 0o644,
    "/etc/systemd/system/secure-sandbox-native-egress-watchdog.service": 0o644,
    "/etc/systemd/system/nftables.service.d/secure-sandbox-native-watchdog.conf": 0o644,
}


class NativeGatewayReleaseError(RuntimeError):
    """Stable fail-closed Gateway release error."""


def canonical(value: object) -> bytes:
    try:
        raw = (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeGatewayReleaseError(
            "native_gateway_release_value_invalid") from error
    if len(raw) > MAX_MANIFEST_BYTES:
        raise NativeGatewayReleaseError(
            "native_gateway_release_manifest_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _artifact(path: Path, mode: int, *, trusted_uid: int,
              trusted_gid: int) -> dict[str, Any]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeGatewayReleaseError(
            "native_gateway_release_artifact_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        content = hashlib.sha256()
        total = 0
        while total <= MAX_ARTIFACT_BYTES:
            block = os.read(
                descriptor,
                min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - total),
            )
            if not block:
                break
            total += len(block)
            content.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != trusted_uid
        or opened.st_gid != trusted_gid
        or stat.S_IMODE(opened.st_mode) != mode
        or opened.st_size < 1
        or total != opened.st_size
        or total > MAX_ARTIFACT_BYTES
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
    ):
        raise NativeGatewayReleaseError(
            "native_gateway_release_artifact_untrusted")
    return {"path": str(path), "mode": mode, "sha256": content.hexdigest()}


def observe(*, package_sha256: str, trusted_uid: int = 0,
            trusted_gid: int = 0) -> dict[str, Any]:
    if not isinstance(package_sha256, str) or SHA256.fullmatch(package_sha256) is None:
        raise NativeGatewayReleaseError("native_gateway_release_package_invalid")
    artifacts = [
        _artifact(Path(name), mode, trusted_uid=trusted_uid,
                  trusted_gid=trusted_gid)
        for name, mode in sorted(EXPECTED_ARTIFACTS.items())
    ]
    body = {
        "schema": SCHEMA,
        "package_sha256": package_sha256,
        "artifacts": artifacts,
    }
    return {**body, "release_id": digest(body)}


def validate(value: object) -> dict[str, Any]:
    fields = {"schema", "package_sha256", "artifacts", "release_id"}
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema") != SCHEMA
        or not isinstance(value.get("package_sha256"), str)
        or SHA256.fullmatch(value["package_sha256"]) is None
        or not isinstance(value.get("artifacts"), list)
        or len(value["artifacts"]) != len(EXPECTED_ARTIFACTS)
    ):
        raise NativeGatewayReleaseError(
            "native_gateway_release_manifest_invalid")
    names: list[str] = []
    for item in value["artifacts"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "mode", "sha256"}
            or item.get("path") not in EXPECTED_ARTIFACTS
            or item.get("mode") != EXPECTED_ARTIFACTS[item["path"]]
            or not isinstance(item.get("sha256"), str)
            or SHA256.fullmatch(item["sha256"]) is None
        ):
            raise NativeGatewayReleaseError(
                "native_gateway_release_manifest_invalid")
        names.append(item["path"])
    body = {
        "schema": SCHEMA,
        "package_sha256": value["package_sha256"],
        "artifacts": value["artifacts"],
    }
    if (
        names != sorted(EXPECTED_ARTIFACTS)
        or not isinstance(value.get("release_id"), str)
        or value["release_id"] != digest(body)
    ):
        raise NativeGatewayReleaseError(
            "native_gateway_release_manifest_invalid")
    return value


def verify_installed(
    *, manifest: Path = MANIFEST, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    try:
        before = manifest.lstat()
        descriptor = os.open(
            manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            raw = bytearray()
            while len(raw) <= MAX_MANIFEST_BYTES:
                block = os.read(
                    descriptor,
                    min(65536, MAX_MANIFEST_BYTES + 1 - len(raw)),
                )
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeGatewayReleaseError(
            "native_gateway_release_manifest_unavailable") from error
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != trusted_uid
        or opened.st_gid != trusted_gid
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o444
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or len(raw) != opened.st_size
        or len(raw) > MAX_MANIFEST_BYTES
        or bytes(raw) != canonical(value)
    ):
        raise NativeGatewayReleaseError(
            "native_gateway_release_manifest_untrusted")
    admitted = validate(value)
    observed = observe(
        package_sha256=admitted["package_sha256"],
        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    )
    if observed != admitted:
        raise NativeGatewayReleaseError(
            "native_gateway_release_readback_mismatch")
    return observed
