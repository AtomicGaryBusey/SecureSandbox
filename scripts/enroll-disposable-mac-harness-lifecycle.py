#!/usr/bin/env python3
"""Create a non-authorizing enrollment receipt for a clean disposable Mac."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    ENROLLMENT_SCHEMA,
    canonical,
    digest,
    validate_enrollment,
)


ACKNOWLEDGEMENT = "THIS MAC IS DISPOSABLE AND CONTAINS NO PRODUCTION DATA OR CREDENTIALS"
PROVIDER_ENVIRONMENT = frozenset({
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AZURE_OPENAI_API_KEY", "AZURE_CLIENT_SECRET",
    "ABLITERATION_API_KEY", "OP_SERVICE_ACCOUNT_TOKEN",
})
FORBIDDEN_HOME_PATHS = (
    "Library/Application Support/SecureSandbox",
    ".config/secure-sandbox",
    ".aws/credentials",
    ".config/gcloud/application_default_credentials.json",
    ".azure/accessTokens.json",
    ".config/op",
)
KEYCHAIN_SERVICES = ("op-service-account-agents",)
UUID_LINE = re.compile(rb'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"')
SERIAL_LINE = re.compile(rb'"IOPlatformSerialNumber"\s*=\s*"([^"\r\n]{1,128})"')
MODEL_LINE = re.compile(rb'"model"\s*=\s*<"([^"\r\n]{1,128})')


def command(runner: Callable[..., subprocess.CompletedProcess[bytes]], arguments: list[str]) -> bytes:
    result = runner(
        arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=10,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024 or len(result.stderr) > 64 * 1024:
        raise AcceptanceError("machine_identity_probe_failed")
    return result.stdout


def machine_identity(runner: Callable[..., subprocess.CompletedProcess[bytes]]) -> str:
    raw = command(runner, ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    platform_uuid = UUID_LINE.search(raw)
    serial = SERIAL_LINE.search(raw)
    model = MODEL_LINE.search(raw)
    if platform_uuid is None or serial is None or model is None:
        raise AcceptanceError("machine_identity_probe_invalid")
    material = b"\0".join((platform_uuid.group(1).lower(), serial.group(1), model.group(1)))
    return hashlib.sha256(material).hexdigest()


def keychain_absent(runner: Callable[..., subprocess.CompletedProcess[bytes]]) -> None:
    for service in KEYCHAIN_SERVICES:
        result = runner(
            ["/usr/bin/security", "find-generic-password", "-s", service],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode == 0:
            raise AcceptanceError("production_credential_marker_present")
        if result.returncode not in {44, 45}:
            raise AcceptanceError("keychain_probe_ambiguous")


def enroll(*, acknowledgement: str, home: Path, environment: dict[str, str], now: int,
           runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
           system: str | None = None, machine: str | None = None) -> dict:
    if acknowledgement != ACKNOWLEDGEMENT:
        raise AcceptanceError("operator_acknowledgement_invalid")
    if (system or platform.system()) != "Darwin" or (machine or platform.machine()) not in {"arm64", "x86_64"}:
        raise AcceptanceError("disposable_mac_required")
    present = sorted(name for name in PROVIDER_ENVIRONMENT if environment.get(name))
    if present:
        raise AcceptanceError("production_credential_environment_present")
    for relative in FORBIDDEN_HOME_PATHS:
        path = home / relative
        if os.path.lexists(path):
            raise AcceptanceError("production_material_path_present")
    keychain_absent(runner)
    value = {
        "schema": ENROLLMENT_SCHEMA,
        "enrollment_id": str(uuid.uuid4()),
        "machine_identity_sha256": machine_identity(runner),
        "observed_at": now,
        "disposable": True,
        "production_data_present": False,
        "production_credentials_present": False,
        "synthetic_credentials_only": True,
        "collector": "secure-sandbox-disposable-supervisor-v1",
    }
    value["enrollment_sha256"] = digest(value)
    return validate_enrollment(value, now)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Enroll a clean Mac for destructive lifecycle acceptance")
    value.add_argument("--acknowledgement", required=True, help=argparse.SUPPRESS)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    result = enroll(
        acknowledgement=args.acknowledgement,
        home=Path.home(),
        environment=dict(os.environ),
        now=int(time.time()),
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, AcceptanceError) else "enrollment_probe_failed"
        print(json.dumps({
            "schema": "secure-sandbox-disposable-mac-enrollment-error-v1",
            "status": "rejected",
            "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
