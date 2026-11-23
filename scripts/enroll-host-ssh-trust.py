#!/usr/bin/env python3
"""Enroll the repository's exact SSH identities through Touch ID.

This client is intentionally unprivileged.  The installed release manager
creates a short-lived source/host-bound plan, and the installed authorization
broker is the sole path to the root-owned trust store.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
CURRENT = Path("/usr/local/libexec/secure-sandbox-host/current")
RELEASE_MANAGER = CURRENT / "release_manager"
AUTHORIZATION_BROKER = CURRENT / "authorization_broker"
RESOURCE = "/usr/local/var/lib/secure-sandbox/host-ssh-trust"
OPERATION = "host-ssh-trust-enroll"
PLAN_SCHEMA = "secure-sandbox-host-ssh-trust-enrollment-plan-v1"
RESULT_SCHEMA = "secure-sandbox-host-ssh-trust-enrollment-result-v1"
STATUS_SCHEMA = "secure-sandbox-host-ssh-trust-status-v1"
MATERIAL_SCHEMA = "secure-sandbox-host-ssh-trust-material-v1"
ALIASES = (
    "SecureSandbox-Gateway",
    "SecureSandbox-Research",
    "SecureSandbox-Target",
)
SOURCE_PATHS = {
    "provisioning_key": "runs/provisioning_key.pub",
    "control_key": "runs/control_key.pub",
    "known_hosts": "runs/known_hosts",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
SAFE_AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._@:/+-]{0,79}")
SAFE_SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}")
MAX_JSON = 1024 * 1024


class HostSSHTrustClientError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, allow_nan=False, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise HostSSHTrustClientError(
            "host_ssh_trust_client_json_invalid"
        ) from error


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _sha(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def validate_plan(
    value: object, *, operator_uid: int, now: int | None = None,
) -> dict[str, Any]:
    fields = {
        "schema", "plan_id", "created_at", "expires_at", "operator_uid",
        "machine_identity_sha256", "host_release_id", "ssh_config_sha256",
        "previous_trust_id", "sources", "trust_id", "plan_sha256",
    }
    key_fields = {
        "relative_path", "device", "inode", "mode", "uid", "gid",
        "nlink", "size", "mtime_ns", "ctime_ns", "source_sha256",
        "projected_sha256", "fingerprint",
    }
    known_fields = (key_fields - {"fingerprint"}) | {"host_fingerprints"}
    current = int(time.time()) if now is None else now
    if not isinstance(value, dict) or set(value) != fields:
        raise HostSSHTrustClientError("host_ssh_trust_plan_invalid")
    previous = value.get("previous_trust_id")
    sources = value.get("sources")
    if (value.get("schema") != PLAN_SCHEMA
            or not isinstance(value.get("plan_id"), str)
            or UUID4.fullmatch(value["plan_id"]) is None
            or not isinstance(value.get("created_at"), int)
            or isinstance(value.get("created_at"), bool)
            or not isinstance(value.get("expires_at"), int)
            or isinstance(value.get("expires_at"), bool)
            or not value["created_at"] <= current < value["expires_at"]
            or value["expires_at"] - value["created_at"] > 300
            or value.get("operator_uid") != operator_uid
            or isinstance(value.get("operator_uid"), bool)
            or operator_uid <= 0
            or any(not _sha(value.get(name)) for name in (
                "machine_identity_sha256", "host_release_id",
                "ssh_config_sha256", "trust_id", "plan_sha256",
            ))
            or (previous is not None and not _sha(previous))
            or not isinstance(sources, dict)
            or set(sources) != set(SOURCE_PATHS)):
        raise HostSSHTrustClientError("host_ssh_trust_plan_invalid")
    for name, relative in SOURCE_PATHS.items():
        record = sources.get(name)
        expected = known_fields if name == "known_hosts" else key_fields
        if (not isinstance(record, dict) or set(record) != expected
                or record.get("relative_path") != relative
                or any(not isinstance(record.get(field), int)
                       or isinstance(record.get(field), bool)
                       or record[field] < 0
                       for field in (
                           "device", "inode", "mode", "uid", "gid",
                           "nlink", "size", "mtime_ns", "ctime_ns",
                       ))
                or record.get("mode") != 0o600
                or record.get("uid") != operator_uid
                or record.get("nlink") != 1
                or not 0 < record["size"] <= 64 * 1024
                or not _sha(record.get("source_sha256"))
                or not _sha(record.get("projected_sha256"))):
            raise HostSSHTrustClientError("host_ssh_trust_plan_invalid")
        if name == "known_hosts":
            fingerprints = record.get("host_fingerprints")
            if (not isinstance(fingerprints, dict)
                    or tuple(fingerprints) != ALIASES
                    or any(not isinstance(item, str)
                           or FINGERPRINT.fullmatch(item) is None
                           for item in fingerprints.values())
                    or len(set(fingerprints.values())) != len(ALIASES)):
                raise HostSSHTrustClientError("host_ssh_trust_plan_invalid")
        elif (not isinstance(record.get("fingerprint"), str)
              or FINGERPRINT.fullmatch(record["fingerprint"]) is None):
            raise HostSSHTrustClientError("host_ssh_trust_plan_invalid")
    material = {
        "schema": MATERIAL_SCHEMA,
        "operator_uid": operator_uid,
        "machine_identity_sha256": value["machine_identity_sha256"],
        "ssh_config_sha256": value["ssh_config_sha256"],
        "provisioning_public_key_sha256": sources[
            "provisioning_key"
        ]["projected_sha256"],
        "provisioning_public_key_fingerprint": sources[
            "provisioning_key"
        ]["fingerprint"],
        "control_public_key_sha256": sources[
            "control_key"
        ]["projected_sha256"],
        "control_public_key_fingerprint": sources[
            "control_key"
        ]["fingerprint"],
        "known_hosts_sha256": sources["known_hosts"]["projected_sha256"],
        "known_host_fingerprints": sources[
            "known_hosts"
        ]["host_fingerprints"],
    }
    unsigned = {
        name: item for name, item in value.items() if name != "plan_sha256"
    }
    if (value["trust_id"] != digest(material)
            or value["plan_sha256"] != digest(unsigned)):
        raise HostSSHTrustClientError("host_ssh_trust_plan_invalid")
    return dict(value)


def validate_result(
    value: object, plan: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "status", "trust_id", "previous_trust_id",
        "manifest_sha256", "plan_sha256", "authorization_sha256",
        "operator_uid", "machine_identity_sha256", "ssh_config_sha256",
        "enrolled_release_id",
    }
    status = value.get("status") if isinstance(value, dict) else None
    enrolled_release_id = (
        value.get("enrolled_release_id") if isinstance(value, dict) else None
    )
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != RESULT_SCHEMA
            or status not in {"enrolled", "already-enrolled"}
            or value.get("trust_id") != plan["trust_id"]
            or value.get("previous_trust_id") != plan["previous_trust_id"]
            or value.get("plan_sha256") != plan["plan_sha256"]
            or value.get("operator_uid") != plan["operator_uid"]
            or value.get("machine_identity_sha256")
               != plan["machine_identity_sha256"]
            or value.get("ssh_config_sha256") != plan["ssh_config_sha256"]
            or (status == "enrolled"
                and enrolled_release_id != plan["host_release_id"])
            or (status == "already-enrolled"
                and not _sha(enrolled_release_id))
            or not _sha(value.get("manifest_sha256"))
            or not _sha(value.get("authorization_sha256"))):
        raise HostSSHTrustClientError("host_ssh_trust_result_invalid")
    return dict(value)


def validate_status(
    value: object, result: dict[str, Any], plan: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "schema", "status", "trust_id", "manifest_sha256",
        "manifest_file_sha256", "operator_uid", "machine_identity_sha256",
        "ssh_config_sha256", "enrolled_release_id", "plan_sha256",
    }
    already_enrolled = result.get("status") == "already-enrolled"
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != STATUS_SCHEMA
            or value.get("status") != "verified"
            or value.get("trust_id") != result["trust_id"]
            or value.get("manifest_sha256") != result["manifest_sha256"]
            or value.get("operator_uid") != plan["operator_uid"]
            or value.get("machine_identity_sha256")
               != plan["machine_identity_sha256"]
            or value.get("ssh_config_sha256") != plan["ssh_config_sha256"]
            or value.get("enrolled_release_id")
               != result["enrolled_release_id"]
            or (not already_enrolled
                and value.get("plan_sha256") != plan["plan_sha256"])
            or (already_enrolled and not _sha(value.get("plan_sha256")))
            or not _sha(value.get("manifest_file_sha256"))):
        raise HostSSHTrustClientError("host_ssh_trust_readback_invalid")
    return dict(value)


def run_json(
    command: list[str], *, timeout: int,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    allow_stderr: bool = False,
) -> object:
    try:
        result = runner(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=timeout,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C", "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HostSSHTrustClientError(
            "host_ssh_trust_subprocess_failed"
        ) from error
    if (result.returncode != 0 or len(result.stderr) > 64 * 1024
            or (result.stderr and not allow_stderr)
            or not 2 <= len(result.stdout) <= MAX_JSON):
        raise HostSSHTrustClientError("host_ssh_trust_subprocess_rejected")
    if allow_stderr:
        try:
            prompt = result.stderr.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HostSSHTrustClientError(
                "host_ssh_trust_subprocess_response_invalid"
            ) from error
        if any(character == "\0" or (
                ord(character) < 32 and character not in "\n\r\t"
        ) for character in prompt):
            raise HostSSHTrustClientError(
                "host_ssh_trust_subprocess_response_invalid"
            )
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HostSSHTrustClientError(
            "host_ssh_trust_subprocess_response_invalid"
        ) from error
    if result.stdout != canonical(value):
        raise HostSSHTrustClientError(
            "host_ssh_trust_subprocess_response_invalid"
        )
    return value


def enroll(
    *, repo: Path, operator_uid: int, agent: str, session: str,
    manager: Path = RELEASE_MANAGER, broker: Path = AUTHORIZATION_BROKER,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    now: int | None = None,
) -> dict[str, Any]:
    if (os.getuid() == 0 or os.geteuid() == 0
            or os.getuid() != os.geteuid()
            or operator_uid != os.geteuid()):
        raise HostSSHTrustClientError(
            "host_ssh_trust_unprivileged_operator_required"
        )
    if (not isinstance(agent, str) or SAFE_AGENT.fullmatch(agent) is None
            or not isinstance(session, str)
            or SAFE_SESSION.fullmatch(session) is None):
        raise HostSSHTrustClientError("host_ssh_trust_attribution_invalid")
    plan_value = run_json([
        str(manager), "plan-host-ssh-trust", "--repo", str(repo),
        "--operator-uid", str(operator_uid),
    ], timeout=30, runner=runner)
    validation_time = int(time.time()) if now is None else now
    plan = validate_plan(
        plan_value, operator_uid=operator_uid, now=validation_time,
    )
    result = validate_result(run_json([
        str(broker), "request", "--agent", agent, "--session", session,
        "--purpose", "Enroll exact Host SSH trust plan",
        "--resource", RESOURCE, "--operation", OPERATION,
        "--ceremony", "approve", "--parameters-json",
        canonical({"repo": str(repo), "plan": plan}).decode("ascii").strip(),
    ], timeout=480, runner=runner, allow_stderr=True), plan)
    status = run_json([
        str(manager), "status-host-ssh-trust",
        "--operator-uid", str(operator_uid),
    ], timeout=30, runner=runner)
    validate_status(status, result, plan)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Enroll this checkout's exact SSH trust via Touch ID",
    )
    value.add_argument(
        "--requesting-agent",
        default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"),
    )
    value.add_argument(
        "--requesting-session",
        default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"),
    )
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        if not args.requesting_agent or not args.requesting_session:
            raise HostSSHTrustClientError(
                "host_ssh_trust_attribution_required"
            )
        value = enroll(
            repo=ROOT.resolve(strict=True), operator_uid=os.geteuid(),
            agent=args.requesting_agent, session=args.requesting_session,
        )
        sys.stdout.buffer.write(canonical(value))
        return 0
    except (HostSSHTrustClientError, OSError) as error:
        code = str(error)
        if not code.startswith("host_ssh_trust_"):
            code = "host_ssh_trust_client_failed"
        sys.stderr.buffer.write(canonical({
            "schema": "secure-sandbox-host-ssh-trust-client-error-v1",
            "status": "rejected", "error": code,
        }))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
