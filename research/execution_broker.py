#!/usr/bin/env python3
"""Validate registered fixtures and broker fixed-policy execution to Target."""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import grp
import hashlib
import http.client
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
import syslog
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from source_integrity import (
    MAX_MANIFEST_BYTES, IntegrityError, expected_records, fixed_tree_path,
    hash_regular, load_control_json, registered_source, safe_relative,
)
from evidence_receipts import ReceiptError, active_run, publish

CONFIG = "/etc/secure-sandbox/execution-broker.json"
APPROVAL_FLOOR = Path("/etc/secure-sandbox/execution-approval-floor.json")
LIFECYCLE = Path("/var/lib/secure-sandbox/run-lifecycle/active.json")
APPROVAL_ROOT = Path("/var/lib/secure-sandbox/execution-approvals")
APPROVAL_NAMESPACE = "secure-sandbox-execution-approval-v1"
APPROVAL_V2_ALGORITHM = "ecdsa-p256-sha256-x962-low-s"
APPROVAL_V2_ATTESTATION = "secure-sandbox-execution-approval-attestation-v2"
APPROVAL_V2_ENVELOPE = "secure-sandbox-execution-approval-envelope-v2"
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
P256_HALF_ORDER = P256_ORDER // 2
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
APPROVAL_TTL_SECONDS = 90
MAX_BODY = 128 * 1024
MAX_CODE = 24 * 1024
MAX_FILES = 16
MAX_FIXTURES = 1024 * 1024
MAX_OUTPUT = 64 * 1024
REQUEST_READ_TIMEOUT_SECONDS = 3.0
APPROVAL_RELAY_LONG_POLL_SECONDS = 30.0
REJECTION_TOKENS = {
    "active_run_required","active_run_untrusted",
    "control_file_changed","control_file_too_large","file_too_large","filesystem_changed_during_verification",
    "filesystem_race","fixture_changed","fixture_integrity_mismatch","fixture_not_registered_file",
    "fixtures_too_large","integrity_manifest_hash_mismatch","invalid_code_or_source","invalid_control_json",
    "invalid_fixture_path","invalid_fixture_paths","invalid_integrity_manifest","invalid_request","invalid_scope",
    "invalid_source_id","invalid_source_index","invalid_timeout","registered_tree_missing","source_manifest_unavailable",
    "request_incomplete","source_not_registered","too_many_entries","tree_too_large","tree_unreadable","unsafe_fixture",
    "unsafe_fixture_path","unsafe_path_collision","unsafe_registered_path","untrusted_control_file",
    "approval_cancelled","approval_expired","approval_invalid","approval_replayed","approval_required",
}


class Rejected(ValueError):
    pass


def rejection_token(error: Exception) -> str:
    value = str(error)
    return value if value in REJECTION_TOKENS else "invalid_request"


def load_config() -> dict:
    info = os.stat(CONFIG, follow_symlinks=False)
    if info.st_uid != 0 or info.st_mode & 0o027:
        raise RuntimeError("unsafe_config")
    with open(CONFIG, encoding="utf-8") as handle:
        value = json.load(handle)
    if (value.get("schema") not in {
                "secure-sandbox-execution-broker-v2",
                "secure-sandbox-execution-broker-v3",
            }
            or len(str(value.get("token", ""))) < 40
            or not isinstance(value.get("runtime_image_id"), str)
            or not value["runtime_image_id"].startswith("sha256:")):
        raise RuntimeError("invalid_config")
    if value["schema"] == "secure-sandbox-execution-broker-v2":
        if value.get("allowed_signers") != "/etc/secure-sandbox/execution-approval.allowed_signers":
            raise RuntimeError("invalid_config")
    else:
        validate_v3_approval_config(value.get("approval"))
    if APPROVAL_FLOOR.exists():
        floor_info = APPROVAL_FLOOR.stat(follow_symlinks=False)
        floor_raw = APPROVAL_FLOOR.read_bytes()
        floor = json.loads(floor_raw)
        required = {"schema", "minimum_protocol", "minimum_epoch", "generation_id",
                    "algorithm", "public_key_sha256", "updated_at"}
        approval = value.get("approval", {})
        if (not stat.S_ISREG(floor_info.st_mode) or stat.S_ISLNK(floor_info.st_mode)
                or floor_info.st_uid != 0 or stat.S_IMODE(floor_info.st_mode) != 0o640
                or floor_info.st_gid != grp.getgrnam("execution-broker").gr_gid
                or floor_info.st_nlink != 1 or len(floor_raw) > 4096
                or canonical(floor) != floor_raw
                or set(floor) != required
                or floor.get("schema") != "secure-sandbox-execution-approval-floor-v2"
                or floor.get("minimum_protocol") != 2
                or value.get("schema") != "secure-sandbox-execution-broker-v3"
                or approval.get("mode") != "active-v2"
                or approval.get("generation_epoch", -1) < floor.get("minimum_epoch", 0)
                or approval.get("generation_id") != floor.get("generation_id")
                or approval.get("algorithm") != floor.get("algorithm")
                or approval.get("public_key_sha256") != floor.get("public_key_sha256")):
            raise RuntimeError("execution_approval_below_floor")
    return value


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")


def canonical_v2(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise Rejected("approval_invalid") from error
    if b"\n" in encoded or b"\r" in encoded:
        raise Rejected("approval_invalid")
    return encoded


def canonical_base64_decode(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise Rejected("approval_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Rejected("approval_invalid") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Rejected("approval_invalid")
    return decoded


def encode_p256_der(r_value: int, s_value: int) -> bytes:
    def integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\0" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = integer(r_value) + integer(s_value)
    return b"\x30" + bytes([len(body)]) + body


def parse_p256_der(signature: bytes, require_low_s: bool = True) -> tuple[int, int]:
    if len(signature) < 8 or len(signature) > 72 or signature[0] != 0x30:
        raise Rejected("approval_invalid")
    if signature[1] >= 0x80 or signature[1] != len(signature) - 2:
        raise Rejected("approval_invalid")
    offset = 2

    def integer() -> int:
        nonlocal offset
        if offset + 2 > len(signature) or signature[offset] != 0x02:
            raise Rejected("approval_invalid")
        length = signature[offset + 1]
        offset += 2
        if length < 1 or length > 33 or offset + length > len(signature):
            raise Rejected("approval_invalid")
        raw = signature[offset:offset + length]
        offset += length
        if raw[0] & 0x80 or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80):
            raise Rejected("approval_invalid")
        value = int.from_bytes(raw, "big")
        if not 1 <= value < P256_ORDER:
            raise Rejected("approval_invalid")
        return value

    r_value, s_value = integer(), integer()
    if (offset != len(signature) or (require_low_s and s_value > P256_HALF_ORDER)
            or encode_p256_der(r_value, s_value) != signature):
        raise Rejected("approval_invalid")
    return r_value, s_value


def validate_v3_approval_config(value: object) -> None:
    if not isinstance(value, dict) or value.get("mode") not in {"fenced", "active-v2"}:
        raise RuntimeError("invalid_config")
    required = {"mode", "minimum_protocol", "minimum_epoch"}
    if value["mode"] == "active-v2":
        required |= {
            "algorithm", "generation_id", "generation_epoch",
            "public_key_sha256", "public_key_spki_der_b64",
        }
    if set(value) != required or value.get("minimum_protocol") != 2:
        raise RuntimeError("invalid_config")
    floor = value.get("minimum_epoch")
    if not isinstance(floor, int) or isinstance(floor, bool) or floor < 1:
        raise RuntimeError("invalid_config")
    if value["mode"] == "fenced":
        return
    try:
        generation = uuid.UUID(value["generation_id"])
    except (TypeError, ValueError, AttributeError) as error:
        raise RuntimeError("invalid_config") from error
    if (generation.version != 4 or str(generation) != value["generation_id"]
            or value.get("algorithm") != APPROVAL_V2_ALGORITHM
            or not isinstance(value.get("generation_epoch"), int)
            or isinstance(value.get("generation_epoch"), bool)
            or value["generation_epoch"] < floor
            or not isinstance(value.get("public_key_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["public_key_sha256"]) is None):
        raise RuntimeError("invalid_config")
    try:
        spki = canonical_base64_decode(value["public_key_spki_der_b64"], 256)
    except Rejected as error:
        raise RuntimeError("invalid_config") from error
    if (len(spki) != 91 or not spki.startswith(P256_SPKI_PREFIX)
            or hashlib.sha256(spki).hexdigest() != value["public_key_sha256"]):
        raise RuntimeError("invalid_config")


def verify_v2_signature(spki: bytes, message: bytes, signature: bytes) -> None:
    parse_p256_der(signature)
    encoded = base64.b64encode(spki).decode("ascii")
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + "\n".join(encoded[index:index + 64] for index in range(0, len(encoded), 64))
           + "\n-----END PUBLIC KEY-----\n").encode("ascii")
    with tempfile.TemporaryDirectory(prefix="execution-approval-v2-") as directory:
        public_path = Path(directory) / "public.pem"
        signature_path = Path(directory) / "signature.der"
        public_path.write_bytes(pem)
        signature_path.write_bytes(signature)
        verified = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(public_path),
             "-signature", str(signature_path)],
            input=message, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
        )
    if verified.returncode:
        raise Rejected("approval_invalid")


def lifecycle_context(path: Path = LIFECYCLE, trusted_uid: int = 0) -> tuple[str, str]:
    try:
        info = path.lstat()
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise Rejected("active_run_required") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != trusted_uid
            or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1
            or value.get("schema") != "secure-sandbox-run-lifecycle-v2"
            or value.get("phase") != "active"):
        raise Rejected("active_run_untrusted")
    run_id = str(value.get("run_id", "")); session_id = str(value.get("session_id", ""))
    try:
        for candidate in (run_id, session_id):
            parsed = uuid.UUID(candidate)
            if parsed.version != 4 or str(parsed) != candidate:
                raise ValueError
    except ValueError as error:
        raise Rejected("active_run_untrusted") from error
    return run_id, session_id


def atomic_file(path: Path, data: bytes, mode: int, owner: int | None = None,
                group: int | None = None) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4()}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        try:
            os.write(descriptor, data); os.fsync(descriptor); os.fchmod(descriptor, mode)
            if owner is not None or group is not None:
                os.fchown(descriptor, -1 if owner is None else owner, -1 if group is None else group)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except Exception:
        try: temporary.unlink()
        except FileNotFoundError: pass
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


class AcceptanceAttempt:
    def __init__(self, acceptance: dict, root: Path | None = None):
        root = APPROVAL_ROOT if root is None else root
        self.path = root / "consumed" / (
            "acceptance-" + acceptance["acceptance_attempt_id"] + ".json"
        )
        self.value = {
            "schema":"secure-sandbox-execution-approval-acceptance-attempt-v2",
            "status":"claimed", **acceptance, "claimed_at":int(time.time()),
        }
        try:
            descriptor = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError as error:
            raise Rejected("approval_replayed") from error
        try:
            data = canonical(self.value)
            view = memoryview(data)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise OSError("short_write")
                view = view[count:]
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        self.finished = False

    def fail(self, error: BaseException) -> None:
        if self.finished:
            return
        self.value.update({
            "status":"failed", "failed_at":int(time.time()),
            "failure_class":type(error).__name__,
        })
        atomic_file(self.path, canonical(self.value), 0o600)
        self.finished = True

    def succeed(self, receipt: dict) -> None:
        if self.finished:
            raise RuntimeError("acceptance_attempt_already_final")
        self.value.update({
            "status":"succeeded", "succeeded_at":int(time.time()),
            "research_receipt_id":receipt["receipt_id"],
            "research_receipt_sha256":receipt["receipt_sha256"],
        })
        atomic_file(self.path, canonical(self.value), 0o600)
        self.finished = True


def approval_directories(root: Path = APPROVAL_ROOT) -> tuple[Path, Path, Path, Path]:
    pending, claims, responses, consumed = (
        root / "pending", root / "claims", root / "responses", root / "consumed"
    )
    return pending, claims, responses, consumed


def verify_v1_envelope(envelope: object, approval: dict, config: dict) -> tuple[dict, str]:
    if (not isinstance(envelope, dict)
            or envelope.get("schema") != "secure-sandbox-execution-approval-envelope-v1"
            or set(envelope) != {"schema", "attestation", "signature_b64"}):
        raise Rejected("approval_invalid")
    attestation = envelope["attestation"]
    if (not isinstance(attestation, dict)
            or attestation.get("schema") != "secure-sandbox-execution-approval-attestation-v1"
            or attestation.get("approval") != approval
            or attestation.get("approval_request_sha256") != hashlib.sha256(canonical(approval)).hexdigest()
            or not isinstance(attestation.get("authorization_request_id"), str)
            or not isinstance(attestation.get("host_release_id"), str)
            or not isinstance(attestation.get("approved_at"), int)
            or not approval["created_at"] <= attestation["approved_at"] <= approval["expires_at"]):
        raise Rejected("approval_invalid")
    try:
        authorization_request_id = uuid.UUID(attestation["authorization_request_id"])
        if (authorization_request_id.version != 4
                or str(authorization_request_id) != attestation["authorization_request_id"]
                or len(attestation["host_release_id"]) != 64
                or any(character not in "0123456789abcdef"
                       for character in attestation["host_release_id"])):
            raise ValueError
    except ValueError as error:
        raise Rejected("approval_invalid") from error
    try:
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
    except Exception as error:
        raise Rejected("approval_invalid") from error
    with tempfile.NamedTemporaryFile(prefix="execution-approval-", suffix=".sig") as handle:
        handle.write(signature); handle.flush()
        verified = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", config["allowed_signers"],
             "-I", "secure-sandbox-host", "-n", APPROVAL_NAMESPACE, "-s", handle.name],
            input=canonical(attestation), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=10,
        )
    if verified.returncode:
        raise Rejected("approval_invalid")
    return attestation, hashlib.sha256(canonical(envelope)).hexdigest()


def verify_v2_envelope(envelope: object, approval: dict, config: dict) -> tuple[dict, str]:
    approval_config = config["approval"]
    if approval_config["mode"] != "active-v2":
        raise Rejected("approval_required")
    if (not isinstance(envelope, dict) or set(envelope) != {
                "schema", "attestation", "signature_der_b64"
            } or envelope.get("schema") != APPROVAL_V2_ENVELOPE):
        raise Rejected("approval_invalid")
    attestation = envelope["attestation"]
    required = {
        "schema", "approval", "approval_request_sha256",
        "authorization_request_id", "host_release_id", "approved_at",
        "key_generation_id", "key_generation_epoch", "public_key_sha256",
        "signature_algorithm",
    }
    if (not isinstance(attestation, dict) or set(attestation) != required
            or attestation.get("schema") != APPROVAL_V2_ATTESTATION
            or attestation.get("approval") != approval
            or attestation.get("approval_request_sha256")
            != hashlib.sha256(canonical(approval)).hexdigest()
            or attestation.get("key_generation_id") != approval_config["generation_id"]
            or attestation.get("key_generation_epoch") != approval_config["generation_epoch"]
            or attestation.get("public_key_sha256") != approval_config["public_key_sha256"]
            or attestation.get("signature_algorithm") != APPROVAL_V2_ALGORITHM
            or not isinstance(attestation.get("approved_at"), int)
            or isinstance(attestation.get("approved_at"), bool)
            or not approval["created_at"] <= attestation["approved_at"] <= approval["expires_at"]):
        raise Rejected("approval_invalid")
    try:
        authorization_request_id = uuid.UUID(attestation["authorization_request_id"])
        if (authorization_request_id.version != 4
                or str(authorization_request_id) != attestation["authorization_request_id"]
                or not isinstance(attestation["host_release_id"], str)
                or len(attestation["host_release_id"]) != 64
                or any(character not in "0123456789abcdef"
                       for character in attestation["host_release_id"])):
            raise ValueError
    except (TypeError, ValueError) as error:
        raise Rejected("approval_invalid") from error
    signature = canonical_base64_decode(envelope["signature_der_b64"], 128)
    spki = canonical_base64_decode(approval_config["public_key_spki_der_b64"], 256)
    verify_v2_signature(spki, canonical_v2(attestation), signature)
    return attestation, hashlib.sha256(canonical_v2(attestation)).hexdigest()


def await_operator_approval(approval: dict, config: dict,
                            root: Path = APPROVAL_ROOT,
                            trusted_uid: int = 0) -> tuple[dict, str]:
    pending, _claims, responses, consumed = approval_directories(root)
    approval_id = approval["approval_id"]
    pending_path = pending / f"{approval_id}.json"
    response_path = responses / f"{approval_id}.json"
    consume_path = consumed / f"{approval_id}.json"
    atomic_file(pending_path, canonical(approval), 0o600)
    deadline = min(approval["expires_at"], int(time.time()) + APPROVAL_TTL_SECONDS)
    try:
        while int(time.time()) <= deadline:
            try:
                info = response_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != trusted_uid or stat.S_IMODE(info.st_mode) != 0o640
                        or info.st_nlink != 1 or info.st_size > 64 * 1024):
                    raise Rejected("approval_invalid")
                response = json.loads(response_path.read_text(encoding="ascii"))
                break
            except FileNotFoundError:
                time.sleep(0.05)
        else:
            raise Rejected("approval_expired")
        if (not isinstance(response, dict)
                or response.get("schema") != "secure-sandbox-execution-approval-response-v1"
                or response.get("approval_id") != approval_id):
            raise Rejected("approval_invalid")
        if response.get("status") == "cancelled":
            raise Rejected("approval_cancelled")
        if response.get("status") != "approved" or set(response) != {"schema", "approval_id", "status", "envelope"}:
            raise Rejected("approval_invalid")
        envelope = response["envelope"]
        if config.get("schema", "secure-sandbox-execution-broker-v2") == "secure-sandbox-execution-broker-v2":
            attestation, attestation_digest = verify_v1_envelope(envelope, approval, config)
        else:
            attestation, attestation_digest = verify_v2_envelope(envelope, approval, config)
        try:
            descriptor = os.open(consume_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError as error:
            raise Rejected("approval_replayed") from error
        try:
            os.fchmod(descriptor, 0o600)
            consumed_record = {"approval_id":approval_id,
                               "attestation_sha256":attestation_digest,
                               "consumed_at":int(time.time())}
            if attestation.get("schema") == APPROVAL_V2_ATTESTATION:
                consumed_record.update({
                    "generation_id":attestation["key_generation_id"],
                    "generation_epoch":attestation["key_generation_epoch"],
                    "public_key_sha256":attestation["public_key_sha256"],
                    "signature_algorithm":attestation["signature_algorithm"],
                })
            data = canonical(consumed_record)
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("short_write")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(consumed, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return attestation, attestation_digest
    finally:
        # The broker owns pending/, but responses/ is deliberately root-owned
        # so an execution-broker compromise cannot forge or replace operator
        # decisions.  Removing the pending marker acknowledges that the
        # response was observed; the root relay reclaims the orphaned response
        # on its next poll.  Trying to unlink the root-owned response here
        # would raise PermissionError and mask a typed rejection such as
        # approval_cancelled.
        try: pending_path.unlink()
        except FileNotFoundError: pass


def audit(event: str, request_id: str = "", source_id: str = "", code_hash: str = "", status: str = "", duration_ms: int = 0) -> None:
    record = {
        "event": event, "request_id": request_id[:64], "source_id": source_id[:64],
        "code_sha256": code_hash[:64], "status": status[:160], "duration_ms": int(duration_ms),
    }
    try:
        syslog.openlog("secure-sandbox-execution", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING if event.endswith(("rejected", "failed", "timed_out")) else syslog.LOG_INFO,
                      json.dumps(record, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass


def read_fixture(baseline: str, relative: str, expected: dict) -> tuple[bytes, str]:
    relative = safe_relative(relative)
    record = expected.get(relative)
    if not isinstance(record, dict) or record.get("type") != "file":
        raise Rejected("fixture_not_registered_file")
    path = os.path.join(baseline, relative)
    required = baseline.rstrip("/") + "/"
    if not os.path.normpath(path).startswith(required):
        raise Rejected("unsafe_fixture_path")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Rejected("unsafe_fixture")
    digest, size = hash_regular(path, info)
    if digest != record.get("sha256") or size != record.get("bytes"):
        raise Rejected("fixture_integrity_mismatch")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(descriptor, size + 1)
    finally:
        os.close(descriptor)
    if len(data) != size:
        raise Rejected("fixture_changed")
    return data, digest


def validate_and_forward(value: object, config: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"source_id", "code", "fixture_paths", "timeout_seconds"}:
        raise Rejected("invalid_request")
    source_id = value["source_id"]
    code = value["code"]
    paths = value["fixture_paths"]
    timeout = value["timeout_seconds"]
    if not isinstance(source_id, str) or not isinstance(code, str) or not 1 <= len(code.encode("utf-8")) <= MAX_CODE:
        raise Rejected("invalid_code_or_source")
    if not isinstance(paths, list) or len(paths) > MAX_FILES or len(set(map(str, paths))) != len(paths):
        raise Rejected("invalid_fixture_paths")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 10:
        raise Rejected("invalid_timeout")
    record = registered_source(source_id)
    manifest_relative = record.get("integrity_manifest_path")
    if not manifest_relative:
        raise Rejected("source_manifest_unavailable")
    manifest = load_control_json(fixed_tree_path(manifest_relative, "source-manifests"), MAX_MANIFEST_BYTES)
    if not isinstance(manifest, dict) or manifest.get("source_id") != source_id:
        raise Rejected("invalid_integrity_manifest")
    expected = expected_records(manifest)
    baseline = fixed_tree_path(record.get("baseline_path"), "baselines")
    fixtures = []
    total = 0
    for path in paths:
        if (not isinstance(path, str)
                or any(ord(character) < 32 or ord(character) > 126 for character in path)):
            raise Rejected("invalid_fixture_path")
        data, digest = read_fixture(baseline, path, expected)
        total += len(data)
        if total > MAX_FIXTURES:
            raise Rejected("fixtures_too_large")
        fixtures.append({"path": path, "content_b64": base64.b64encode(data).decode("ascii"), "sha256": digest})
    run_id = active_run()
    lifecycle_run_id, session_id = lifecycle_context()
    if lifecycle_run_id != run_id:
        raise Rejected("active_run_untrusted")
    request_id = str(uuid.uuid4())
    request = {
        "schema": "secure-sandbox-execution-request-v1", "request_id": request_id,
        "source_id": source_id, "code_b64": base64.b64encode(code.encode()).decode("ascii"),
        "fixtures": fixtures, "timeout_seconds": timeout,
    }
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    fixture_manifest_hash = hashlib.sha256(json.dumps(
        [{"path": item["path"], "bytes": len(base64.b64decode(item["content_b64"])),
          "sha256": item["sha256"]} for item in fixtures],
        separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    fixture_manifest = [
        {"path": item["path"], "bytes": len(base64.b64decode(item["content_b64"])),
         "sha256": item["sha256"]} for item in fixtures
    ]
    source_manifest_hash = hashlib.sha256(canonical(manifest)).hexdigest()
    lifecycle_value = load_control_json(str(LIFECYCLE), 16 * 1024)
    acceptance = lifecycle_value.get("execution_approval_acceptance")
    if acceptance is not None:
        expected_acceptance = {
            "transaction_id", "generation_id", "generation_epoch", "run_id", "session_id",
            "source_id", "code_sha256", "fixture_manifest_sha256", "timeout_seconds",
            "runtime_image_id", "expires_at", "acceptance_attempt_id",
            "acceptance_attempt_number", "previous_acceptance_binding_sha256",
            "acceptance_binding_sha256",
        }
        acceptance_now = int(time.time())
        if (not isinstance(acceptance, dict) or set(acceptance) != expected_acceptance
                or acceptance.get("run_id") != run_id
                or acceptance.get("session_id") != session_id
                or acceptance.get("source_id") != source_id
                or acceptance.get("code_sha256") != code_hash
                or acceptance.get("fixture_manifest_sha256") != fixture_manifest_hash
                or acceptance.get("timeout_seconds") != timeout
                or acceptance.get("runtime_image_id") != config["runtime_image_id"]
                or not isinstance(acceptance.get("acceptance_attempt_number"), int)
                or isinstance(acceptance.get("acceptance_attempt_number"), bool)
                or acceptance["acceptance_attempt_number"] < 1
                or not isinstance(acceptance.get("expires_at"), int)
                or acceptance["expires_at"] < acceptance_now):
            raise Rejected("approval_invalid")
        attempt = AcceptanceAttempt(acceptance)
    else:
        attempt = None
    try:
        created_at = int(time.time())
        approval = {
            "schema":"secure-sandbox-execution-approval-request-v1",
            "approval_id":str(uuid.uuid4()), "created_at":created_at,
            "expires_at":created_at + APPROVAL_TTL_SECONDS,
            "run_id":run_id, "session_id":session_id, "source_id":source_id,
            "source_manifest_sha256":source_manifest_hash,
            "code_sha256":code_hash, "fixture_manifest":fixture_manifest,
            "fixture_manifest_sha256":fixture_manifest_hash,
            "timeout_seconds":timeout, "runtime_image_id":config["runtime_image_id"],
        }
        approval_attestation, approval_attestation_sha256 = await_operator_approval(approval, config)
        audit("execution_accepted", request_id, source_id, code_hash, "accepted")
        started = time.monotonic()
        connection = http.client.HTTPConnection("172.30.20.2", 8080, timeout=timeout + 8)
        connection.request("POST", "/v1/execute", body=json.dumps(request, separators=(",", ":")), headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + config["token"],
        })
        response = connection.getresponse()
        raw = response.read(256 * 1024 + 1)
        connection.close()
        if response.status != 200 or len(raw) > 256 * 1024:
            raise RuntimeError("target_execution_failed")
        result = json.loads(raw)
        if (not isinstance(result, dict) or result.get("schema") != "secure-sandbox-execution-result-v1"
                or result.get("request_id") != request_id or result.get("source_id") != source_id
                or not isinstance(result.get("exit_code"), int) or isinstance(result.get("exit_code"), bool)
                or not -255 <= result["exit_code"] <= 255
                or any(not isinstance(result.get(name), bool) for name in
                       ("timed_out", "output_limit_exceeded", "stdout_truncated", "stderr_truncated"))
                or not isinstance(result.get("duration_ms"), int) or isinstance(result.get("duration_ms"), bool)
                or not 0 <= result["duration_ms"] <= 120_000):
            raise RuntimeError("invalid_target_result")
        for stream in ("stdout", "stderr"):
            try:
                decoded = base64.b64decode(result.pop(stream + "_b64"), validate=True)
            except Exception as error:
                raise RuntimeError("invalid_target_output") from error
            if len(decoded) > MAX_OUTPUT:
                raise RuntimeError("oversized_target_output")
            if hashlib.sha256(decoded).hexdigest() != result.get(stream + "_sha256"):
                raise RuntimeError("target_output_hash_mismatch")
            result[stream] = decoded.decode("utf-8", "backslashreplace")
        result["code_sha256"] = code_hash
        result["fixture_manifest_sha256"] = fixture_manifest_hash
        if result.get("runtime_image_id") != config["runtime_image_id"]:
            raise RuntimeError("target_runtime_identity_mismatch")
        projection = {
            "class":"measured_execution","source_id":source_id,"request_id":request_id,"run_id":run_id,
            "code_sha256":code_hash,"stdout_sha256":result["stdout_sha256"],
            "stderr_sha256":result["stderr_sha256"],"exit_code":result["exit_code"],
            "timed_out":result["timed_out"],"output_limit_exceeded":result["output_limit_exceeded"],
            "stdout_truncated":result["stdout_truncated"],"stderr_truncated":result["stderr_truncated"],
            "timeout_seconds":timeout,"duration_ms":result["duration_ms"],
            "fixture_manifest_sha256":result["fixture_manifest_sha256"],
            "image_digest":result["runtime_image_id"],
            "session_id":session_id,"approval_id":approval["approval_id"],
            "approval_attestation_sha256":approval_attestation_sha256,
        }
        if approval_attestation.get("schema") == APPROVAL_V2_ATTESTATION:
            projection.update({
                "approval_key_generation_id":approval_attestation["key_generation_id"],
                "approval_key_generation_epoch":approval_attestation["key_generation_epoch"],
                "approval_public_key_sha256":approval_attestation["public_key_sha256"],
                "approval_signature_algorithm":approval_attestation["signature_algorithm"],
            })
        result["run_id"] = run_id
        result["evidence_receipt"] = publish("execution-broker", "run_python_fixture", projection)
        if attempt is not None:
            attempt.succeed(result["evidence_receipt"])
        duration = round((time.monotonic() - started) * 1000)
        event = "execution_timed_out" if result.get("timed_out") else "execution_completed"
        audit(event, request_id, source_id, code_hash, "timeout" if result.get("timed_out") else "completed", duration)
        return result
    except Exception as error:
        if attempt is not None:
            attempt.fail(error)
        raise


def _claim_pending_once(run_id: str, session_id: str, root: Path,
                        trusted_uid: int,
                        reported_skips: set[tuple[str, str]] | None = None) -> dict | None:
    if os.geteuid() != trusted_uid:
        raise PermissionError("root_required")
    for candidate in (run_id, session_id):
        parsed = uuid.UUID(candidate)
        if parsed.version != 4 or str(parsed) != candidate:
            raise ValueError("approval_context_invalid")
    pending, claims, responses, _consumed = approval_directories(root)
    response_entries = sorted(responses.iterdir(), key=lambda path: path.name)
    if len(response_entries) > 64:
        raise RuntimeError("approval_response_limit_exceeded")
    responses_pruned = False
    for response in response_entries:
        info = response.lstat()
        if (not response.name.endswith(".json") or not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode) or info.st_uid != trusted_uid
                or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1
                or info.st_size > 64 * 1024):
            raise RuntimeError("approval_state_untrusted")
        if not (pending / response.name).exists():
            response.unlink()
            responses_pruned = True
    if responses_pruned:
        directory = os.open(responses, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    claim_entries = sorted(claims.iterdir(), key=lambda path: path.name)
    if len(claim_entries) > 64:
        raise RuntimeError("approval_claim_limit_exceeded")
    claims_pruned = False
    for claim in claim_entries:
        info = claim.lstat()
        if (not claim.name.endswith(".json") or not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode) or info.st_uid != trusted_uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 4096):
            raise RuntimeError("approval_state_untrusted")
        if not (pending / claim.name).exists():
            claim.unlink()
            claims_pruned = True
    if claims_pruned:
        directory = os.open(claims, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    entries = sorted(pending.iterdir(), key=lambda path: path.name)
    if len(entries) > 32:
        raise RuntimeError("approval_pending_limit_exceeded")
    broker_uid = pwd.getpwnam("execution-broker").pw_uid
    now = int(time.time())
    reported_skips = set() if reported_skips is None else reported_skips

    def report_skip(approval_id: str, reason: str) -> None:
        key = (approval_id, reason)
        if key not in reported_skips:
            audit("approval_claim_skipped", request_id=approval_id, status=reason)
            reported_skips.add(key)

    for path in entries:
        if not path.name.endswith(".json"):
            raise RuntimeError("approval_state_untrusted")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != broker_uid or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size > 16 * 1024):
            raise RuntimeError("approval_state_untrusted")
        raw = path.read_bytes()
        value = json.loads(raw)
        if raw != canonical(value):
            raise RuntimeError("approval_state_untrusted")
        approval_id = str(value.get("approval_id", ""))
        # A root-owned response means authorization has already been delivered
        # and the broker has not yet removed its pending acknowledgement.  Do
        # not reclaim the request and present a duplicate authorization UI in
        # that narrow handoff window.
        if (responses / path.name).exists():
            continue
        if value.get("run_id") != run_id or value.get("session_id") != session_id:
            report_skip(approval_id, "context_mismatch")
            continue
        if value.get("expires_at", 0) < now:
            report_skip(approval_id, "expired")
            continue
        claim = claims / path.name
        try:
            descriptor = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            try:
                claim_raw = claim.read_bytes()
                claim_value = json.loads(claim_raw)
            except (OSError, ValueError, json.JSONDecodeError) as error:
                raise RuntimeError("approval_state_untrusted") from error
            if (claim_raw != canonical(claim_value)
                    or not isinstance(claim_value, dict)
                    or set(claim_value) != {
                        "approval_id", "request_sha256", "claimed_at"
                    }
                    or claim_value.get("approval_id") != approval_id
                    or claim_value.get("request_sha256")
                    != hashlib.sha256(raw).hexdigest()
                    or not isinstance(claim_value.get("claimed_at"), int)
                    or isinstance(claim_value.get("claimed_at"), bool)
                    or not isinstance(value.get("created_at"), int)
                    or isinstance(value.get("created_at"), bool)
                    or not isinstance(value.get("expires_at"), int)
                    or isinstance(value.get("expires_at"), bool)
                    or not value["created_at"] <= claim_value["claimed_at"]
                    <= min(now, value["expires_at"])):
                raise RuntimeError("approval_state_untrusted")
            # Claim creation and delivery cross an SSH boundary.  The guest may
            # durably create the claim while the first response is lost.  The
            # exact run/session may therefore retrieve the same still-pending,
            # content-bound request again.  Approval consumption remains
            # separately one-time and replay protected.
            audit("approval_claim_redelivered", request_id=approval_id,
                  status="claimed")
            return value
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, canonical({"approval_id":value["approval_id"],
                                            "request_sha256":hashlib.sha256(raw).hexdigest(),
                                            "claimed_at":now}))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        audit("approval_claimed", request_id=approval_id, status="claimed")
        return value
    return None


def claim_pending(run_id: str, session_id: str, root: Path = APPROVAL_ROOT,
                  trusted_uid: int = 0, wait_seconds: float = 0.0) -> dict | None:
    if not isinstance(wait_seconds, (int, float)) or isinstance(wait_seconds, bool) \
            or not 0 <= wait_seconds <= APPROVAL_RELAY_LONG_POLL_SECONDS:
        raise ValueError("approval_wait_invalid")
    deadline = time.monotonic() + wait_seconds
    reported_skips: set[tuple[str, str]] = set()
    while True:
        value = _claim_pending_once(
            run_id, session_id, root, trusted_uid, reported_skips)
        if value is not None or time.monotonic() >= deadline:
            return value
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def deliver_approval_response(data: bytes, root: Path = APPROVAL_ROOT,
                              trusted_uid: int = 0) -> dict:
    if os.geteuid() != trusted_uid:
        raise PermissionError("root_required")
    if not data or len(data) > 64 * 1024:
        raise ValueError("approval_response_size_invalid")
    value = json.loads(data)
    if canonical(value) != data:
        raise ValueError("approval_response_not_canonical")
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-execution-approval-response-v1"
            or set(value) not in ({"schema", "approval_id", "status"},
                                  {"schema", "approval_id", "status", "envelope"})
            or value.get("status") not in {"approved", "cancelled"}):
        raise ValueError("approval_response_invalid")
    approval_id = str(value.get("approval_id", ""))
    parsed = uuid.UUID(approval_id)
    if parsed.version != 4 or str(parsed) != approval_id:
        raise ValueError("approval_response_invalid")
    pending, claims, responses, _consumed = approval_directories(root)
    for path in (pending / f"{approval_id}.json", claims / f"{approval_id}.json"):
        if not path.is_file() or path.is_symlink():
            raise ValueError("approval_not_claimed")
    if value["status"] == "approved":
        envelope = value.get("envelope")
        if (not isinstance(envelope, dict)
                or envelope.get("attestation", {}).get("approval", {}).get("approval_id") != approval_id):
            raise ValueError("approval_response_invalid")
    elif "envelope" in value:
        raise ValueError("approval_response_invalid")
    broker_gid = grp.getgrnam("execution-broker").gr_gid
    target = responses / f"{approval_id}.json"
    if target.exists():
        raise FileExistsError("approval_response_already_delivered")
    atomic_file(target, data, 0o640, owner=trusted_uid, group=broker_gid)
    claim_path = claims / f"{approval_id}.json"
    claim_path.unlink()
    directory = os.open(claims, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return {"schema":"secure-sandbox-execution-approval-delivery-v1",
            "approval_id":approval_id,"status":"delivered"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    attempts = collections.deque()

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        self._framing_lock = threading.Lock()
        self._framing_state = "open"
        self._deadline_timer = threading.Timer(REQUEST_READ_TIMEOUT_SECONDS, self._expire_framing)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _expire_framing(self) -> None:
        with self._framing_lock:
            if self._framing_state != "open":
                return
            self._framing_state = "expired"
        audit("execution_rejected", status="request_incomplete")
        try:
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def _complete_framing(self) -> bool:
        with self._framing_lock:
            if self._framing_state == "expired":
                return False
            self._framing_state = "complete"
        self._deadline_timer.cancel()
        # Socket deadlines apply only while client I/O is pending. Retaining
        # this finite timeout does not shorten Target execution, but prevents a
        # client that stops reading from monopolizing the serialized server.
        self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        return True

    def finish(self) -> None:
        if hasattr(self, "_framing_lock"):
            with self._framing_lock:
                if self._framing_state == "open":
                    self._framing_state = "complete"
        if hasattr(self, "_deadline_timer"):
            self._deadline_timer.cancel()
        super().finish()

    def reply(self, status: int, value: dict) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        try:
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass

    def do_POST(self) -> None:
        now = time.monotonic()
        while self.attempts and self.attempts[0] < now - 60: self.attempts.popleft()
        if len(self.attempts) >= 12:
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            self.reply(429, {"error": "rate_limited"}); return
        self.attempts.append(now)
        if self.path != "/v1/run-python":
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            self.reply(404, {"error": "not_found"}); return
        try: length = int(self.headers.get("Content-Length", "-1"))
        except ValueError: length = -1
        if not 0 <= length <= MAX_BODY:
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            self.reply(413, {"error": "request_too_large"}); return
        source_id = ""; code_hash = ""
        try:
            body = self.rfile.read(length)
            if not self._complete_framing():
                self.reply(408, {"error": "request_incomplete"}); return
            if len(body) != length:
                raise Rejected("request_incomplete")
            value = json.loads(body); source_id = str(value.get("source_id", "")) if isinstance(value, dict) else ""
            code_hash = hashlib.sha256(str(value.get("code", "")).encode()).hexdigest() if isinstance(value, dict) else ""
            result = validate_and_forward(value, self.server.config)
        except (socket.timeout, TimeoutError):
            self.close_connection = True
            self._expire_framing()
            self.reply(408, {"error": "request_incomplete"}); return
        except (Rejected, IntegrityError, ReceiptError, json.JSONDecodeError) as error:
            token=rejection_token(error)
            audit("execution_rejected", source_id=source_id, code_hash=code_hash, status=token); self.reply(400, {"error": token}); return
        except Exception as error:
            audit("execution_failed", source_id=source_id, code_hash=code_hash,
                  status=f"internal_error:{type(error).__name__}")
            self.reply(502, {"error": "execution_failed"}); return
        self.reply(200, result)

    def log_message(self, *_: object) -> None: return


def main() -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command")
    pending = sub.add_parser("approval-next"); pending.add_argument("run_id"); pending.add_argument("session_id")
    sub.add_parser("approval-deliver")
    args = parser.parse_args()
    if args.command == "approval-next":
        value = claim_pending(
            args.run_id, args.session_id, wait_seconds=APPROVAL_RELAY_LONG_POLL_SECONDS)
        if value is None:
            return 3
        sys.stdout.buffer.write(canonical(value)); return 0
    if args.command == "approval-deliver":
        data = sys.stdin.buffer.read(64 * 1024 + 1)
        print(json.dumps(deliver_approval_response(data), separators=(",", ":"), sort_keys=True))
        return 0
    config = load_config(); server = HTTPServer(("127.0.0.1", 18081), Handler); server.config = config; server.serve_forever()
    return 0


if __name__ == "__main__": raise SystemExit(main())
