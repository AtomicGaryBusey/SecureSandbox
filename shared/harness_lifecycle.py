#!/usr/bin/env python3
"""Fail-closed, non-executing harness release acquisition primitives."""

from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator


POLICY_SCHEMA = "secure-sandbox-harness-release-policy-v1"
ENVELOPE_SCHEMA = "secure-sandbox-harness-release-metadata-envelope-v1"
METADATA_SCHEMA = "secure-sandbox-harness-release-metadata-v1"
MANIFEST_SCHEMA = "secure-sandbox-harness-release-manifest-v1"
FLOOR_SCHEMA = "secure-sandbox-harness-metadata-floor-v1"
RECEIPT_SCHEMA = "secure-sandbox-harness-lifecycle-receipt-v1"
STATUS_SCHEMA = "secure-sandbox-harness-lifecycle-status-v1"
MAX_JSON_BYTES = 1024 * 1024
MAX_RELEASES = 64
MAX_KEYS = 8
MAX_EVIDENCE = 32
MAX_RECEIPTS = 256
ARTIFACT_DOWNLOAD_DEADLINE_SECONDS = 300
METADATA_DOWNLOAD_DEADLINE_SECONDS = 60
DEFAULT_OPENSSL = Path("/opt/local/bin/openssl")
MAX_LIFETIME_SECONDS = 31 * 86400
FUTURE_SKEW_SECONDS = 300
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,62}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
PLATFORM_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}/[a-zA-Z0-9][a-zA-Z0-9.+-]{0,63}")
EVIDENCE_KINDS = {
    "vendor-signature", "vendor-checksum-manifest", "source-provenance",
    "build-provenance", "sbom", "license-report", "vulnerability-report",
    "malware-report", "static-review",
}


class HarnessLifecycleError(RuntimeError):
    """Stable, content-free lifecycle failure."""


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise HarnessLifecycleError("json_not_canonicalizable") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def ed25519_spki_der(public_key_pem: str) -> bytes:
    lines = public_key_pem.splitlines()
    if (len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----"
            or lines[-1] != "-----END PUBLIC KEY-----"):
        raise HarnessLifecycleError("policy_key_invalid")
    try:
        value = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError) as error:
        raise HarnessLifecycleError("policy_key_invalid") from error
    if len(value) != 44 or value[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise HarnessLifecycleError("policy_key_invalid")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessLifecycleError("json_duplicate_key")
        result[key] = value
    return result


def parse_json(raw: bytes, *, maximum: int = MAX_JSON_BYTES,
               require_canonical: bool = True) -> dict[str, Any]:
    if not 0 < len(raw) <= maximum:
        raise HarnessLifecycleError("json_size_invalid")
    try:
        value = json.loads(
            raw, object_pairs_hook=_unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                HarnessLifecycleError("json_number_invalid")
            ),
        )
    except HarnessLifecycleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessLifecycleError("json_invalid") from error
    if not isinstance(value, dict):
        raise HarnessLifecycleError("json_object_required")
    if require_canonical and canonical_bytes(value) != raw:
        raise HarnessLifecycleError("json_noncanonical")
    return value


def _exact(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise HarnessLifecycleError(f"{label}_fields_invalid")


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise HarnessLifecycleError(f"{label}_invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise HarnessLifecycleError(f"{label}_invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise HarnessLifecycleError(f"{label}_invalid")
    return value


def _https_url(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise HarnessLifecycleError(f"{label}_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise HarnessLifecycleError(f"{label}_invalid") from error
    hostname = parsed.hostname
    if (parsed.scheme != "https" or not hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or port not in {None, 443}):
        raise HarnessLifecycleError(f"{label}_invalid")
    if hostname != hostname.lower() or parsed.netloc != parsed.netloc.lower():
        raise HarnessLifecycleError(f"{label}_invalid")
    try:
        ascii_hostname = hostname.encode("ascii").decode("ascii")
    except UnicodeError as error:
        raise HarnessLifecycleError(f"{label}_invalid") from error
    try:
        address = ipaddress.ip_address(ascii_hostname)
    except ValueError:
        labels = ascii_hostname.split(".")
        if (len(ascii_hostname) > 253 or len(labels) < 2
                or any(not 1 <= len(item) <= 63
                       or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", item) is None
                       for item in labels)):
            raise HarnessLifecycleError(f"{label}_invalid")
    else:
        if not address.is_global:
            raise HarnessLifecycleError(f"{label}_invalid")
    return value


def url_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    return f"https://{parsed.hostname}"


def generation_identity(manifest: dict[str, Any]) -> str:
    body = dict(manifest)
    body.pop("generation_id", None)
    return sha256_bytes(canonical_bytes(body))


def validate_evidence(value: object, artifact_sha256: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_EVIDENCE:
        raise HarnessLifecycleError("manifest_evidence_invalid")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise HarnessLifecycleError("manifest_evidence_invalid")
        _exact(item, {"kind", "media_type", "required", "sha256", "subject_sha256"},
               "manifest_evidence")
        kind = item.get("kind")
        if kind not in EVIDENCE_KINDS or kind in seen:
            raise HarnessLifecycleError("manifest_evidence_invalid")
        seen.add(kind)
        if not isinstance(item.get("required"), bool):
            raise HarnessLifecycleError("manifest_evidence_invalid")
        if (not isinstance(item.get("media_type"), str)
                or MEDIA_TYPE_RE.fullmatch(item["media_type"]) is None):
            raise HarnessLifecycleError("manifest_evidence_invalid")
        _sha256(item.get("sha256"), "manifest_evidence_sha256")
        if not hmac.compare_digest(
            _sha256(item.get("subject_sha256"), "manifest_evidence_subject_sha256"),
            artifact_sha256,
        ):
            raise HarnessLifecycleError("manifest_evidence_subject_mismatch")
        result.append(dict(item))
    return result


def validate_manifest(value: object, policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessLifecycleError("manifest_invalid")
    _exact(value, {
        "adapter_id", "artifact", "compatibility", "evidence", "generation_id",
        "harness_id", "platform", "release_sequence", "schema", "vendor_id", "version",
    }, "manifest")
    if value.get("schema") != MANIFEST_SCHEMA:
        raise HarnessLifecycleError("manifest_schema_invalid")
    for field in ("adapter_id", "harness_id", "vendor_id"):
        _identifier(value.get(field), f"manifest_{field}")
    if not isinstance(value.get("version"), str) or VERSION_RE.fullmatch(value["version"]) is None:
        raise HarnessLifecycleError("manifest_version_invalid")
    if not isinstance(value.get("platform"), str) or PLATFORM_RE.fullmatch(value["platform"]) is None:
        raise HarnessLifecycleError("manifest_platform_invalid")
    _integer(value.get("release_sequence"), "manifest_release_sequence", 1, 2**63 - 1)
    artifact = value.get("artifact")
    if not isinstance(artifact, dict):
        raise HarnessLifecycleError("manifest_artifact_invalid")
    _exact(artifact, {"filename", "media_type", "sha256", "size", "url"}, "manifest_artifact")
    if (not isinstance(artifact.get("filename"), str)
            or FILENAME_RE.fullmatch(artifact["filename"]) is None):
        raise HarnessLifecycleError("manifest_artifact_filename_invalid")
    if (not isinstance(artifact.get("media_type"), str)
            or MEDIA_TYPE_RE.fullmatch(artifact["media_type"]) is None):
        raise HarnessLifecycleError("manifest_artifact_media_type_invalid")
    artifact_hash = _sha256(artifact.get("sha256"), "manifest_artifact_sha256")
    size = _integer(artifact.get("size"), "manifest_artifact_size", 1, policy["max_artifact_bytes"])
    if size > policy["max_artifact_bytes"]:
        raise HarnessLifecycleError("manifest_artifact_size_invalid")
    artifact_url = _https_url(artifact.get("url"), "manifest_artifact_url")
    if url_origin(artifact_url) not in policy["artifact_origins"]:
        raise HarnessLifecycleError("manifest_artifact_origin_rejected")
    validate_evidence(value.get("evidence"), artifact_hash)
    required = set(policy["mandatory_evidence_kinds"])
    declared_required = {
        item["kind"] for item in value["evidence"] if item["required"] is True
    }
    if not required <= declared_required:
        raise HarnessLifecycleError("manifest_mandatory_evidence_missing")
    compatibility = value.get("compatibility")
    if not isinstance(compatibility, dict):
        raise HarnessLifecycleError("manifest_compatibility_invalid")
    _exact(compatibility, {"adapter_sha256", "controller_schema"}, "manifest_compatibility")
    _sha256(compatibility.get("adapter_sha256"), "manifest_adapter_sha256")
    _identifier(compatibility.get("controller_schema"), "manifest_controller_schema")
    generation = _sha256(value.get("generation_id"), "manifest_generation_id")
    if not hmac.compare_digest(generation, generation_identity(value)):
        raise HarnessLifecycleError("manifest_generation_id_mismatch")
    return value


def validate_policy(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessLifecycleError("policy_invalid")
    _exact(value, {
        "artifact_origins", "keys", "mandatory_evidence_kinds", "max_artifact_bytes",
        "max_metadata_bytes", "metadata_url", "schema", "threshold",
    }, "policy")
    if value.get("schema") != POLICY_SCHEMA:
        raise HarnessLifecycleError("policy_schema_invalid")
    metadata_url = _https_url(value.get("metadata_url"), "policy_metadata_url")
    origins = value.get("artifact_origins")
    if not isinstance(origins, list) or not 1 <= len(origins) <= 16 or len(set(origins)) != len(origins):
        raise HarnessLifecycleError("policy_artifact_origins_invalid")
    for origin in origins:
        if _https_url(origin, "policy_artifact_origin") != url_origin(origin):
            raise HarnessLifecycleError("policy_artifact_origins_invalid")
    max_metadata = _integer(value.get("max_metadata_bytes"), "policy_max_metadata_bytes", 1024, MAX_JSON_BYTES)
    max_artifact = _integer(value.get("max_artifact_bytes"), "policy_max_artifact_bytes", 1, 16 * 1024**3)
    mandatory = value.get("mandatory_evidence_kinds")
    if (not isinstance(mandatory, list) or not 1 <= len(mandatory) <= len(EVIDENCE_KINDS)
            or len(set(mandatory)) != len(mandatory)
            or not set(mandatory) <= EVIDENCE_KINDS):
        raise HarnessLifecycleError("policy_mandatory_evidence_invalid")
    keys = value.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        raise HarnessLifecycleError("policy_keys_invalid")
    seen: set[str] = set()
    for key in keys:
        if not isinstance(key, dict):
            raise HarnessLifecycleError("policy_keys_invalid")
        _exact(key, {"algorithm", "key_id", "public_key_pem"}, "policy_key")
        if key.get("algorithm") != "ed25519":
            raise HarnessLifecycleError("policy_key_algorithm_invalid")
        pem = key.get("public_key_pem")
        if (not isinstance(pem, str) or not pem.endswith("\n") or len(pem) > 4096
                or "-----BEGIN PUBLIC KEY-----" not in pem
                or "-----END PUBLIC KEY-----" not in pem):
            raise HarnessLifecycleError("policy_key_invalid")
        try:
            pem_bytes = pem.encode("ascii")
        except UnicodeEncodeError as error:
            raise HarnessLifecycleError("policy_key_invalid") from error
        key_id = _sha256(key.get("key_id"), "policy_key_id")
        if key_id != sha256_bytes(ed25519_spki_der(pem)) or key_id in seen:
            raise HarnessLifecycleError("policy_key_id_mismatch")
        seen.add(key_id)
    threshold = _integer(value.get("threshold"), "policy_threshold", 1, len(keys))
    return {
        **value, "artifact_origins": list(origins), "keys": list(keys),
        "mandatory_evidence_kinds": list(mandatory), "max_metadata_bytes": max_metadata,
        "max_artifact_bytes": max_artifact, "metadata_url": metadata_url,
        "threshold": threshold,
    }


def validate_metadata(value: object, policy: dict[str, Any], now: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessLifecycleError("metadata_invalid")
    _exact(value, {"expires_at", "published_at", "releases", "schema", "sequence"}, "metadata")
    if value.get("schema") != METADATA_SCHEMA:
        raise HarnessLifecycleError("metadata_schema_invalid")
    sequence = _integer(value.get("sequence"), "metadata_sequence", 1, 2**63 - 1)
    published = _integer(value.get("published_at"), "metadata_published_at", 0, 2**63 - 1)
    expires = _integer(value.get("expires_at"), "metadata_expires_at", 0, 2**63 - 1)
    if published > now + FUTURE_SKEW_SECONDS:
        raise HarnessLifecycleError("metadata_from_future")
    if expires <= now:
        raise HarnessLifecycleError("metadata_expired")
    if expires <= published or expires - published > MAX_LIFETIME_SECONDS:
        raise HarnessLifecycleError("metadata_lifetime_invalid")
    releases = value.get("releases")
    if not isinstance(releases, list) or not 1 <= len(releases) <= MAX_RELEASES:
        raise HarnessLifecycleError("metadata_releases_invalid")
    generations: set[str] = set()
    identities: set[tuple[str, int]] = set()
    for manifest in releases:
        validate_manifest(manifest, policy)
        generation = manifest["generation_id"]
        identity = (manifest["harness_id"], manifest["release_sequence"])
        if generation in generations or identity in identities:
            raise HarnessLifecycleError("metadata_release_duplicate")
        generations.add(generation); identities.add(identity)
    return value


def verify_ed25519(public_key_pem: str, payload: bytes, signature: bytes,
                   openssl: Path = DEFAULT_OPENSSL) -> bool:
    try:
        link_info = openssl.lstat()
        resolved = openssl.resolve(strict=True)
        binary_info = resolved.stat()
    except OSError as error:
        raise HarnessLifecycleError("signature_verifier_unavailable") from error
    try:
        package_uid = pwd.getpwnam("macports").pw_uid
    except KeyError:
        package_uid = -1
    if (link_info.st_uid != 0 or resolved != Path("/opt/local/libexec/openssl3/bin/openssl")
            or not stat.S_ISREG(binary_info.st_mode)
            or binary_info.st_uid not in {0, package_uid} or binary_info.st_mode & 0o022
            or not binary_info.st_mode & 0o111):
        raise HarnessLifecycleError("signature_verifier_untrusted")
    with tempfile.TemporaryDirectory(prefix="secure-sandbox-harness-signature.") as directory:
        root = Path(directory)
        key_path = root / "key.pem"
        data_path = root / "payload"
        signature_path = root / "signature"
        key_path.write_text(public_key_pem, encoding="ascii")
        data_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        for path in (key_path, data_path, signature_path):
            path.chmod(0o600)
        try:
            result = subprocess.run(
                [str(resolved), "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path),
                 "-rawin", "-in", str(data_path), "-sigfile", str(signature_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HarnessLifecycleError("signature_verifier_unavailable") from error
    return result.returncode == 0


def validate_envelope(raw: bytes, policy: dict[str, Any], now: int | None = None,
                      verifier: Callable[[str, bytes, bytes], bool] = verify_ed25519,
                      ) -> tuple[dict[str, Any], str]:
    envelope = parse_json(raw, maximum=policy["max_metadata_bytes"])
    _exact(envelope, {"schema", "signatures", "signed"}, "metadata_envelope")
    if envelope.get("schema") != ENVELOPE_SCHEMA or not isinstance(envelope.get("signed"), dict):
        raise HarnessLifecycleError("metadata_envelope_invalid")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= MAX_KEYS:
        raise HarnessLifecycleError("metadata_signatures_invalid")
    keys = {key["key_id"]: key for key in policy["keys"]}
    signed_bytes = canonical_bytes(envelope["signed"])
    accepted: set[str] = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            raise HarnessLifecycleError("metadata_signatures_invalid")
        _exact(signature, {"algorithm", "key_id", "signature"}, "metadata_signature")
        key_id = _sha256(signature.get("key_id"), "metadata_signature_key_id")
        if signature.get("algorithm") != "ed25519" or key_id not in keys or key_id in accepted:
            raise HarnessLifecycleError("metadata_signature_identity_invalid")
        encoded = signature.get("signature")
        if not isinstance(encoded, str) or len(encoded) > 256:
            raise HarnessLifecycleError("metadata_signature_invalid")
        try:
            signature_bytes = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise HarnessLifecycleError("metadata_signature_invalid") from error
        if len(signature_bytes) != 64 or not verifier(keys[key_id]["public_key_pem"], signed_bytes, signature_bytes):
            raise HarnessLifecycleError("metadata_signature_invalid")
        accepted.add(key_id)
    if len(accepted) < policy["threshold"]:
        raise HarnessLifecycleError("metadata_signature_threshold_unmet")
    validate_metadata(envelope["signed"], policy, int(time.time()) if now is None else now)
    return envelope, sha256_bytes(raw)


def _trusted_directory(path: Path, uid: int, *, create: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise HarnessLifecycleError("state_directory_missing")
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=False)
            info = path.lstat()
        except OSError as error:
            raise HarnessLifecycleError("state_directory_create_failed") from error
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise HarnessLifecycleError("state_directory_untrusted")


def read_regular(path: Path, uid: int, maximum: int, mode: int = 0o600) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise HarnessLifecycleError("state_file_missing") from error
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= maximum):
        raise HarnessLifecycleError("state_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise HarnessLifecycleError("state_file_changed")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > maximum or (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    ):
        raise HarnessLifecycleError("state_file_changed")
    return bytes(data)


def hash_regular(path: Path, uid: int, expected_size: int, mode: int = 0o600) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise HarnessLifecycleError("state_file_missing") from error
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode or before.st_size != expected_size):
        raise HarnessLifecycleError("state_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256(); total = 0
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise HarnessLifecycleError("state_file_changed")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk); digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (total != expected_size or (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    )):
        raise HarnessLifecycleError("state_file_changed")
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.new-{uuid.uuid4()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HarnessLifecycleError("state_write_failed")
            view = view[written:]
        os.fchmod(descriptor, mode); os.fsync(descriptor)
    except BaseException:
        os.close(descriptor); temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path); fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def open_https(url: str, *, timeout: int = 30) -> BinaryIO:
    _https_url(url, "download_url")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect(),
    )
    try:
        response = opener.open(
            urllib.request.Request(url, headers={"User-Agent": "SecureSandbox-Harness/1"}),
            timeout=timeout,
        )
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise HarnessLifecycleError("download_failed") from error
    if getattr(response, "status", 200) != 200 or response.geturl() != url:
        response.close()
        raise HarnessLifecycleError("download_response_rejected")
    return response


class HarnessStore:
    def __init__(self, root: Path, policy_path: Path, *, uid: int | None = None,
                 now: Callable[[], int] | None = None,
                 monotonic: Callable[[], float] | None = None) -> None:
        self.root = root
        self.policy_path = policy_path
        self.uid = os.geteuid() if uid is None else uid
        self.now = now or (lambda: int(time.time()))
        self.monotonic = monotonic or time.monotonic
        self.metadata = root / "metadata"
        self.quarantine = root / "quarantine"
        self.receipts = root / "receipts"
        self.lock_path = root / ".lock"

    def prepare(self) -> None:
        old_umask = os.umask(0o077)
        try:
            _trusted_directory(self.root.parent, self.uid, create=True)
            _trusted_directory(self.root, self.uid, create=True)
            for directory in (self.metadata, self.quarantine, self.receipts):
                _trusted_directory(directory, self.uid, create=True)
            try:
                info = self.lock_path.lstat()
            except FileNotFoundError:
                descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
                info = self.lock_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise HarnessLifecycleError("state_lock_untrusted")
        finally:
            os.umask(old_umask)

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        self.prepare()
        descriptor = os.open(self.lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)

    def policy(self) -> dict[str, Any]:
        raw = read_regular(self.policy_path, self.uid, 64 * 1024)
        return validate_policy(parse_json(raw))

    def _require_receipt_capacity(self) -> None:
        entries = list(self.receipts.iterdir())
        if len(entries) >= MAX_RECEIPTS:
            raise HarnessLifecycleError("receipt_capacity_exceeded")
        if any(entry.is_symlink() or not entry.is_file() for entry in entries):
            raise HarnessLifecycleError("receipt_store_untrusted")

    def _receipt(self, action: str, status: str, **fields: object) -> dict[str, Any]:
        self._require_receipt_capacity()
        value = {
            "action": action, "observed_at": self.now(), "receipt_id": str(uuid.uuid4()),
            "schema": RECEIPT_SCHEMA, "status": status, **fields,
        }
        atomic_write(self.receipts / f"{value['receipt_id']}.json", canonical_bytes(value))
        return value

    def _floor(self) -> dict[str, Any] | None:
        path = self.metadata / "floor.json"
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        value = parse_json(read_regular(path, self.uid, MAX_JSON_BYTES))
        _exact(value, {"envelope_sha256", "policy_sha256", "schema", "sequence"}, "metadata_floor")
        if value.get("schema") != FLOOR_SCHEMA:
            raise HarnessLifecycleError("metadata_floor_invalid")
        _integer(value.get("sequence"), "metadata_floor_sequence", 1, 2**63 - 1)
        _sha256(value.get("envelope_sha256"), "metadata_floor_sha256")
        _sha256(value.get("policy_sha256"), "metadata_floor_policy_sha256")
        return value

    def check_bytes(self, raw: bytes,
                    verifier: Callable[[str, bytes, bytes], bool] = verify_ed25519,
                    ) -> dict[str, Any]:
        with self.locked():
            return self._check_bytes_locked(raw, verifier)

    def _check_bytes_locked(
        self, raw: bytes,
        verifier: Callable[[str, bytes, bytes], bool] = verify_ed25519,
    ) -> dict[str, Any]:
        policy = self.policy()
        policy_digest = sha256_bytes(canonical_bytes(policy))
        envelope, digest = validate_envelope(raw, policy, self.now(), verifier)
        self._require_receipt_capacity()
        sequence = envelope["signed"]["sequence"]
        floor = self._floor()
        if floor is not None:
            if not hmac.compare_digest(policy_digest, floor["policy_sha256"]):
                raise HarnessLifecycleError("metadata_policy_changed")
            if sequence < floor["sequence"] or (
                sequence == floor["sequence"]
                and not hmac.compare_digest(digest, floor["envelope_sha256"])
            ):
                raise HarnessLifecycleError("metadata_rollback_or_equivocation")
        atomic_write(self.metadata / "verified.json", raw)
        atomic_write(self.metadata / "floor.json", canonical_bytes({
            "envelope_sha256": digest, "schema": FLOOR_SCHEMA, "sequence": sequence,
            "policy_sha256": policy_digest,
        }))
        return self._receipt(
            "check", "metadata_verified", envelope_sha256=digest,
            policy_sha256=policy_digest,
            release_count=len(envelope["signed"]["releases"]), sequence=sequence,
            signing_key_ids=sorted(item["key_id"] for item in envelope["signatures"]),
        )

    def check(self) -> dict[str, Any]:
        with self.locked():
            policy = self.policy()
            with open_https(policy["metadata_url"]) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError as error:
                        raise HarnessLifecycleError("metadata_length_invalid") from error
                    if not 0 < declared <= policy["max_metadata_bytes"]:
                        raise HarnessLifecycleError("metadata_length_invalid")
                reader = getattr(response, "read1", response.read)
                deadline = self.monotonic() + METADATA_DOWNLOAD_DEADLINE_SECONDS
                content = bytearray()
                while len(content) <= policy["max_metadata_bytes"]:
                    if self.monotonic() >= deadline:
                        raise HarnessLifecycleError("metadata_download_deadline_exceeded")
                    chunk = reader(min(64 * 1024, policy["max_metadata_bytes"] + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                    if self.monotonic() >= deadline:
                        raise HarnessLifecycleError("metadata_download_deadline_exceeded")
                raw = bytes(content)
            if len(raw) > policy["max_metadata_bytes"]:
                raise HarnessLifecycleError("metadata_size_invalid")
            return self._check_bytes_locked(raw)

    def _verified(self) -> tuple[dict[str, Any], dict[str, Any], str]:
        policy = self.policy()
        policy_digest = sha256_bytes(canonical_bytes(policy))
        raw = read_regular(self.metadata / "verified.json", self.uid, policy["max_metadata_bytes"])
        envelope, digest = validate_envelope(raw, policy, self.now())
        floor = self._floor()
        if (floor is None or envelope["signed"]["sequence"] != floor["sequence"]
                or not hmac.compare_digest(digest, floor["envelope_sha256"])
                or not hmac.compare_digest(policy_digest, floor["policy_sha256"])):
            raise HarnessLifecycleError("metadata_floor_mismatch")
        return policy, envelope, digest

    @staticmethod
    def _find(envelope: dict[str, Any], generation_id: str) -> dict[str, Any]:
        _sha256(generation_id, "generation_id")
        matches = [item for item in envelope["signed"]["releases"]
                   if item["generation_id"] == generation_id]
        if len(matches) != 1:
            raise HarnessLifecycleError("generation_not_found")
        return matches[0]

    def acquire(self, generation_id: str,
                opener: Callable[..., BinaryIO] = open_https) -> dict[str, Any]:
        with self.locked():
            policy, envelope, envelope_digest = self._verified()
            self._require_receipt_capacity()
            manifest = self._find(envelope, generation_id)
            artifact = manifest["artifact"]
            generation = self.quarantine / generation_id
            try:
                generation.lstat()
            except FileNotFoundError:
                generation.mkdir(mode=0o700); fsync_directory(self.quarantine)
            else:
                _trusted_directory(generation, self.uid)
            artifact_path = generation / "artifact"
            manifest_path = generation / "manifest.json"
            names = {entry.name for entry in generation.iterdir()}
            if not names <= {"artifact", "manifest.json"}:
                raise HarnessLifecycleError("quarantine_partial_state")
            if names:
                if names != {"artifact", "manifest.json"}:
                    raise HarnessLifecycleError("quarantine_partial_state")
                self._verify_files(policy, manifest, generation)
                return self._receipt(
                    "acquire", "already_acquired", generation_id=generation_id,
                    artifact_sha256=artifact["sha256"], envelope_sha256=envelope_digest,
                    policy_sha256=sha256_bytes(canonical_bytes(policy)),
                )
            temporary = generation / f".artifact.new-{uuid.uuid4()}"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            digest = hashlib.sha256(); total = 0
            deadline = self.monotonic() + ARTIFACT_DOWNLOAD_DEADLINE_SECONDS
            try:
                with opener(artifact["url"]) as response:
                    reader = getattr(response, "read1", response.read)
                    declared = response.headers.get("Content-Length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError as error:
                            raise HarnessLifecycleError("artifact_length_invalid") from error
                        if declared_size != artifact["size"]:
                            raise HarnessLifecycleError("artifact_length_mismatch")
                    while True:
                        if self.monotonic() >= deadline:
                            raise HarnessLifecycleError("artifact_download_deadline_exceeded")
                        chunk = reader(min(1024 * 1024, artifact["size"] + 1 - total))
                        if not chunk:
                            break
                        if self.monotonic() >= deadline:
                            raise HarnessLifecycleError("artifact_download_deadline_exceeded")
                        total += len(chunk)
                        if total > artifact["size"]:
                            raise HarnessLifecycleError("artifact_size_mismatch")
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise HarnessLifecycleError("artifact_write_failed")
                            view = view[written:]
                if total != artifact["size"] or not hmac.compare_digest(digest.hexdigest(), artifact["sha256"]):
                    raise HarnessLifecycleError("artifact_digest_mismatch")
                os.fsync(descriptor)
            except BaseException:
                os.close(descriptor); temporary.unlink(missing_ok=True)
                raise
            else:
                os.close(descriptor)
            try:
                os.link(temporary, artifact_path, follow_symlinks=False)
                fsync_directory(generation)
            finally:
                temporary.unlink(missing_ok=True)
            atomic_write(manifest_path, canonical_bytes(manifest))
            self._verify_files(policy, manifest, generation)
            return self._receipt(
                "acquire", "artifact_quarantined", artifact_sha256=artifact["sha256"],
                envelope_sha256=envelope_digest, generation_id=generation_id,
                policy_sha256=sha256_bytes(canonical_bytes(policy)),
            )

    def _verify_files(self, policy: dict[str, Any], manifest: dict[str, Any],
                      generation: Path) -> str:
        _trusted_directory(generation, self.uid)
        manifest_raw = read_regular(generation / "manifest.json", self.uid, MAX_JSON_BYTES)
        observed_manifest = parse_json(manifest_raw)
        validate_manifest(observed_manifest, policy)
        if not hmac.compare_digest(
            sha256_bytes(manifest_raw), sha256_bytes(canonical_bytes(manifest))
        ):
            raise HarnessLifecycleError("quarantine_manifest_mismatch")
        artifact = manifest["artifact"]
        digest = hash_regular(generation / "artifact", self.uid, artifact["size"])
        if not hmac.compare_digest(digest, artifact["sha256"]):
            raise HarnessLifecycleError("artifact_digest_mismatch")
        return sha256_bytes(manifest_raw)

    def verify(self, generation_id: str) -> dict[str, Any]:
        with self.locked():
            policy, envelope, envelope_digest = self._verified()
            self._require_receipt_capacity()
            manifest = self._find(envelope, generation_id)
            manifest_digest = self._verify_files(
                policy, manifest, self.quarantine / generation_id,
            )
            evidence = manifest["evidence"]
            return self._receipt(
                "verify", "artifact_and_evidence_bindings_verified",
                artifact_sha256=manifest["artifact"]["sha256"],
                envelope_sha256=envelope_digest, evidence_sha256=[item["sha256"] for item in evidence],
                generation_id=generation_id, manifest_sha256=manifest_digest,
                note="not_admitted_not_executable",
                policy_sha256=sha256_bytes(canonical_bytes(policy)),
            )

    def status(self) -> dict[str, Any]:
        with self.locked():
            try:
                policy = self.policy()
            except HarnessLifecycleError as error:
                if str(error) != "state_file_missing":
                    raise
                policy_configured = False
                policy_digest = None
            else:
                policy_configured = True
                policy_digest = sha256_bytes(canonical_bytes(policy))
            floor = self._floor()
            generations: list[dict[str, Any]] = []
            entries = list(self.quarantine.iterdir())
            if len(entries) > MAX_RELEASES * 2:
                raise HarnessLifecycleError("quarantine_entry_limit_exceeded")
            for entry in sorted(entries, key=lambda path: path.name):
                if SHA256_RE.fullmatch(entry.name) is None:
                    raise HarnessLifecycleError("quarantine_entry_untrusted")
                _trusted_directory(entry, self.uid)
                names = {child.name for child in entry.iterdir()}
                if not names <= {"artifact", "manifest.json"}:
                    raise HarnessLifecycleError("quarantine_entry_untrusted")
                for child in entry.iterdir():
                    info = child.lstat()
                    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                            or info.st_uid != self.uid or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600):
                        raise HarnessLifecycleError("quarantine_entry_untrusted")
                generations.append({
                    "artifact_present": (entry / "artifact").is_file(),
                    "generation_id": entry.name,
                    "manifest_present": (entry / "manifest.json").is_file(),
                    "state": "quarantined",
                })
            return {
                "authority": "none", "automatic_download": False,
                "automatic_install": False, "floor": floor, "generations": generations,
                "policy_configured": policy_configured, "policy_sha256": policy_digest,
                "schema": STATUS_SCHEMA,
            }
