#!/usr/bin/env python3
"""Name-bound release identity for the complete Research native runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "secure-sandbox-native-research-release-v3"
PRIOR_SCHEMA = "secure-sandbox-native-research-release-v2"
LEGACY_SCHEMA = "secure-sandbox-native-research-release-v1"
LEGACY_ADMISSION_SCHEMA = "secure-sandbox-native-research-legacy-admission-v1"
MANIFEST = Path("/etc/secure-sandbox/native-research-release.json")
CATALOG = Path("/etc/secure-sandbox/native-vendor-stacks.json")
LIFECYCLE_ROOT = Path(
    "/var/lib/secure-sandbox/native-vendor/controller/lifecycle")
CATALOG_PUBLICATION_SCHEMA = (
    "secure-sandbox-native-stack-research-catalog-publication-v1")
CATALOG_TRANSITION_AWARE = True
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MAX_CATALOG_BYTES = 1024 * 1024
MAX_CATALOG_TRANSITIONS = 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}")
EMPTY_CATALOG_SHA256 = hashlib.sha256(
    b'{"schema":"secure-sandbox-native-vendor-stack-catalog-v1","stacks":[]}\n'
).hexdigest()
ROOT = "/usr/local/libexec/secure-sandbox"
RESEARCH = ROOT + "/research"
SHARED = ROOT + "/shared"

# Exact names prevent a manifest from silently omitting a control or config.
PRIOR_EXPECTED_ARTIFACTS: Mapping[str, int] = {
    f"{ROOT}/privileged_control.py": 0o755,
    f"{ROOT}/native_guest_control.py": 0o755,
    f"{ROOT}/render_research_firewall.py": 0o755,
    f"{ROOT}/native_provider_controller.py": 0o755,
    f"{ROOT}/native_claude_login_channel.py": 0o755,
    f"{ROOT}/native_claude_session_controller.py": 0o755,
    f"{ROOT}/native_codex_session_controller.py": 0o755,
    f"{ROOT}/native_harness_supervisor.py": 0o755,
    f"{ROOT}/native_codex_protocol_firewall.py": 0o555,
    f"{ROOT}/native_codex_isolation_qualification.py": 0o555,
    f"{ROOT}/native-codex-isolation-probe": 0o555,
    f"{ROOT}/native-codex-launcher": 0o555,
    f"{RESEARCH}/native_claude_adapter.py": 0o444,
    f"{RESEARCH}/native_claude_login_channel.py": 0o444,
    f"{RESEARCH}/native_claude_login_replay.py": 0o444,
    f"{RESEARCH}/native_claude_session_controller.py": 0o444,
    f"{RESEARCH}/native_codex_isolation_qualification.py": 0o444,
    f"{RESEARCH}/native_codex_policy.py": 0o444,
    f"{RESEARCH}/native_codex_protocol_firewall.py": 0o444,
    f"{RESEARCH}/native_codex_run_journal.py": 0o444,
    f"{RESEARCH}/native_codex_runtime_driver.py": 0o444,
    f"{RESEARCH}/native_codex_session_controller.py": 0o444,
    f"{RESEARCH}/native_harness_supervisor.py": 0o444,
    f"{RESEARCH}/native_lifecycle_fence.py": 0o444,
    f"{RESEARCH}/native_projection_isolation.py": 0o444,
    f"{RESEARCH}/native_provider_controller.py": 0o444,
    f"{RESEARCH}/session_policy_runtime.py": 0o444,
    f"{SHARED}/__init__.py": 0o444,
    f"{SHARED}/harness_generation_store.py": 0o444,
    f"{SHARED}/harness_runtime_binding.py": 0o444,
    f"{SHARED}/model_stack_runtime_binding.py": 0o444,
    f"{SHARED}/native_codex_projection.py": 0o444,
    f"{SHARED}/native_deployment.py": 0o444,
    f"{SHARED}/native_deployment_lifecycle.py": 0o444,
    f"{SHARED}/native_egress.py": 0o444,
    f"{SHARED}/native_guest_control.py": 0o444,
    f"{SHARED}/native_research_release.py": 0o444,
    f"{SHARED}/native_stack_operations.py": 0o444,
    f"{SHARED}/native_stack_runtime_binding.py": 0o444,
    f"{SHARED}/native_stack_session.py": 0o444,
    f"{SHARED}/native_vendor_stack.py": 0o444,
    f"{SHARED}/privileged_workflow.py": 0o444,
    f"{SHARED}/runtime_authority.py": 0o444,
    f"{SHARED}/session_context_binding.py": 0o444,
    "/etc/secure-sandbox/native-codex-policy/config.toml": 0o444,
    "/etc/secure-sandbox/native-egress-installed": 0o600,
    "/etc/secure-sandbox/native-egress-role": 0o600,
    "/etc/secure-sandbox/native-vendor-stacks.json": 0o644,
    "/etc/claude-code/native-claude-session-settings.json": 0o444,
    "/etc/claude-code/secure-sandbox-persona.md": 0o444,
    "/etc/claude-code/managed-settings.json": 0o644,
    "/etc/claude-code/managed-mcp.json": 0o644,
    "/etc/systemd/system/native-harness-supervisor.service": 0o644,
    "/etc/systemd/system/secure-sandbox-native-egress-watchdog.service": 0o644,
    "/etc/systemd/system/nftables.service.d/secure-sandbox-native-watchdog.conf": 0o644,
    "/etc/tmpfiles.d/secure-sandbox-native.conf": 0o644,
}
EXPECTED_ARTIFACTS: Mapping[str, int] = {
    path: mode for path, mode in PRIOR_EXPECTED_ARTIFACTS.items()
    if path != str(CATALOG)
}
LEGACY_NEW_ONLY = {
    f"{SHARED}/native_deployment.py",
    f"{SHARED}/native_deployment_lifecycle.py",
}
LEGACY_EXPECTED_ARTIFACTS: Mapping[str, int] = {
    path: mode for path, mode in PRIOR_EXPECTED_ARTIFACTS.items()
    if path not in LEGACY_NEW_ONLY
}


class NativeResearchReleaseError(RuntimeError):
    """Stable fail-closed native release error."""


def canonical(value: object) -> bytes:
    try:
        raw = (json.dumps(value, allow_nan=False, ensure_ascii=True,
                          separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeResearchReleaseError(
            "native_research_release_value_invalid") from error
    if len(raw) > MAX_MANIFEST_BYTES:
        raise NativeResearchReleaseError(
            "native_research_release_manifest_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _artifact(path: Path, mode: int, *, trusted_uid: int,
              trusted_gid: int) -> dict[str, Any]:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeResearchReleaseError(
            "native_research_release_artifact_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        content = hashlib.sha256()
        total = 0
        while total <= MAX_ARTIFACT_BYTES:
            block = os.read(
                descriptor, min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            content.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_nlink != 1 or opened.st_uid != trusted_uid
            or opened.st_gid != trusted_gid
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_size < 1 or total != opened.st_size
            or total > MAX_ARTIFACT_BYTES
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)):
        raise NativeResearchReleaseError(
            "native_research_release_artifact_untrusted")
    return {"path": str(path), "mode": mode, "sha256": content.hexdigest()}


def observe(*, package_sha256: str, trusted_uid: int = 0,
            trusted_gid: int = 0) -> dict[str, Any]:
    if not isinstance(package_sha256, str) or SHA256.fullmatch(package_sha256) is None:
        raise NativeResearchReleaseError(
            "native_research_release_package_invalid")
    artifacts = [
        _artifact(Path(name), mode, trusted_uid=trusted_uid,
                  trusted_gid=trusted_gid)
        for name, mode in sorted(EXPECTED_ARTIFACTS.items())
    ]
    body = {"schema": SCHEMA, "package_sha256": package_sha256,
            "artifacts": artifacts}
    return {**body, "release_id": digest(body)}


def validate(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != {
                "schema", "package_sha256", "artifacts", "release_id"
            }
            or value.get("schema") != SCHEMA
            or not isinstance(value.get("artifacts"), list)
            or len(value["artifacts"]) != len(EXPECTED_ARTIFACTS)):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_invalid")
    expected_names = sorted(EXPECTED_ARTIFACTS)
    observed_names: list[str] = []
    for item in value["artifacts"]:
        if (not isinstance(item, dict)
                or set(item) != {"path", "mode", "sha256"}
                or item.get("path") not in EXPECTED_ARTIFACTS
                or item.get("mode") != EXPECTED_ARTIFACTS[item["path"]]
                or not isinstance(item.get("sha256"), str)
                or SHA256.fullmatch(item["sha256"]) is None):
            raise NativeResearchReleaseError(
                "native_research_release_manifest_invalid")
        observed_names.append(item["path"])
    body = {"schema": SCHEMA, "package_sha256": value["package_sha256"],
            "artifacts": value["artifacts"]}
    if (observed_names != expected_names
            or not isinstance(value.get("package_sha256"), str)
            or SHA256.fullmatch(value["package_sha256"]) is None
            or not isinstance(value.get("release_id"), str)
            or value["release_id"] != digest(body)):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_invalid")
    return value


def _validate_prior(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != {
                "schema", "package_sha256", "artifacts", "release_id"
            }
            or value.get("schema") != PRIOR_SCHEMA
            or not isinstance(value.get("artifacts"), list)
            or len(value["artifacts"]) != len(PRIOR_EXPECTED_ARTIFACTS)):
        raise NativeResearchReleaseError(
            "native_research_prior_release_manifest_invalid")
    names: list[str] = []
    for item in value["artifacts"]:
        if (not isinstance(item, dict)
                or set(item) != {"path", "mode", "sha256"}
                or item.get("path") not in PRIOR_EXPECTED_ARTIFACTS
                or item.get("mode") != PRIOR_EXPECTED_ARTIFACTS[item["path"]]
                or not isinstance(item.get("sha256"), str)
                or SHA256.fullmatch(item["sha256"]) is None):
            raise NativeResearchReleaseError(
                "native_research_prior_release_manifest_invalid")
        names.append(item["path"])
    body = {
        "schema": PRIOR_SCHEMA, "package_sha256": value["package_sha256"],
        "artifacts": value["artifacts"],
    }
    if (names != sorted(PRIOR_EXPECTED_ARTIFACTS)
            or not isinstance(value.get("package_sha256"), str)
            or SHA256.fullmatch(value["package_sha256"]) is None
            or value.get("release_id") != digest(body)):
        raise NativeResearchReleaseError(
            "native_research_prior_release_manifest_invalid")
    return value


def _validate_legacy(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != {"schema", "artifacts", "release_id"}
            or value.get("schema") != LEGACY_SCHEMA
            or not isinstance(value.get("artifacts"), list)
            or len(value["artifacts"]) != len(LEGACY_EXPECTED_ARTIFACTS)):
        raise NativeResearchReleaseError(
            "native_research_legacy_release_manifest_invalid")
    names: list[str] = []
    for item in value["artifacts"]:
        if (not isinstance(item, dict)
                or set(item) != {"path", "mode", "sha256"}
                or item.get("path") not in LEGACY_EXPECTED_ARTIFACTS
                or item.get("mode") != LEGACY_EXPECTED_ARTIFACTS[item["path"]]
                or not isinstance(item.get("sha256"), str)
                or SHA256.fullmatch(item["sha256"]) is None):
            raise NativeResearchReleaseError(
                "native_research_legacy_release_manifest_invalid")
        names.append(item["path"])
    body = {"schema": LEGACY_SCHEMA, "artifacts": value["artifacts"]}
    if (names != sorted(LEGACY_EXPECTED_ARTIFACTS)
            or value.get("release_id") != digest(body)):
        raise NativeResearchReleaseError(
            "native_research_legacy_release_manifest_invalid")
    return value


def _admit_legacy(
    value: Mapping[str, Any], artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    package_body = {
        "schema": LEGACY_ADMISSION_SCHEMA,
        "legacy_release_id": value["release_id"],
        "artifacts": artifacts,
    }
    package_sha256 = digest(package_body)
    release_body = {
        "schema": LEGACY_ADMISSION_SCHEMA,
        "legacy_release_id": value["release_id"],
        "package_sha256": package_sha256,
        "artifacts": artifacts,
    }
    return {**release_body, "release_id": digest(release_body)}


def _catalog_digest(
    path: Path, *, catalog_module: Any, trusted_uid: int, trusted_gid: int,
) -> str:
    artifact = _artifact(
        path, 0o644, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    try:
        value = catalog_module.load_catalog(path, private=False)
        raw = catalog_module.canonical_bytes(value)
    except Exception as error:
        raise NativeResearchReleaseError(
            "native_research_catalog_untrusted") from error
    observed = hashlib.sha256(raw).hexdigest()
    if observed != artifact["sha256"]:
        raise NativeResearchReleaseError(
            "native_research_catalog_readback_changed")
    return observed


def _catalog_terminal(
    lifecycle_fd: int, name: str, *, trusted_uid: int, trusted_gid: int,
) -> dict[str, Any]:
    match = re.fullmatch(
        r"catalog-publication\.([0-9a-f-]{36})\.released\.json", name)
    if match is None or UUID4.fullmatch(match.group(1)) is None:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_terminal_invalid")
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=lifecycle_fd)
    except OSError as error:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_terminal_unavailable") from error
    try:
        before = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_MANIFEST_BYTES:
            block = os.read(
                descriptor, min(65536, MAX_MANIFEST_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (not stat.S_ISREG(before.st_mode)
            or before.st_uid != trusted_uid or before.st_gid != trusted_gid
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
            or len(raw) != before.st_size or len(raw) > MAX_MANIFEST_BYTES
            or identity(before) != identity(after)):
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_terminal_untrusted")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_terminal_invalid") from error
    fields = {
        "schema", "promotion_id", "plan_sha256",
        "host_previous_catalog_sha256", "previous_catalog_sha256",
        "catalog_sha256", "fence_sha256", "publish_request_sha256",
        "phase", "observed_catalog_sha256", "release_request_sha256",
        "release_evidence_sha256", "journal_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_terminal_invalid")
    body = {
        key: item for key, item in value.items()
        if key not in {"schema", "journal_sha256"}
    }
    digest_fields = {
        "plan_sha256",
        "previous_catalog_sha256", "catalog_sha256", "fence_sha256",
        "publish_request_sha256", "observed_catalog_sha256",
        "release_request_sha256", "release_evidence_sha256",
        "journal_sha256",
    }
    if (
        bytes(raw) != canonical(value)
        or value["schema"] != CATALOG_PUBLICATION_SCHEMA
        or value["promotion_id"] != match.group(1)
        or value["phase"] != "released"
        or any(
            not isinstance(value[field], str)
            or SHA256.fullmatch(value[field]) is None
            for field in digest_fields
        )
        or not (
            value["host_previous_catalog_sha256"]
            == value["previous_catalog_sha256"]
            or (
                value["host_previous_catalog_sha256"] is None
                and value["previous_catalog_sha256"]
                == EMPTY_CATALOG_SHA256
            )
        )
        or value["previous_catalog_sha256"] == value["catalog_sha256"]
        or value["observed_catalog_sha256"] != value["catalog_sha256"]
        or value["journal_sha256"] != digest(body)
    ):
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_terminal_invalid")
    return value


def _require_catalog_transition_chain(
    lifecycle_fd: int, *, previous_catalog_sha256: str,
    catalog_sha256: str, lifecycle_root: Path,
    trusted_uid: int, trusted_gid: int,
) -> None:
    try:
        opened = os.fstat(lifecycle_fd)
        current = lifecycle_root.lstat()
    except OSError as error:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_lock_unavailable") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_lock_untrusted")
    inventory = sorted(os.listdir(lifecycle_fd))
    publication_entries = [
        name for name in inventory
        if name.startswith("catalog-publication.")
        or name.startswith(".catalog-publication")
    ]
    names = sorted(
        name for name in publication_entries
        if re.fullmatch(
            r"catalog-publication\.[0-9a-f-]{36}\.released\.json", name))
    if len(names) != len(publication_entries):
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_active")
    if previous_catalog_sha256 == catalog_sha256:
        if names:
            # Historical terminals are acceptable only when none continue the
            # exact baseline generation being admitted below.
            for name in names:
                terminal = _catalog_terminal(
                    lifecycle_fd, name, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid)
                if terminal["previous_catalog_sha256"] == catalog_sha256:
                    raise NativeResearchReleaseError(
                        "native_research_catalog_transition_history_invalid")
        return
    if not 1 <= len(names) <= MAX_CATALOG_TRANSITIONS:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_history_invalid")
    outgoing: dict[str, list[dict[str, Any]]] = {}
    for name in names:
        terminal = _catalog_terminal(
            lifecycle_fd, name, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid)
        outgoing.setdefault(terminal["previous_catalog_sha256"], []).append(
            terminal)
    observed: set[str] = set()
    current_sha256 = previous_catalog_sha256
    for _index in range(MAX_CATALOG_TRANSITIONS + 1):
        if current_sha256 in observed:
            break
        observed.add(current_sha256)
        candidates = outgoing.get(current_sha256, [])
        if not candidates:
            if current_sha256 == catalog_sha256:
                return
            break
        if len(candidates) != 1:
            break
        current_sha256 = candidates[0]["catalog_sha256"]
    raise NativeResearchReleaseError(
        "native_research_catalog_transition_history_invalid")


def verify_transition_predecessor(
    *, lifecycle_fd: int, catalog_module: Any,
    expected_catalog_sha256: str,
    manifest: Path = MANIFEST, catalog_path: Path = CATALOG,
    lifecycle_root: Path = LIFECYCLE_ROOT,
    trusted_uid: int = 0, trusted_gid: int = 0,
) -> dict[str, Any]:
    if (not isinstance(expected_catalog_sha256, str)
            or SHA256.fullmatch(expected_catalog_sha256) is None):
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_plan_mismatch")
    value = _trusted_manifest_value(
        manifest, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if value.get("schema") == PRIOR_SCHEMA:
        value = _validate_prior(value)
        inventory = EXPECTED_ARTIFACTS
        generation = "protected"
    elif value.get("schema") == LEGACY_SCHEMA:
        if any(Path(name).exists() or Path(name).is_symlink()
               for name in LEGACY_NEW_ONLY):
            raise NativeResearchReleaseError(
                "native_research_legacy_release_mixed_generation")
        value = _validate_legacy(value)
        inventory = {
            path: mode for path, mode in LEGACY_EXPECTED_ARTIFACTS.items()
            if path != str(CATALOG)
        }
        generation = "legacy"
    else:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_generation_invalid")
    observed = [
        _artifact(Path(name), mode, trusted_uid=trusted_uid,
                  trusted_gid=trusted_gid)
        for name, mode in sorted(inventory.items())
    ]
    expected = [
        item for item in value["artifacts"] if item["path"] != str(CATALOG)]
    catalog_entries = [
        item for item in value["artifacts"] if item["path"] == str(CATALOG)]
    if observed != expected or len(catalog_entries) != 1:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_artifact_mismatch")
    current_catalog_sha256 = _catalog_digest(
        catalog_path, catalog_module=catalog_module,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if current_catalog_sha256 != expected_catalog_sha256:
        raise NativeResearchReleaseError(
            "native_research_catalog_transition_plan_mismatch")
    _require_catalog_transition_chain(
        lifecycle_fd,
        previous_catalog_sha256=catalog_entries[0]["sha256"],
        catalog_sha256=current_catalog_sha256,
        lifecycle_root=lifecycle_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid)
    if generation == "legacy":
        return _admit_legacy(value, list(value["artifacts"]))
    return value


def _trusted_manifest_value(
    manifest: Path, *, trusted_uid: int, trusted_gid: int,
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
                    min(65536, MAX_MANIFEST_BYTES + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeResearchReleaseError(
            "native_research_release_manifest_unavailable") from error
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != trusted_uid or opened.st_gid != trusted_gid
            or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o444
            or identity(before) != identity(opened)
            or identity(opened) != identity(after)
            or len(raw) != opened.st_size or len(raw) > MAX_MANIFEST_BYTES
            or bytes(raw) != canonical(value)):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_untrusted")
    if not isinstance(value, dict):
        raise NativeResearchReleaseError(
            "native_research_release_manifest_invalid")
    return value


def verify_legacy_installed(
    *, manifest: Path = MANIFEST, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    """Admit only the exact prior v1 manifest and its complete artifacts."""
    if any(Path(name).exists() or Path(name).is_symlink()
           for name in LEGACY_NEW_ONLY):
        raise NativeResearchReleaseError(
            "native_research_legacy_release_mixed_generation")
    value = _validate_legacy(_trusted_manifest_value(
        manifest, trusted_uid=trusted_uid, trusted_gid=trusted_gid))
    observed = [
        _artifact(Path(name), mode, trusted_uid=trusted_uid,
                  trusted_gid=trusted_gid)
        for name, mode in sorted(LEGACY_EXPECTED_ARTIFACTS.items())
    ]
    if observed != value["artifacts"]:
        raise NativeResearchReleaseError(
            "native_research_legacy_release_readback_mismatch")
    return _admit_legacy(value, observed)


def current_release(
    *, trusted_uid: int = 0, trusted_gid: int = 0,
    lifecycle_fd: int | None = None, catalog_module: Any | None = None,
    expected_catalog_sha256: str | None = None,
    manifest: Path = MANIFEST, catalog_path: Path = CATALOG,
    lifecycle_root: Path = LIFECYCLE_ROOT,
) -> tuple[str, dict[str, Any] | None]:
    """Return one exact protected/legacy generation or exact absence."""
    if manifest.exists() or manifest.is_symlink():
        try:
            return "protected", verify_installed(
                manifest=manifest, trusted_uid=trusted_uid,
                trusted_gid=trusted_gid)
        except NativeResearchReleaseError as protected_error:
            if lifecycle_fd is not None and catalog_module is not None:
                try:
                    admitted = verify_transition_predecessor(
                        lifecycle_fd=lifecycle_fd,
                        catalog_module=catalog_module,
                        expected_catalog_sha256=expected_catalog_sha256,
                        manifest=manifest, catalog_path=catalog_path,
                        lifecycle_root=lifecycle_root,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                except NativeResearchReleaseError:
                    pass
                else:
                    return (
                        "legacy"
                        if admitted.get("schema") == LEGACY_ADMISSION_SCHEMA
                        else "protected",
                        admitted,
                    )
            try:
                return "legacy", verify_legacy_installed(
                    manifest=manifest, trusted_uid=trusted_uid,
                    trusted_gid=trusted_gid)
            except NativeResearchReleaseError:
                raise protected_error
    if any(Path(name).exists() or Path(name).is_symlink()
           for name in PRIOR_EXPECTED_ARTIFACTS):
        raise NativeResearchReleaseError(
            "native_research_release_partial_generation")
    return "absent", None


def verify_installed(
    *, manifest: Path = MANIFEST, trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    value = _trusted_manifest_value(
        manifest, trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    if value.get("schema") == SCHEMA:
        admitted = validate(value)
        observed = observe(
            package_sha256=admitted["package_sha256"],
            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    elif value.get("schema") == PRIOR_SCHEMA:
        admitted = _validate_prior(value)
        artifacts = [
            _artifact(Path(name), mode, trusted_uid=trusted_uid,
                      trusted_gid=trusted_gid)
            for name, mode in sorted(PRIOR_EXPECTED_ARTIFACTS.items())
        ]
        body = {
            "schema": PRIOR_SCHEMA,
            "package_sha256": admitted["package_sha256"],
            "artifacts": artifacts,
        }
        observed = {**body, "release_id": digest(body)}
    else:
        raise NativeResearchReleaseError(
            "native_research_release_manifest_invalid")
    if observed != admitted:
        raise NativeResearchReleaseError(
            "native_research_release_readback_mismatch")
    return observed
