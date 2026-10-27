#!/usr/bin/env python3
"""Read-only identity and recovery helpers for the Secure Enclave DDD."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path


SHA256_RE = re.compile(r"[0-9a-f]{64}")
UUID4_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
LOCAL_CONFIG_SCHEMA = "secure-sandbox-secure-enclave-ddd-local-config-v1"


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_user_directory(path: Path, uid: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("checkpoint_directory_untrusted")


def local_config(path: Path, uid: int) -> dict[str, str]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("local_config_untrusted") from error
    required = {
        "schema", "acceptance_source_id",
        "legacy_launchservices_ui_bundle_sha256",
    }
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not isinstance(value, dict) or set(value) != required
            or value.get("schema") != LOCAL_CONFIG_SCHEMA
            or not isinstance(value.get("acceptance_source_id"), str)
            or UUID4_RE.fullmatch(value["acceptance_source_id"]) is None
            or not isinstance(value.get("legacy_launchservices_ui_bundle_sha256"), str)
            or SHA256_RE.fullmatch(
                value["legacy_launchservices_ui_bundle_sha256"]
            ) is None):
        raise RuntimeError("local_config_untrusted")
    return value


def bridge_checkpoint(path: Path, uid: int) -> tuple[bytes, dict[str, object]]:
    trusted_user_directory(path, uid)
    state = path / "state.json"
    info = state.lstat()
    raw = state.read_bytes()
    value = json.loads(raw)
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not isinstance(value, dict)
            or value.get("schema")
            != "secure-sandbox-secure-enclave-ddd-checkpoint-v1"
            or value.get("stage") != "bridge_committed"):
        raise RuntimeError("bridge_checkpoint_untrusted")
    return raw, value


def archive_bridge_checkpoint(state_dir: Path, archive: Path, uid: int,
                              fault_after: str | None = None) -> dict[str, object]:
    """Durably move a bridge checkpoint and preserve any resurrected duplicate."""
    source_parent = state_dir.parent
    destination_parent = archive.parent
    trusted_user_directory(source_parent, uid)
    trusted_user_directory(destination_parent, uid)
    source_raw, source = bridge_checkpoint(state_dir, uid)
    prepared = source.get("prepared")
    transaction_id = prepared.get("transaction_id") if isinstance(prepared, dict) else None
    if not isinstance(transaction_id, str) or archive.name != f"{transaction_id}.bridge":
        raise RuntimeError("bridge_checkpoint_identity_mismatch")
    recovered_duplicate: Path | None = None
    if archive.exists() or archive.is_symlink():
        if archive.is_symlink():
            raise RuntimeError("bridge_archive_untrusted")
        archive_raw, archived = bridge_checkpoint(archive, uid)
        if archive_raw != source_raw or archived != source:
            raise RuntimeError("bridge_archive_conflict")
        recovered_duplicate = destination_parent / (
            f"{transaction_id}.bridge-recovered-{uuid.uuid4()}"
        )
        os.replace(state_dir, recovered_duplicate)
    else:
        os.replace(state_dir, archive)
    if fault_after == "rename":
        raise RuntimeError("injected_after_rename")
    fsync_directory(destination_parent)
    if fault_after == "destination_fsync":
        raise RuntimeError("injected_after_destination_fsync")
    if source_parent != destination_parent:
        fsync_directory(source_parent)
    if fault_after == "source_fsync":
        raise RuntimeError("injected_after_source_fsync")
    return {
        "schema":"secure-sandbox-secure-enclave-bridge-archive-v1",
        "status":"archived",
        "transaction_id":transaction_id,
        "archive":str(archive),
        "recovered_duplicate":(
            str(recovered_duplicate) if recovered_duplicate is not None else None
        ),
    }


def require_sha256(value: str, field: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise ValueError(f"{field}_invalid")
    return value


def preactivation_repair_required(
    checkpoint_host_release_id: str,
    source_host_release_id: str,
    live_host_release_id: str,
    checkpoint_research_release_id: str,
    source_research_release_id: str,
) -> bool:
    values = {
        "checkpoint_host_release_id": checkpoint_host_release_id,
        "source_host_release_id": source_host_release_id,
        "live_host_release_id": live_host_release_id,
        "checkpoint_research_release_id": checkpoint_research_release_id,
        "source_research_release_id": source_research_release_id,
    }
    for field, value in values.items():
        require_sha256(value, field)
    return (
        source_host_release_id != checkpoint_host_release_id
        or live_host_release_id != checkpoint_host_release_id
        or source_research_release_id != checkpoint_research_release_id
    )


def reusable_deployed_host(
    checkpoint_host_release_id: str,
    source_host_release_id: str,
    live_host_release_id: str,
    previous_host_release_id: str,
) -> bool:
    require_sha256(checkpoint_host_release_id, "checkpoint_host_release_id")
    require_sha256(source_host_release_id, "source_host_release_id")
    require_sha256(live_host_release_id, "live_host_release_id")
    require_sha256(previous_host_release_id, "previous_host_release_id")
    return (
        live_host_release_id == source_host_release_id
        and (
            live_host_release_id == checkpoint_host_release_id
            or previous_host_release_id == checkpoint_host_release_id
        )
    )


def selector_restore_required(
    checkpoint_host_release_id: str,
    source_host_release_id: str,
    live_host_release_id: str,
    previous_host_release_id: str,
) -> bool:
    return (
        live_host_release_id != checkpoint_host_release_id
        and not reusable_deployed_host(
            checkpoint_host_release_id,
            source_host_release_id,
            live_host_release_id,
            previous_host_release_id,
        )
    )


def host_release_manager(repo: Path):
    manager_path = repo.resolve() / "scripts/host-controller-release.py"
    spec = importlib.util.spec_from_file_location(
        "secure_sandbox_host_controller_release", manager_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("host_release_manager_unavailable")
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)
    return manager


def source_host_release_id(repo: Path) -> str:
    manager = host_release_manager(repo)
    _values, _hashes, release_id = manager.source_payload(repo.resolve())
    return require_sha256(release_id, "source_host_release_id")


def protected_selector_identities(repo: Path, install_root: Path) -> dict[str, str]:
    manager = host_release_manager(repo)
    # Once protocol v2 is active, the monotonic floor is intentionally
    # root-readable only.  This helper runs as the operator while deciding
    # whether a prepared rotation needs a bounded pre-activation repair, so
    # verify both immutable selector targets without that redundant read and
    # replace it with explicit v2-capability checks plus a live protected
    # broker identity query.  A legacy/software-key rollback target therefore
    # remains unusable even though allow_legacy permits its manifest schema.
    manager.enforce_execution_approval_floor = lambda _broker, _uid=0: None
    current, _ = manager.verified_release(
        install_root, install_root / "current", 0
    )
    previous, _ = manager.verified_release(
        install_root, install_root / "previous", 0, allow_legacy=True
    )
    for label, path in (("current", current), ("previous", previous)):
        broker = manager.read_regular(path / "authorization_broker")
        if manager.EXECUTION_APPROVAL_V2_CAPABILITY not in broker:
            raise RuntimeError(f"{label}_selector_below_execution_approval_floor")
    completed = subprocess.run(
        [str(current / "authorization_broker"),
         "execution-approval-public-key"],
        check=True, capture_output=True, text=True,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=10,
    )
    identity = json.loads(completed.stdout)
    if (not isinstance(identity, dict)
            or identity.get("schema")
            != "secure-sandbox-execution-approval-key-v2"
            or identity.get("status") != "active"
            or identity.get("algorithm")
            != "ecdsa-p256-sha256-x962-low-s"
            or not SHA256_RE.fullmatch(identity.get("public_key_sha256", ""))
            or not isinstance(identity.get("generation_epoch"), int)
            or isinstance(identity.get("generation_epoch"), bool)
            or identity["generation_epoch"] < 1):
        raise RuntimeError("active_execution_approval_identity_invalid")
    return {
        "current":require_sha256(current.name, "live_host_release_id"),
        "previous":require_sha256(previous.name, "previous_host_release_id"),
    }


def verify_postactivation_host_release(
    repo: Path, install_root: Path, launcher: Path
) -> dict[str, object]:
    manager = host_release_manager(repo)
    # The v2 floor is deliberately root-only after activation.  Reuse the
    # complete immutable-release verifier while substituting only that one
    # redundant read; the protected broker query below independently proves
    # that the installed current broker is operating under the active v2 key.
    manager.enforce_execution_approval_floor = lambda _broker, _uid=0: None
    result = manager.verify(repo.resolve(), install_root, launcher, 0)
    completed = subprocess.run(
        [str(install_root / "current/authorization_broker"),
         "execution-approval-public-key"],
        check=True, capture_output=True, text=True,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=10,
    )
    identity = json.loads(completed.stdout)
    if (not isinstance(identity, dict)
            or identity.get("schema") != "secure-sandbox-execution-approval-key-v2"
            or identity.get("status") != "active"
            or identity.get("algorithm") != "ecdsa-p256-sha256-x962-low-s"
            or not SHA256_RE.fullmatch(identity.get("public_key_sha256", ""))
            or not isinstance(identity.get("generation_epoch"), int)
            or isinstance(identity.get("generation_epoch"), bool)
            or identity["generation_epoch"] < 1):
        raise RuntimeError("active_execution_approval_identity_invalid")
    return result


def verify_checkpoint_host_release(
    repo: Path, install_root: Path, launcher: Path, expected_release_id: str,
    expected_generation_id: str, expected_generation_epoch: int,
    expected_public_key_sha256: str, expected_ui_bundle_sha256: str,
) -> dict[str, object]:
    """Verify an immutable live predecessor while reviewed source has advanced."""
    require_sha256(expected_release_id, "expected_release_id")
    require_sha256(expected_public_key_sha256, "expected_public_key_sha256")
    require_sha256(expected_ui_bundle_sha256, "expected_ui_bundle_sha256")
    if (not isinstance(expected_generation_epoch, int)
            or isinstance(expected_generation_epoch, bool)
            or expected_generation_epoch < 1):
        raise ValueError("expected_generation_epoch_invalid")
    manager = host_release_manager(repo)
    # The monotonic v2 floor is deliberately root-only after activation.  The
    # immutable release verifier would otherwise fail here solely because this
    # restart-safe resume runs as the operator.  Skip only that redundant read;
    # the protected broker query below independently requires the exact active
    # v2 generation, epoch, key, algorithm, and Host release from the checkpoint.
    manager.enforce_execution_approval_floor = lambda _broker, _uid=0: None
    path, manifest = manager.verified_release(
        install_root, install_root / "current", 0
    )
    if path.name != expected_release_id:
        raise RuntimeError("checkpoint_host_release_mismatch")
    if manifest.get("payloads", {}).get(
        "authorization_ui_bundle"
    ) != expected_ui_bundle_sha256:
        raise RuntimeError("checkpoint_ui_bundle_mismatch")
    installed_launcher = manager.read_regular(launcher)
    source_launcher = manager.read_regular(repo / manager.LAUNCHER_SOURCE)
    info = launcher.stat()
    if (manager.sha256_bytes(installed_launcher) != manager.sha256_bytes(source_launcher)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o755
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("checkpoint_launcher_mismatch")
    completed = subprocess.run(
        [str(path / "authorization_broker"), "execution-approval-public-key"],
        check=True, capture_output=True, text=True,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=10,
    )
    identity = json.loads(completed.stdout)
    if (not isinstance(identity, dict)
            or identity.get("schema") != "secure-sandbox-execution-approval-key-v2"
            or identity.get("status") != "active"
            or identity.get("generation_id") != expected_generation_id
            or identity.get("generation_epoch") != expected_generation_epoch
            or identity.get("public_key_sha256") != expected_public_key_sha256
            or identity.get("algorithm") != "ecdsa-p256-sha256-x962-low-s"):
        raise RuntimeError("checkpoint_execution_approval_identity_mismatch")
    return {
        "schema":"secure-sandbox-checkpoint-host-release-verification-v1",
        "status":"verified",
        "release_id":expected_release_id,
        "generation_id":expected_generation_id,
        "generation_epoch":expected_generation_epoch,
        "public_key_sha256":expected_public_key_sha256,
        "authorization_ui_bundle_sha256":expected_ui_bundle_sha256,
        "launcher_sha256":manager.sha256_bytes(installed_launcher),
    }


def verify_installed_host_release(
    repo: Path, install_root: Path, launcher: Path, expected_release_id: str,
    expected_generation_id: str, expected_generation_epoch: int,
    expected_public_key_sha256: str,
) -> dict[str, object]:
    """Verify an exact immutable installed release after reviewed source advances."""
    require_sha256(expected_release_id, "expected_release_id")
    require_sha256(expected_public_key_sha256, "expected_public_key_sha256")
    if (not isinstance(expected_generation_epoch, int)
            or isinstance(expected_generation_epoch, bool)
            or expected_generation_epoch < 1):
        raise ValueError("expected_generation_epoch_invalid")
    manager = host_release_manager(repo)
    manager.enforce_execution_approval_floor = lambda _broker, _uid=0: None
    path, manifest = manager.verified_release(
        install_root, install_root / "current", 0
    )
    if path.name != expected_release_id:
        raise RuntimeError("installed_host_release_mismatch")
    installed_launcher = manager.read_regular(launcher)
    source_launcher = manager.read_regular(repo / manager.LAUNCHER_SOURCE)
    info = launcher.stat()
    if (manager.sha256_bytes(installed_launcher) != manager.sha256_bytes(source_launcher)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o755
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("installed_launcher_mismatch")
    completed = subprocess.run(
        [str(path / "authorization_broker"), "execution-approval-public-key"],
        check=True, capture_output=True, text=True,
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}, timeout=10,
    )
    identity = json.loads(completed.stdout)
    if (not isinstance(identity, dict)
            or identity.get("schema") != "secure-sandbox-execution-approval-key-v2"
            or identity.get("status") != "active"
            or identity.get("generation_id") != expected_generation_id
            or identity.get("generation_epoch") != expected_generation_epoch
            or identity.get("public_key_sha256") != expected_public_key_sha256
            or identity.get("algorithm") != "ecdsa-p256-sha256-x962-low-s"):
        raise RuntimeError("installed_execution_approval_identity_mismatch")
    return {
        "schema":"secure-sandbox-installed-host-release-verification-v1",
        "status":"verified", "release_id":expected_release_id,
        "launcher_sha256":manager.sha256_bytes(installed_launcher),
        "payloads":manifest["payloads"],
        "generation_id":expected_generation_id,
        "generation_epoch":expected_generation_epoch,
        "public_key_sha256":expected_public_key_sha256,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    source = subparsers.add_parser("source-host-release-id")
    source.add_argument("--repo", type=Path, required=True)
    selectors = subparsers.add_parser("protected-selector-identities")
    selectors.add_argument("--repo", type=Path, required=True)
    selectors.add_argument("--install-root", type=Path, required=True)
    verify_host = subparsers.add_parser("verify-postactivation-host-release")
    verify_host.add_argument("--repo", type=Path, required=True)
    verify_host.add_argument("--install-root", type=Path, required=True)
    verify_host.add_argument("--launcher", type=Path, required=True)
    checkpoint_host = subparsers.add_parser("verify-checkpoint-host-release")
    checkpoint_host.add_argument("--repo", type=Path, required=True)
    checkpoint_host.add_argument("--install-root", type=Path, required=True)
    checkpoint_host.add_argument("--launcher", type=Path, required=True)
    checkpoint_host.add_argument("--expected-release-id", required=True)
    checkpoint_host.add_argument("--expected-generation-id", required=True)
    checkpoint_host.add_argument("--expected-generation-epoch", type=int, required=True)
    checkpoint_host.add_argument("--expected-public-key-sha256", required=True)
    checkpoint_host.add_argument("--expected-ui-bundle-sha256", required=True)
    installed_host = subparsers.add_parser("verify-installed-host-release")
    installed_host.add_argument("--repo", type=Path, required=True)
    installed_host.add_argument("--install-root", type=Path, required=True)
    installed_host.add_argument("--launcher", type=Path, required=True)
    installed_host.add_argument("--expected-release-id", required=True)
    installed_host.add_argument("--expected-generation-id", required=True)
    installed_host.add_argument("--expected-generation-epoch", type=int, required=True)
    installed_host.add_argument("--expected-public-key-sha256", required=True)
    archive = subparsers.add_parser("archive-bridge-checkpoint")
    archive.add_argument("--state-dir", type=Path, required=True)
    archive.add_argument("--archive", type=Path, required=True)
    repair = subparsers.add_parser("repair-required")
    repair.add_argument("--checkpoint-host", required=True)
    repair.add_argument("--source-host", required=True)
    repair.add_argument("--live-host", required=True)
    repair.add_argument("--checkpoint-research", required=True)
    repair.add_argument("--source-research", required=True)
    restore = subparsers.add_parser("selector-restore-required")
    restore.add_argument("--checkpoint-host", required=True)
    restore.add_argument("--source-host", required=True)
    restore.add_argument("--live-host", required=True)
    restore.add_argument("--previous-host", required=True)
    reuse = subparsers.add_parser("reusable-deployed-host")
    reuse.add_argument("--checkpoint-host", required=True)
    reuse.add_argument("--source-host", required=True)
    reuse.add_argument("--live-host", required=True)
    reuse.add_argument("--previous-host", required=True)
    config = subparsers.add_parser("local-config-field")
    config.add_argument("--path", type=Path, required=True)
    config.add_argument(
        "--field", required=True,
        choices=("acceptance_source_id", "legacy_launchservices_ui_bundle_sha256"),
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "source-host-release-id":
        print(source_host_release_id(args.repo))
        return 0
    if args.command == "protected-selector-identities":
        print(json.dumps(
            protected_selector_identities(args.repo, args.install_root),
            separators=(",", ":"), sort_keys=True,
        ))
        return 0
    if args.command == "verify-postactivation-host-release":
        print(json.dumps(
            verify_postactivation_host_release(
                args.repo, args.install_root, args.launcher
            ), separators=(",", ":"), sort_keys=True,
        ))
        return 0
    if args.command == "verify-checkpoint-host-release":
        print(json.dumps(
            verify_checkpoint_host_release(
                args.repo, args.install_root, args.launcher,
                args.expected_release_id, args.expected_generation_id,
                args.expected_generation_epoch, args.expected_public_key_sha256,
                args.expected_ui_bundle_sha256,
            ), separators=(",", ":"), sort_keys=True,
        ))
        return 0
    if args.command == "verify-installed-host-release":
        print(json.dumps(
            verify_installed_host_release(
                args.repo, args.install_root, args.launcher,
                args.expected_release_id, args.expected_generation_id,
                args.expected_generation_epoch, args.expected_public_key_sha256,
            ), separators=(",", ":"), sort_keys=True,
        ))
        return 0
    if args.command == "archive-bridge-checkpoint":
        print(json.dumps(
            archive_bridge_checkpoint(args.state_dir, args.archive, os.geteuid()),
            separators=(",", ":"), sort_keys=True,
        ))
        return 0
    if args.command == "local-config-field":
        print(local_config(args.path, os.geteuid())[args.field])
        return 0
    if args.command == "selector-restore-required":
        print("true" if selector_restore_required(
            args.checkpoint_host,
            args.source_host,
            args.live_host,
            args.previous_host,
        ) else "false")
        return 0
    if args.command == "reusable-deployed-host":
        print("true" if reusable_deployed_host(
            args.checkpoint_host,
            args.source_host,
            args.live_host,
            args.previous_host,
        ) else "false")
        return 0
    print("true" if preactivation_repair_required(
        args.checkpoint_host,
        args.source_host,
        args.live_host,
        args.checkpoint_research,
        args.source_research,
    ) else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
