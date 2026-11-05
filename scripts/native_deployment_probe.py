#!/usr/bin/env python3
"""Read-only, content-bound deployment observation for one native guest plane."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Callable, Sequence


MAX_OUTPUT = 1024 * 1024
ROLE_LOCKS = {
    "gateway": (
        Path("/var/lib/secure-sandbox/native-egress-control/install.lock"),
        Path("/var/lib/secure-sandbox/native-egress-control/.lock"),
    ),
    "research": (
        Path("/var/lib/secure-sandbox/native-vendor/install/install.lock"),
        Path("/var/lib/secure-sandbox/native-vendor/controller/lifecycle/promotion.lock"),
        Path("/var/lib/secure-sandbox/native-egress-control/.lock"),
    ),
}
STATE_BASE = Path("/var/lib/secure-sandbox")
ROLE_DIRECTORY_LAYOUT = {
    "gateway": (
        (Path("native-egress-control"), 0o700),
    ),
    "research": (
        (Path("native-vendor"), 0o700),
        (Path("native-vendor/install"), 0o700),
        (Path("native-vendor/controller"), 0o700),
        (Path("native-vendor/controller/lifecycle"), 0o700),
        (Path("native-egress-control"), 0o700),
    ),
}
ROLE_LOCK_LAYOUT = {
    "gateway": (
        Path("native-egress-control/install.lock"),
        Path("native-egress-control/.lock"),
    ),
    "research": (
        Path("native-vendor/install/install.lock"),
        Path("native-vendor/controller/lifecycle/promotion.lock"),
        Path("native-egress-control/.lock"),
    ),
}


class NativeDeploymentProbeError(RuntimeError):
    """Stable fail-closed deployment probe error."""


def _load(path: Path, name: str, *, trusted_uid: int = 0) -> ModuleType:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_module_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= 16 * 1024 * 1024:
            block = os.read(
                descriptor, min(
                    1024 * 1024, 16 * 1024 * 1024 + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_uid != trusted_uid
        or opened.st_nlink != 1
        or opened.st_mode & 0o022
        or not 1 <= opened.st_size <= 16 * 1024 * 1024
        or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
    ):
        raise NativeDeploymentProbeError(
            "native_deployment_probe_module_untrusted")
    try:
        code = compile(bytes(raw), str(path), "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_module_unavailable") from error
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    exec(code, module.__dict__)
    return module


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_command_failed") from error
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_command_failed")
    return result


def _service(name: str, *, runner: Callable[[Sequence[str]],
                                            subprocess.CompletedProcess[bytes]]) -> dict[str, str]:
    shown = runner([
        "/usr/bin/systemctl", "show", name, "--property=LoadState",
        "--property=ActiveState", "--property=SubState", "--property=MainPID",
        "--property=UnitFileState",
    ])
    values: dict[str, str] = {}
    for line in shown.stdout.decode("ascii", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_service_invalid")
        values[key] = value
    if values != {
        "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "MainPID": "0", "UnitFileState": "disabled",
    }:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_service_not_closed")
    return values


def _process_identity(pid: int) -> tuple[list[bytes], Path]:
    arguments = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
    if arguments[-1:] == [b""]:
        arguments.pop()
    executable = (Path("/proc") / str(pid) / "exe").resolve(strict=True)
    return arguments, executable


def _watchdog(
    *, runner: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]],
    process_reader: Callable[[int], tuple[list[bytes], Path]],
) -> dict[str, object]:
    shown = runner([
        "/usr/bin/systemctl", "show",
        "secure-sandbox-native-egress-watchdog.service",
        "--property=LoadState", "--property=ActiveState",
        "--property=SubState", "--property=MainPID",
        "--property=ExecMainStartTimestampMonotonic",
        "--property=FragmentPath",
    ])
    values: dict[str, str] = {}
    for line in shown.stdout.decode("ascii", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_watchdog_invalid")
        values[key] = value
    expected_keys = {
        "LoadState", "ActiveState", "SubState", "MainPID",
        "ExecMainStartTimestampMonotonic", "FragmentPath",
    }
    try:
        pid = int(values.get("MainPID", ""))
        generation = int(values.get("ExecMainStartTimestampMonotonic", ""))
    except ValueError as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_invalid") from error
    if (set(values) != expected_keys or values["LoadState"] != "loaded"
            or values["ActiveState"] != "active"
            or values["SubState"] != "running" or pid <= 1
            or generation <= 0
            or values["FragmentPath"] != (
                "/etc/systemd/system/"
                "secure-sandbox-native-egress-watchdog.service")):
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_invalid")
    python_name = shutil.which(
        "python3", path=(
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))
    if python_name is None:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_invalid")
    try:
        arguments, executable = process_reader(pid)
        expected_python = Path(python_name).resolve(strict=True)
    except OSError as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_invalid") from error
    if (len(arguments) != 4
            or arguments[1:] != [
                b"/usr/local/libexec/secure-sandbox/native_guest_control.py",
                b"installed", b"watchdog",
            ]
            or arguments[0] not in {b"python3", os.fsencode(python_name)}
            or executable != expected_python):
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_process_mismatch")
    repeated = runner([
        "/usr/bin/systemctl", "show",
        "secure-sandbox-native-egress-watchdog.service",
        "--property=MainPID",
        "--property=ExecMainStartTimestampMonotonic",
    ])
    repeated_values: dict[str, str] = {}
    for line in repeated.stdout.decode("ascii", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in repeated_values:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_watchdog_generation_changed")
        repeated_values[key] = value
    if repeated_values != {
        "MainPID": str(pid),
        "ExecMainStartTimestampMonotonic": str(generation),
    }:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_watchdog_generation_changed")
    return {"pid": pid, "generation": generation,
            "executable": str(executable)}


def _open_exact_directory(path: Path, *, uid: int, gid: int,
                          mode: int) -> int:
    before = path.lstat()
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = os.fstat(descriptor)
    if (not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(before.st_mode)
            or opened.st_uid != uid or opened.st_gid != gid
            or stat.S_IMODE(opened.st_mode) != mode
            or (before.st_dev, before.st_ino)
               != (opened.st_dev, opened.st_ino)):
        os.close(descriptor)
        raise NativeDeploymentProbeError(
            "native_deployment_probe_barrier_directory_untrusted")
    return descriptor


def _ensure_exact_directory(path: Path, *, uid: int, gid: int,
                            mode: int) -> None:
    parent = _open_exact_directory(
        path.parent, uid=uid, gid=gid,
        mode=0o755 if path.parent.name in {"lib", "secure-sandbox"}
        else 0o700)
    try:
        created = False
        try:
            os.mkdir(path.name, mode, dir_fd=parent)
        except FileExistsError:
            pass
        else:
            created = True
        child = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            if created:
                os.fchown(child, uid, gid)
                os.fchmod(child, mode)
                os.fsync(child)
                os.fsync(parent)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                    or info.st_gid != gid
                    or stat.S_IMODE(info.st_mode) != mode):
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_barrier_directory_untrusted")
        finally:
            os.close(child)
    finally:
        os.close(parent)


def _bootstrap_role_barriers(
    role: str, *, base: Path = STATE_BASE,
) -> tuple[Path, ...]:
    if role not in ROLE_DIRECTORY_LAYOUT:
        raise NativeDeploymentProbeError("native_deployment_probe_role_invalid")
    uid, gid = os.geteuid(), os.getegid()
    # The guest entry point requires uid/gid zero.  Tests may exercise the
    # same descriptor logic under their own identity in a private tree.
    _ensure_exact_directory(base, uid=uid, gid=gid, mode=0o755)
    for relative, mode in ROLE_DIRECTORY_LAYOUT[role]:
        _ensure_exact_directory(base / relative, uid=uid, gid=gid, mode=mode)
    result: list[Path] = []
    for relative in ROLE_LOCK_LAYOUT[role]:
        path = base / relative
        parent = _open_exact_directory(
            path.parent, uid=uid, gid=gid, mode=0o700)
        try:
            created = False
            try:
                descriptor = os.open(
                    path.name,
                    os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            except FileNotFoundError:
                descriptor = os.open(
                    path.name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL
                    | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent,
                )
                created = True
            try:
                if created:
                    os.fchown(descriptor, uid, gid)
                    os.fchmod(descriptor, 0o600)
                    os.fsync(descriptor)
                    os.fsync(parent)
                info = os.fstat(descriptor)
                current = os.stat(
                    path.name, dir_fd=parent, follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                        or info.st_gid != gid or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or stat.S_ISLNK(current.st_mode)
                        or (info.st_dev, info.st_ino)
                           != (current.st_dev, current.st_ino)):
                    raise NativeDeploymentProbeError(
                        "native_deployment_probe_barrier_untrusted")
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
        result.append(path)
    return tuple(result)


@contextlib.contextmanager
def _barriers(paths: Sequence[Path]):
    descriptors: list[int] = []
    try:
        for path in paths:
            before = path.lstat()
            descriptor = os.open(
                path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_gid != os.getegid()
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or (before.st_dev, before.st_ino)
                       != (opened.st_dev, opened.st_ino)):
                os.close(descriptor)
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_barrier_untrusted")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            current = path.lstat()
            if (stat.S_ISLNK(current.st_mode)
                    or (current.st_dev, current.st_ino)
                       != (opened.st_dev, opened.st_ino)):
                os.close(descriptor)
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_barrier_identity_changed")
            descriptors.append(descriptor)
        yield tuple(descriptors)
    except OSError as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_barrier_unavailable") from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def observe(
    role: str, release_module: ModuleType, deployment_module: ModuleType,
    *, runner: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]] = _run,
    now: int | None = None, lock_paths: Sequence[Path] | None = None,
    process_reader: Callable[[int], tuple[list[bytes], Path]] = _process_identity,
    catalog_module: ModuleType | None = None,
    expected_catalog_sha256: str | None = None,
) -> dict:
    if role not in ROLE_LOCKS:
        raise NativeDeploymentProbeError("native_deployment_probe_role_invalid")
    paths = (
        _bootstrap_role_barriers(role)
        if lock_paths is None else tuple(lock_paths)
    )
    with _barriers(paths):
        lifecycle_fd = None
        lifecycle_root = None
        try:
            if role == "research" and getattr(
                release_module, "CATALOG_TRANSITION_AWARE", False
            ):
                lifecycle_root = paths[1].parent
                lifecycle_fd = os.open(
                    lifecycle_root,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    | os.O_CLOEXEC)
                opened = os.fstat(lifecycle_fd)
                current = lifecycle_root.lstat()
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_ISLNK(current.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_gid != os.getegid()
                    or stat.S_IMODE(opened.st_mode) != 0o700
                    or (opened.st_dev, opened.st_ino)
                    != (current.st_dev, current.st_ino)
                ):
                    raise NativeDeploymentProbeError(
                        "native_deployment_probe_lifecycle_root_untrusted")
            return _observe_locked(
                role, release_module, deployment_module, runner=runner, now=now,
                process_reader=process_reader, catalog_module=catalog_module,
                lifecycle_fd=lifecycle_fd, lifecycle_root=lifecycle_root,
                expected_catalog_sha256=expected_catalog_sha256)
        finally:
            if lifecycle_fd is not None:
                os.close(lifecycle_fd)


def _observe_locked(
    role: str, release_module: ModuleType, deployment_module: ModuleType,
    *, runner: Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]],
    now: int | None,
    process_reader: Callable[[int], tuple[list[bytes], Path]],
    catalog_module: ModuleType | None = None,
    lifecycle_fd: int | None = None,
    lifecycle_root: Path | None = None,
    expected_catalog_sha256: str | None = None,
) -> dict:
    if role not in {"gateway", "research"}:
        raise NativeDeploymentProbeError("native_deployment_probe_role_invalid")
    pending = (
        Path("/var/lib/secure-sandbox/native-egress-control/"
             "gateway-install.pending.json")
        if role == "gateway"
        else Path("/var/lib/secure-sandbox/native-vendor/install/"
                  "native-research-install.pending.json")
    )
    if pending.exists() or pending.is_symlink():
        raise NativeDeploymentProbeError(
            "native_deployment_probe_recovery_required")
    manifest = release_module.MANIFEST
    legacy = False
    current_reader = getattr(release_module, "current_release", None)
    if callable(current_reader):
        if role == "research" and getattr(
            release_module, "CATALOG_TRANSITION_AWARE", False
        ):
            if lifecycle_fd is None or catalog_module is None:
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_catalog_authority_missing")
            generation_kind, release = current_reader(
                lifecycle_fd=lifecycle_fd, catalog_module=catalog_module,
                expected_catalog_sha256=expected_catalog_sha256,
                lifecycle_root=lifecycle_root)
        else:
            generation_kind, release = current_reader()
        if generation_kind == "absent":
            return deployment_module.make_status(
                role=role, state="absent", generation_kind="absent",
                package_sha256=None, release_id=None, catalog_sha256=None,
                closed_evidence_sha256=None,
                observed_at=int(time.time()) if now is None else now,
            )
        if generation_kind not in {"legacy", "protected"} or release is None:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_generation_invalid")
        legacy = generation_kind == "legacy"
    elif not manifest.exists() and not manifest.is_symlink():
        legacy_verifier = getattr(release_module, "verify_legacy_installed", None)
        if callable(legacy_verifier):
            try:
                release = legacy_verifier()
                legacy = True
            except Exception as error:
                if any(Path(name).exists() or Path(name).is_symlink()
                       for name in release_module.EXPECTED_ARTIFACTS):
                    raise NativeDeploymentProbeError(
                        "native_deployment_probe_partial_installation") from error
                return deployment_module.make_status(
                    role=role, state="absent", generation_kind="absent",
                    package_sha256=None, release_id=None, catalog_sha256=None,
                    closed_evidence_sha256=None,
                    observed_at=int(time.time()) if now is None else now,
                )
        else:
            if any(Path(name).exists() or Path(name).is_symlink()
                   for name in release_module.EXPECTED_ARTIFACTS):
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_partial_installation")
            return deployment_module.make_status(
                role=role, state="absent", generation_kind="absent",
                package_sha256=None, release_id=None, catalog_sha256=None,
                closed_evidence_sha256=None,
                observed_at=int(time.time()) if now is None else now,
            )
    elif not callable(current_reader):
        try:
            release = release_module.verify_installed()
        except Exception:
            legacy_verifier = getattr(
                release_module, "verify_legacy_installed", None)
            if not callable(legacy_verifier):
                raise
            release = legacy_verifier()
            legacy = True
    closed_raw = runner([
        "/usr/local/libexec/secure-sandbox/native_guest_control.py",
        "installed", "verify-closed",
    ]).stdout
    try:
        closed = json.loads(closed_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeploymentProbeError(
            "native_deployment_probe_closed_readback_invalid") from error
    if (
        closed_raw != deployment_module.canonical(closed)
        or not isinstance(closed, dict)
        or set(closed) != {
            "schema", "live_policy_sha256", "persistent_policy_sha256",
            "service", "state",
        }
        or closed.get("schema") != "secure-sandbox-native-closed-state-v1"
        or closed.get("state") != "closed"
        or closed.get("service") != "inactive"
        or any(deployment_module.SHA256.fullmatch(
            str(closed.get(name, ""))) is None for name in (
                "live_policy_sha256", "persistent_policy_sha256"))
    ):
        raise NativeDeploymentProbeError(
            "native_deployment_probe_closed_readback_invalid")
    watchdog = _watchdog(runner=runner, process_reader=process_reader)
    service_name = (
        "native-opaque-tunnel.service" if role == "gateway"
        else "native-harness-supervisor.service"
    )
    service = _service(service_name, runner=runner)
    catalog_sha256 = None
    if role == "research":
        if catalog_module is None:
            catalog = [
                item["sha256"] for item in release["artifacts"]
                if item["path"]
                == "/etc/secure-sandbox/native-vendor-stacks.json"
            ]
            if len(catalog) != 1:
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_catalog_identity_missing")
            catalog_sha256 = catalog[0]
        else:
            catalog_path = getattr(
                release_module, "CATALOG",
                Path("/etc/secure-sandbox/native-vendor-stacks.json"))
            try:
                catalog_value = catalog_module.load_catalog(
                    catalog_path, private=False)
                catalog_raw = catalog_module.canonical_bytes(catalog_value)
            except Exception as error:
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_catalog_identity_missing") from error
            catalog_sha256 = hashlib.sha256(catalog_raw).hexdigest()
        if (expected_catalog_sha256 is not None
                and catalog_sha256 != expected_catalog_sha256):
            raise NativeDeploymentProbeError(
                "native_deployment_probe_catalog_plan_mismatch")
    closed_evidence = deployment_module.digest({
        "closed": closed, "watchdog": watchdog, "service": service,
    })
    return deployment_module.make_status(
        role=role, state="verified",
        generation_kind="legacy" if legacy else "protected",
        package_sha256=release["package_sha256"],
        release_id=release["release_id"],
        catalog_sha256=catalog_sha256,
        closed_evidence_sha256=closed_evidence,
        observed_at=int(time.time()) if now is None else now,
    )


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) not in {4, 5}:
        return 64
    role, release_path, deployment_path, catalog_path = values[:4]
    if (role == "research") != (len(values) == 5):
        return 64
    try:
        if os.geteuid() != 0 or os.getegid() != 0:
            raise NativeDeploymentProbeError(
                "native_deployment_probe_root_required")
        release_module = _load(Path(release_path), "_native_deployment_release")
        deployment_module = _load(
            Path(deployment_path), "_native_deployment_contract")
        catalog_module = _load(
            Path(catalog_path), "_native_deployment_catalog")
        expected_catalog_sha256 = None
        if role == "research":
            expected_catalog_path = Path(values[4])
            try:
                expected_catalog = catalog_module.load_catalog(
                    expected_catalog_path, private=True)
                expected_catalog_raw = catalog_module.canonical_bytes(
                    expected_catalog)
            except Exception as error:
                raise NativeDeploymentProbeError(
                    "native_deployment_probe_catalog_authority_invalid") from error
            expected_catalog_sha256 = hashlib.sha256(
                expected_catalog_raw).hexdigest()
        result = observe(
            role, release_module, deployment_module,
            catalog_module=catalog_module,
            expected_catalog_sha256=expected_catalog_sha256)
        sys.stdout.buffer.write(deployment_module.canonical(result))
        return 0
    except Exception as error:
        code = str(error)
        if not code.startswith("native_deployment_"):
            code = "native_deployment_probe_rejected"
        print(code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
