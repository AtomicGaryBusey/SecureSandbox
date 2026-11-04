#!/usr/bin/env python3
"""Ephemeral legacy bootstrap for the Research deployment lifecycle fence.

This consumer is transported by the already-authenticated privileged deploy
operation and executes from its private ``/tmp`` mount.  It never installs a
dispatcher or controller.  Its only durable mutation is the normal protected
lifecycle fence (or its immutable rollback release terminal).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterator, Sequence


INSTALL_ROOT = Path("/var/lib/secure-sandbox/native-vendor/install")
LIFECYCLE_ROOT = Path(
    "/var/lib/secure-sandbox/native-vendor/controller/lifecycle")
EGRESS_CONTROL_ROOT = Path(
    "/var/lib/secure-sandbox/native-egress-control")
INSTALL_LOCK = INSTALL_ROOT / "install.lock"
EGRESS_LOCK = EGRESS_CONTROL_ROOT / ".lock"
INSTALL_PENDING = INSTALL_ROOT / "native-research-install.pending.json"
ACTIVE_GRANT = Path("/var/lib/secure-sandbox/native-egress/active.json")
DENY_TRANSITION = EGRESS_CONTROL_ROOT / "deny-transition.json"
RETIRED_GRANT = EGRESS_CONTROL_ROOT / "retired.json"
INSTALLED_CATALOG = Path("/etc/secure-sandbox/native-vendor-stacks.json")
PAYLOAD_CATALOG = Path("/tmp/native-vendor-stacks.json")
ACQUIRE_REQUEST = Path("/tmp/native-deployment-fence-request.json")
RELEASE_REQUEST = Path("/tmp/native-deployment-release-request.json")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
SESSION_ROOTS = (
    Path("/var/lib/secure-sandbox/native-vendor/controller/native-runs"),
    Path("/var/lib/secure-sandbox/native-vendor/controller/native-claude-runs"),
    Path("/run/secure-sandbox/native-codex/preparations"),
    Path("/run/secure-sandbox/native-codex/permits"),
    Path("/run/secure-sandbox/native-codex/ui"),
    Path("/run/secure-sandbox/native-codex/session-state"),
    Path("/run/secure-sandbox/native-claude/preparations"),
    Path("/run/secure-sandbox/native-claude/session-state"),
)
IDENTITIES = ("native-harness", "native-claude", "native-codex")


class NativeDeploymentFenceBootstrapError(RuntimeError):
    """Stable fail-closed bootstrap error."""


def _read_regular(
    path: Path, *, trusted_uid: int, trusted_gid: int,
    modes: set[int], maximum: int = MAX_FILE_BYTES,
) -> bytes:
    try:
        before = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_file_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(
                descriptor, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != trusted_uid
        or opened.st_gid != trusted_gid
        or stat.S_IMODE(opened.st_mode) not in modes
        or not 1 <= opened.st_size <= maximum
        or len(raw) != opened.st_size
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
    ):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_file_untrusted")
    return bytes(raw)


def _load(
    path: Path, name: str, *, trusted_uid: int, trusted_gid: int,
) -> ModuleType:
    raw = _read_regular(
        path, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        modes={0o600})
    module = ModuleType(name)
    module.__file__ = str(path)
    prior = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except Exception as error:
        if prior is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_module_invalid") from error
    return module


def load_closed_observer(
    payload_root: Path, *, trusted_uid: int, trusted_gid: int,
) -> Callable[[str], dict[str, Any]]:
    """Load the exact candidate closed-state verifier from one payload."""
    shared_package = ModuleType("shared")
    shared_package.__path__ = []
    sys.modules["shared"] = shared_package

    def load_shared(name: str) -> ModuleType:
        module = _load(
            payload_root / f"{name}.py", f"shared.{name}",
            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
        setattr(shared_package, name, module)
        return module

    for dependency in (
        "native_vendor_stack",
        "harness_runtime_binding",
        "native_stack_runtime_binding",
        "model_stack_runtime_binding",
        "session_context_binding",
        "runtime_authority",
    ):
        load_shared(dependency)
    load_shared("native_egress")
    guest_control = _load(
        payload_root / "native_guest_control.py", "_native_guest_control",
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    observer = getattr(guest_control, "verify_closed_state", None)
    if not callable(observer):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_closed_observer_invalid")
    return observer


def _read_request(
    path: Path, deployment: ModuleType, *, trusted_uid: int,
    trusted_gid: int,
) -> dict[str, Any]:
    raw = _read_regular(
        path, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
        modes={0o600})
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_request_invalid") from error
    if not isinstance(value, dict) or raw != deployment.canonical(value):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_request_invalid")
    return value


def _catalog_digest(
    path: Path, deployment: ModuleType, *, trusted_uid: int,
    trusted_gid: int, modes: set[int],
) -> str:
    raw = _read_regular(
        path, trusted_uid=trusted_uid, trusted_gid=trusted_gid, modes=modes,
        maximum=deployment.MAX_CANONICAL_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_catalog_invalid") from error
    if not isinstance(value, dict) or raw != deployment.canonical(value):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_catalog_invalid")
    return hashlib.sha256(raw).hexdigest()


def _ensure_directory(
    path: Path, *, trusted_uid: int, trusted_gid: int,
) -> None:
    created = False
    try:
        path.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    if created:
        os.chown(path, trusted_uid, trusted_gid)
        os.chmod(path, 0o700)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != trusted_uid
        or info.st_gid != trusted_gid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_directory_untrusted")


def prepare_state_roots(
    *, trusted_uid: int = 0, trusted_gid: int = 0,
) -> None:
    anchor = Path("/var/lib/secure-sandbox")
    anchor_info = anchor.lstat()
    if (
        not stat.S_ISDIR(anchor_info.st_mode)
        or stat.S_ISLNK(anchor_info.st_mode)
        or anchor_info.st_uid != trusted_uid
        or anchor_info.st_gid != trusted_gid
        or anchor_info.st_mode & 0o022
    ):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_anchor_untrusted")
    for path in (
        anchor / "native-vendor",
        anchor / "native-vendor/controller",
        LIFECYCLE_ROOT,
        INSTALL_ROOT,
        EGRESS_CONTROL_ROOT,
    ):
        _ensure_directory(
            path, trusted_uid=trusted_uid, trusted_gid=trusted_gid)


@contextlib.contextmanager
def _locked(
    path: Path, *, trusted_uid: int, trusted_gid: int,
) -> Iterator[int]:
    descriptor = -1
    try:
        descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600)
        os.fchown(descriptor, trusted_uid, trusted_gid)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != trusted_uid
            or opened.st_gid != trusted_gid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_ISLNK(current.st_mode)
            or (opened.st_dev, opened.st_ino)
               != (current.st_dev, current.st_ino)
        ):
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or (opened.st_dev, opened.st_ino)
               != (current.st_dev, current.st_ino)
        ):
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_lock_changed")
        yield descriptor
    except OSError as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_lock_unavailable") from error
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _run(
    command: Sequence[str], *, accepted: set[int] = {0},
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(command), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"})
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_command_failed") from error
    if (
        result.returncode not in accepted
        or len(result.stdout) > MAX_OUTPUT_BYTES
        or len(result.stderr) > MAX_OUTPUT_BYTES
    ):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_command_failed")
    return result


def _service(
    name: str, *, runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> dict[str, str]:
    result = runner([
        "/usr/bin/systemctl", "show", name, "--property=LoadState",
        "--property=ActiveState", "--property=SubState",
        "--property=MainPID", "--property=UnitFileState",
    ], accepted={0})
    values: dict[str, str] = {}
    try:
        lines = result.stdout.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_service_invalid") from error
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_service_invalid")
        values[key] = value
    return values


def _verify_quiescent(
    kind: str, deployment: ModuleType, *, runner: Callable[..., Any],
    closed_observer: Callable[[str], dict[str, Any]],
    user_lookup: Callable[[str], Any], session_roots: Sequence[Path],
    active_grant: Path, pending: Path, trusted_uid: int, trusted_gid: int,
) -> None:
    for path in (active_grant, pending, DENY_TRANSITION, RETIRED_GRANT):
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_active_state")
    for path in session_roots:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if kind == "absent":
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_absence_ambiguous")
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid
            or info.st_mode & 0o022
            or any(path.iterdir())
        ):
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_session_state")
    for identity in IDENTITIES:
        try:
            account = user_lookup(identity)
        except KeyError:
            continue
        if kind == "absent":
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_absence_ambiguous")
        result = runner(
            ["/usr/bin/pgrep", "-u", str(account.pw_uid)], accepted={0, 1})
        if result.returncode == 0 or result.stdout.strip():
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_process_active")
    supervisor = _service("native-harness-supervisor.service", runner=runner)
    if kind == "legacy":
        expected = {
            "LoadState": "loaded", "ActiveState": "inactive",
            "SubState": "dead", "MainPID": "0", "UnitFileState": "disabled",
        }
        if supervisor != expected:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_service_not_closed")
        try:
            closed = closed_observer("research")
        except Exception as error:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_closed_invalid") from error
        if (
            not isinstance(closed, dict)
            or set(closed) != {
                "schema", "live_policy_sha256", "persistent_policy_sha256",
                "service", "state",
            }
            or closed.get("schema") != "secure-sandbox-native-closed-state-v1"
            or closed.get("service") != "inactive"
            or closed.get("state") != "closed"
            or any(deployment.SHA256.fullmatch(
                str(closed.get(name, ""))) is None for name in (
                    "live_policy_sha256", "persistent_policy_sha256"))
        ):
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_closed_invalid")
        watchdog = runner([
            "/usr/bin/systemctl", "is-active",
            "secure-sandbox-native-egress-watchdog.service",
        ], accepted={0})
        if watchdog.stdout != b"active\n":
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_watchdog_invalid")
    elif kind == "absent":
        if supervisor != {
            "LoadState": "not-found", "ActiveState": "inactive",
            "SubState": "dead", "MainPID": "0", "UnitFileState": "",
        }:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_absence_ambiguous")
        watchdog = _service(
            "secure-sandbox-native-egress-watchdog.service", runner=runner)
        if watchdog != {
            "LoadState": "not-found", "ActiveState": "inactive",
            "SubState": "dead", "MainPID": "0", "UnitFileState": "",
        }:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_absence_ambiguous")
    else:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_generation_forbidden")


def execute(
    action: str, request: dict[str, Any], *, deployment: ModuleType,
    lifecycle: ModuleType, fence: ModuleType, release: ModuleType,
    release_observer: Callable[[], tuple[str, dict[str, Any] | None]],
    payload_catalog: Path = PAYLOAD_CATALOG,
    installed_catalog: Path = INSTALLED_CATALOG,
    install_lock: Path = INSTALL_LOCK,
    lifecycle_root: Path = LIFECYCLE_ROOT,
    egress_lock: Path = EGRESS_LOCK,
    pending: Path = INSTALL_PENDING,
    active_grant: Path = ACTIVE_GRANT,
    session_roots: Sequence[Path] = SESSION_ROOTS,
    runner: Callable[..., Any] = _run,
    closed_observer: Callable[[str], dict[str, Any]] | None = None,
    user_lookup: Callable[[str], Any] = pwd.getpwnam,
    trusted_uid: int = 0, trusted_gid: int = 0,
    now: int | None = None,
    crash_hook: Callable[[str], None] = lambda _phase: None,
) -> dict[str, Any]:
    if action not in {"acquire", "release"}:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_action_invalid")
    if not callable(closed_observer):
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_closed_observer_missing")
    try:
        if action == "acquire":
            if not isinstance(request, dict) or set(request) != {
                "schema", "plan", "request_sha256"
            }:
                raise ValueError("request-fields")
            plan = deployment.validate_plan(
                request.get("plan"), now=now, require_fresh=False)
            admitted = deployment.make_fence_request(plan)
            if request != admitted:
                raise ValueError("request-digest")
        else:
            admitted = deployment.validate_release_request(request, now=now)
    except Exception as error:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_request_invalid") from error
    payload_catalog_sha256 = _catalog_digest(
        payload_catalog, deployment, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid, modes={0o600})
    if payload_catalog_sha256 != admitted["plan"]["catalog_sha256"]:
        raise NativeDeploymentFenceBootstrapError(
            "native_deployment_bootstrap_catalog_mismatch")
    with _locked(
        install_lock, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
    ):
        with fence.locked(
            root=lifecycle_root, trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
        ) as lifecycle_fd:
            with _locked(
                egress_lock, trusted_uid=trusted_uid, trusted_gid=trusted_gid,
            ):
                try:
                    generation, observed_release = release_observer()
                except Exception as error:
                    raise NativeDeploymentFenceBootstrapError(
                        "native_deployment_bootstrap_release_invalid") from error
                previous = admitted["plan"]["previous_research_package_sha256"]
                if generation == "legacy":
                    if (
                        not isinstance(observed_release, dict)
                        or observed_release.get("package_sha256") != previous
                        or previous is None
                    ):
                        raise NativeDeploymentFenceBootstrapError(
                            "native_deployment_bootstrap_predecessor_mismatch")
                    installed = _catalog_digest(
                        installed_catalog, deployment,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                        modes={0o644})
                    if installed != payload_catalog_sha256:
                        raise NativeDeploymentFenceBootstrapError(
                            "native_deployment_bootstrap_catalog_mismatch")
                elif generation == "absent":
                    if observed_release is not None or previous is not None:
                        raise NativeDeploymentFenceBootstrapError(
                            "native_deployment_bootstrap_predecessor_mismatch")
                else:
                    raise NativeDeploymentFenceBootstrapError(
                        "native_deployment_bootstrap_generation_forbidden")
                _verify_quiescent(
                    generation, deployment, runner=runner,
                    closed_observer=closed_observer,
                    user_lookup=user_lookup, session_roots=session_roots,
                    active_grant=active_grant, pending=pending,
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid)
                if action == "acquire":
                    return lifecycle.acquire_locked(
                        admitted, lifecycle_fd,
                        catalog_sha256=payload_catalog_sha256,
                        live_run_count=0, deployment=deployment, fence=fence,
                        trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                        now=now)
                return lifecycle.release_locked(
                    admitted, lifecycle_fd,
                    catalog_sha256=payload_catalog_sha256,
                    live_run_count=0, deployment=deployment, fence=fence,
                    trusted_uid=trusted_uid, trusted_gid=trusted_gid,
                    now=now, crash_hook=crash_hook)


def main(arguments: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    try:
        if values not in (["acquire"], ["release"]):
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_action_invalid")
        if os.geteuid() != 0 or os.getegid() != 0:
            raise NativeDeploymentFenceBootstrapError(
                "native_deployment_bootstrap_root_required")
        action = values[0]
        deployment = _load(
            Path("/tmp/native_deployment.py"), "_native_deployment",
            trusted_uid=0, trusted_gid=0)
        lifecycle = _load(
            Path("/tmp/native_deployment_lifecycle.py"),
            "_native_deployment_lifecycle", trusted_uid=0, trusted_gid=0)
        fence = _load(
            Path("/tmp/native_lifecycle_fence.py"), "_native_lifecycle_fence",
            trusted_uid=0, trusted_gid=0)
        release = _load(
            Path("/tmp/native_research_release.py"),
            "_native_research_release", trusted_uid=0, trusted_gid=0)
        closed_observer = load_closed_observer(
            Path("/tmp"), trusted_uid=0, trusted_gid=0)
        request = _read_request(
            ACQUIRE_REQUEST if action == "acquire" else RELEASE_REQUEST,
            deployment, trusted_uid=0, trusted_gid=0)
        prepare_state_roots()
        result = execute(
            action, request, deployment=deployment, lifecycle=lifecycle,
            fence=fence, release=release,
            release_observer=release.current_release,
            closed_observer=closed_observer)
        sys.stdout.buffer.write(deployment.canonical(result))
        return 0
    except Exception as error:
        reason = str(error)
        if not reason.startswith("native_deployment_"):
            reason = "native_deployment_bootstrap_rejected"
        print(reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
