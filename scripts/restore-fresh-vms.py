#!/usr/bin/env python3
"""Resumable, identity-bound restoration of the three SecureSandbox guests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import importlib.util
import re
import signal
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".private" / "restoration"
JOURNAL = PRIVATE / "current.json"
PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")
CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
PKI_ANCHOR = Path("/usr/local/libexec/secure-sandbox-host/current/pki_anchor")
LAUNCHER_PATH = ROOT / "scripts" / "secure-sandbox-claude-launcher.py"
VMS = ("SecureSandbox-Gateway", "SecureSandbox-Research", "SecureSandbox-Target")


def load_launcher():
    spec = importlib.util.spec_from_file_location("secure_sandbox_launcher_restore", LAUNCHER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


LAUNCHER = load_launcher()
DEFERRED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)

PHASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("bounded_package_provisioning", ("scripts/provision-fresh-vm-dependencies.sh", "--apply")),
    ("foundation", ("scripts/deploy-foundation.sh",)),
    ("pki_lifecycle", (sys.executable, "scripts/pki-operation.py", "deploy", "--inherited-lock")),
    ("pki_generation", (sys.executable, "scripts/pki-operation.py", "rotate", "--inherited-lock")),
    ("source_acquisition", ("scripts/deploy-source-acquisition.sh",)),
    ("source_integrity", ("scripts/deploy-source-integrity.sh",)),
    ("corpus_intelligence", ("scripts/deploy-corpus-intelligence.sh",)),
    ("codegraph", ("scripts/deploy-codegraph-adapter.sh",)),
    ("dependencies", ("scripts/deploy-dependency-orchestration.sh",)),
    ("disposable_execution", ("scripts/deploy-disposable-execution.sh",)),
    ("evidence_receipts", ("scripts/deploy-evidence-receipts.sh",)),
    ("agent_memory", ("scripts/deploy-agent-memory-governance.sh",)),
    ("review_bundles", ("scripts/deploy-review-bundle-verifier.sh",)),
    ("findings", ("scripts/deploy-findings-adjudication.sh",)),
    ("run_leases", ("scripts/deploy-run-leases.sh",)),
    ("hot_acceptance", ("scripts/verify-boundaries.sh",)),
    ("cold_boot_acceptance", ("scripts/cold-boot-acceptance.sh",)),
    ("publication_safety", (sys.executable, "scripts/check-public-identifiers.py", "--ref", "HEAD")),
)


class RestoreFailure(RuntimeError):
    pass


class DeferredSignals:
    def __init__(self) -> None:
        self.received: int | None = None
        self.previous: dict[int, object] = {}

    def handle(self, signum: int, _frame: object) -> None:
        if self.received is None:
            self.received = signum

    def __enter__(self) -> "DeferredSignals":
        for signum in DEFERRED_SIGNALS:
            self.previous[signum] = signal.signal(signum, self.handle)
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def archive_incomplete_journal() -> Path:
    while True:
        archive = PRIVATE / (
            "abandoned-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}-"
            f"{uuid.uuid4().hex}.json"
        )
        try:
            os.link(JOURNAL, archive, follow_symlinks=False)
            break
        except FileExistsError:
            continue
    # Make the preserved name durable before removing the authoritative name.
    # A crash between these fsyncs leaves two names for the same valid journal,
    # which is safe and visibly recoverable; it never loses or overwrites evidence.
    fsync_directory(PRIVATE)
    os.unlink(JOURNAL)
    fsync_directory(PRIVATE)
    return archive


def require_regular(path: Path, executable: bool = False) -> None:
    if path.is_symlink() or not path.is_file() or (executable and not os.access(path, os.X_OK)):
        raise RestoreFailure(f"prerequisite_invalid:{path}")


def public_worktree_paths() -> list[Path]:
    raw = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    )
    paths: list[Path] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        if relative.is_absolute() or ".." in relative.parts:
            raise RestoreFailure("publication_worktree_path_invalid")
        paths.append(ROOT / relative)
    return paths


def publication_identity() -> bytes:
    head = subprocess.check_output(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
    ).strip()
    if not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise RestoreFailure("publication_head_invalid")
    tags = subprocess.check_output(
        [
            "git", "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(objecttype)",
            "refs/tags",
        ],
        cwd=ROOT,
    )
    return b"HEAD\0" + head + b"\0TAGS\0" + tags


def hash_regular_file(path: Path) -> bytes:
    directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        absolute = path if path.is_absolute() else Path.cwd() / path
        if ".." in absolute.parts:
            raise RestoreFailure(f"prerequisite_invalid:{path}")
        components = absolute.relative_to(absolute.anchor).parts
        if not components:
            raise RestoreFailure(f"prerequisite_invalid:{path}")
        current = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
        directory_fds.append(current)
        for component in components[:-1]:
            current = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            directory_fds.append(current)
        file_fd = os.open(
            components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise RestoreFailure(f"prerequisite_invalid:{path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                return digest.digest()
            digest.update(chunk)
    except OSError as error:
        raise RestoreFailure(f"prerequisite_invalid:{path}") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


def vm_inventory() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in VMS:
        completed = subprocess.run(
            [str(PRLCTL), "list", "-a", "-i", "-j", name],
            check=True, capture_output=True, text=True,
        )
        rows = json.loads(completed.stdout)
        if not isinstance(rows, list) or len(rows) != 1:
            raise RestoreFailure(f"vm_identity_ambiguous:{name}")
        row = rows[0]
        expected_home = (ROOT / "vms" / f"{name}.pvm").resolve()
        actual_home = Path(str(row.get("Home", "")).rstrip("/")).resolve()
        if actual_home != expected_home:
            raise RestoreFailure(f"vm_home_invalid:{name}")
        vm_id = str(row.get("ID", "")).strip("{}")
        if len(vm_id) != 36:
            raise RestoreFailure(f"vm_uuid_invalid:{name}")
        result[name] = {"uuid": vm_id, "home": str(actual_home)}
    return result


def input_digest() -> str:
    digest = hashlib.sha256()
    roots = ("scripts", "gateway", "research", "target")
    paths: list[Path] = []
    for root in roots:
        paths.extend(
            path for path in (ROOT / root).rglob("*")
            if path.is_file() and not path.is_symlink()
            and "__pycache__" not in path.parts and path.name != ".DS_Store"
        )
    paths.extend((
        ROOT / ".gitignore",
        ROOT / "config" / "conversation-age-recipient.txt",
        ROOT / "config" / "privileged-control.sudoers",
        ROOT / "config" / "ssh_config",
        ROOT / "config" / "sshd-control.conf",
        ROOT / "runs" / "control_key.pub",
        ROOT / "research" / "glm-persona.md",
        ROOT / "artifacts" / "claude-code" / "claude-2.1.300-linux-arm64",
        ROOT / "artifacts" / "ubuntu-26.04.1" / "packages" / "bubblewrap_0.11.1-1ubuntu0.3_arm64.deb",
        ROOT / "artifacts" / "ubuntu-26.04.1" / "packages" / "socat_1.8.1.1-1ubuntu0.1_arm64.deb",
        Path.home() / "CodeGraph" / "release" / "codegraph-linux-arm64.tar.gz",
    ))
    paths.extend(public_worktree_paths())
    denylist = ROOT / ".private" / "public-deny-patterns.txt"
    if denylist.exists() or denylist.is_symlink():
        paths.append(denylist)
    for path in sorted(set(paths), key=lambda item: str(item)):
        digest.update(str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path.name).encode("utf-8"))
        digest.update(b"\0")
        digest.update(hash_regular_file(path))
    digest.update(b"git-publication-identity\0")
    digest.update(hashlib.sha256(publication_identity()).digest())
    return digest.hexdigest()


def preflight() -> tuple[dict[str, dict[str, str]], str]:
    require_regular(PRLCTL, executable=True)
    require_regular(CLIENT, executable=True)
    require_regular(SSH_CONFIG)
    subprocess.run([sys.executable, str(ROOT / "scripts/host-controller-release.py"), "verify"], check=True)
    inventory = vm_inventory()
    source_digest = input_digest()
    # Resolve the execution credential now, with output discarded, so a later
    # phase never discovers a missing secret after guest mutation has begun.
    subprocess.run(
        ["op-agents", "read", "op://Agents/SecureSandbox-Execution-Broker/password"],
        check=True, stdout=subprocess.DEVNULL,
    )
    return inventory, source_digest


def load_journal() -> dict[str, object] | None:
    if not JOURNAL.exists():
        return None
    if JOURNAL.is_symlink() or not JOURNAL.is_file():
        raise RestoreFailure("restoration_journal_invalid")
    value = json.loads(JOURNAL.read_text(encoding="utf-8"))
    if value.get("schema") != "secure-sandbox-fresh-vm-restoration-v1":
        raise RestoreFailure("restoration_journal_schema_invalid")
    return value


def command_for(parts: tuple[str, ...]) -> list[str]:
    command = list(parts)
    if command[0].startswith("scripts/"):
        command[0] = str(ROOT / command[0])
    elif len(command) > 1 and command[1].startswith("scripts/"):
        command[1] = str(ROOT / command[1])
    return command


def require_no_active_controller() -> None:
    marker_root = LAUNCHER.STATE_ROOT / "active"
    if not marker_root.exists():
        return
    info = marker_root.lstat()
    entries = list(marker_root.iterdir())
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or len(entries) > 64):
        raise RestoreFailure("active_marker_directory_invalid")
    if entries:
        raise RestoreFailure("active_controller_invocation")


def run_phase(parts: tuple[str, ...], deferred: DeferredSignals) -> int:
    environment = os.environ.copy()
    environment["SECURE_SANDBOX_STATE_ROOT"] = str(LAUNCHER.STATE_ROOT)
    environment["SECURE_SANDBOX_COORDINATION_HOLDER_PID"] = str(os.getpid())
    if deferred.received is not None:
        return 128 + deferred.received
    # The parent handlers defer termination while this phase owns cleanup.  Do
    # not block the signals around Popen: that mask is inherited across exec and
    # would prevent the phase's own TERM/INT/HUP cleanup traps from running.
    process = subprocess.Popen(
        command_for(parts), cwd=ROOT, env=environment, start_new_session=True,
    )
    return process.wait()


def validate_recovery_generation(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise RestoreFailure("pki_recovery_generation_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise RestoreFailure("pki_recovery_generation_invalid")
    return value


def anchor_value(command: str, allow_missing: bool = False) -> dict[str, object] | None:
    completed = subprocess.run(
        [str(PKI_ANCHOR), command], check=False, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        if (command == "pending" or allow_missing) \
                and "No such file or directory" in completed.stderr:
            return None
        raise RestoreFailure(f"pki_anchor_{command}_unavailable")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RestoreFailure(f"pki_anchor_{command}_invalid") from error
    if not isinstance(value, dict):
        raise RestoreFailure(f"pki_anchor_{command}_invalid")
    generation = value.get("generation_id")
    if not isinstance(generation, str):
        raise RestoreFailure(f"pki_anchor_{command}_invalid")
    validate_recovery_generation(generation)
    return value


def pki_recovery_candidate(journal: dict[str, object]) -> str:
    completed = journal.get("completed")
    if not isinstance(completed, list) or "pki_lifecycle" not in completed \
            or "pki_generation" in completed:
        return ""
    pending = anchor_value("pending")
    if pending is not None:
        return str(pending["generation_id"])
    active = anchor_value("verify", allow_missing=True)
    if "pki_anchor_before_generation" in journal:
        baseline = journal["pki_anchor_before_generation"]
        if baseline is None:
            return str(active["generation_id"]) if active is not None else ""
        if not isinstance(baseline, dict):
            raise RestoreFailure("pki_recovery_evidence_invalid")
        for field in ("generation_id", "manifest_sha256", "record_sha256"):
            if not isinstance(baseline.get(field), str):
                raise RestoreFailure("pki_recovery_evidence_invalid")
        if active is None:
            raise RestoreFailure("pki_anchor_verify_unavailable")
        if any(active.get(field) != baseline[field]
               for field in ("generation_id", "manifest_sha256", "record_sha256")):
            return str(active["generation_id"])
        return ""
    if active is None:
        raise RestoreFailure("pki_anchor_verify_unavailable")
    created_at = journal.get("created_at")
    committed_at = active.get("committed_at")
    if not isinstance(created_at, str) or not isinstance(committed_at, int):
        raise RestoreFailure("pki_recovery_evidence_invalid")
    try:
        journal_epoch = datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
    except ValueError as error:
        raise RestoreFailure("pki_recovery_evidence_invalid") from error
    if committed_at >= int(journal_epoch):
        return str(active["generation_id"])
    return ""


def apply(restart: bool = False, recover_pki_generation: str = "",
          requesting_agent: str = "", requesting_session: str = "") -> int:
    if recover_pki_generation:
        validate_recovery_generation(recover_pki_generation)
    inventory, source_digest = preflight()
    lock = None
    with DeferredSignals() as deferred:
        try:
            lock = LAUNCHER.acquire_lock(LAUNCHER.STATE_ROOT, timeout=10.0)
            require_no_active_controller()
            journal = load_journal()
            recovery_candidate = ""
            if journal is not None and journal.get("status") != "complete":
                recovery_candidate = pki_recovery_candidate(journal)
                if recovery_candidate and not recover_pki_generation:
                    raise RestoreFailure(f"pki_recovery_required:{recovery_candidate}")
                if (recovery_candidate and recover_pki_generation
                        and recovery_candidate != recover_pki_generation):
                    raise RestoreFailure("pki_recovery_generation_mismatch")
            if restart and journal is not None and journal.get("status") != "complete":
                archive_incomplete_journal()
                journal = None
            if journal is None or journal.get("status") == "complete":
                journal = {
                    "schema": "secure-sandbox-fresh-vm-restoration-v1",
                    "status": "pending", "created_at": now(),
                    "source_digest": source_digest, "vms": inventory, "completed": [],
                }
                atomic_json(JOURNAL, journal)
            elif journal.get("source_digest") != source_digest or journal.get("vms") != inventory:
                raise RestoreFailure("restoration_identity_changed")
            completed = journal.get("completed")
            if not isinstance(completed, list) or not all(isinstance(item, str) for item in completed):
                raise RestoreFailure("restoration_journal_completed_invalid")
            expected_prefix = [name for name, _ in PHASES[: len(completed)]]
            if completed != expected_prefix:
                raise RestoreFailure("restoration_journal_order_invalid")
            if recover_pki_generation:
                if "pki_generation" in completed:
                    raise RestoreFailure("pki_recovery_phase_invalid")
            for name, parts in PHASES[len(completed) :]:
                if input_digest() != source_digest:
                    raise RestoreFailure(f"restoration_identity_changed:before:{name}")
                if name == "pki_generation" and "pki_anchor_before_generation" not in journal:
                    journal["pki_anchor_before_generation"] = anchor_value(
                        "verify", allow_missing=True,
                    )
                    journal["updated_at"] = now()
                    atomic_json(JOURNAL, journal)
                print(f"RESTORE {name}", flush=True)
                phase_parts = parts
                if name == "bounded_package_provisioning":
                    phase_parts = (
                        *parts,
                        "--gateway-uuid", inventory["SecureSandbox-Gateway"]["uuid"],
                        "--research-uuid", inventory["SecureSandbox-Research"]["uuid"],
                        "--target-uuid", inventory["SecureSandbox-Target"]["uuid"],
                    )
                if name == "pki_generation" and recover_pki_generation:
                    phase_parts = (
                        sys.executable, "scripts/pki-operation.py", "rotate",
                        recover_pki_generation, "--recover", "--inherited-lock",
                    )
                if name == "pki_generation" and requesting_agent and requesting_session:
                    phase_parts = (
                        *phase_parts, "--requesting-agent", requesting_agent,
                        "--requesting-session", requesting_session,
                    )
                result = run_phase(phase_parts, deferred)
                if result != 0:
                    raise subprocess.CalledProcessError(result, command_for(phase_parts))
                if input_digest() != source_digest:
                    raise RestoreFailure(f"restoration_identity_changed:after:{name}")
                if deferred.received is not None:
                    return 128 + deferred.received
                completed.append(name)
                journal["completed"] = completed
                journal["updated_at"] = now()
                atomic_json(JOURNAL, journal)
            if input_digest() != source_digest:
                raise RestoreFailure("restoration_identity_changed:before_completion")
            journal["status"] = "complete"
            journal["completed_at"] = now()
            atomic_json(JOURNAL, journal)
            print("fresh-vm-restoration:complete")
            return 0
        finally:
            if lock is not None:
                LAUNCHER.release_lock(lock)


def plan() -> int:
    inventory, source_digest = preflight()
    print(json.dumps({
        "schema": "secure-sandbox-fresh-vm-restoration-plan-v1",
        "source_digest": source_digest,
        "vms": inventory,
        "phases": [name for name, _ in PHASES],
        "status": "verified_plan",
    }, sort_keys=True, indent=2))
    return 0


def status() -> int:
    journal = load_journal()
    print(json.dumps(journal or {"status": "not_started"}, sort_keys=True, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "apply", "status"))
    parser.add_argument("--restart", action="store_true", help="archive an incomplete journal and start a new identity-bound restoration")
    parser.add_argument("--recover-pki-generation", default="", help="resume an interrupted PKI phase using its exact UUIDv4")
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    arguments = parser.parse_args()
    if arguments.restart and arguments.command != "apply":
        parser.error("--restart is valid only with apply")
    if arguments.recover_pki_generation and arguments.command != "apply":
        parser.error("--recover-pki-generation is valid only with apply")
    if arguments.command == "apply" and (not arguments.requesting_agent or not arguments.requesting_session):
        parser.error("apply requires --requesting-agent and --requesting-session for PKI authorization")
    try:
        if arguments.command == "apply":
            return apply(
                arguments.restart, arguments.recover_pki_generation,
                arguments.requesting_agent, arguments.requesting_session,
            )
        return {"plan": plan, "status": status}[arguments.command]()
    except (OSError, ValueError, subprocess.CalledProcessError, RestoreFailure, LAUNCHER.LaunchFailure) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
