#!/usr/bin/env python3
"""Root-only protected harness lifecycle planner and authorization consumer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import BinaryIO, Callable


SHARED = Path(__file__).resolve().parent / "shared"
if not SHARED.exists():
    SHARED = Path("/usr/local/libexec/secure-sandbox/shared")
sys.path.insert(0, str(SHARED))

from harness_generation_store import (  # noqa: E402
    GenerationStore,
    GenerationStoreError,
    MANAGEMENT_PLAN_SCHEMA,
    PLAN_SCHEMA,
    canonical_bytes,
    sha256_value,
)


SCHEMA = "secure-sandbox-harness-consumer-stage-v1"
PLAN_WRAPPER_SCHEMA = "secure-sandbox-harness-consumer-plan-v1"
APPLY_SCHEMA = "secure-sandbox-harness-consumer-apply-v1"
RECOVERY_SCHEMA = "secure-sandbox-harness-consumer-recovery-v1"
DEFAULT_RELEASE_ROOT = Path("/usr/local/libexec/secure-sandbox-harnesses")
DEFAULT_STATE_ROOT = Path("/var/lib/secure-sandbox/harnesses")
DEFAULT_STAGE_ROOT = DEFAULT_STATE_ROOT / "staging"
ACTIVE_RUN = Path("/var/lib/secure-sandbox/run-lifecycle/active.json")
FAILURE_LATCH = Path("/var/lib/secure-sandbox/run-lifecycle/failure-latched.json")
RUN_MARKERS = (Path("/run/secure-sandbox/run-id"), Path("/run/secure-sandbox/evidence-run-id"))
RUN_LIFECYCLE_SCHEMA = "secure-sandbox-run-lifecycle-v2"
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SAFE_FILES = ("artifact", "manifest.json", "verification.json", "qualification.json", "adapter.json")
MAX_HEADER = 64 * 1024
MAX_ARTIFACT = 256 * 1024 * 1024 - 2 * 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_STAGES = 32


class ConsumerError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def exact(value: dict, names: set[str], label: str) -> None:
    if set(value) != names:
        raise ConsumerError(f"{label}_fields_invalid")


def require_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise ConsumerError(f"{label}_invalid")
    return value


def require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ConsumerError(f"{label}_invalid")
    return value


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_directory(path: Path, uid: int, mode: int, *, create: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise ConsumerError("stage_directory_missing")
        path.mkdir(mode=mode, parents=False)
        info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode):
        raise ConsumerError("stage_directory_untrusted")


def read_regular(path: Path, uid: int, maximum: int, mode: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode or info.st_size > maximum):
            raise ConsumerError("stage_file_untrusted")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != info.st_size or len(data) > maximum:
            raise ConsumerError("stage_file_untrusted")
        return bytes(data)
    finally:
        os.close(descriptor)


def write_regular(path: Path, source: BinaryIO, size: int, expected_sha256: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest = hashlib.sha256()
    remaining = size
    try:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ConsumerError("stage_payload_truncated")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ConsumerError("stage_write_failed")
                view = view[written:]
            remaining -= len(chunk)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if digest.hexdigest() != expected_sha256:
        raise ConsumerError("stage_digest_mismatch")


def atomic_json(path: Path, value: dict, uid: int) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.new")
    payload = canonical_bytes(value)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ConsumerError("stage_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    if temporary.stat().st_uid != uid:
        temporary.unlink()
        raise ConsumerError("stage_owner_invalid")
    os.rename(temporary, path)
    fsync_directory(path.parent)


def parse_stage_header(stream: BinaryIO) -> tuple[dict, list[dict]]:
    raw = stream.read(4)
    if len(raw) != 4:
        raise ConsumerError("stage_header_truncated")
    length = struct.unpack(">I", raw)[0]
    if not 2 <= length <= MAX_HEADER:
        raise ConsumerError("stage_header_size_invalid")
    body = stream.read(length)
    if len(body) != length:
        raise ConsumerError("stage_header_truncated")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConsumerError("stage_header_invalid") from error
    if not isinstance(value, dict) or canonical(value) != body:
        raise ConsumerError("stage_header_noncanonical")
    exact(value, {"schema", "stage_id", "generation_id", "files"}, "stage_header")
    if value["schema"] != SCHEMA:
        raise ConsumerError("stage_schema_invalid")
    require_uuid(value["stage_id"], "stage_id")
    require_sha(value["generation_id"], "generation_id")
    files = value["files"]
    if not isinstance(files, list) or len(files) != len(SAFE_FILES):
        raise ConsumerError("stage_files_invalid")
    total = 0
    for expected_name, entry in zip(SAFE_FILES, files, strict=True):
        if not isinstance(entry, dict):
            raise ConsumerError("stage_files_invalid")
        exact(entry, {"name", "sha256", "size"}, "stage_file")
        maximum = MAX_ARTIFACT if expected_name == "artifact" else MAX_JSON
        if (entry.get("name") != expected_name
                or not isinstance(entry.get("size"), int) or isinstance(entry["size"], bool)
                or not 0 < entry["size"] <= maximum):
            raise ConsumerError("stage_file_invalid")
        require_sha(entry.get("sha256"), "stage_file_sha256")
        total += entry["size"]
    if total > 256 * 1024 * 1024 - MAX_HEADER - 4:
        raise ConsumerError("stage_payload_too_large")
    return value, files


def stage_paths(root: Path) -> dict[str, Path]:
    return {name: root / name for name in SAFE_FILES}


def plan_wrapper(stage_id: str, plan: dict, reference: dict | None = None) -> dict:
    value = {"schema": PLAN_WRAPPER_SCHEMA, "stage_id": stage_id,
             "plan": plan, "reference": reference}
    value["wrapper_sha256"] = sha256_value(value)
    return value


class FixedHealthProbe:
    """Start the immutable candidate without credentials in a private network."""

    def __init__(self, runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run):
        self.runner = runner

    def probe(self, plan: dict, executable: Path) -> dict:
        command = [
            "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
            "--service-type=exec", "--property=DynamicUser=yes", "--property=PrivateNetwork=yes",
            "--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes", "--property=PrivateDevices=yes",
            "--property=NoNewPrivileges=yes", "--property=IPAddressDeny=any",
            "--property=RestrictAddressFamilies=AF_UNIX", "--property=MemoryMax=512M",
            "--property=CPUQuota=25%", "--property=RuntimeMaxSec=20",
            str(executable), "--version",
        ]
        result = self.runner(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=30,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        if result.returncode != 0 or len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
            raise ConsumerError("harness_health_probe_failed")
        value = {
            "schema": "secure-sandbox-harness-health-receipt-v1",
            "plan_id": plan["plan_id"], "plan_sha256": plan["plan_sha256"],
            "generation_id": plan["candidate"]["generation_id"],
            "artifact_sha256": plan["candidate"]["artifact_sha256"],
            "adapter_sha256": plan["candidate"]["adapter_sha256"],
            "health_probe_sha256": plan["candidate"]["health_probe_sha256"],
            "observer": "secure-sandbox-fixed-health-supervisor-v1",
            "synthetic": True, "production_credential_present": False,
            "network_attempts": [], "status": "passed",
        }
        value["health_sha256"] = sha256_value(value)
        return value


class HarnessGenerationConsumer:
    def __init__(self, release_root: Path = DEFAULT_RELEASE_ROOT,
                 state_root: Path = DEFAULT_STATE_ROOT,
                 stage_root: Path = DEFAULT_STAGE_ROOT, *, uid: int | None = None,
                 active_run: Path = ACTIVE_RUN, failure_latch: Path = FAILURE_LATCH,
                 run_markers: tuple[Path, ...] = RUN_MARKERS,
                 now: Callable[[], int] | None = None,
                 health_probe: FixedHealthProbe | None = None) -> None:
        self.uid = os.geteuid() if uid is None else uid
        self.now = now or (lambda: int(time.time()))
        self.store = GenerationStore(release_root, state_root, uid=self.uid, now=self.now)
        self.stage_root = stage_root
        self.active_run = active_run
        self.failure_latch = failure_latch
        self.run_markers = run_markers
        self.health_probe = health_probe or FixedHealthProbe()

    def prepare_staging(self) -> None:
        self.store.prepare()
        trusted_directory(self.stage_root, self.uid, 0o700, create=True)
        entries = list(self.stage_root.iterdir())
        if len(entries) >= MAX_STAGES or any(entry.is_symlink() or not entry.is_dir() for entry in entries):
            raise ConsumerError("stage_capacity_or_integrity_failed")

    def stage_activate(self, stream: BinaryIO) -> dict:
        self.prepare_staging()
        header, files = parse_stage_header(stream)
        destination = self.stage_root / header["stage_id"]
        created = False
        try:
            destination.mkdir(mode=0o700)
            created = True
            for entry in files:
                write_regular(destination / entry["name"], stream, entry["size"], entry["sha256"])
            if stream.read(1):
                raise ConsumerError("stage_payload_trailing_data")
            fsync_directory(destination)
            paths = stage_paths(destination)
            plan = self.store.create_plan(
                paths["manifest.json"], paths["artifact"], paths["verification.json"],
                paths["qualification.json"], paths["adapter.json"], operation="activate",
                now=self.now(),
            )
            if plan["candidate"]["generation_id"] != header["generation_id"]:
                raise ConsumerError("stage_generation_mismatch")
            atomic_json(destination / "plan.json", plan, self.uid)
            return plan_wrapper(header["stage_id"], plan)
        except BaseException:
            if created and destination.exists() and not destination.is_symlink():
                shutil.rmtree(destination)
            raise

    def _copy_release_to_stage(self, generation_id: str, stage_id: str) -> Path:
        self.prepare_staging()
        require_sha(generation_id, "generation_id")
        source = self.store.releases / generation_id
        destination = self.stage_root / stage_id
        created = False
        mappings = {"artifact": "harness", "manifest.json": "manifest.json",
                    "verification.json": "verification.json",
                    "qualification.json": "qualification.json", "adapter.json": "adapter.json"}
        try:
            destination.mkdir(mode=0o700)
            created = True
            for target, origin in mappings.items():
                maximum = MAX_ARTIFACT if target == "artifact" else MAX_JSON
                mode = 0o555 if origin == "harness" else 0o444
                payload = read_regular(source / origin, self.uid, maximum, mode)
                descriptor = os.open(destination / target,
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    view = memoryview(payload)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise ConsumerError("stage_write_failed")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            fsync_directory(destination)
            return destination
        except BaseException:
            if created and destination.exists() and not destination.is_symlink():
                shutil.rmtree(destination)
            raise

    def prepare_rollback(self, generation_id: str) -> dict:
        stage_id = str(uuid.uuid4())
        destination = self._copy_release_to_stage(generation_id, stage_id)
        try:
            paths = stage_paths(destination)
            plan = self.store.create_plan(
                paths["manifest.json"], paths["artifact"], paths["verification.json"],
                paths["qualification.json"], paths["adapter.json"], operation="rollback",
                now=self.now(),
            )
            atomic_json(destination / "plan.json", plan, self.uid)
            return plan_wrapper(stage_id, plan)
        except BaseException:
            if destination.exists() and not destination.is_symlink():
                shutil.rmtree(destination)
            raise

    def active_run_count(self, generation_id: str) -> int:
        if not self.active_run.exists():
            return 0
        raw = read_regular(self.active_run, self.uid, MAX_JSON, 0o644)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConsumerError("active_run_state_invalid") from error
        if not isinstance(value, dict) or value.get("schema") != RUN_LIFECYCLE_SCHEMA:
            raise ConsumerError("active_run_state_invalid")
        observed = value.get("harness_generation_id")
        if observed is None:
            raise ConsumerError("active_run_generation_unbound")
        require_sha(observed, "active_run_generation")
        return 1 if observed == generation_id else 0

    def runtime_idle(self) -> bool:
        return not any(path.exists() or path.is_symlink()
                       for path in (*self.run_markers, self.active_run, self.failure_latch))

    def plan_management(self, operation: str, generation_id: str, reason_sha256: str,
                        resumable_session_count: int) -> dict:
        if operation not in {"retire", "revoke"}:
            raise ConsumerError("management_operation_invalid")
        require_sha(generation_id, "generation_id"); require_sha(reason_sha256, "reason_sha256")
        if (not isinstance(resumable_session_count, int) or isinstance(resumable_session_count, bool)
                or not 0 <= resumable_session_count <= 10_000):
            raise ConsumerError("resumable_session_count_invalid")
        self.prepare_staging()
        stage_id = str(uuid.uuid4())
        destination = self.stage_root / stage_id
        created = False
        try:
            destination.mkdir(mode=0o700)
            created = True
            reference = {
                "schema": "secure-sandbox-harness-session-reference-readback-v1",
                "generation_id": generation_id,
                "active_run_count": self.active_run_count(generation_id),
                "resumable_session_count": resumable_session_count,
                "observed_at": self.now(), "observer": "secure-sandbox-session-catalog-readback-v1",
            }
            reference["reference_sha256"] = sha256_value(reference)
            atomic_json(destination / "reference.json", reference, self.uid)
            plan = self.store.create_management_plan(
                operation, generation_id, reason_sha256, destination / "reference.json", now=self.now(),
            )
            atomic_json(destination / "plan.json", plan, self.uid)
            return plan_wrapper(stage_id, plan, reference)
        except BaseException:
            if created and destination.exists() and not destination.is_symlink():
                shutil.rmtree(destination)
            raise

    def _load_stage_plan(self, stage_id: str) -> tuple[Path, dict]:
        require_uuid(stage_id, "stage_id")
        root = self.stage_root / stage_id
        trusted_directory(root, self.uid, 0o700)
        raw = read_regular(root / "plan.json", self.uid, MAX_JSON, 0o600)
        try:
            plan = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConsumerError("stage_plan_invalid") from error
        if canonical_bytes(plan) != raw:
            raise ConsumerError("stage_plan_noncanonical")
        return root, plan

    def apply(self, raw: object) -> dict:
        if not isinstance(raw, dict):
            raise ConsumerError("apply_request_invalid")
        exact(raw, {"schema", "stage_id", "plan", "authorization",
                    "resumable_session_count"}, "apply_request")
        if raw["schema"] != APPLY_SCHEMA:
            raise ConsumerError("apply_schema_invalid")
        root, stored_plan = self._load_stage_plan(raw["stage_id"])
        if raw["plan"] != stored_plan:
            raise ConsumerError("apply_plan_changed")
        plan = raw["plan"]
        if plan.get("schema") == PLAN_SCHEMA:
            paths = stage_paths(root)
            return self.store.activate(
                plan, raw["authorization"], paths["manifest.json"], paths["artifact"],
                paths["verification.json"], paths["qualification.json"], paths["adapter.json"],
                self.health_probe, runtime_idle=self.runtime_idle, now=self.now(),
            )
        if plan.get("schema") == MANAGEMENT_PLAN_SCHEMA:
            count = raw["resumable_session_count"]
            if (not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 10_000):
                raise ConsumerError("resumable_session_count_invalid")
            reference_path = root / "reference.json"
            reference = json.loads(read_regular(reference_path, self.uid, MAX_JSON, 0o600))
            if (reference.get("resumable_session_count") != count
                    or reference.get("active_run_count") != self.active_run_count(plan["generation_id"])):
                raise ConsumerError("management_reference_changed")
            return self.store.apply_management_plan(
                plan, raw["authorization"], reference_path,
                runtime_idle=self.runtime_idle, now=self.now(),
            )
        raise ConsumerError("apply_plan_schema_invalid")

    def recovery_status(self) -> dict:
        self.store.prepare()
        entries = list(self.store.journals.iterdir())
        if not entries:
            return {"schema": RECOVERY_SCHEMA, "pending": False, "journal_sha256": None}
        if len(entries) != 1:
            raise ConsumerError("recovery_journal_ambiguous")
        raw = read_regular(entries[0], self.uid, MAX_JSON, 0o600)
        return {"schema": RECOVERY_SCHEMA, "pending": True,
                "journal_sha256": hashlib.sha256(raw).hexdigest()}

    def recover(self, expected_sha256: str) -> dict:
        require_sha(expected_sha256, "recovery_journal_sha256")
        status = self.recovery_status()
        if not status["pending"] or status["journal_sha256"] != expected_sha256:
            raise ConsumerError("recovery_journal_changed")
        return self.store.recover(now=self.now())


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Protected harness lifecycle consumer")
    value.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT, help=argparse.SUPPRESS)
    value.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT, help=argparse.SUPPRESS)
    value.add_argument("--stage-root", type=Path, default=DEFAULT_STAGE_ROOT, help=argparse.SUPPRESS)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("stage-activate")
    rollback = commands.add_parser("prepare-rollback"); rollback.add_argument("generation_id")
    management = commands.add_parser("plan-management")
    management.add_argument("operation", choices=("retire", "revoke"))
    management.add_argument("generation_id"); management.add_argument("reason_sha256")
    management.add_argument("resumable_session_count", type=int)
    commands.add_parser("apply")
    commands.add_parser("recovery-status")
    recover = commands.add_parser("recover"); recover.add_argument("journal_sha256")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    consumer = HarnessGenerationConsumer(args.release_root, args.state_root, args.stage_root)
    if args.command == "stage-activate":
        result = consumer.stage_activate(sys.stdin.buffer)
    elif args.command == "prepare-rollback":
        result = consumer.prepare_rollback(args.generation_id)
    elif args.command == "plan-management":
        result = consumer.plan_management(args.operation, args.generation_id,
                                          args.reason_sha256, args.resumable_session_count)
    elif args.command == "apply":
        try:
            raw = sys.stdin.buffer.read(2 * MAX_JSON + 1)
            if len(raw) > 2 * MAX_JSON or canonical(json.loads(raw)) != raw:
                raise ConsumerError("apply_request_noncanonical")
            request = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConsumerError("apply_request_invalid") from error
        result = consumer.apply(request)
    elif args.command == "recovery-status":
        result = consumer.recovery_status()
    else:
        result = consumer.recover(args.journal_sha256)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConsumerError, GenerationStoreError, OSError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, (ConsumerError, GenerationStoreError)) else "consumer_io_failed"
        print(json.dumps({"error": code, "schema": "secure-sandbox-harness-consumer-error-v1",
                          "status": "rejected"}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
