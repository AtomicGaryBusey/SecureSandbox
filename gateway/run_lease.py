#!/usr/bin/env python3
"""Root-issued, durable run leases for the model broker."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import syslog
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

LEASE_SCHEMA = "secure-sandbox-run-lease-v1"
COUNTER_SCHEMA = "secure-sandbox-run-lease-counter-v1"
SUMMARY_SCHEMA = "secure-sandbox-run-lease-summary-v1"
PROFILE_SCHEMA = "secure-sandbox-run-lease-profiles-v1"
MAX_LEASES = 256
SHA256 = re.compile(r"^[0-9a-f]{64}$")
INSTALL_PENDING = Path("/var/lib/secure-sandbox/policy-backups/run-leases-gateway-install.pending")


class LeaseDenied(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_uuid4(value: str, name: str) -> str:
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return str(parsed)


def read_json(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def atomic_json(path: Path, value: dict[str, Any], mode: int,
                owner: tuple[int, int] | None = None) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.new"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if owner is not None:
            os.chown(temporary, owner[0], owner[1])
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_profiles(path: Path) -> dict[str, Any]:
    value = read_json(path)
    if value.get("schema") != PROFILE_SCHEMA:
        raise ValueError("invalid lease profile schema")
    if value.get("model") != "abliterated-model-large-v2":
        raise ValueError("invalid lease profile model")
    for price in ("input_microusd_per_million_tokens", "output_microusd_per_million_tokens"):
        if not isinstance(value.get(price), int) or value[price] < 1:
            raise ValueError(f"invalid {price}")
    profiles = value.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("lease profiles are missing")
    required = {
        "duration_seconds", "maximum_total_seconds", "max_requests",
        "max_input_tokens", "max_output_tokens", "max_cost_microusd",
    }
    for name, profile in profiles.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) or not isinstance(profile, dict):
            raise ValueError("invalid lease profile")
        if set(profile) != required or any(not isinstance(profile[key], int) or profile[key] < 1 for key in required):
            raise ValueError(f"invalid lease profile: {name}")
        if profile["duration_seconds"] > profile["maximum_total_seconds"]:
            raise ValueError(f"invalid lease duration: {name}")
    return value


def cost_microusd(input_tokens: int, output_tokens: int, profiles: dict[str, Any]) -> int:
    numerator = (
        input_tokens * profiles["input_microusd_per_million_tokens"]
        + output_tokens * profiles["output_microusd_per_million_tokens"]
    )
    return (numerator + 999_999) // 1_000_000


def validate_active_state(lease: dict[str, Any], counter: dict[str, Any], run_id: str) -> None:
    if lease.get("schema") != LEASE_SCHEMA or counter.get("schema") != COUNTER_SCHEMA:
        raise ValueError("invalid lease state schema")
    lease_id = canonical_uuid4(str(lease.get("lease_id", "")), "lease ID")
    if lease.get("run_id") != run_id or counter.get("run_id") != run_id:
        raise ValueError("lease run ID mismatch")
    if counter.get("lease_id") != lease_id:
        raise ValueError("lease identity mismatch")
    if not isinstance(lease.get("profile"), str) or not lease["profile"]:
        raise ValueError("invalid lease profile")
    if not SHA256.fullmatch(str(lease.get("relay_sha256", ""))):
        raise ValueError("invalid lease relay identity")
    if not isinstance(lease.get("model"), str) or not lease["model"]:
        raise ValueError("invalid lease model")
    if not SHA256.fullmatch(str(lease.get("policy_sha256", ""))):
        raise ValueError("invalid lease policy identity")
    for name in ("issued_at", "expires_at", "maximum_expires_at", "renewals"):
        value = lease.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid lease {name}")
    limits = lease.get("limits")
    if not isinstance(limits, dict):
        raise ValueError("invalid lease limits")
    for name in ("max_requests", "max_input_tokens", "max_output_tokens", "max_cost_microusd"):
        value = limits.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"invalid lease limit: {name}")
    pricing = lease.get("pricing")
    if not isinstance(pricing, dict):
        raise ValueError("invalid lease pricing")
    for name in ("input_microusd_per_million_tokens", "output_microusd_per_million_tokens"):
        value = pricing.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"invalid lease price: {name}")
    for name in ("requests", "input_tokens", "output_tokens", "cost_microusd", "updated_at"):
        value = counter.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid lease counter: {name}")


class LeaseStore:
    def __init__(self, state: Path, profiles: Path, broker_config: Path, policy_hash: Path):
        self.state = state
        self.leases = state / "leases"
        self.counters = state / "counters"
        self.summaries = state / "summaries"
        self.profiles_path = profiles
        self.broker_config = broker_config
        self.policy_hash_path = policy_hash
        self.lock_path = self.counters / ".lock"

    @contextmanager
    def lock(self):
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "r+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def _bounded_entries(self, directory: Path, suffix: str = ".json") -> list[Path]:
        entries = sorted(path for path in directory.iterdir() if path.name.endswith(suffix))
        if len(entries) > MAX_LEASES:
            raise LeaseDenied("lease_state_limit_exceeded")
        return entries

    def _policy_hash(self) -> str:
        value = self.policy_hash_path.read_text(encoding="ascii").strip()
        if not SHA256.fullmatch(value):
            raise LeaseDenied("lease_policy_unavailable")
        return value

    def _discard_active(self, run_id: str) -> None:
        changed = []
        for directory in (self.leases, self.counters):
            try:
                (directory / f"{run_id}.json").unlink()
                changed.append(directory)
            except FileNotFoundError:
                pass
        for directory in changed:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _relay_identity(self) -> str:
        config = read_json(self.broker_config)
        values = config.get("allowed_client_sha256")
        if not isinstance(values, list) or len(values) != 1 or not SHA256.fullmatch(str(values[0])):
            raise LeaseDenied("lease_relay_identity_unavailable")
        return str(values[0])

    def issue(self, run_id: str, profile_name: str, now: int | None = None) -> dict[str, Any]:
        if INSTALL_PENDING.exists():
            raise LeaseDenied("lease_deployment_incomplete")
        run_id = canonical_uuid4(run_id, "run ID")
        now = int(time.time()) if now is None else int(now)
        self.recover(now)
        profiles = load_profiles(self.profiles_path)
        profile = profiles["profiles"].get(profile_name)
        if not isinstance(profile, dict):
            raise ValueError("unknown lease profile")
        with self.lock():
            if len(self._bounded_entries(self.leases)) >= MAX_LEASES:
                raise LeaseDenied("lease_state_limit_exceeded")
            if (self.leases / f"{run_id}.json").exists() or (self.summaries / f"{run_id}.json").exists():
                raise FileExistsError("run lease already exists")
            lease_id = str(uuid.uuid4())
            lease = {
                "schema": LEASE_SCHEMA,
                "lease_id": lease_id,
                "run_id": run_id,
                "profile": profile_name,
                "issued_at": now,
                "expires_at": now + profile["duration_seconds"],
                "maximum_expires_at": now + profile["maximum_total_seconds"],
                "relay_sha256": self._relay_identity(),
                "model": profiles["model"],
                "policy_sha256": self._policy_hash(),
                "limits": {key: profile[key] for key in (
                    "max_requests", "max_input_tokens", "max_output_tokens", "max_cost_microusd"
                )},
                "pricing": {
                    "input_microusd_per_million_tokens": profiles["input_microusd_per_million_tokens"],
                    "output_microusd_per_million_tokens": profiles["output_microusd_per_million_tokens"],
                },
                "renewals": 0,
            }
            counter = {
                "schema": COUNTER_SCHEMA,
                "lease_id": lease_id,
                "run_id": run_id,
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_microusd": 0,
                "updated_at": now,
            }
            lease_directory = self.leases.stat()
            counter_directory = self.counters.stat()
            atomic_json(self.leases / f"{run_id}.json", lease, 0o640, (lease_directory.st_uid, lease_directory.st_gid))
            atomic_json(self.counters / f"{run_id}.json", counter, 0o600, (counter_directory.st_uid, counter_directory.st_gid))
        emit("lease_issued", lease)
        return lease

    def reserve(self, run_id: str, relay_sha256: str, model: str, input_tokens: int,
                output_tokens: int, now: int | None = None) -> dict[str, Any]:
        if INSTALL_PENDING.exists():
            raise LeaseDenied("lease_deployment_incomplete")
        try:
            run_id = canonical_uuid4(run_id, "run ID")
        except ValueError as error:
            raise LeaseDenied("lease_run_id_invalid") from error
        if not SHA256.fullmatch(relay_sha256):
            raise LeaseDenied("lease_relay_identity_invalid")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (input_tokens, output_tokens)):
            raise LeaseDenied("lease_reservation_invalid")
        now = int(time.time()) if now is None else int(now)
        with self.lock():
            lease_path = self.leases / f"{run_id}.json"
            counter_path = self.counters / f"{run_id}.json"
            if (self.summaries / f"{run_id}.json").exists():
                raise LeaseDenied("lease_closed")
            if not lease_path.is_file() or not counter_path.is_file():
                raise LeaseDenied("lease_not_found")
            try:
                lease = read_json(lease_path)
                counter = read_json(counter_path)
                validate_active_state(lease, counter, run_id)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                raise LeaseDenied("lease_state_invalid") from error
            if now >= int(lease.get("expires_at", 0)):
                raise LeaseDenied("lease_expired")
            if lease.get("relay_sha256") != relay_sha256:
                raise LeaseDenied("lease_relay_mismatch")
            if lease.get("model") != model:
                raise LeaseDenied("lease_model_mismatch")
            if lease.get("policy_sha256") != self._policy_hash():
                raise LeaseDenied("lease_policy_mismatch")
            pricing = {"input_microusd_per_million_tokens": lease["pricing"]["input_microusd_per_million_tokens"],
                       "output_microusd_per_million_tokens": lease["pricing"]["output_microusd_per_million_tokens"]}
            increment_cost = cost_microusd(input_tokens, output_tokens, pricing)
            proposed = {
                "requests": int(counter["requests"]) + 1,
                "input_tokens": int(counter["input_tokens"]) + input_tokens,
                "output_tokens": int(counter["output_tokens"]) + output_tokens,
                "cost_microusd": int(counter["cost_microusd"]) + increment_cost,
            }
            limits = lease.get("limits", {})
            mapping = {
                "requests": "max_requests", "input_tokens": "max_input_tokens",
                "output_tokens": "max_output_tokens", "cost_microusd": "max_cost_microusd",
            }
            for counter_name, limit_name in mapping.items():
                if proposed[counter_name] > int(limits.get(limit_name, -1)):
                    raise LeaseDenied(f"lease_{counter_name}_exhausted")
            counter.update(proposed)
            counter["updated_at"] = now
            atomic_json(counter_path, counter, 0o600)
            return {"lease_id": lease["lease_id"], "reserved": {
                "input_tokens": input_tokens, "output_tokens": output_tokens,
                "cost_microusd": increment_cost,
            }, "cumulative": proposed, "expires_at": lease["expires_at"]}

    def renew(self, run_id: str, seconds: int, now: int | None = None) -> dict[str, Any]:
        run_id = canonical_uuid4(run_id, "run ID")
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 60:
            raise ValueError("renewal must be at least 60 seconds")
        now = int(time.time()) if now is None else int(now)
        with self.lock():
            path = self.leases / f"{run_id}.json"
            if not path.is_file() or (self.summaries / f"{run_id}.json").exists():
                raise LeaseDenied("lease_not_active")
            try:
                lease = read_json(path)
                counter = read_json(self.counters / f"{run_id}.json")
                validate_active_state(lease, counter, run_id)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                raise LeaseDenied("lease_state_invalid") from error
            if now >= int(lease["expires_at"]):
                raise LeaseDenied("lease_expired")
            proposed = int(lease["expires_at"]) + seconds
            if proposed > int(lease["maximum_expires_at"]):
                raise LeaseDenied("lease_renewal_limit_exceeded")
            lease["expires_at"] = proposed
            lease["renewals"] = int(lease.get("renewals", 0)) + 1
            lease_directory = self.leases.stat()
            atomic_json(path, lease, 0o640, (lease_directory.st_uid, lease_directory.st_gid))
        emit("lease_renewed", lease)
        return lease

    def finalize(self, run_id: str, reason: str, now: int | None = None) -> dict[str, Any]:
        run_id = canonical_uuid4(run_id, "run ID")
        if reason not in {"completed", "expired", "operator_closed", "launch_failed", "session_failed"}:
            raise ValueError("invalid finalization reason")
        now = int(time.time()) if now is None else int(now)
        with self.lock():
            summary_path = self.summaries / f"{run_id}.json"
            if summary_path.exists():
                summary = read_json(summary_path)
                self._discard_active(run_id)
                return summary
            lease = read_json(self.leases / f"{run_id}.json")
            counter = read_json(self.counters / f"{run_id}.json")
            validate_active_state(lease, counter, run_id)
            summary = {
                "schema": SUMMARY_SCHEMA, "lease": lease, "final_counters": counter,
                "finalized_at": now, "reason": reason,
            }
            atomic_json(summary_path, summary, 0o444)
            self._discard_active(run_id)
        emit("lease_finalized", {"run_id": run_id, "lease_id": lease["lease_id"], "reason": reason})
        return summary

    def status(self, run_id: str) -> dict[str, Any]:
        run_id = canonical_uuid4(run_id, "run ID")
        with self.lock():
            summary_path = self.summaries / f"{run_id}.json"
            if summary_path.exists():
                summary = read_json(summary_path)
                return {"lease": summary["lease"], "counters": summary["final_counters"],
                        "summary": summary}
            lease = read_json(self.leases / f"{run_id}.json")
            counter = read_json(self.counters / f"{run_id}.json")
            validate_active_state(lease, counter, run_id)
            return {"lease": lease, "counters": counter, "summary": None}

    def recover(self, now: int | None = None) -> list[str]:
        now = int(time.time()) if now is None else int(now)
        with self.lock():
            paths = self._bounded_entries(self.leases)
            expired = []
            for path in paths:
                try:
                    lease = read_json(path)
                    run_id = canonical_uuid4(str(lease.get("run_id", "")), "run ID")
                    if lease.get("schema") != LEASE_SCHEMA:
                        raise ValueError("invalid lease schema")
                    if (self.summaries / f"{run_id}.json").exists():
                        self._discard_active(run_id)
                    elif now >= int(lease.get("expires_at", 0)):
                        expired.append(run_id)
                except (OSError, ValueError, json.JSONDecodeError) as error:
                    raise LeaseDenied("lease_state_invalid") from error
        for run_id in expired:
            self.finalize(run_id, "expired", now)
        return expired


def emit(event: str, value: dict[str, Any]) -> None:
    record = {
        "event": event,
        "run_id": str(value.get("run_id", "preflight")),
        "lease_id": str(value.get("lease_id", "")),
        "profile": str(value.get("profile", "")),
        "expires_at": int(value.get("expires_at", 0)),
        "reason": str(value.get("reason", "")),
    }
    try:
        syslog.openlog("secure-sandbox-lease")
        syslog.syslog(syslog.LOG_INFO, json.dumps(record, separators=(",", ":"), sort_keys=True))
    finally:
        syslog.closelog()


def default_store(args: argparse.Namespace) -> LeaseStore:
    return LeaseStore(Path(args.state), Path(args.profiles), Path(args.broker_config), Path(args.policy_hash))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="/var/lib/secure-sandbox/run-leases")
    parser.add_argument("--profiles", default="/etc/secure-sandbox/run-lease-profiles.json")
    parser.add_argument("--broker-config", default="/etc/secure-sandbox/broker.json")
    parser.add_argument("--policy-hash", default="/etc/secure-sandbox/policy.sha256")
    sub = parser.add_subparsers(dest="command", required=True)
    issue = sub.add_parser("issue"); issue.add_argument("run_id"); issue.add_argument("profile")
    renew = sub.add_parser("renew"); renew.add_argument("run_id"); renew.add_argument("seconds", type=int)
    final = sub.add_parser("finalize"); final.add_argument("run_id"); final.add_argument("reason")
    status = sub.add_parser("status"); status.add_argument("run_id")
    sub.add_parser("recover")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run-lease administration requires root")
    store = default_store(args)
    if args.command == "issue": result = store.issue(args.run_id, args.profile)
    elif args.command == "renew": result = store.renew(args.run_id, args.seconds)
    elif args.command == "finalize": result = store.finalize(args.run_id, args.reason)
    elif args.command == "status": result = store.status(args.run_id)
    else: result = {"recovered": store.recover()}
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LeaseDenied, ValueError, OSError, json.JSONDecodeError) as error:
        code = error.code if isinstance(error, LeaseDenied) else type(error).__name__
        print(json.dumps({"error": code}, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)

