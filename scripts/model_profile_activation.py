#!/usr/bin/env python3
"""Create and submit exact, non-secret model-profile activation plans."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))
import model_profiles  # noqa: E402

BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
CONTROL = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
OP_AGENTS = Path.home() / ".local/bin/op-agents"
SCHEMA = "secure-sandbox-model-profile-activation-plan-v1"
IDENTITY_FIELDS = ("adapter", "mode", "model", "profile_id", "profile_sha256", "vendor_id")


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def global_ipv4(hostname: str) -> list[str]:
    answers = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
    addresses = sorted({answer[4][0] for answer in answers})
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("model_profile_upstream_addresses_invalid")
    return addresses


def active_identity() -> dict:
    observed = []
    for host, operation in (("sandbox-gateway-control", "model-profile-status"),
                            ("sandbox-research-control", "model-profile-research-status")):
        result = subprocess.run(
            [str(CONTROL), "client", "--ssh-config", str(SSH_CONFIG), host,
             "run", operation],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=15,
        )
        if result.returncode or len(result.stdout) > 64 * 1024:
            raise RuntimeError("model_profile_current_generation_unavailable")
        try: value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("model_profile_current_generation_unavailable") from error
        identity = {key:value.get(key) for key in IDENTITY_FIELDS}
        if (identity["adapter"] not in {
                "anthropic-messages-v1", "openai-responses-v1", "google-openai-chat-v1"}
                or identity["mode"] not in {"mock", "production"}
                or not all(isinstance(identity[key], str) and identity[key]
                           for key in IDENTITY_FIELDS)):
            raise RuntimeError("model_profile_current_generation_invalid")
        observed.append(identity)
    if observed[0] != observed[1]:
        raise RuntimeError("model_profile_current_generation_mismatch")
    return observed[0]


def create_plan(profile_id: str, mode: str = "production", now: int | None = None) -> dict:
    if mode not in {"mock", "production"}:
        raise ValueError("model_profile_activation_mode_invalid")
    catalog_path = ROOT / "config/model-profiles.json"
    catalog = model_profiles.load_catalog(catalog_path)
    matches = [item for item in catalog["profiles"] if item["profile_id"] == profile_id]
    if len(matches) != 1:
        raise ValueError("model_profile_not_found")
    profile = matches[0]
    revision = model_profiles.profile_revision(profile)
    hostname = urllib.parse.urlsplit(profile["upstream_origin"]).hostname
    addresses = [] if mode == "mock" else global_ipv4(str(hostname))
    oauth_addresses = (global_ipv4("oauth2.googleapis.com")
                       if mode == "production" and profile["adapter"] == "google-openai-chat-v1"
                       else [])
    created = int(time.time()) if now is None else now
    current = active_identity()
    desired = {
        "adapter": profile["adapter"],
        "allowed_models": [profile["model_id"]],
        "allowed_upstream_hosts": [] if mode == "mock" else [hostname],
        "credential_scheme": profile["credential"]["scheme"],
        "deployment": profile["deployment"],
        "max_request_bytes": profile["limits"]["max_request_bytes"],
        "max_response_bytes": profile["limits"]["max_response_bytes"],
        "max_tokens": profile["limits"]["max_output_tokens"],
        "mode": mode,
        "oauth_ipv4": oauth_addresses,
        "profile_id": profile["profile_id"],
        "profile_sha256": revision,
        "rate_limit_requests": profile["limits"]["rate_limit_requests"],
        "rate_limit_window_seconds": profile["limits"]["rate_limit_window_seconds"],
        "client_timeout_seconds": profile["limits"]["client_timeout_seconds"],
        "settings": profile["settings"],
        "upstream_ipv4": addresses,
        "upstream_origin": profile["upstream_origin"],
        "upstream_timeout_seconds": profile["limits"]["upstream_timeout_seconds"],
        "vendor_id": profile["vendor_id"],
    }
    lease = {
        "adapter": profile["adapter"], "model": profile["model_id"],
        "profile_id": profile["profile_id"], "profile_sha256": revision,
        "vendor_id": profile["vendor_id"], "profiles": profile["lease_profiles"],
        **profile["pricing"], "schema": "secure-sandbox-run-lease-profiles-v1",
    }
    plan = {
        "activation_id": str(uuid.uuid4()), "broker": desired,
        "created_at": created, "credential_reference": profile["credential"]["reference"],
        "current": current, "current_generation_sha256": digest(current),
        "display_name": profile["display_name"], "expires_at": created + 300,
        "lease_profiles": lease, "model_name": profile["model_name"],
        "schema": SCHEMA,
    }
    plan["credential_reference_sha256"] = hashlib.sha256(
        profile["credential"]["reference"].encode("ascii")
    ).hexdigest()
    plan["plan_sha256"] = digest(plan)
    return plan


def submit(plan: dict, agent: str, session: str) -> int:
    if plan["broker"]["mode"] == "production":
        reader = subprocess.Popen([str(OP_AGENTS), "read", plan["credential_reference"]],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert reader.stdout is not None
        stage = subprocess.run(
            [str(CONTROL), "client", "--ssh-config", str(SSH_CONFIG),
             "sandbox-gateway-control", "pipe", "model-profile-activate",
             "stage-credential", plan["broker"]["profile_sha256"],
             plan["credential_reference_sha256"], plan["broker"]["credential_scheme"]],
            stdin=reader.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=30,
        )
        reader.stdout.close(); reader_status = reader.wait(timeout=10)
        if reader_status != 0 or stage.returncode != 0:
            return 1
    parameters = {"plan": plan}
    command = [str(BROKER), "request", "--agent", agent, "--session", session,
               "--purpose", "Activate this exact SecureSandbox model profile",
               "--resource", "Gateway broker and Research harness model authority",
               "--operation", "model-profile-activate", "--parameters-json",
               canonical(parameters).decode("ascii")]
    return subprocess.run(command, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("plan", "activate"))
    parser.add_argument("profile_id")
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    args = parser.parse_args()
    plan = create_plan(args.profile_id, "mock" if args.mock else "production")
    print(json.dumps(plan, ensure_ascii=True, indent=2, sort_keys=True))
    if args.operation == "plan":
        return 0
    if not args.requesting_agent or not args.requesting_session:
        parser.error("activate requires attributed agent and session")
    return submit(plan, args.requesting_agent, args.requesting_session)


if __name__ == "__main__":
    raise SystemExit(main())
