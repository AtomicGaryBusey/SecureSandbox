#!/usr/bin/env python3
"""Run a side-effect-free, attributed operator-authorization acceptance probe."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
RESOURCE = "/usr/local/libexec/secure-sandbox-host"
SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:/+-]{0,79}$")
SAFE_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requesting-agent", required=True)
    parser.add_argument("--requesting-session", required=True)
    parser.add_argument("--purpose", default="Live acceptance of Touch ID operator authorization")
    args = parser.parse_args()
    if not SAFE_AGENT.fullmatch(args.requesting_agent):
        parser.error("invalid requesting agent")
    if not SAFE_SESSION.fullmatch(args.requesting_session):
        parser.error("invalid requesting session")
    if not BROKER.is_file():
        print("protected_authorization_broker_unavailable", file=os.sys.stderr)
        return 1
    challenge = str(uuid.uuid4())
    parameters = json.dumps({"challenge": challenge}, separators=(",", ":"), sort_keys=True)
    result = subprocess.run([
        str(BROKER), "request",
        "--agent", args.requesting_agent,
        "--session", args.requesting_session,
        "--purpose", args.purpose,
        "--resource", RESOURCE,
        "--operation", "authorization-probe",
        "--parameters-json", parameters,
    ], check=False)
    if result.returncode == 0:
        print(json.dumps({
            "challenge": challenge,
            "schema": "secure-sandbox-touchid-authorization-probe-v1",
            "status": "succeeded",
        }, sort_keys=True))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
