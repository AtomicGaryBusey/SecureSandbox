#!/usr/bin/env python3
"""Request an attributed, typed installer-store publication."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
STORE = "/Library/Application Support/SecureSandbox/installers"
DIGESTS = {
    "promote": "af78753c94b924c85c4964c670692a853f7c80299a4064e317edad95462e3168",
    "promote-autoinstall": "c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804",
    "repair-store-access": "af78753c94b924c85c4964c670692a853f7c80299a4064e317edad95462e3168",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=tuple(DIGESTS))
    parser.add_argument("--requesting-agent", default=os.environ.get("SECURE_SANDBOX_REQUESTING_AGENT"))
    parser.add_argument("--requesting-session", default=os.environ.get("SECURE_SANDBOX_REQUESTING_SESSION"))
    parser.add_argument("--purpose")
    args = parser.parse_args()
    if not args.requesting_agent or not args.requesting_session:
        parser.error("--requesting-agent and --requesting-session are required for an attributed authorization prompt")
    repo = Path(__file__).resolve().parent.parent
    release_directory = repo / "artifacts/ubuntu-26.04.1"
    operation = {
        "promote": "installer-promote-canonical",
        "promote-autoinstall": "installer-promote-autoinstall",
        "repair-store-access": "installer-repair-store-access",
    }[args.operation]
    purpose = args.purpose or {
        "promote": "Publish the Canonical-signed Ubuntu installer to the protected store",
        "promote-autoinstall": "Publish the reviewed autoinstall derivative to the protected store",
        "repair-store-access": "Repair protected installer-store traversal modes after verification",
    }[args.operation]
    parameters = {
        "repo": str(repo),
        "release_directory": str(release_directory),
        "expected_sha256": DIGESTS[args.operation],
    }
    command = [
        str(BROKER), "request", "--agent", args.requesting_agent,
        "--session", args.requesting_session, "--purpose", purpose,
        "--resource", STORE, "--operation", operation, "--parameters-json",
        json.dumps(parameters, separators=(",", ":"), sort_keys=True),
    ]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
