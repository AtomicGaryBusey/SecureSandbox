#!/usr/bin/env python3
"""Atomically update mTLS leaf-certificate fingerprints during rotation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import stat
import tempfile


def fingerprint(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        der = ssl.PEM_cert_to_DER_cert(handle.read())
    return hashlib.sha256(der).hexdigest()


def update(path: str, new_fingerprint: str, retain_existing: bool) -> None:
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("config is not a regular file")
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    old = value.get("allowed_client_sha256", [])
    if not isinstance(old, list):
        raise ValueError("invalid client allowlist")
    value["allowed_client_sha256"] = list(dict.fromkeys(old + [new_fingerprint])) if retain_existing else [new_fingerprint]
    descriptor, temporary = tempfile.mkstemp(prefix=".fingerprints.", dir=os.path.dirname(path))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.replace(temporary, path)
        temporary = ""
        directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary:
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker-cert", required=True)
    parser.add_argument("--telemetry-cert", required=True)
    parser.add_argument("--conversation-cert", required=True)
    parser.add_argument("--retain-existing", action="store_true")
    args = parser.parse_args()
    update("/etc/secure-sandbox/broker.json", fingerprint(args.broker_cert), args.retain_existing)
    update("/etc/secure-sandbox/telemetry.json", fingerprint(args.telemetry_cert), args.retain_existing)
    update("/etc/secure-sandbox/conversation-receiver.json", fingerprint(args.conversation_cert), args.retain_existing)


if __name__ == "__main__":
    main()
