#!/usr/bin/env python3
"""Ship already-encrypted transcript chunks to the Gateway over pinned mTLS."""

import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import time

OUTBOX = "/var/lib/secure-sandbox/conversation-outbox"
QUARANTINE = "/var/lib/secure-sandbox/conversation-quarantine"
IDENTITY = "/etc/secure-sandbox/conversation-transport"
MAX_CHUNK_BYTES = 5 * 1024 * 1024
NAME_RE = re.compile(
    r"^(?:[0-9a-f-]{36}|(?:artifact|source)-[0-9a-f-]{36})-[0-9]{12}-[0-9a-f]{64}\.age$"
)


class PermanentChunkError(RuntimeError):
    pass


def event_name(name: str, success: bool) -> str:
    if name.startswith("artifact-"):
        return "artifact_forwarded" if success else "artifact_forward_failed"
    if name.startswith("source-"):
        return "source_manifest_forwarded" if success else "source_manifest_forward_failed"
    return "conversation_chunk_forwarded" if success else "conversation_forward_failed"


class Connection(http.client.HTTPSConnection):
    def __init__(self):
        context = ssl.create_default_context(cafile=f"{IDENTITY}/ca.crt")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(f"{IDENTITY}/client.crt", f"{IDENTITY}/client.key")
        super().__init__("secure-sandbox-gateway", 9553, timeout=20, context=context)

    def connect(self):
        raw = __import__("socket").create_connection(("172.30.10.1", 9553), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def send(path: str) -> None:
    name = os.path.basename(path)
    if not NAME_RE.fullmatch(name) or os.path.islink(path):
        raise PermanentChunkError("invalid encrypted chunk")
    with open(path, "rb") as handle:
        body = handle.read(MAX_CHUNK_BYTES + 1)
    if not body or len(body) > MAX_CHUNK_BYTES:
        raise PermanentChunkError("invalid encrypted chunk size")
    expected = name[-68:-4]
    if hashlib.sha256(body).hexdigest() != expected:
        raise PermanentChunkError("encrypted chunk hash mismatch")
    connection = Connection()
    try:
        connection.request("PUT", "/v1/chunks/" + name, body=body, headers={
            "Content-Type": "application/age", "Content-Length": str(len(body)),
            "If-None-Match": "*", "X-Content-SHA256": expected,
        })
        response = connection.getresponse()
        response.read(4096)
        if response.status not in (201, 412):
            raise RuntimeError(f"gateway status {response.status}")
    finally:
        connection.close()
    os.unlink(path)


def quarantine(path: str) -> str:
    name = os.path.basename(path)
    if not NAME_RE.fullmatch(name):
        raise PermanentChunkError("invalid quarantine name")
    os.makedirs(QUARANTINE, mode=0o770, exist_ok=True)
    destination = os.path.join(QUARANTINE, name)
    if os.path.lexists(destination):
        raise PermanentChunkError("quarantine collision")
    os.rename(path, destination)
    for directory in (OUTBOX, QUARANTINE):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return destination


def health() -> None:
    connection = Connection()
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        response.read(4096)
        if response.status != 200:
            raise RuntimeError(f"gateway health status {response.status}")
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args()
    if args.health:
        health()
        return
    while True:
        try:
            names = sorted(n for n in os.listdir(OUTBOX) if NAME_RE.fullmatch(n))
            if not names:
                time.sleep(1)
                continue
            name = names[0]
            send(os.path.join(OUTBOX, name))
            print(json.dumps({"event":event_name(name, True),"name":name}), flush=True)
        except PermanentChunkError as error:
            name = locals().get("name", "")
            path = os.path.join(OUTBOX, name)
            quarantined = quarantine(path)
            print(json.dumps({"event":event_name(name, False),"name":name,
                              "error":type(error).__name__,"quarantined":quarantined}), flush=True)
            raise
        except (OSError, RuntimeError, ssl.SSLError, http.client.HTTPException) as error:
            name = locals().get("name", "")
            print(json.dumps({"event":event_name(name, False),"name":name,"error":type(error).__name__}), flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
