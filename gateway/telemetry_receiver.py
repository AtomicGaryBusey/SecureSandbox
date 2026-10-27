#!/usr/bin/env python3
"""mTLS metadata receiver with a bounded local spool."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import ssl
import time
import uuid
from http.server import BaseHTTPRequestHandler

from shared.bounded_http import AbsoluteFramingHandler, BoundedHTTPServer, RequestIncomplete

LISTEN = ("172.30.10.1", 9443)
SPOOL = "/var/lib/secure-sandbox/telemetry/current.jsonl"
SPOOL_LOCK = "/var/lib/secure-sandbox/telemetry/.spool.lock"
MAX_BODY = 1024 * 1024
MAX_EVENTS = 100
MAX_FILE = 10 * 1024 * 1024
ROTATIONS = 5
STRING_LIMIT = 512

FIELDS = {
    "RunId": str,
    "VmId": str,
    "AgentId": str,
    "EventType": str,
    "Severity": str,
    "Decision": str,
    "Destination": str,
    "DestinationPort": int,
    "Status": int,
    "RequestBytes": int,
    "ResponseBytes": int,
    "RequestId": str,
    "PolicyHash": str,
    "Message": str,
}


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    allowed = config.get("allowed_client_sha256")
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("telemetry client allowlist is empty")
    return config


def normalize(event: object) -> dict:
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    result: dict[str, object] = {
        "TimeGenerated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    for name, expected in FIELDS.items():
        value = event.get(name)
        if value is None:
            result[name] = 0 if expected is int else ""
        elif expected is str and isinstance(value, str):
            result[name] = value[:STRING_LIMIT]
        elif expected is int and isinstance(value, int) and not isinstance(value, bool):
            result[name] = value
        else:
            raise ValueError(f"invalid field: {name}")
    if not result["EventType"]:
        raise ValueError("EventType is required")
    return result


def append_events(events: list[dict]) -> None:
    # Receiver and local exporter are separate processes.  A dedicated lock
    # serializes rotation and append across both, rather than locking an inode
    # that may be renamed during rotation.
    lock_flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    lock_descriptor = os.open(SPOOL_LOCK, lock_flags, 0o600)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if os.path.islink(SPOOL):
            raise RuntimeError("spool must not be a symlink")
        if os.path.exists(SPOOL) and os.path.getsize(SPOOL) >= MAX_FILE:
            oldest = f"{SPOOL}.{ROTATIONS}"
            if os.path.exists(oldest):
                os.unlink(oldest)
            for index in range(ROTATIONS - 1, 0, -1):
                source = f"{SPOOL}.{index}"
                if os.path.exists(source):
                    os.replace(source, f"{SPOOL}.{index + 1}")
            os.replace(SPOOL, f"{SPOOL}.1")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        descriptor = os.open(SPOOL, flags, 0o600)
        try:
            # The Azure shipper has read-only supplementary membership in the
            # telemetry group.  It never shares the receiver's write access.
            os.fchmod(descriptor, 0o640)
            payload = b"".join(
                json.dumps(event, separators=(",", ":"), sort_keys=True).encode() + b"\n"
                for event in events
            )
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(os.path.dirname(SPOOL), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(lock_descriptor)


class Receiver(BoundedHTTPServer):
    allow_reuse_address = True

    def __init__(self, config: dict, context: ssl.SSLContext | None = None):
        super().__init__(LISTEN, Handler, tls_context=context)
        self.config = config


class Handler(AbsoluteFramingHandler, BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SecureSandboxTelemetry/1"
    sys_version = ""

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _json(self, status: int, value: dict) -> None:
        if not self.complete_framing():
            self.close_connection = True
            return
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _authorized(self) -> bool:
        certificate = self.connection.getpeercert(binary_form=True)
        if not certificate:
            return False
        fingerprint = hashlib.sha256(certificate).hexdigest()
        return fingerprint in self.server.config["allowed_client_sha256"]  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        if not self._authorized() or self.path != "/healthz":
            self._json(404, {"error": "not_found"})
            return
        self._json(200, {"status": "ok"})

    def do_POST(self) -> None:
        request_id = str(uuid.uuid4())
        if not self._authorized():
            self._json(403, {"error": "not_authorized"})
            return
        if self.path != "/v1/events":
            self._json(404, {"error": "not_found"})
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._json(400, {"error": "transfer_encoding_not_allowed"})
            return
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            self._json(411, {"error": "single_content_length_required"})
            return
        try:
            length = int(lengths[0])
            if length < 2 or length > MAX_BODY:
                raise ValueError
            payload = json.loads(self.read_exact_body(length).decode("utf-8"))
            if not isinstance(payload, list) or not 1 <= len(payload) <= MAX_EVENTS:
                raise ValueError
            events = [normalize(item) for item in payload]
            append_events(events)
        except RequestIncomplete:
            self.close_connection = True
            return
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, OSError):
            self._json(400, {"error": "invalid_event_batch", "request_id": request_id})
            return
        print(
            json.dumps(
                {"event": "telemetry_received", "count": len(events), "request_id": request_id},
                separators=(",", ":"),
            ),
            flush=True,
        )
        self._json(202, {"accepted": len(events), "request_id": request_id})

    def _method_not_allowed(self) -> None:
        self._json(405, {"error": "method_not_allowed"})

    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_CONNECT = _method_not_allowed

    def framing_expired(self) -> None:
        print(json.dumps({"event":"telemetry_rejected","error":"request_incomplete"},
                         separators=(",", ":"), sort_keys=True), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(config["server_certificate"], config["server_private_key"])
    context.load_verify_locations(cafile=config["client_ca_certificate"])
    server = Receiver(config, context)
    print(json.dumps({"event": "telemetry_receiver_started"}), flush=True)
    server.serve_forever(0.5)


if __name__ == "__main__":
    main()
