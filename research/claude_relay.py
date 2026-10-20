#!/usr/bin/env python3
"""Fixed-destination loopback relay from Claude Code to the mTLS Gateway."""

from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


LISTEN = ("127.0.0.1", 18080)
GATEWAY_HOST = "172.30.10.1"
GATEWAY_PORT = 8443
CA_FILE = "/etc/secure-sandbox/relay/ca.crt"
CERT_FILE = "/etc/secure-sandbox/relay/client.crt"
KEY_FILE = "/etc/secure-sandbox/relay/client.key"
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
ALLOWED_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
RUN_ID_FILE = "/run/secure-sandbox/run-id"


def current_run_id() -> str:
    """Read the non-secret, root-controlled run marker."""
    try:
        with open(RUN_ID_FILE, encoding="ascii") as handle:
            value = handle.read(64).strip()
    except OSError:
        return "preflight"
    if value == "boundary-test":
        return value
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return "preflight"
    return str(parsed) if parsed.version == 4 and str(parsed) == value.lower() else "preflight"


def safe_request_path(value: str) -> str:
    """Return bounded path metadata without retaining query parameters."""
    return urllib.parse.urlsplit(value).path[:256]


def safe_query_keys(value: str) -> list[str]:
    """Return bounded query-key metadata while discarding every value."""
    query = urllib.parse.urlsplit(value).query
    keys = {key[:64] for key, _value in urllib.parse.parse_qsl(query, keep_blank_values=True)}
    return sorted(keys)[:16]


def canonical_api_path(value: str) -> str | None:
    """Accept only approved paths, optionally with the exact local beta marker."""
    target = urllib.parse.urlsplit(value)
    if target.fragment or target.path not in ALLOWED_PATHS:
        return None
    if target.query not in {"", "beta=true"}:
        return None
    return target.path


class RelayServer(HTTPServer):
    allow_reuse_address = True


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SecureSandboxClaudeRelay/1"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _audit(self, event: str, **fields: object) -> None:
        print(
            json.dumps(
                {"ts": int(time.time()), "event": event, **fields},
                separators=(",", ":"),
                sort_keys=True,
            ),
            flush=True,
        )

    def _reply(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _deny(
        self, status: int, code: str, request_id: str, run_id: str, request_path: str = ""
    ) -> None:
        fields = {"request_id": request_id, "run_id": run_id, "code": code}
        if request_path:
            fields["path"] = safe_request_path(request_path)
            fields["query_keys"] = safe_query_keys(request_path)
        self._audit("relay_denied", **fields)
        body = json.dumps(
            {"type": "error", "error": {"type": code, "message": code}},
            separators=(",", ":"),
        ).encode()
        self._reply(status, "application/json", body)

    def do_GET(self) -> None:
        request_id = str(uuid.uuid4())
        run_id = current_run_id()
        if self.path != "/healthz":
            self._deny(404, "path_not_allowed", request_id, run_id, self.path)
            return
        self._forward(request_id, run_id, b"", "GET", "/healthz")

    def do_CONNECT(self) -> None:
        self._deny(405, "connect_not_allowed", str(uuid.uuid4()), current_run_id())

    def do_POST(self) -> None:
        request_id = str(uuid.uuid4())
        run_id = current_run_id()
        forward_path = canonical_api_path(self.path)
        if forward_path is None:
            self._deny(404, "path_not_allowed", request_id, run_id, self.path)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._deny(400, "transfer_encoding_not_allowed", request_id, run_id)
            return
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            self._deny(411, "single_content_length_required", request_id, run_id)
            return
        try:
            length = int(lengths[0])
        except (TypeError, ValueError):
            self._deny(400, "invalid_content_length", request_id, run_id)
            return
        if length < 2 or length > MAX_REQUEST_BYTES:
            self._deny(413, "request_size_not_allowed", request_id, run_id)
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._deny(415, "json_required", request_id, run_id)
            return
        body = self.rfile.read(length)
        self._forward(request_id, run_id, body, "POST", forward_path)

    def _forward(
        self, request_id: str, run_id: str, body: bytes, method: str, forward_path: str
    ) -> None:
        started = time.monotonic()
        context = ssl.create_default_context(cafile=CA_FILE)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(CERT_FILE, KEY_FILE)
        connection = http.client.HTTPSConnection(
            GATEWAY_HOST, GATEWAY_PORT, timeout=90, context=context
        )
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": "SecureSandboxClaudeRelay/1",
            "X-Sandbox-Request-Id": request_id,
            "X-Sandbox-Run-Id": run_id,
        }
        response_started = False
        try:
            connection.request(method, forward_path, body=body or None, headers=headers)
            response = connection.getresponse()
            declared = response.getheader("Content-Length")
            if declared is not None and int(declared) > MAX_RESPONSE_BYTES:
                raise RuntimeError("response exceeds limit")
            content_type = response.getheader("Content-Type", "application/json").split(
                ";", 1
            )[0]
            if content_type not in {"application/json", "text/event-stream"}:
                raise RuntimeError("unexpected response content type")
            if content_type == "text/event-stream" and response.status < 300:
                self.send_response(response.status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.send_header("Connection", "close")
                self.end_headers()
                response_started = True
                response_bytes = 0
                while True:
                    chunk = response.read1(16384)
                    if not chunk:
                        break
                    response_bytes += len(chunk)
                    if response_bytes > MAX_RESPONSE_BYTES:
                        raise RuntimeError("response exceeds limit")
                    self.wfile.write(chunk)
                    self.wfile.flush()
                self.close_connection = True
            else:
                result = response.read(MAX_RESPONSE_BYTES + 1)
                if len(result) > MAX_RESPONSE_BYTES:
                    raise RuntimeError("response exceeds limit")
                response_bytes = len(result)
                self._reply(response.status, content_type, result)
            self._audit(
                "relay_complete",
                request_id=request_id,
                run_id=run_id,
                path=forward_path,
                request_bytes=len(body),
                response_bytes=response_bytes,
                status=response.status,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        except Exception as error:
            self._audit(
                "relay_failed", request_id=request_id, run_id=run_id, error=type(error).__name__
            )
            if response_started:
                self.close_connection = True
            else:
                self._deny(502, "gateway_unavailable", request_id, run_id)
        finally:
            connection.close()


def main() -> None:
    server = RelayServer(LISTEN, RelayHandler)
    print(json.dumps({"event": "relay_started", "listen": "127.0.0.1:18080"}), flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
