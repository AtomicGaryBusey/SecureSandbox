#!/usr/bin/env python3

import json
import socket
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler

from shared.bounded_http import (
    AbsoluteFramingHandler,
    BoundedHTTPServer,
    RequestIncomplete,
)


class Handler(AbsoluteFramingHandler, BaseHTTPRequestHandler):
    framing_seconds = 0.35
    write_seconds = 0.35
    protocol_version = "HTTP/1.1"

    def reply(self, status: int, value: dict) -> None:
        if not self.complete_framing():
            return
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        if self.path == "/large":
            self.complete_framing()
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            body = b"x" * (4 * 1024 * 1024)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        self.reply(200, {"status": "ok"})

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= length <= 1024:
                raise ValueError
            body = self.read_exact_body(length)
        except RequestIncomplete:
            self.close_connection = True
            return
        except ValueError:
            self.reply(400, {"error": "invalid_length"})
            return
        self.reply(200, {"bytes": len(body)})

    def log_message(self, *_args: object) -> None:
        return


class BoundedHTTPTests(unittest.TestCase):
    def server(self):
        server = BoundedHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def request(self, server, wire: bytes) -> bytes:
        client = socket.create_connection(server.server_address, timeout=1)
        self.addCleanup(client.close)
        client.sendall(wire)
        client.settimeout(1)
        response = bytearray()
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return bytes(response)
            response.extend(chunk)

    def test_complete_request_succeeds(self):
        response = self.request(
            self.server(), b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
        self.assertIn(b"200 OK", response)

    def test_slow_headers_cannot_hold_serial_server(self):
        server = self.server()
        slow = socket.create_connection(server.server_address, timeout=1)
        self.addCleanup(slow.close)
        slow.sendall(b"GET / HTTP/1.1\r\nHost:")
        started = time.monotonic()
        time.sleep(0.45)
        response = self.request(
            server, b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
        self.assertIn(b"200 OK", response)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_slow_body_cannot_extend_absolute_deadline(self):
        server = self.server()
        slow = socket.create_connection(server.server_address, timeout=1)
        self.addCleanup(slow.close)
        slow.sendall(
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 9\r\n"
            b"Connection: close\r\n\r\n{")
        for _ in range(3):
            time.sleep(0.15)
            try:
                slow.sendall(b"x")
            except OSError:
                break
        response = self.request(
            server, b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
        self.assertIn(b"200 OK", response)

    def test_tls_handshake_has_absolute_deadline(self):
        class NeverCompletes:
            def __init__(self, raw):
                self.raw = raw

            def settimeout(self, value):
                self.raw.settimeout(value)

            def do_handshake(self):
                raise ssl.SSLWantReadError()

            def close(self):
                self.raw.close()

        class Context:
            def wrap_socket(self, raw, **_kwargs):
                return NeverCompletes(raw)

        server = BoundedHTTPServer(
            ("127.0.0.1", 0), Handler, tls_context=Context(),
            handshake_seconds=0.1)
        self.addCleanup(server.server_close)
        client = socket.create_connection(server.server_address, timeout=1)
        self.addCleanup(client.close)
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, "tls_handshake_deadline_exceeded"):
            server.get_request()
        self.assertLess(time.monotonic() - started, 0.5)

    def test_non_reading_client_cannot_hold_serial_server(self):
        server = self.server()
        blocked = socket.create_connection(server.server_address, timeout=1)
        self.addCleanup(blocked.close)
        blocked.sendall(
            b"GET /large HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
        time.sleep(0.45)
        response = self.request(
            server, b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
        self.assertIn(b"200 OK", response)


if __name__ == "__main__":
    unittest.main()
