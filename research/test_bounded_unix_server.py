#!/usr/bin/env python3

import multiprocessing
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

import bounded_unix_server


def run_server(path: str) -> None:
    bounded_unix_server.serve(path, 1024, 2, lambda raw: b"ok:" + raw,
                              lambda: b"incomplete", allowed_uids={os.getuid()},
                              unauthorized=lambda: b"unauthorized",
                              overloaded=lambda: b"busy",
                              peer_uid=lambda _connection: os.getuid())


def run_single_client_server(path: str) -> None:
    bounded_unix_server.serve(
        path, 1024, 2, lambda raw: b"ok:" + raw, lambda: b"incomplete",
        allowed_uids={os.getuid()}, unauthorized=lambda: b"unauthorized",
        overloaded=lambda: b"busy", max_clients=1,
        peer_uid=lambda _connection: os.getuid())


def run_unauthorized_server(path: str) -> None:
    bounded_unix_server.serve(
        path, 1024, 2, lambda raw: b"ok:" + raw, lambda: b"incomplete",
        allowed_uids={os.getuid()}, unauthorized=lambda: b"unauthorized",
        overloaded=lambda: b"busy", peer_uid=lambda _connection: os.getuid() + 1)


def run_failing_handler_server(path: str) -> None:
    def fail(_raw: bytes) -> bytes:
        raise RuntimeError("sensitive handler detail")

    bounded_unix_server.serve(
        path, 1024, 2, fail, lambda: b"incomplete", failed=lambda: b"internal",
        allowed_uids={os.getuid()}, peer_uid=lambda _connection: os.getuid())


class BoundedUnixServerTests(unittest.TestCase):
    def start(self, target, path: str):
        process = multiprocessing.get_context("fork").Process(target=target, args=(path,))
        process.start()
        for _ in range(100):
            if Path(path).exists():
                break
            time.sleep(0.01)
        self.assertTrue(Path(path).exists())
        return process

    def test_slow_client_does_not_starve_complete_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "broker.sock")
            process = self.start(run_server, path)
            try:
                slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                slow.connect(path); slow.sendall(b"partial")
                complete = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                complete.settimeout(1); complete.connect(path); complete.sendall(b"request")
                complete.shutdown(socket.SHUT_WR)
                self.assertEqual(complete.recv(64), b"ok:request")
                complete.close(); slow.close()
            finally:
                process.terminate(); process.join(2)

    def test_absolute_deadline_is_not_extended_by_slow_drip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "broker.sock")
            process = self.start(run_server, path)
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(3); client.connect(path)
                started = time.monotonic()
                for _ in range(6):
                    try:
                        client.sendall(b"x")
                    except OSError:
                        break
                    time.sleep(0.45)
                response = client.recv(64)
                self.assertEqual(response, b"incomplete")
                self.assertLess(time.monotonic() - started, 2.8)
                client.close()
            finally:
                process.terminate(); process.join(2)

    def test_excess_client_gets_fixed_overload_response(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "broker.sock")
            process = self.start(run_single_client_server, path)
            try:
                holding = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                holding.connect(path); holding.sendall(b"partial")
                time.sleep(0.05)
                excess = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                excess.settimeout(1); excess.connect(path)
                self.assertEqual(excess.recv(64), b"busy")
                excess.close(); holding.close()
            finally:
                process.terminate(); process.join(2)

    def test_unauthorized_peer_gets_fixed_response_without_handler_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "broker.sock")
            process = self.start(run_unauthorized_server, path)
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(1); client.connect(path)
                self.assertEqual(client.recv(64), b"unauthorized")
                client.close()
            finally:
                process.terminate(); process.join(2)

    def test_handler_failure_is_isolated_and_content_free(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "broker.sock")
            process = self.start(run_failing_handler_server, path)
            try:
                failed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                failed.settimeout(1); failed.connect(path); failed.sendall(b"secret")
                failed.shutdown(socket.SHUT_WR)
                self.assertEqual(failed.recv(64), b"internal")
                failed.close()
                again = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                again.settimeout(1); again.connect(path); again.sendall(b"other")
                again.shutdown(socket.SHUT_WR)
                self.assertEqual(again.recv(64), b"internal")
                again.close()
            finally:
                process.terminate(); process.join(2)

    def test_untrusted_existing_path_is_not_unlinked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sock"
            path.write_text("do not delete", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "socket_path_untrusted"):
                bounded_unix_server.serve(path, 10, 1, lambda raw: raw,
                                          lambda: b"incomplete")
            self.assertEqual(path.read_text(encoding="utf-8"), "do not delete")


if __name__ == "__main__": unittest.main()
