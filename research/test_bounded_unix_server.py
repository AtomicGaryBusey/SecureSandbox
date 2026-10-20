#!/usr/bin/env python3

import multiprocessing
import socket
import tempfile
import time
import unittest
from pathlib import Path

import bounded_unix_server


def run_server(path: str) -> None:
    bounded_unix_server.serve(path, 1024, 2, lambda raw: b"ok:" + raw,
                              lambda: b"incomplete")


class BoundedUnixServerTests(unittest.TestCase):
    def test_slow_client_does_not_starve_complete_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "broker.sock")
            process = multiprocessing.get_context("fork").Process(target=run_server, args=(path,))
            process.start()
            try:
                for _ in range(100):
                    if Path(path).exists(): break
                    time.sleep(0.01)
                slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                slow.connect(path); slow.sendall(b"partial")
                complete = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                complete.settimeout(1); complete.connect(path); complete.sendall(b"request")
                complete.shutdown(socket.SHUT_WR)
                self.assertEqual(complete.recv(64), b"ok:request")
                complete.close(); slow.close()
            finally:
                process.terminate(); process.join(2)


if __name__ == "__main__": unittest.main()
