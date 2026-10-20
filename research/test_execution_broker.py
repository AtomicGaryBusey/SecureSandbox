#!/usr/bin/env python3

import base64
import hashlib
import json
import socket
import threading
import time
import unittest
import uuid
from unittest import mock

import execution_broker


class ExecutionBrokerTransportTests(unittest.TestCase):
    @staticmethod
    def read_response(connection):
        chunks = []
        while True:
            value = connection.recv(4096)
            if not value:
                return b"".join(chunks)
            chunks.append(value)

    def run_server(self, handler=execution_broker.Handler):
        original_timeout = execution_broker.REQUEST_READ_TIMEOUT_SECONDS
        execution_broker.REQUEST_READ_TIMEOUT_SECONDS = 0.15
        server = execution_broker.HTTPServer(("127.0.0.1", 0), handler)
        server.config = {"token": "x" * 64}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(setattr, execution_broker, "REQUEST_READ_TIMEOUT_SECONDS", original_timeout)
        self.addCleanup(thread.join, 1)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def assert_following_request_is_served(self, server, maximum_seconds=0.45):
        started = time.monotonic()
        second = socket.create_connection(server.server_address, timeout=1)
        try:
            second.sendall(
                b"POST /v1/run-python HTTP/1.1\r\nHost: localhost\r\n"
                b"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
            )
            second.settimeout(1)
            self.assertIn(b"400", self.read_response(second))
            self.assertLess(time.monotonic() - started, maximum_seconds)
        finally:
            second.close()

    def test_partial_body_cannot_starve_following_request(self):
        server = self.run_server()
        first = socket.create_connection(server.server_address, timeout=1)
        try:
            first.sendall(
                b"POST /v1/run-python HTTP/1.1\r\nHost: localhost\r\n"
                b"Content-Length: 100\r\nConnection: close\r\n\r\n{}"
            )
            time.sleep(0.25)
            first.settimeout(1)
            response = self.read_response(first)
            self.assertIn(b"408", response)
            self.assertIn(b"request_incomplete", response)
            self.assert_following_request_is_served(server)
        finally:
            first.close()

    def test_slow_drip_cannot_extend_absolute_framing_deadline(self):
        server = self.run_server()
        first = socket.create_connection(server.server_address, timeout=1)
        first.sendall(
            b"POST /v1/run-python HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Length: 100\r\nConnection: close\r\n\r\n"
        )
        started = time.monotonic()
        try:
            with mock.patch.object(execution_broker, "audit") as audit:
                while time.monotonic() - started < 0.13:
                    try:
                        first.sendall(b"x")
                    except OSError:
                        break
                    time.sleep(0.05)
                response = self.read_response(first)
                self.assertIn(b"408", response)
                incomplete = [call for call in audit.call_args_list
                              if call.kwargs.get("status") == "request_incomplete"]
                self.assertEqual(len(incomplete), 1)
            self.assert_following_request_is_served(server)
            self.assertLess(time.monotonic() - started, 0.65)
        finally:
            first.close()

    def test_incomplete_headers_cannot_starve_following_request(self):
        server = self.run_server()
        first = socket.create_connection(server.server_address, timeout=1)
        first.sendall(b"POST /v1/run-python HTTP/1.1\r\nHost: local")
        time.sleep(0.25)
        try:
            self.assert_following_request_is_served(server)
        finally:
            first.close()

    def test_nonreading_client_cannot_starve_following_request(self):
        class BackpressureHandler(execution_broker.Handler):
            def setup(self):
                super().setup()
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)

        server = self.run_server(BackpressureHandler)
        first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        first.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        first.settimeout(1)
        result = {"stdout": "\x00" * (64 * 1024), "stderr": "\x00" * (64 * 1024)}
        try:
            with mock.patch.object(
                execution_broker,
                "validate_and_forward",
                side_effect=[result, execution_broker.Rejected("invalid_request")],
            ):
                first.connect(server.server_address)
                first.sendall(
                    b"POST /v1/run-python HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
                )
                time.sleep(0.25)
                self.assert_following_request_is_served(server)
        finally:
            first.close()


class ExecutionBrokerReceiptTests(unittest.TestCase):
    def test_active_run_errors_remain_precise_fixed_rejections(self):
        self.assertEqual(execution_broker.rejection_token(
            execution_broker.ReceiptError("active_run_required")), "active_run_required")
        self.assertEqual(execution_broker.rejection_token(
            execution_broker.ReceiptError("unexpected detail")), "invalid_request")

    def test_timed_out_nonzero_measurement_mints_outcome_bound_receipt(self):
        source_id="11111111-1111-4111-8111-111111111111"
        request_id="22222222-2222-4222-8222-222222222222"
        run_id="33333333-3333-4333-8333-333333333333"
        image="sha256:"+"a"*64; output=b"measured\n"
        target={"schema":"secure-sandbox-execution-result-v1","request_id":request_id,"source_id":source_id,
            "runtime":"python3.14","runtime_image_id":image,"exit_code":-9,"timed_out":True,
            "duration_ms":5007,
            "output_limit_exceeded":True,"stdout_b64":base64.b64encode(output).decode(),
            "stdout_sha256":hashlib.sha256(output).hexdigest(),"stdout_truncated":True,
            "stderr_b64":"","stderr_sha256":hashlib.sha256(b"").hexdigest(),"stderr_truncated":True}
        class Response:
            status=200
            def read(self, size): return json.dumps(target).encode()
        class Connection:
            def __init__(self,*args,**kwargs): pass
            def request(self,*args,**kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        receipt={"class":"measured_execution","receipt_id":"44444444-4444-4444-8444-444444444444","receipt_sha256":"b"*64}
        with (mock.patch.object(execution_broker,"registered_source",return_value={"integrity_manifest_path":"source-manifests/x.json","baseline_path":"baselines/"+source_id}),
              mock.patch.object(execution_broker,"load_control_json",return_value={"source_id":source_id}),
              mock.patch.object(execution_broker,"expected_records",return_value={}),
              mock.patch.object(execution_broker,"fixed_tree_path",return_value="/trusted"),
              mock.patch.object(execution_broker,"active_run",return_value=run_id),
              mock.patch.object(execution_broker.uuid,"uuid4",return_value=uuid.UUID(request_id)),
              mock.patch.object(execution_broker.http.client,"HTTPConnection",Connection),
              mock.patch.object(execution_broker,"publish",return_value=receipt) as publish):
            result=execution_broker.validate_and_forward({"source_id":source_id,"code":"print('x')",
                "fixture_paths":[],"timeout_seconds":5},{"token":"x"*64})
        self.assertEqual(result["evidence_receipt"],receipt); self.assertEqual(result["run_id"],run_id)
        projection=publish.call_args.args[2]
        self.assertEqual(projection["stdout_sha256"],hashlib.sha256(output).hexdigest())
        self.assertEqual(projection["stderr_sha256"],hashlib.sha256(b"").hexdigest())
        self.assertEqual(projection["exit_code"],-9); self.assertTrue(projection["timed_out"])
        self.assertEqual(projection["timeout_seconds"],5); self.assertEqual(projection["duration_ms"],5007)
        self.assertTrue(projection["output_limit_exceeded"]); self.assertTrue(projection["stderr_truncated"])
        self.assertEqual(projection["image_digest"],image)


if __name__=="__main__": unittest.main()
