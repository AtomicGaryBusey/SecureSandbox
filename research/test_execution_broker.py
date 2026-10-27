#!/usr/bin/env python3

import base64
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

import execution_broker


class ExecutionApprovalFloorTests(unittest.TestCase):
    def test_public_floor_rejects_v1_and_mismatched_v2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            floor_path = root / "floor.json"
            generation = str(uuid.uuid4())
            spki = execution_broker.P256_SPKI_PREFIX + b"\x04" + b"\x01" * 64
            public_hash = hashlib.sha256(spki).hexdigest()
            floor = {
                "schema":"secure-sandbox-execution-approval-floor-v2",
                "minimum_protocol":2, "minimum_epoch":4,
                "generation_id":generation,
                "algorithm":execution_broker.APPROVAL_V2_ALGORITHM,
                "public_key_sha256":public_hash, "updated_at":1,
            }
            floor_path.write_bytes(execution_broker.canonical(floor))
            legacy = {"schema":"secure-sandbox-execution-broker-v2", "token":"x" * 64,
                      "runtime_image_id":"sha256:" + "1" * 64,
                      "allowed_signers":"/etc/secure-sandbox/execution-approval.allowed_signers"}
            config_path.write_text(json.dumps(legacy))
            trusted = SimpleNamespace(st_uid=0, st_gid=777, st_nlink=1,
                                      st_mode=__import__("stat").S_IFREG | 0o640)
            with mock.patch.object(execution_broker, "CONFIG", str(config_path)), \
                    mock.patch.object(execution_broker, "APPROVAL_FLOOR", floor_path), \
                    mock.patch.object(execution_broker.os, "stat", return_value=trusted), \
                    mock.patch.object(execution_broker.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=777)):
                with self.assertRaisesRegex(RuntimeError, "execution_approval_below_floor"):
                    execution_broker.load_config()
                active = {
                    "schema":"secure-sandbox-execution-broker-v3", "token":"x" * 64,
                    "runtime_image_id":"sha256:" + "1" * 64,
                    "approval":{
                        "mode":"active-v2", "minimum_protocol":2, "minimum_epoch":4,
                        "generation_id":generation, "generation_epoch":4,
                        "algorithm":execution_broker.APPROVAL_V2_ALGORITHM,
                        "public_key_spki_der_b64":base64.b64encode(spki).decode("ascii"),
                        "public_key_sha256":public_hash,
                    },
                }
                config_path.write_text(json.dumps(active))
                self.assertEqual(execution_broker.load_config(), active)
                active["approval"]["generation_id"] = str(uuid.uuid4())
                config_path.write_text(json.dumps(active))
                with self.assertRaisesRegex(RuntimeError, "execution_approval_below_floor"):
                    execution_broker.load_config()


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
        session_id="55555555-5555-4555-8555-555555555555"
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
              mock.patch.object(execution_broker,"lifecycle_context",return_value=(run_id,session_id)),
              mock.patch.object(execution_broker,"await_operator_approval",return_value=({},"c"*64)),
              mock.patch.object(execution_broker.uuid,"uuid4",return_value=uuid.UUID(request_id)),
              mock.patch.object(execution_broker.http.client,"HTTPConnection",Connection),
              mock.patch.object(execution_broker,"publish",return_value=receipt) as publish):
            result=execution_broker.validate_and_forward({"source_id":source_id,"code":"print('x')",
                "fixture_paths":[],"timeout_seconds":5},{"token":"x"*64,
                "runtime_image_id":image,"allowed_signers":"/etc/secure-sandbox/execution-approval.allowed_signers"})
        self.assertEqual(result["evidence_receipt"],receipt); self.assertEqual(result["run_id"],run_id)
        projection=publish.call_args.args[2]
        self.assertEqual(projection["stdout_sha256"],hashlib.sha256(output).hexdigest())
        self.assertEqual(projection["stderr_sha256"],hashlib.sha256(b"").hexdigest())
        self.assertEqual(projection["exit_code"],-9); self.assertTrue(projection["timed_out"])
        self.assertEqual(projection["timeout_seconds"],5); self.assertEqual(projection["duration_ms"],5007)
        self.assertTrue(projection["output_limit_exceeded"]); self.assertTrue(projection["stderr_truncated"])
        self.assertEqual(projection["image_digest"],image)
        self.assertEqual(projection["session_id"],session_id)
        self.assertEqual(projection["approval_attestation_sha256"],"c"*64)

    def test_acceptance_lifecycle_is_exact_and_consumed_before_approval(self):
        source_id = "11111111-1111-4111-8111-111111111111"
        run_id = "33333333-3333-4333-8333-333333333333"
        session_id = "55555555-5555-4555-8555-555555555555"
        transaction_id = "66666666-6666-4666-8666-666666666666"
        generation_id = "77777777-7777-4777-8777-777777777777"
        image = "sha256:" + "a" * 64
        code = 'print("accepted")'
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        fixture_hash = hashlib.sha256(b"[]").hexdigest()
        acceptance = {
            "transaction_id":transaction_id, "generation_id":generation_id,
            "generation_epoch":4, "run_id":run_id, "session_id":session_id,
            "source_id":source_id, "code_sha256":code_hash,
            "fixture_manifest_sha256":fixture_hash, "timeout_seconds":5,
            "runtime_image_id":image, "expires_at":int(time.time()) + 60,
            "acceptance_attempt_id":str(uuid.uuid4()), "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "acceptance_binding_sha256":"a" * 64,
        }
        target = {
            "schema":"secure-sandbox-execution-result-v1",
            "request_id":"22222222-2222-4222-8222-222222222222",
            "source_id":source_id, "runtime":"python3.14", "runtime_image_id":image,
            "exit_code":0, "timed_out":False, "duration_ms":1,
            "output_limit_exceeded":False,
            "stdout_b64":base64.b64encode(b"accepted\n").decode(),
            "stdout_sha256":hashlib.sha256(b"accepted\n").hexdigest(),
            "stdout_truncated":False, "stderr_b64":"",
            "stderr_sha256":hashlib.sha256(b"").hexdigest(),
            "stderr_truncated":False,
        }

        class Response:
            status = 200
            def read(self, _size): return json.dumps(target).encode()

        class Connection:
            def __init__(self, *_args, **_kwargs): pass
            def request(self, *_args, **_kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass

        config = {"token":"x" * 64, "runtime_image_id":image,
                  "approval":{"mode":"active-v2"}}
        attestation = {
            "schema":execution_broker.APPROVAL_V2_ATTESTATION,
            "key_generation_id":generation_id, "key_generation_epoch":4,
            "public_key_sha256":"b" * 64,
            "signature_algorithm":execution_broker.APPROVAL_V2_ALGORITHM,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "consumed").mkdir()
            def load(path, _maximum):
                if path == str(execution_broker.LIFECYCLE):
                    return {"run_id":run_id, "session_id":session_id,
                            "execution_approval_acceptance":acceptance}
                return {"source_id":source_id}
            with (mock.patch.object(execution_broker, "APPROVAL_ROOT", root),
                  mock.patch.object(execution_broker, "registered_source", return_value={
                      "integrity_manifest_path":"source-manifests/x.json",
                      "baseline_path":"baselines/" + source_id,
                  }),
                  mock.patch.object(execution_broker, "load_control_json", side_effect=load),
                  mock.patch.object(execution_broker, "expected_records", return_value={}),
                  mock.patch.object(execution_broker, "fixed_tree_path", return_value="/trusted"),
                  mock.patch.object(execution_broker, "active_run", return_value=run_id),
                  mock.patch.object(execution_broker, "lifecycle_context",
                                    return_value=(run_id, session_id)),
                  mock.patch.object(execution_broker, "await_operator_approval",
                                    return_value=(attestation, "c" * 64)) as approve,
                  mock.patch.object(execution_broker.uuid, "uuid4",
                                    return_value=uuid.UUID(target["request_id"])),
                  mock.patch.object(execution_broker.http.client, "HTTPConnection", Connection),
                  mock.patch.object(execution_broker, "publish", return_value={
                      "class":"measured_execution", "receipt_id":str(uuid.uuid4()),
                      "receipt_sha256":"d" * 64,
                  })):
                result = execution_broker.validate_and_forward({
                    "source_id":source_id, "code":code,
                    "fixture_paths":[], "timeout_seconds":5,
                }, config)
                self.assertEqual(result["exit_code"], 0)
                marker = json.loads((root / "consumed" /
                    f"acceptance-{acceptance['acceptance_attempt_id']}.json").read_bytes())
                self.assertEqual(marker["run_id"], run_id)
                self.assertEqual(marker["status"], "succeeded")
                approve.assert_called_once()
                with self.assertRaisesRegex(execution_broker.Rejected, "approval_replayed"):
                    execution_broker.validate_and_forward({
                        "source_id":source_id, "code":code,
                        "fixture_paths":[], "timeout_seconds":5,
                    }, config)
                approve.assert_called_once()

                wrong = {**acceptance, "code_sha256":"f" * 64}
                marker_path = root / "consumed" / f"acceptance-{acceptance['acceptance_attempt_id']}.json"
                marker_path.unlink()
                with mock.patch.object(execution_broker, "load_control_json",
                                       side_effect=lambda path, maximum: (
                                           {"run_id":run_id, "session_id":session_id,
                                            "execution_approval_acceptance":wrong}
                                           if path == str(execution_broker.LIFECYCLE)
                                           else {"source_id":source_id})):
                    with self.assertRaisesRegex(execution_broker.Rejected, "approval_invalid"):
                        execution_broker.validate_and_forward({
                            "source_id":source_id, "code":code,
                            "fixture_paths":[], "timeout_seconds":5,
                        }, config)
                self.assertFalse(marker_path.exists())


class ExecutionApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("pending", "claims", "responses", "consumed"):
            (self.root / name).mkdir(mode=0o700)
        self.key = self.root / "host-key"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(self.key)], check=True)
        public = Path(str(self.key) + ".pub").read_text().split()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text("secure-sandbox-host " + " ".join(public[:2]) + "\n")
        now = int(time.time())
        fixtures = [{"path":"fixtures/input.txt", "bytes":4, "sha256":"a" * 64}]
        self.approval = {
            "schema":"secure-sandbox-execution-approval-request-v1",
            "approval_id":str(uuid.uuid4()), "created_at":now, "expires_at":now + 90,
            "run_id":str(uuid.uuid4()), "session_id":str(uuid.uuid4()),
            "source_id":str(uuid.uuid4()), "source_manifest_sha256":"b" * 64,
            "code_sha256":"c" * 64, "fixture_manifest":fixtures,
            "fixture_manifest_sha256":hashlib.sha256(json.dumps(
                fixtures, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "d" * 64,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_acceptance_attempts_preserve_cancel_and_target_failure_as_distinct_history(self):
        base = {
            "transaction_id":str(uuid.uuid4()), "generation_id":str(uuid.uuid4()),
            "generation_epoch":1, "run_id":str(uuid.uuid4()),
            "session_id":str(uuid.uuid4()), "source_id":str(uuid.uuid4()),
            "code_sha256":"a" * 64, "fixture_manifest_sha256":"b" * 64,
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "c" * 64,
            "expires_at":int(time.time()) + 60, "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "acceptance_binding_sha256":"d" * 64,
        }
        cancelled = {**base, "acceptance_attempt_id":str(uuid.uuid4())}
        target_failed = {
            **base, "acceptance_attempt_id":str(uuid.uuid4()),
            "acceptance_attempt_number":2,
            "previous_acceptance_binding_sha256":base["acceptance_binding_sha256"],
            "acceptance_binding_sha256":"e" * 64,
        }
        first = execution_broker.AcceptanceAttempt(cancelled, self.root)
        first.fail(execution_broker.Rejected("approval_cancelled"))
        second = execution_broker.AcceptanceAttempt(target_failed, self.root)
        second.fail(RuntimeError("target_execution_failed"))
        first_value = json.loads(first.path.read_bytes())
        second_value = json.loads(second.path.read_bytes())
        self.assertEqual((first_value["status"], first_value["failure_class"]),
                         ("failed", "Rejected"))
        self.assertEqual((second_value["status"], second_value["failure_class"]),
                         ("failed", "RuntimeError"))
        self.assertTrue(first.path.exists())
        self.assertTrue(second.path.exists())

    def test_acceptance_attempt_success_uses_published_receipt_projection(self):
        acceptance = {
            "transaction_id":str(uuid.uuid4()), "generation_id":str(uuid.uuid4()),
            "generation_epoch":1, "run_id":str(uuid.uuid4()),
            "session_id":str(uuid.uuid4()), "source_id":str(uuid.uuid4()),
            "code_sha256":"a" * 64, "fixture_manifest_sha256":"b" * 64,
            "timeout_seconds":5, "runtime_image_id":"sha256:" + "c" * 64,
            "expires_at":int(time.time()) + 60, "acceptance_attempt_number":1,
            "previous_acceptance_binding_sha256":None,
            "acceptance_binding_sha256":"d" * 64,
            "acceptance_attempt_id":str(uuid.uuid4()),
        }
        receipt = {
            "class":"measured_execution",
            "receipt_id":str(uuid.uuid4()),
            "receipt_sha256":"e" * 64,
        }
        attempt = execution_broker.AcceptanceAttempt(acceptance, self.root)
        attempt.succeed(receipt)
        value = json.loads(attempt.path.read_bytes())
        self.assertEqual(value["status"], "succeeded")
        self.assertEqual(value["research_receipt_id"], receipt["receipt_id"])
        self.assertEqual(value["research_receipt_sha256"], receipt["receipt_sha256"])
        self.assertNotIn("content_sha256", receipt)

    def envelope(self, approval=None):
        approval = self.approval if approval is None else approval
        attestation = {
            "schema":"secure-sandbox-execution-approval-attestation-v1",
            "approval":approval,
            "approval_request_sha256":hashlib.sha256(
                execution_broker.canonical(approval)).hexdigest(),
            "authorization_request_id":str(uuid.uuid4()),
            "host_release_id":"e" * 64,
            "approved_at":approval["created_at"],
        }
        signed = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n",
             execution_broker.APPROVAL_NAMESPACE],
            input=execution_broker.canonical(attestation), capture_output=True, check=True,
        ).stdout
        return {"schema":"secure-sandbox-execution-approval-envelope-v1",
                "attestation":attestation,
                "signature_b64":base64.b64encode(signed).decode()}

    def v2_envelope_and_config(self, approval=None):
        approval = self.approval if approval is None else approval
        private_key = self.root / "p256-private.pem"
        public_der = self.root / "p256-public.der"
        subprocess.run([
            "/usr/bin/openssl", "ecparam", "-name", "prime256v1", "-genkey",
            "-noout", "-out", str(private_key),
        ], check=True, capture_output=True)
        subprocess.run([
            "/usr/bin/openssl", "pkey", "-in", str(private_key), "-pubout",
            "-outform", "DER", "-out", str(public_der),
        ], check=True, capture_output=True)
        spki = public_der.read_bytes()
        generation = str(uuid.uuid4())
        digest = hashlib.sha256(spki).hexdigest()
        attestation = {
            "schema":execution_broker.APPROVAL_V2_ATTESTATION,
            "approval":approval,
            "approval_request_sha256":hashlib.sha256(
                execution_broker.canonical(approval)).hexdigest(),
            "authorization_request_id":str(uuid.uuid4()),
            "host_release_id":"e" * 64,
            "approved_at":approval["created_at"],
            "key_generation_id":generation,
            "key_generation_epoch":1,
            "public_key_sha256":digest,
            "signature_algorithm":execution_broker.APPROVAL_V2_ALGORITHM,
        }
        signed = subprocess.run([
            "/usr/bin/openssl", "dgst", "-sha256", "-sign", str(private_key),
        ], input=execution_broker.canonical_v2(attestation), capture_output=True, check=True).stdout
        r_value, s_value = execution_broker.parse_p256_der(signed, require_low_s=False)
        # OpenSSL may already return low-S. If it does not, parse without the
        # low-S gate and normalize exactly as the signed UI does.
        if s_value > execution_broker.P256_HALF_ORDER:
            signed = execution_broker.encode_p256_der(
                r_value, execution_broker.P256_ORDER - s_value
            )
        envelope = {
            "schema":execution_broker.APPROVAL_V2_ENVELOPE,
            "attestation":attestation,
            "signature_der_b64":base64.b64encode(signed).decode("ascii"),
        }
        config = {
            "schema":"secure-sandbox-execution-broker-v3",
            "approval":{
                "mode":"active-v2", "minimum_protocol":2, "minimum_epoch":1,
                "algorithm":execution_broker.APPROVAL_V2_ALGORITHM,
                "generation_id":generation, "generation_epoch":1,
                "public_key_sha256":digest,
                "public_key_spki_der_b64":base64.b64encode(spki).decode("ascii"),
            },
        }
        return envelope, config

    def write_response(self, status="approved", envelope=None):
        value = {"schema":"secure-sandbox-execution-approval-response-v1",
                 "approval_id":self.approval["approval_id"], "status":status}
        if status == "approved": value["envelope"] = envelope or self.envelope()
        path = self.root / "responses" / f'{self.approval["approval_id"]}.json'
        path.write_bytes(execution_broker.canonical(value)); path.chmod(0o640)

    def test_signed_approval_is_consumed_once_before_execution(self):
        self.write_response()
        attestation, digest = execution_broker.await_operator_approval(
            self.approval, {"allowed_signers":str(self.allowed)}, self.root, os.geteuid())
        self.assertEqual(attestation["approval"], self.approval)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue((self.root / "consumed" / f'{self.approval["approval_id"]}.json').is_file())
        self.write_response()
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_replayed"):
            execution_broker.await_operator_approval(
                self.approval, {"allowed_signers":str(self.allowed)}, self.root, os.geteuid())

    def test_v2_p256_approval_is_verified_and_content_bound(self):
        envelope, config = self.v2_envelope_and_config()
        execution_broker.validate_v3_approval_config(config["approval"])
        self.write_response(envelope=envelope)
        attestation, digest = execution_broker.await_operator_approval(
            self.approval, config, self.root, os.geteuid())
        self.assertEqual(attestation["approval"], self.approval)
        consumed = json.loads((
            self.root / "consumed" / f'{self.approval["approval_id"]}.json'
        ).read_bytes())
        self.assertEqual(consumed["generation_id"], config["approval"]["generation_id"])
        self.assertEqual(consumed["generation_epoch"], 1)
        self.assertEqual(consumed["public_key_sha256"], config["approval"]["public_key_sha256"])
        self.assertEqual(consumed["signature_algorithm"], execution_broker.APPROVAL_V2_ALGORITHM)
        self.assertEqual(digest, hashlib.sha256(
            execution_broker.canonical_v2(attestation)).hexdigest())

    def test_v2_rejects_high_s_wrong_generation_and_fenced_mode(self):
        envelope, config = self.v2_envelope_and_config()
        signature = base64.b64decode(envelope["signature_der_b64"])
        r_value, s_value = execution_broker.parse_p256_der(signature)
        envelope["signature_der_b64"] = base64.b64encode(
            execution_broker.encode_p256_der(r_value, execution_broker.P256_ORDER - s_value)
        ).decode("ascii")
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_invalid"):
            execution_broker.verify_v2_envelope(envelope, self.approval, config)

        envelope, config = self.v2_envelope_and_config()
        config["approval"]["generation_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_invalid"):
            execution_broker.verify_v2_envelope(envelope, self.approval, config)

        fenced = {"schema":"secure-sandbox-execution-broker-v3",
                  "approval":{"mode":"fenced", "minimum_protocol":2,
                              "minimum_epoch":1}}
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_required"):
            execution_broker.verify_v2_envelope(envelope, self.approval, fenced)

    def test_cancel_and_substitution_fail_closed(self):
        self.write_response(status="cancelled")
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_cancelled"):
            execution_broker.await_operator_approval(
                self.approval, {"allowed_signers":str(self.allowed)}, self.root, os.geteuid())
        # The unprivileged broker acknowledges consumption by removing only
        # its pending marker.  It must not try to unlink the root-owned
        # response and mask approval_cancelled with PermissionError.
        response = self.root / "responses" / f'{self.approval["approval_id"]}.json'
        self.assertTrue(response.is_file())
        self.assertFalse((self.root / "pending" / response.name).exists())
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            self.assertIsNone(execution_broker.claim_pending(
                self.approval["run_id"], self.approval["session_id"],
                self.root, os.geteuid()))
        self.assertFalse(response.exists())
        substituted = {**self.approval, "code_sha256":"f" * 64}
        self.write_response(envelope=self.envelope(substituted))
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_invalid"):
            execution_broker.await_operator_approval(
                self.approval, {"allowed_signers":str(self.allowed)}, self.root, os.geteuid())

    def test_expired_approval_fails_closed_without_consumption(self):
        expired = {**self.approval, "expires_at":int(time.time()) - 1}
        with self.assertRaisesRegex(execution_broker.Rejected, "approval_expired"):
            execution_broker.await_operator_approval(
                expired, {"allowed_signers":str(self.allowed)}, self.root, os.geteuid())
        name = f'{expired["approval_id"]}.json'
        self.assertFalse((self.root / "pending" / name).exists())
        self.assertFalse((self.root / "consumed" / name).exists())

    def test_root_relay_claim_and_delivery_are_context_bound(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        pending.write_bytes(execution_broker.canonical(self.approval)); pending.chmod(0o600)
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            claimed = execution_broker.claim_pending(
                self.approval["run_id"], self.approval["session_id"], self.root,
                os.geteuid())
        self.assertEqual(claimed, self.approval)
        response = {"schema":"secure-sandbox-execution-approval-response-v1",
                    "approval_id":self.approval["approval_id"], "status":"cancelled"}
        group = type("Group", (), {"gr_gid":os.getegid()})()
        with mock.patch.object(execution_broker.grp, "getgrnam", return_value=group):
            result = execution_broker.deliver_approval_response(
                execution_broker.canonical(response), self.root, os.geteuid())
        self.assertEqual(result["status"], "delivered")
        self.assertFalse((self.root / "claims" / f'{self.approval["approval_id"]}.json').exists())

    def test_delivered_response_prevents_duplicate_claim_until_acknowledged(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        pending.write_bytes(execution_broker.canonical(self.approval)); pending.chmod(0o600)
        self.write_response(status="cancelled")
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            self.assertIsNone(execution_broker.claim_pending(
                self.approval["run_id"], self.approval["session_id"],
                self.root, os.geteuid()))
        self.assertTrue(pending.exists())
        self.assertTrue((self.root / "responses" / pending.name).exists())

    def test_long_poll_claims_request_created_after_poll_begins(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()

        def publish_pending():
            time.sleep(0.05)
            pending.write_bytes(execution_broker.canonical(self.approval))
            pending.chmod(0o600)

        publisher = threading.Thread(target=publish_pending)
        publisher.start()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            claimed = execution_broker.claim_pending(
                self.approval["run_id"], self.approval["session_id"], self.root,
                os.geteuid(), wait_seconds=0.5)
        publisher.join()
        self.assertEqual(claimed, self.approval)

    def test_claim_diagnostics_are_content_free_fixed_reason_tokens(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        pending.write_bytes(execution_broker.canonical(self.approval)); pending.chmod(0o600)
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        wrong_session = str(uuid.uuid4())
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity), \
             mock.patch.object(execution_broker, "audit") as audit:
            self.assertIsNone(execution_broker.claim_pending(
                self.approval["run_id"], wrong_session, self.root, os.geteuid()))
        audit.assert_called_once_with(
            "approval_claim_skipped", request_id=self.approval["approval_id"],
            status="context_mismatch")

        pending.unlink()
        expired = {**self.approval, "expires_at":int(time.time()) - 1}
        pending.write_bytes(execution_broker.canonical(expired)); pending.chmod(0o600)
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity), \
             mock.patch.object(execution_broker, "audit") as audit:
            self.assertIsNone(execution_broker.claim_pending(
                expired["run_id"], expired["session_id"], self.root, os.geteuid()))
        audit.assert_called_once_with(
            "approval_claim_skipped", request_id=expired["approval_id"],
            status="expired")

    def test_existing_matching_claim_is_idempotently_redelivered(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        raw = execution_broker.canonical(self.approval)
        pending.write_bytes(raw); pending.chmod(0o600)
        claim = self.root / "claims" / pending.name
        claim.write_bytes(execution_broker.canonical({
            "approval_id":self.approval["approval_id"],
            "claimed_at":int(time.time()),
            "request_sha256":hashlib.sha256(raw).hexdigest(),
        })); claim.chmod(0o600)
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity), \
             mock.patch.object(execution_broker, "audit") as audit:
            self.assertEqual(self.approval, execution_broker.claim_pending(
                self.approval["run_id"], self.approval["session_id"], self.root,
                os.geteuid(), wait_seconds=0.25))
        audit.assert_called_once_with(
            "approval_claim_redelivered", request_id=self.approval["approval_id"],
            status="claimed")

    def test_existing_claim_with_wrong_request_hash_fails_closed(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        pending.write_bytes(execution_broker.canonical(self.approval)); pending.chmod(0o600)
        claim = self.root / "claims" / pending.name
        claim.write_bytes(execution_broker.canonical({
            "approval_id":self.approval["approval_id"],
            "claimed_at":int(time.time()),
            "request_sha256":"a" * 64,
        })); claim.chmod(0o600)
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            with self.assertRaisesRegex(RuntimeError, "approval_state_untrusted"):
                execution_broker.claim_pending(
                    self.approval["run_id"], self.approval["session_id"], self.root,
                    os.geteuid(), wait_seconds=0.25)

    def test_existing_claim_outside_request_lifetime_fails_closed(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        raw = execution_broker.canonical(self.approval)
        pending.write_bytes(raw); pending.chmod(0o600)
        claim = self.root / "claims" / pending.name
        claim.write_bytes(execution_broker.canonical({
            "approval_id":self.approval["approval_id"],
            "claimed_at":self.approval["created_at"] - 1,
            "request_sha256":hashlib.sha256(raw).hexdigest(),
        })); claim.chmod(0o600)
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            with self.assertRaisesRegex(RuntimeError, "approval_state_untrusted"):
                execution_broker.claim_pending(
                    self.approval["run_id"], self.approval["session_id"], self.root,
                    os.geteuid(), wait_seconds=0.25)

    def test_oversized_existing_claim_fails_closed_before_read(self):
        pending = self.root / "pending" / f'{self.approval["approval_id"]}.json'
        pending.write_bytes(execution_broker.canonical(self.approval)); pending.chmod(0o600)
        claim = self.root / "claims" / pending.name
        claim.write_bytes(b"x" * 4097); claim.chmod(0o600)
        identity = type("Identity", (), {"pw_uid":os.geteuid()})()
        with mock.patch.object(execution_broker.pwd, "getpwnam", return_value=identity):
            with self.assertRaisesRegex(RuntimeError, "approval_state_untrusted"):
                execution_broker.claim_pending(
                    self.approval["run_id"], self.approval["session_id"], self.root,
                    os.geteuid(), wait_seconds=0.25)

    def test_approval_next_cli_serializes_claim_to_stdout(self):
        output = type("Output", (), {"buffer":io.BytesIO()})()
        with mock.patch.object(execution_broker, "claim_pending",
                               return_value=self.approval), \
             mock.patch.object(execution_broker.sys, "argv", [
                 "execution_broker.py", "approval-next",
                 self.approval["run_id"], self.approval["session_id"],
             ]), \
             mock.patch.object(execution_broker.sys, "stdout", output):
            self.assertEqual(execution_broker.main(), 0)
        self.assertEqual(output.buffer.getvalue(),
                         execution_broker.canonical(self.approval))


if __name__=="__main__": unittest.main()
