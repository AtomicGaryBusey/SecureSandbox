import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "render_transcript", os.path.join(os.path.dirname(__file__), "render-transcript.py")
)
renderer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(renderer)
RUN_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


@unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen") and shutil.which("jq"),
                     "archive tools unavailable")
class TranscriptRendererTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        identity_path = self.directory / "identity"
        subprocess.run(["age-keygen", "-o", str(identity_path)], check=True, capture_output=True)
        self.identity = identity_path.read_bytes()
        self.recipient = next(line.split(b": ", 1)[1].decode()
                              for line in self.identity.splitlines() if line.startswith(b"# public key: "))

    def chunk(self, sequence, previous, records, *, header_override=None):
        header = {
            "schema": "secure-sandbox-conversation-v1", "run_id": RUN_ID,
            "sequence": sequence, "previous_cipher_sha256": previous,
            "record_bytes": len(records),
        }
        if header_override:
            header.update(header_override)
        plaintext = json.dumps(header).encode() + b"\n" + records
        ciphertext = subprocess.run(["age", "-r", self.recipient], input=plaintext,
                                    check=True, capture_output=True).stdout
        digest = hashlib.sha256(ciphertext).hexdigest()
        path = self.directory / f"{RUN_ID}-{sequence:012d}-{digest}.age"
        path.write_bytes(ciphertext)
        return path, digest

    def test_two_chunks_verify_and_render_with_one_identity(self):
        _, first = self.chunk(0, "", b'{"a": 1}\n')
        self.chunk(1, first, b'{"b": 2}\n')
        result = subprocess.run([str(Path(renderer.__file__)), str(self.directory), RUN_ID],
                                input=self.identity, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'{"a":1}\n{"b":2}\n')
        self.assertFalse(list(self.directory.glob("*.plain")))

    def test_ciphertext_tamper_rejected_before_output(self):
        path, _ = self.chunk(0, "", b'{"a":1}\n')
        path.write_bytes(path.read_bytes() + b"corrupt")
        result = subprocess.run([str(Path(renderer.__file__)), str(self.directory), RUN_ID],
                                input=self.identity, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_chain_gap_rejected_before_output(self):
        self.chunk(0, "", b'{"a":1}\n')
        self.chunk(1, "0" * 64, b'{"b":2}\n')
        result = subprocess.run([str(Path(renderer.__file__)), str(self.directory), RUN_ID],
                                input=self.identity, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(list(self.directory.glob("*.plain")))

    def test_record_byte_mismatch_rejected(self):
        self.chunk(0, "", b'{"a":1}\n', header_override={"record_bytes": 1})
        result = subprocess.run([str(Path(renderer.__file__)), str(self.directory), RUN_ID],
                                input=self.identity, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
