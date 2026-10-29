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
    "render_artifact", os.path.join(os.path.dirname(__file__), "render-artifact.py")
)
renderer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(renderer)


class ArtifactRendererTests(unittest.TestCase):
    def test_terminal_control_bytes_are_escaped(self):
        value = renderer.safe_text("safe\x1b]52;c;payload\x07\n")
        self.assertEqual(value, "safe\\x1b]52;c;payload\\x07\n")
        self.assertNotIn("\x1b", value)

    def test_newline_and_tab_remain_readable(self):
        self.assertEqual(renderer.safe_text("a\tb\nc"), "a\tb\nc")

    def test_bidi_formatting_controls_are_escaped(self):
        self.assertEqual(renderer.safe_text("left\u202eright"), "left\\u202eright")

    @unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "age tools unavailable")
    def test_encrypted_catalog_verifies_ciphertext_and_envelope_with_one_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            identity_path = directory / "identity"
            subprocess.run(["age-keygen", "-o", str(identity_path)], check=True, capture_output=True)
            identity = identity_path.read_bytes()
            recipient = next(line.split(b": ", 1)[1].decode() for line in identity.splitlines()
                             if line.startswith(b"# public key: "))
            artifact_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            content = b"verified report\n"
            header = {
                "schema": "secure-sandbox-artifact-v1",
                "artifact_id": artifact_id,
                "file_name": "report.md",
                "record_bytes": len(content),
                "source_sha256": hashlib.sha256(content).hexdigest(),
                "captured_at": "2026-10-29T12:00:00Z",
                "version": 1,
                "run_id": "11111111-1111-4111-8111-111111111111",
            }
            envelope = json.dumps(header).encode() + b"\n" + content
            ciphertext = subprocess.run(["age", "-r", recipient], input=envelope,
                                        check=True, capture_output=True).stdout
            digest = hashlib.sha256(ciphertext).hexdigest()
            chunk = directory / f"artifact-{artifact_id}-000000000001-{digest}.age"
            chunk.write_bytes(ciphertext)

            rows = renderer.encrypted_catalog(directory, identity)
            self.assertEqual(rows, [renderer.metadata_line(header)])
            self.assertFalse(list(directory.glob("*.plain")))

            chunk.write_bytes(ciphertext + b"corrupt")
            with self.assertRaisesRegex(ValueError, "ciphertext hash mismatch"):
                renderer.encrypted_catalog(directory, identity)
            chunk.write_bytes(ciphertext)
            mismatched = directory / f"artifact-22222222-2222-4222-8222-222222222222-000000000001-{digest}.age"
            chunk.rename(mismatched)
            with self.assertRaisesRegex(ValueError, "filename and envelope disagree"):
                renderer.encrypted_catalog(directory, identity)
            self.assertFalse(list(directory.glob("*.plain")))


if __name__ == "__main__":
    unittest.main()
