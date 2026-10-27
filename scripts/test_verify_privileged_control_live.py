import importlib.util
import io
import json
import struct
import tarfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/verify-privileged-control-live.py"
SPEC = importlib.util.spec_from_file_location("verify_privileged_control_live", PATH)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


class LiveVerificationTests(unittest.TestCase):
    def test_integrity_probe_is_well_framed_but_has_a_false_content_digest(self):
        request_id = str(uuid.uuid4())
        framed = LIVE.integrity_rejection_request(request_id)
        header_length = struct.unpack(">I", framed[:4])[0]
        request = json.loads(framed[4:4 + header_length])
        payload = framed[4 + header_length:]
        self.assertEqual(request["request_id"], request_id)
        self.assertEqual(request["payload_length"], len(payload))
        self.assertEqual(request["files"][0]["sha256"], "0" * 64)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            member = archive.getmembers()[0]
            self.assertEqual(member.name, "files/install-integrity-probe.sh")
            self.assertNotEqual(request["files"][0]["sha256"], LIVE.hashlib.sha256(archive.extractfile(member).read()).hexdigest())

    def test_local_expected_hashes_cover_every_guest_reported_file(self):
        hashes = LIVE.expected_hashes("gateway")
        self.assertEqual(
            set(hashes),
            {"dispatcher", "entrypoint", "sudoers", "sshd_policy", "authorized_key", "role"},
        )
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_one_json_rejects_ambiguous_output(self):
        with self.assertRaisesRegex(LIVE.AcceptanceFailure, "output_invalid"):
            LIVE.one_json("{}\n{}\n", "probe")


if __name__ == "__main__":
    unittest.main()
