import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("verify_ubuntu_installer.py")
SPEC = importlib.util.spec_from_file_location("verify_ubuntu_installer", MODULE_PATH)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verifier)


class UbuntuInstallerVerificationTests(unittest.TestCase):
    def release(self, root: Path, payload: bytes = b"approved installer") -> Path:
        digest = hashlib.sha256(payload).hexdigest()
        (root / verifier.ARTIFACT_NAME).write_bytes(payload)
        (root / "SHA256SUMS").write_text(f"{digest} *{verifier.ARTIFACT_NAME}\n", encoding="ascii")
        (root / "SHA256SUMS.gpg").write_bytes(b"signature")
        (root / "ubuntu-archive-keyring.gpg").write_bytes(b"keyring")
        return root

    def test_exact_signed_installer_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.release(Path(directory))
            with mock.patch.object(verifier, "verify_signature") as signature:
                result = verifier.verify(root)
            signature.assert_called_once()
            self.assertEqual(result["status"], "verified")

    def test_modified_installer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.release(Path(directory))
            (root / verifier.ARTIFACT_NAME).write_bytes(b"substituted installer")
            with mock.patch.object(verifier, "verify_signature"):
                with self.assertRaisesRegex(verifier.VerificationFailure, "digest_mismatch"):
                    verifier.verify(root)

    def test_manifest_and_installer_cannot_be_replaced_together_without_publisher_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.release(Path(directory), b"attacker installer")
            with mock.patch.object(
                verifier, "verify_signature",
                side_effect=verifier.VerificationFailure("manifest_signature_invalid"),
            ):
                with self.assertRaisesRegex(verifier.VerificationFailure, "signature_invalid"):
                    verifier.verify(root)

    def test_symlinked_installer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = self.release(Path(directory))
            (root / verifier.ARTIFACT_NAME).unlink()
            (root / verifier.ARTIFACT_NAME).symlink_to(Path(outside) / "installer.iso")
            with mock.patch.object(verifier, "verify_signature"):
                with self.assertRaisesRegex(verifier.VerificationFailure, "untrusted_input"):
                    verifier.verify(root)

    def test_only_pinned_signer_is_accepted(self):
        completed = mock.Mock(returncode=0, stdout="[GNUPG:] VALIDSIG DEADBEEF 2026-01-01\n")
        with mock.patch.object(verifier, "gpgv_binary", return_value=(None, "/usr/bin/gpgv")), \
                mock.patch.object(verifier.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(verifier.VerificationFailure, "signature_invalid"):
                verifier.verify_signature(b"manifest", b"signature", b"keyring")

    def test_pinned_signer_is_accepted(self):
        completed = mock.Mock(
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {verifier.SIGNER_FINGERPRINT} 2026-08-27\n",
        )
        with mock.patch.object(verifier, "gpgv_binary", return_value=(None, "/usr/bin/gpgv")), \
                mock.patch.object(verifier.subprocess, "run", return_value=completed):
            verifier.verify_signature(b"manifest", b"signature", b"keyring")

    def test_duplicate_manifest_entry_is_rejected(self):
        digest = "a" * 64
        manifest = f"{digest} *{verifier.ARTIFACT_NAME}\n{digest} *{verifier.ARTIFACT_NAME}\n".encode()
        with self.assertRaisesRegex(verifier.VerificationFailure, "entry_invalid"):
            verifier.expected_digest(manifest)

    def test_promotion_rejects_path_replacement_after_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / verifier.ARTIFACT_NAME
            source.write_bytes(b"authenticated installer")
            descriptor, opened = verifier.open_regular(source, verifier.MAX_INSTALLER_BYTES)
            digest = hashlib.sha256(b"authenticated installer").hexdigest()
            source.unlink()
            source.write_bytes(b"replacement after authentication")
            store = root / "store"
            store.mkdir()
            result = {"artifact": verifier.ARTIFACT_NAME, "sha256": digest,
                      "signer": verifier.SIGNER_FINGERPRINT, "status": "verified"}
            with mock.patch.object(verifier, "validate_store"), \
                    mock.patch.object(verifier, "validate_promoted"), \
                    mock.patch.object(verifier, "open_verified", return_value=(descriptor, opened, result)):
                with self.assertRaisesRegex(verifier.VerificationFailure, "input_changed_during_read"):
                    verifier.promote(root, store)
            self.assertEqual(list(store.iterdir()), [])

    def test_promotion_publishes_exact_authenticated_bytes_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.release(Path(directory), b"authenticated installer")
            store = root / "store"
            store.mkdir()
            with mock.patch.object(verifier, "validate_store"), \
                    mock.patch.object(verifier, "validate_promoted"), \
                    mock.patch.object(verifier, "verify_signature"):
                promoted = verifier.promote(root, store)
            destination = Path(promoted["path"])
            self.assertEqual(destination.read_bytes(), b"authenticated installer")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o444)


if __name__ == "__main__":
    unittest.main()
