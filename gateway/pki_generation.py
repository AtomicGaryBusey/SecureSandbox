#!/usr/bin/env python3
"""Gateway half of the transactional SecureSandbox PKI lifecycle."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from pki_lifecycle import (
    LifecycleError,
    PHASES,
    TransactionStore,
    activation_event,
    atomic_write,
    build_manifest,
    canonical_bytes,
    certificate_metadata,
    load_json,
    validate_generation_id,
    validate_manifest,
)


OPENSSL = "/usr/bin/openssl"
LIVE_ROOT = Path("/etc/secure-sandbox")
STATE_ROOT = Path("/var/lib/secure-sandbox/pki-lifecycle")
SERVICES = ("model-broker.service", "telemetry-receiver.service", "conversation-receiver.service")
CLIENTS = {
    "broker": ("secure-sandbox-research", LIVE_ROOT / "broker.json"),
    "telemetry": ("secure-sandbox-research-telemetry", LIVE_ROOT / "telemetry.json"),
    "conversation": ("secure-sandbox-research-conversation", LIVE_ROOT / "conversation-receiver.json"),
}
SERVER_TARGETS = {
    "pki": "model-broker",
    "telemetry": "telemetry",
}


def run(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(arguments, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode:
        raise LifecycleError("openssl_operation_failed")
    return result.stdout


def require_regular(path: Path, maximum: int = 128 * 1024) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise LifecycleError("input_untrusted")


def atomic_copy(source: Path, target: Path, mode: int, uid: int | None = None, gid: int | None = None) -> None:
    require_regular(source)
    source_info = source.lstat()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary: Path | None = Path(temporary_name)
    try:
        source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(source_descriptor, "rb") as source_handle, os.fdopen(descriptor, "wb") as target_handle:
            opened = os.fstat(source_handle.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (source_info.st_dev, source_info.st_ino, source_info.st_size):
                raise LifecycleError("input_changed_during_copy")
            shutil.copyfileobj(source_handle, target_handle, 64 * 1024)
            after = os.fstat(source_handle.fileno())
            if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                raise LifecycleError("input_changed_during_copy")
            target_handle.flush()
            os.fsync(target_handle.fileno())
            os.fchmod(target_handle.fileno(), mode)
            os.fchown(target_handle.fileno(), os.geteuid() if uid is None else uid, os.getegid() if gid is None else gid)
        os.replace(temporary, target)
        temporary = None
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def key_spki(key: Path) -> bytes:
    require_regular(key)
    return run(OPENSSL, "pkey", "-in", str(key), "-pubout", "-outform", "DER")


def cert_spki(cert: Path) -> bytes:
    require_regular(cert)
    public = run(OPENSSL, "x509", "-in", str(cert), "-pubkey", "-noout")
    return run(OPENSSL, "pkey", "-pubin", "-outform", "DER", input_bytes=public)


def validate_chain(cert: Path, ca: Path) -> None:
    run(OPENSSL, "verify", "-CAfile", str(ca), str(cert))


def validate_subject(cert: Path, expected_cn: str) -> None:
    value = run(OPENSSL, "x509", "-in", str(cert), "-subject", "-noout", "-nameopt", "RFC2253").decode().strip()
    if value != f"subject=CN={expected_cn}":
        raise LifecycleError("certificate_subject_invalid")


def validate_ca(cert: Path, key: Path | None = None) -> None:
    if key is not None and key_spki(key) != cert_spki(cert):
        raise LifecycleError("certificate_key_mismatch")
    validate_subject(cert, "SecureSandbox Broker CA")
    text = run(OPENSSL, "x509", "-in", str(cert), "-text", "-noout").decode()
    purpose = run(OPENSSL, "x509", "-in", str(cert), "-purpose", "-noout").decode()
    if "CA:TRUE" not in text or "SSL client CA : Yes" not in purpose or "SSL server CA : Yes" not in purpose:
        raise LifecycleError("certificate_role_invalid")


def validate_server(cert: Path, key: Path, ca: Path) -> None:
    if key_spki(key) != cert_spki(cert):
        raise LifecycleError("certificate_key_mismatch")
    validate_chain(cert, ca)
    validate_subject(cert, "secure-sandbox-gateway")
    run(OPENSSL, "x509", "-in", str(cert), "-checkip", "172.30.10.1", "-noout")
    run(OPENSSL, "x509", "-in", str(cert), "-checkhost", "secure-sandbox-gateway", "-noout")
    purpose = run(OPENSSL, "x509", "-in", str(cert), "-purpose", "-noout").decode()
    if "SSL server : Yes" not in purpose or "SSL client : No" not in purpose:
        raise LifecycleError("certificate_role_invalid")


def validate_client(cert: Path, csr: Path, ca: Path, expected_cn: str) -> None:
    csr_public = run(OPENSSL, "req", "-in", str(csr), "-pubkey", "-noout")
    csr_der = run(OPENSSL, "pkey", "-pubin", "-outform", "DER", input_bytes=csr_public)
    if csr_der != cert_spki(cert):
        raise LifecycleError("certificate_csr_mismatch")
    validate_chain(cert, ca)
    validate_subject(cert, expected_cn)
    purpose = run(OPENSSL, "x509", "-in", str(cert), "-purpose", "-noout").decode()
    if "SSL client : Yes" not in purpose or "SSL server : No" not in purpose:
        raise LifecycleError("certificate_role_invalid")


def write_extensions(path: Path, lines: tuple[str, ...]) -> None:
    atomic_write(path, ("\n".join(lines) + "\n").encode(), 0o600)


class GatewayPKI:
    def __init__(self, state_root: Path, live_root: Path = LIVE_ROOT, manage_services: bool = True) -> None:
        self.store = TransactionStore(state_root)
        self.live_root = live_root
        self.manage_services = manage_services

    def _restart_services(self) -> None:
        if not self.manage_services:
            return
        run("/usr/bin/systemctl", "restart", *SERVICES)
        run("/usr/bin/systemctl", "is-active", "--quiet", *SERVICES)

    @staticmethod
    def _require_installed(path: Path, mode: int, uid: int, gid: int) -> None:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
                or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode):
            raise LifecycleError("installed_file_untrusted")

    def verify_active(self) -> dict:
        manifest_path = self.live_root / "pki-generation.json"
        manifest = validate_manifest(load_json(manifest_path))
        self._require_installed(manifest_path, 0o644, 0, 0)
        for directory, group_name in SERVER_TARGETS.items():
            live = self.live_root / directory
            gid = grp.getgrnam(group_name).gr_gid
            for name in ("ca.crt", "server.key", "server.crt"):
                self._require_installed(live / name, 0o640, 0, gid)
            if (live / "ca.crt").read_bytes().count(b"-----BEGIN CERTIFICATE-----") != 1:
                raise LifecycleError("active_ca_bundle_invalid")
            if certificate_metadata(live / "ca.crt", OPENSSL) != manifest["identities"]["ca"]:
                raise LifecycleError("active_ca_mismatch")
            if certificate_metadata(live / "server.crt", OPENSSL) != manifest["identities"]["server"]:
                raise LifecycleError("active_server_mismatch")
            validate_server(live / "server.crt", live / "server.key", live / "ca.crt")
        pki = self.live_root / "pki"
        self._require_installed(pki / "ca.key", 0o600, 0, 0)
        if key_spki(pki / "ca.key") != cert_spki(pki / "ca.crt"):
            raise LifecycleError("active_ca_key_mismatch")
        validate_ca(pki / "ca.crt", pki / "ca.key")
        for name in CLIENTS:
            if load_json(self.config_path(name)).get("allowed_client_sha256") != [manifest["identities"][name]["fingerprint_sha256"]]:
                raise LifecycleError("active_client_allowlist_mismatch")
            staged = self.generation(manifest["generation_id"]) / f"{name}.crt"
            if certificate_metadata(staged, OPENSSL) != manifest["identities"][name]:
                raise LifecycleError("active_client_certificate_mismatch")
            validate_chain(staged, pki / "ca.crt")
            validate_subject(staged, CLIENTS[name][0])
        return {"generation_id": manifest["generation_id"], "manifest_sha256": manifest["manifest_sha256"], "status": "verified"}

    def generation(self, generation_id: str) -> Path:
        return self.store.generations / validate_generation_id(generation_id)

    def config_path(self, name: str) -> Path:
        return self.live_root / CLIENTS[name][1].relative_to(LIVE_ROOT)

    def prepare(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        self.store.prepare()
        if path.is_symlink():
            raise LifecycleError("generation_exists")
        if path.exists():
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise LifecycleError("generation_untrusted")
            required = ("ca.key", "ca.crt", "server.key", "server.crt", "previous/ca.crt", "previous/server.crt")
            try:
                for name in required:
                    require_regular(path / name)
                validate_server(path / "server.crt", path / "server.key", path / "ca.crt")
                return {"generation_id": generation_id, "status": "gateway_prepared"}
            except (LifecycleError, FileNotFoundError):
                if self.store.path(generation_id).exists() or self.store.path(generation_id).is_symlink():
                    raise LifecycleError("generation_incomplete_after_transaction")
                shutil.rmtree(path)
        if len(list(self.store.generations.iterdir())) >= 8:
            manifest_path = self.live_root / "pki-generation.json"
            if manifest_path.exists() and not manifest_path.is_symlink():
                self.store.prune_committed(validate_manifest(load_json(manifest_path))["generation_id"])
        if len(list(self.store.generations.iterdir())) >= 8:
            raise LifecycleError("generation_limit_exceeded")
        path.mkdir(mode=0o700)
        previous = path / "previous"
        previous.mkdir(mode=0o700)
        try:
            pki = self.live_root / "pki"
            for name in ("ca.key", "ca.crt", "server.key", "server.crt"):
                atomic_copy(pki / name, previous / name, 0o600)
            for name in CLIENTS:
                atomic_copy(self.config_path(name), previous / f"{name}.json", 0o600)
            run(OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(path / "ca.key"))
            os.chmod(path / "ca.key", 0o600)
            run(
                OPENSSL, "req", "-x509", "-new", "-key", str(path / "ca.key"), "-out", str(path / "ca.crt"),
                "-days", "30", "-subj", "/CN=SecureSandbox Broker CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            )
            run(OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(path / "server.key"))
            run(OPENSSL, "req", "-new", "-key", str(path / "server.key"), "-out", str(path / "server.csr"), "-subj", "/CN=secure-sandbox-gateway")
            extensions = path / "server.ext"
            write_extensions(extensions, (
                "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature",
                "extendedKeyUsage=serverAuth", "subjectAltName=IP:172.30.10.1,DNS:secure-sandbox-gateway",
            ))
            run(
                OPENSSL, "x509", "-req", "-in", str(path / "server.csr"), "-CA", str(path / "ca.crt"),
                "-CAkey", str(path / "ca.key"), "-CAcreateserial", "-out", str(path / "server.crt"),
                "-days", "14", "-extfile", str(extensions),
            )
            for item in path.iterdir():
                if item.is_file():
                    os.chmod(item, 0o600)
            validate_server(path / "server.crt", path / "server.key", path / "ca.crt")
            validate_ca(path / "ca.crt", path / "ca.key")
            return {"generation_id": generation_id, "status": "gateway_prepared"}
        except Exception:
            shutil.rmtree(path)
            raise

    def sign(self, generation_id: str, csrs: dict[str, Path]) -> dict:
        path = self.generation(generation_id)
        if not path.is_dir() or path.is_symlink():
            raise LifecycleError("generation_missing")
        if (path / "manifest.json").exists():
            manifest = validate_manifest(load_json(path / "manifest.json"))
            if manifest["generation_id"] != generation_id:
                raise LifecycleError("generation_mismatch")
            transaction = self.store.path(generation_id)
            if not transaction.exists():
                self.store.create(generation_id, manifest["manifest_sha256"])
            elif self.store.load(generation_id)["manifest_sha256"] != manifest["manifest_sha256"]:
                raise LifecycleError("transaction_manifest_mismatch")
            return manifest
        extension = path / "client.ext"
        write_extensions(extension, (
            "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", "extendedKeyUsage=clientAuth",
        ))
        for name, (subject, _) in CLIENTS.items():
            csr = csrs[name]
            target_csr = path / f"{name}.csr"
            atomic_copy(csr, target_csr, 0o600)
            csr_subject = run(OPENSSL, "req", "-in", str(target_csr), "-subject", "-noout", "-nameopt", "RFC2253").decode().strip()
            if csr_subject != f"subject=CN={subject}":
                raise LifecycleError("csr_subject_invalid")
            target_cert = path / f"{name}.crt"
            serial = str(path / f"{name}.srl")
            target_cert.unlink(missing_ok=True)
            Path(serial).unlink(missing_ok=True)
            run(
                OPENSSL, "x509", "-req", "-in", str(target_csr), "-CA", str(path / "ca.crt"),
                "-CAkey", str(path / "ca.key"), "-CAcreateserial", "-CAserial", serial,
                "-out", str(target_cert), "-days", "14", "-extfile", str(extension),
            )
            os.chmod(target_cert, 0o600)
            validate_client(target_cert, target_csr, path / "ca.crt", subject)
        certs = {name: path / f"{name}.crt" for name in CLIENTS}
        certs.update({"ca": path / "ca.crt", "server": path / "server.crt"})
        manifest = build_manifest(generation_id, certs, OPENSSL)
        atomic_write(path / "manifest.json", canonical_bytes(manifest), 0o600)
        self.store.create(generation_id, manifest["manifest_sha256"])
        return manifest

    def _config(self, name: str, fingerprints: list[str]) -> None:
        target = self.config_path(name)
        value = load_json(target)
        old = value.get("allowed_client_sha256")
        if not isinstance(old, list):
            raise LifecycleError("client_allowlist_invalid")
        value["allowed_client_sha256"] = list(dict.fromkeys(fingerprints))
        info = target.lstat()
        atomic_write(target, canonical_bytes(value), stat.S_IMODE(info.st_mode))
        os.chown(target, info.st_uid, info.st_gid)

    def _verify_dual(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        manifest = validate_manifest(load_json(path / "manifest.json"))
        expected_bundle = (path / "previous" / "ca.crt").read_bytes().rstrip() + b"\n" + (path / "ca.crt").read_bytes().rstrip() + b"\n"
        for directory in SERVER_TARGETS:
            live = self.live_root / directory
            if (live / "ca.crt").read_bytes() != expected_bundle:
                raise LifecycleError("dual_ca_bundle_mismatch")
            if certificate_metadata(live / "server.crt", OPENSSL) != manifest["identities"]["server"]:
                raise LifecycleError("active_server_mismatch")
            validate_server(live / "server.crt", live / "server.key", path / "ca.crt")
        for name in CLIENTS:
            old = load_json(path / "previous" / f"{name}.json")["allowed_client_sha256"]
            expected = list(dict.fromkeys(old + [manifest["identities"][name]["fingerprint_sha256"]]))
            if load_json(self.config_path(name)).get("allowed_client_sha256") != expected:
                raise LifecycleError("dual_client_allowlist_mismatch")
        self._restart_services()
        return manifest

    def _install_server_identity(self, path: Path, ca_source: Path) -> None:
        for directory, group_name in SERVER_TARGETS.items():
            live = self.live_root / directory
            gid = grp.getgrnam(group_name).gr_gid
            atomic_copy(path / "server.key", live / "server.key", 0o640, 0, gid)
            atomic_copy(path / "server.crt", live / "server.crt", 0o640, 0, gid)
            atomic_copy(ca_source, live / "ca.crt", 0o640, 0, gid)

    def activate_dual(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        current = self.store.load(generation_id)
        if PHASES.index(current["phase"]) >= PHASES.index("gateway_dual_trust"):
            if PHASES.index(current["phase"]) < PHASES.index("gateway_new_only"):
                self._verify_dual(generation_id)
            else:
                self.verify_active()
            return current
        manifest = validate_manifest(load_json(path / "manifest.json"))
        old_ca = (path / "previous" / "ca.crt").read_bytes()
        new_ca = (path / "ca.crt").read_bytes()
        bundle = path / "dual-ca.crt"
        atomic_write(bundle, old_ca.rstrip() + b"\n" + new_ca.rstrip() + b"\n", 0o600)
        self._install_server_identity(path, bundle)
        for name in CLIENTS:
            old_value = load_json(path / "previous" / f"{name}.json")["allowed_client_sha256"]
            self._config(name, old_value + [manifest["identities"][name]["fingerprint_sha256"]])
        self._restart_services()
        return self.store.advance(generation_id, "research_dual_trust", "gateway_dual_trust")

    def activate_new_only(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        current = self.store.load(generation_id)
        if PHASES.index(current["phase"]) >= PHASES.index("gateway_new_only"):
            self.verify_active()
            return current
        manifest = validate_manifest(load_json(path / "manifest.json"))
        pki = self.live_root / "pki"
        self._install_server_identity(path, path / "ca.crt")
        atomic_copy(path / "ca.key", pki / "ca.key", 0o600)
        for name in CLIENTS:
            self._config(name, [manifest["identities"][name]["fingerprint_sha256"]])
        atomic_write(self.live_root / "pki-generation.json", canonical_bytes(manifest), 0o644)
        self._restart_services()
        if self.manage_services:
            run("/usr/bin/logger", "-t", "secure-sandbox-pki", json.dumps(activation_event(manifest), separators=(",", ":"), sort_keys=True))
        return self.store.advance(generation_id, "research_new_clients", "gateway_new_only")

    def commit(self, generation_id: str) -> dict:
        current = self.store.load(generation_id)
        self.verify_active()
        if PHASES.index(current["phase"]) >= PHASES.index("committed"):
            return current
        return self.store.advance(generation_id, "gateway_new_only", "committed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", default=str(STATE_ROOT))
    parser.add_argument("--live-root", default=str(LIVE_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify")
    for name in ("prepare", "activate-dual", "activate-new-only", "commit"):
        command = sub.add_parser(name)
        command.add_argument("generation_id")
    sign = sub.add_parser("sign")
    sign.add_argument("generation_id")
    for name in CLIENTS:
        sign.add_argument(f"--{name}-csr", required=True)
    args = parser.parse_args()
    try:
        manager = GatewayPKI(Path(args.state_root), Path(args.live_root))
        with manager.store.locked():
            if args.command == "verify":
                result = manager.verify_active()
            elif args.command == "prepare":
                result = manager.prepare(args.generation_id)
            elif args.command == "sign":
                result = manager.sign(args.generation_id, {name: Path(getattr(args, f"{name}_csr")) for name in CLIENTS})
            elif args.command == "activate-dual":
                result = manager.activate_dual(args.generation_id)
            elif args.command == "activate-new-only":
                result = manager.activate_new_only(args.generation_id)
            else:
                result = manager.commit(args.generation_id)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (LifecycleError, OSError, KeyError, ValueError) as error:
        print(json.dumps({"error": str(error)}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
