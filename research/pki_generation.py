#!/usr/bin/env python3
"""Research half of the transactional SecureSandbox PKI lifecycle."""

from __future__ import annotations

import argparse
import grp
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from pki_lifecycle import (
    LifecycleError,
    PHASES,
    TransactionStore,
    activation_event,
    atomic_write,
    canonical_bytes,
    certificate_metadata,
    load_json,
    validate_generation_id,
    validate_manifest,
)
from pki_guest_helpers import atomic_copy, cert_spki, key_spki, require_regular, run, validate_chain, validate_subject


OPENSSL = "/usr/bin/openssl"
LIVE_ROOT = Path("/etc/secure-sandbox")
STATE_ROOT = Path("/var/lib/secure-sandbox/pki-lifecycle")
CLIENTS = {
    "broker": ("secure-sandbox-research", "relay", "claude-relay", "claude-relay.service"),
    "telemetry": ("secure-sandbox-research-telemetry", "telemetry", "telemetry-exporter", "telemetry-exporter.service"),
    "conversation": ("secure-sandbox-research-conversation", "conversation-transport", "conversation-shipper", "conversation-shipper.service"),
}


class ResearchPKI:
    def __init__(self, state_root: Path, live_root: Path = LIVE_ROOT, manage_services: bool = True) -> None:
        self.store = TransactionStore(state_root)
        self.live_root = live_root
        self.manage_services = manage_services

    def generation(self, generation_id: str) -> Path:
        return self.store.generations / validate_generation_id(generation_id)

    def _restart_and_probe(self) -> None:
        if not self.manage_services:
            return
        services = [item[3] for item in CLIENTS.values()]
        run("/usr/bin/systemctl", "restart", *services)
        run("/usr/bin/systemctl", "is-active", "--quiet", *services)
        probes = (
            ("/usr/bin/curl", "-fsS", "--max-time", "5", "http://127.0.0.1:18080/healthz"),
            ("/usr/sbin/runuser", "-u", "telemetry-exporter", "--", "/usr/local/libexec/secure-sandbox/telemetry_exporter.py", "--health"),
            ("/usr/sbin/runuser", "-u", "conversation-shipper", "--", "/usr/local/libexec/secure-sandbox/conversation_shipper.py", "--health"),
        )
        for probe in probes:
            for attempt in range(10):
                try:
                    run(*probe)
                    break
                except LifecycleError:
                    if attempt == 9:
                        raise
                    time.sleep(0.5)

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
        ca_metadata = manifest["identities"]["ca"]
        for name, (_, directory, group_name, _) in CLIENTS.items():
            live = self.live_root / directory
            gid = grp.getgrnam(group_name).gr_gid
            for file_name in ("client.key", "client.crt", "ca.crt"):
                self._require_installed(live / file_name, 0o640, 0, gid)
            if (live / "ca.crt").read_bytes().count(b"-----BEGIN CERTIFICATE-----") != 1:
                raise LifecycleError("active_ca_bundle_invalid")
            if certificate_metadata(live / "ca.crt", OPENSSL) != ca_metadata:
                raise LifecycleError("active_ca_mismatch")
            if certificate_metadata(live / "client.crt", OPENSSL) != manifest["identities"][name]:
                raise LifecycleError("active_client_mismatch")
            if key_spki(live / "client.key") != cert_spki(live / "client.crt"):
                raise LifecycleError("active_client_key_mismatch")
            validate_chain(live / "client.crt", live / "ca.crt")
            validate_subject(live / "client.crt", CLIENTS[name][0])
            purpose = run(OPENSSL, "x509", "-in", str(live / "client.crt"), "-purpose", "-noout").decode()
            if "SSL client : Yes" not in purpose or "SSL server : No" not in purpose:
                raise LifecycleError("certificate_role_invalid")
        return {"generation_id": manifest["generation_id"], "manifest_sha256": manifest["manifest_sha256"], "status": "verified"}

    def prepare(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        self.store.prepare()
        if path.is_symlink():
            raise LifecycleError("generation_exists")
        if path.exists():
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise LifecycleError("generation_untrusted")
            try:
                for name in CLIENTS:
                    require_regular(path / f"{name}.key")
                    require_regular(path / f"{name}.csr")
                    require_regular(path / "previous" / f"{name}.key")
                return {"generation_id": generation_id, "status": "research_prepared"}
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
            for name, (subject, directory, _, _) in CLIENTS.items():
                live = self.live_root / directory
                atomic_copy(live / "client.key", previous / f"{name}.key", 0o600)
                atomic_copy(live / "client.crt", previous / f"{name}.crt", 0o600)
                atomic_copy(live / "ca.crt", previous / f"{name}-ca.crt", 0o600)
                run(OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(path / f"{name}.key"))
                run(OPENSSL, "req", "-new", "-key", str(path / f"{name}.key"), "-out", str(path / f"{name}.csr"), "-subj", f"/CN={subject}")
                os.chmod(path / f"{name}.key", 0o600)
                os.chmod(path / f"{name}.csr", 0o600)
            return {"generation_id": generation_id, "status": "research_prepared"}
        except Exception:
            shutil.rmtree(path)
            raise

    def import_signed(self, generation_id: str, ca: Path, certificates: dict[str, Path], manifest_path: Path) -> dict:
        path = self.generation(generation_id)
        if not path.is_dir() or path.is_symlink():
            raise LifecycleError("generation_missing")
        imported_manifest = path / ".import-manifest.json"
        atomic_copy(manifest_path, imported_manifest, 0o600)
        imported_ca = path / ".import-ca.crt"
        atomic_copy(ca, imported_ca, 0o600)
        imported_certificates = {}
        for name, certificate in certificates.items():
            imported_certificates[name] = path / f".import-{name}.crt"
            atomic_copy(certificate, imported_certificates[name], 0o600)
        manifest = validate_manifest(load_json(imported_manifest))
        if manifest["generation_id"] != generation_id:
            raise LifecycleError("generation_mismatch")
        if (path / "manifest.json").exists():
            installed = validate_manifest(load_json(path / "manifest.json"))
            if installed["manifest_sha256"] != manifest["manifest_sha256"]:
                raise LifecycleError("transaction_manifest_mismatch")
            transaction = self.store.path(generation_id)
            if not transaction.exists():
                self.store.create(generation_id, manifest["manifest_sha256"])
            elif self.store.load(generation_id)["manifest_sha256"] != manifest["manifest_sha256"]:
                raise LifecycleError("transaction_manifest_mismatch")
            return installed
        if certificate_metadata(imported_ca, OPENSSL) != manifest["identities"]["ca"]:
            raise LifecycleError("ca_manifest_mismatch")
        for name, (subject, _, _, _) in CLIENTS.items():
            cert = imported_certificates[name]
            if certificate_metadata(cert, OPENSSL) != manifest["identities"][name]:
                raise LifecycleError("certificate_manifest_mismatch")
            if key_spki(path / f"{name}.key") != cert_spki(cert):
                raise LifecycleError("certificate_key_mismatch")
            validate_chain(cert, imported_ca)
            validate_subject(cert, subject)
            purpose = run(OPENSSL, "x509", "-in", str(cert), "-purpose", "-noout").decode()
            if "SSL client : Yes" not in purpose or "SSL server : No" not in purpose:
                raise LifecycleError("certificate_role_invalid")
            atomic_copy(cert, path / f"{name}.crt", 0o600)
        atomic_copy(imported_ca, path / "ca.crt", 0o600)
        atomic_copy(imported_manifest, path / "manifest.json", 0o600)
        imported_manifest.unlink()
        imported_ca.unlink()
        for cert in imported_certificates.values():
            cert.unlink()
        self.store.create(generation_id, manifest["manifest_sha256"])
        return manifest

    def _install_ca(self, path: Path, dual: bool) -> None:
        for name, (_, directory, group_name, _) in CLIENTS.items():
            target = self.live_root / directory / "ca.crt"
            if dual:
                old = path / "previous" / f"{name}-ca.crt"
                bundle = path / f"{name}-dual-ca.crt"
                atomic_write(bundle, old.read_bytes().rstrip() + b"\n" + (path / "ca.crt").read_bytes().rstrip() + b"\n", 0o600)
                source = bundle
            else:
                source = path / "ca.crt"
            atomic_copy(source, target, 0o640, 0, grp.getgrnam(group_name).gr_gid)

    def _verify_dual(self, generation_id: str, new_clients: bool) -> dict:
        path = self.generation(generation_id)
        manifest = validate_manifest(load_json(path / "manifest.json"))
        for name, (subject, directory, group_name, _) in CLIENTS.items():
            live = self.live_root / directory
            expected_ca = (path / "previous" / f"{name}-ca.crt").read_bytes().rstrip() + b"\n" + (path / "ca.crt").read_bytes().rstrip() + b"\n"
            if (live / "ca.crt").read_bytes() != expected_ca:
                raise LifecycleError("dual_ca_bundle_mismatch")
            expected_cert = path / f"{name}.crt" if new_clients else path / "previous" / f"{name}.crt"
            expected_key = path / f"{name}.key" if new_clients else path / "previous" / f"{name}.key"
            if cert_spki(live / "client.crt") != cert_spki(expected_cert):
                raise LifecycleError("active_client_mismatch")
            if key_spki(live / "client.key") != key_spki(expected_key):
                raise LifecycleError("active_client_key_mismatch")
            validate_subject(live / "client.crt", subject)
            self._require_installed(live / "ca.crt", 0o640, 0, grp.getgrnam(group_name).gr_gid)
        self._restart_and_probe()
        return manifest

    def activate_dual_trust(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        current = self.store.load(generation_id)
        if PHASES.index(current["phase"]) >= PHASES.index("research_dual_trust"):
            if PHASES.index(current["phase"]) < PHASES.index("research_new_clients"):
                self._verify_dual(generation_id, False)
            elif PHASES.index(current["phase"]) < PHASES.index("committed"):
                self._verify_dual(generation_id, True)
            else:
                self.verify_active()
            return current
        validate_manifest(load_json(path / "manifest.json"))
        self._install_ca(path, True)
        self._restart_and_probe()
        return self.store.advance(generation_id, "prepared", "research_dual_trust")

    def activate_clients(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        current = self.store.load(generation_id)
        if PHASES.index(current["phase"]) >= PHASES.index("research_new_clients"):
            if PHASES.index(current["phase"]) < PHASES.index("committed"):
                self._verify_dual(generation_id, True)
            else:
                self.verify_active()
            return current
        manifest = validate_manifest(load_json(path / "manifest.json"))
        for name, (_, directory, group_name, _) in CLIENTS.items():
            live = self.live_root / directory
            gid = grp.getgrnam(group_name).gr_gid
            atomic_copy(path / f"{name}.key", live / "client.key", 0o640, 0, gid)
            atomic_copy(path / f"{name}.crt", live / "client.crt", 0o640, 0, gid)
            if certificate_metadata(live / "client.crt", OPENSSL) != manifest["identities"][name]:
                raise LifecycleError("installed_identity_mismatch")
        self._restart_and_probe()
        return self.store.advance(generation_id, "gateway_dual_trust", "research_new_clients")

    def commit(self, generation_id: str) -> dict:
        path = self.generation(generation_id)
        current = self.store.load(generation_id)
        if PHASES.index(current["phase"]) >= PHASES.index("committed"):
            self.verify_active()
            return current
        manifest = validate_manifest(load_json(path / "manifest.json"))
        self._install_ca(path, False)
        atomic_write(self.live_root / "pki-generation.json", canonical_bytes(manifest), 0o644)
        self._restart_and_probe()
        if self.manage_services:
            run("/usr/bin/logger", "-t", "secure-sandbox-pki", json.dumps(activation_event(manifest), separators=(",", ":"), sort_keys=True))
        return self.store.advance(generation_id, "gateway_new_only", "committed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", default=str(STATE_ROOT))
    parser.add_argument("--live-root", default=str(LIVE_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify")
    for name in ("prepare", "activate-dual-trust", "activate-clients", "commit"):
        command = sub.add_parser(name)
        command.add_argument("generation_id")
    imported = sub.add_parser("import-signed")
    imported.add_argument("generation_id")
    imported.add_argument("--ca", required=True)
    imported.add_argument("--manifest", required=True)
    for name in CLIENTS:
        imported.add_argument(f"--{name}-cert", required=True)
    args = parser.parse_args()
    try:
        manager = ResearchPKI(Path(args.state_root), Path(args.live_root))
        with manager.store.locked():
            if args.command == "verify":
                result = manager.verify_active()
            elif args.command == "prepare":
                result = manager.prepare(args.generation_id)
            elif args.command == "import-signed":
                result = manager.import_signed(
                    args.generation_id, Path(args.ca),
                    {name: Path(getattr(args, f"{name}_cert")) for name in CLIENTS}, Path(args.manifest),
                )
            elif args.command == "activate-dual-trust":
                result = manager.activate_dual_trust(args.generation_id)
            elif args.command == "activate-clients":
                result = manager.activate_clients(args.generation_id)
            else:
                result = manager.commit(args.generation_id)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (LifecycleError, OSError, KeyError, ValueError) as error:
        print(json.dumps({"error": str(error)}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
