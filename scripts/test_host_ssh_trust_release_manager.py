#!/usr/bin/env python3
from __future__ import annotations

import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "host_ssh_trust_release_manager",
    ROOT / "scripts/host-controller-release.py",
)
assert SPEC and SPEC.loader
MANAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANAGER)

NOW = 2_000_000_000


def public_key(byte: int, comment: str = "") -> bytes:
    key_type = b"ssh-ed25519"
    blob = (
        len(key_type).to_bytes(4, "big") + key_type
        + (32).to_bytes(4, "big") + bytes([byte]) * 32
    )
    suffix = f" {comment}" if comment else ""
    return (
        f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')}{suffix}\n"
    ).encode("ascii")


class HostSSHTrustReleaseManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.repo = self.root / "SecureSandbox"
        self.repo.mkdir(mode=0o700)
        self.install_root = self.root / "host-install"
        self.install_root.mkdir(mode=0o755)
        self.install_root.chmod(0o755)
        self.runs = self.repo / "runs"
        self.runs.mkdir(mode=0o700)
        self.provisioning = public_key(1, "provisioning")
        self.control = public_key(2, "control")
        self.known_hosts = b"".join(
            alias.encode("ascii") + b" " + public_key(index).strip() + b"\n"
            for index, alias in enumerate(MANAGER.HOST_SSH_TRUST_ALIASES, 10)
        )
        for name, raw in (
            ("provisioning_key.pub", self.provisioning),
            ("control_key.pub", self.control),
            ("known_hosts", self.known_hosts),
        ):
            path = self.runs / name
            path.write_bytes(raw)
            path.chmod(0o600)
        self.sockets: dict[str, Path] = {}
        self.bound_sockets: list[socket.socket] = []
        for name in ("provisioning_key", "control_key"):
            path = self.root / f"{name}.sock"
            bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            bound.bind(str(path))
            path.chmod(0o600)
            self.bound_sockets.append(bound)
            self.sockets[name] = path
        self.uid = os.geteuid()
        if self.uid == 0:
            self.skipTest("focused source tests require a non-root test uid")

    def tearDown(self) -> None:
        for bound in self.bound_sockets:
            bound.close()
        self.temporary.cleanup()

    def runner(self, command, **kwargs):
        socket_path = Path(kwargs["env"]["SSH_AUTH_SOCK"])
        if socket_path == self.sockets["provisioning_key"]:
            raw = self.provisioning
        elif socket_path == self.sockets["control_key"]:
            raw = self.control
        else:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"bad socket")
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    def sources(self):
        account = SimpleNamespace(
            pw_dir=str(self.root), pw_uid=self.uid, pw_gid=os.getgid(),
        )
        with mock.patch.object(MANAGER.pwd, "getpwuid", return_value=account):
            return MANAGER.host_ssh_trust_sources(
                self.repo, self.uid, agent_runner=self.runner,
                socket_paths=self.sockets,
            )

    def plan(self, trust_root: Path):
        records, projected = self.sources()
        plan = MANAGER.make_host_ssh_trust_plan(
            self.repo, self.uid, trust_root=trust_root, now=NOW,
            install_root=self.install_root,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
            expected_install_uid=self.uid,
        )
        return plan, records, projected

    def authorization(self, plan: dict) -> dict:
        value = {
            "schema": MANAGER.HOST_SSH_TRUST_AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()),
            "request_sha256": "d" * 64,
            "pending_receipt_sha256": "e" * 64,
            "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "trust_id": plan["trust_id"],
            "operator_uid": plan["operator_uid"],
            "method": "touch-id",
            "password_fallback": False,
            "authorized_at": NOW,
            "expires_at": NOW + 120,
            "host_release_id": plan["host_release_id"],
            "requesting_agent_sha256": "f" * 64,
            "requesting_session_sha256": "1" * 64,
            "status": "authorized",
        }
        value["authorization_sha256"] = MANAGER._host_ssh_trust_digest(value)
        return value

    def test_sources_are_canonical_and_agent_bound(self):
        records, projected = self.sources()
        self.assertEqual(set(records), set(MANAGER.HOST_SSH_TRUST_SOURCE_PATHS))
        self.assertEqual(projected["provisioning_key"], public_key(1))
        self.assertEqual(projected["control_key"], public_key(2))
        self.assertEqual(records["known_hosts"]["host_fingerprints"].keys(),
                         dict.fromkeys(MANAGER.HOST_SSH_TRUST_ALIASES).keys())
        self.assertNotEqual(records["provisioning_key"]["fingerprint"],
                            records["control_key"]["fingerprint"])

    def test_root_agent_query_drops_to_operator_identity(self):
        observed = {}

        def runner(command, **kwargs):
            observed.update(kwargs)
            return self.runner(command, **kwargs)

        with mock.patch.object(MANAGER.os, "geteuid", return_value=0):
            raw, _fingerprint = MANAGER._host_ssh_agent_key(
                self.sockets["provisioning_key"], self.uid, os.getgid(),
                runner,
            )
        self.assertEqual(raw, public_key(1))
        self.assertEqual(observed["user"], self.uid)
        self.assertEqual(observed["group"], os.getgid())
        self.assertEqual(observed["extra_groups"], [])

    def test_extra_known_host_fails_closed(self):
        path = self.runs / "known_hosts"
        path.write_bytes(self.known_hosts + b"Other ssh-ed25519 AAAA\n")
        path.chmod(0o600)
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "known_hosts_invalid"):
            self.sources()

    def test_duplicate_known_host_identity_fails_closed(self):
        duplicate = public_key(10).strip()
        path = self.runs / "known_hosts"
        path.write_bytes(b"".join(
            alias.encode("ascii") + b" " + duplicate + b"\n"
            for alias in MANAGER.HOST_SSH_TRUST_ALIASES
        ))
        path.chmod(0o600)
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "known_hosts_invalid"):
            self.sources()

    def test_plan_binds_sources_and_rejects_changed_digest(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        plan, _records, _projected = self.plan(trust_root)
        self.assertEqual(
            MANAGER.validate_host_ssh_trust_plan(plan, now=NOW), plan,
        )
        changed = json.loads(json.dumps(plan))
        changed["sources"]["control_key"]["source_sha256"] = "9" * 64
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "plan_invalid"):
            MANAGER.validate_host_ssh_trust_plan(changed, now=NOW)

    def test_enrollment_publishes_immutable_generation_and_status(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        plan, records, projected = self.plan(trust_root)
        authorization = self.authorization(plan)
        prior_umask = os.umask(0o077)
        try:
            result = MANAGER.enroll_host_ssh_trust(
                self.repo, self.uid, plan, authorization,
                install_root=self.install_root, trust_root=trust_root,
                expected_uid=self.uid, now=NOW + 1,
                machine_identity_reader=lambda: "a" * 64,
                host_binding_reader=lambda _root, _uid: (
                    "b" * 64, "c" * 64,
                ),
                source_reader=lambda _repo, _uid: (records, projected),
            )
        finally:
            os.umask(prior_umask)
        self.assertEqual(result["status"], "enrolled")
        self.assertEqual(stat.S_IMODE(trust_root.stat().st_mode), 0o755)
        self.assertEqual(
            stat.S_IMODE((trust_root / "generations").stat().st_mode),
            0o755,
        )
        generation = trust_root / "generations" / plan["trust_id"]
        self.assertEqual(stat.S_IMODE(generation.stat().st_mode), 0o555)
        self.assertEqual(os.readlink(trust_root / "current"),
                         f"generations/{plan['trust_id']}")
        for path in generation.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
        status = MANAGER.host_ssh_trust_status(
            self.uid, install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
        )
        self.assertEqual(status["status"], "verified")
        self.assertEqual(status["trust_id"], plan["trust_id"])
        replay = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, plan, authorization,
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1_000,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
        )
        self.assertEqual(replay["status"], "already-enrolled")

    def test_fresh_same_material_rerun_is_noop_but_expired_plan_cannot_mutate(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        first, records, projected = self.plan(trust_root)
        initial = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, first, self.authorization(first),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
        )
        second, second_records, second_projected = self.plan(trust_root)
        self.assertEqual(second["trust_id"], first["trust_id"])
        self.assertNotEqual(second["plan_sha256"], first["plan_sha256"])
        replay = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, second, self.authorization(second),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (
                second_records, second_projected,
            ),
        )
        self.assertEqual(replay["status"], "already-enrolled")
        self.assertEqual(replay["manifest_sha256"], initial["manifest_sha256"])
        self.assertEqual(replay["plan_sha256"], second["plan_sha256"])
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "plan_invalid"):
            MANAGER.enroll_host_ssh_trust(
                self.repo, self.uid, second, self.authorization(second),
                install_root=self.install_root, trust_root=trust_root,
                expected_uid=self.uid, now=NOW + 1_000,
                machine_identity_reader=lambda: "a" * 64,
                host_binding_reader=lambda _root, _uid: (
                    "b" * 64, "c" * 64,
                ),
                source_reader=lambda _repo, _uid: (
                    second_records, second_projected,
                ),
            )

    def test_fresh_authority_recovers_unselected_durable_generation(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        first, records, projected = self.plan(trust_root)
        with mock.patch.object(
            MANAGER.os, "replace", side_effect=OSError("selector fault"),
        ), self.assertRaises(OSError):
            MANAGER.enroll_host_ssh_trust(
                self.repo, self.uid, first, self.authorization(first),
                install_root=self.install_root, trust_root=trust_root,
                expected_uid=self.uid, now=NOW + 1,
                machine_identity_reader=lambda: "a" * 64,
                host_binding_reader=lambda _root, _uid: (
                    "b" * 64, "c" * 64,
                ),
                source_reader=lambda _repo, _uid: (records, projected),
            )
        self.assertFalse(os.path.lexists(trust_root / "current"))
        self.assertTrue(
            (trust_root / "generations" / first["trust_id"]).is_dir()
        )
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "plan_invalid"):
            MANAGER.enroll_host_ssh_trust(
                self.repo, self.uid, first, self.authorization(first),
                install_root=self.install_root, trust_root=trust_root,
                expected_uid=self.uid, now=NOW + 1_000,
                machine_identity_reader=lambda: "a" * 64,
                host_binding_reader=lambda _root, _uid: (
                    "b" * 64, "c" * 64,
                ),
                source_reader=lambda _repo, _uid: (records, projected),
            )
        self.assertFalse(os.path.lexists(trust_root / "current"))
        second, second_records, second_projected = self.plan(trust_root)
        recovered = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, second, self.authorization(second),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (
                second_records, second_projected,
            ),
        )
        self.assertEqual(recovered["status"], "enrolled")
        retained = list((trust_root / "generations").glob(
            f".unselected-{first['trust_id']}-*",
        ))
        self.assertEqual(len(retained), 1)
        self.assertEqual(
            os.readlink(trust_root / "current"),
            f"generations/{second['trust_id']}",
        )

    def test_fresh_authority_recovers_exact_empty_trust_root(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.mkdir(parents=True, mode=0o755)
        trust_root.chmod(0o755)

        # Compatibility never treats this interrupted initialization as
        # clean absence.
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "generations_untrusted",
        ):
            MANAGER.enforce_host_ssh_trust_release_compatibility(
                {"ssh_config": "c" * 64}, trust_root=trust_root,
                expected_uid=self.uid,
            )

        plan, records, projected = self.plan(trust_root)
        result = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, plan, self.authorization(plan),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
        )
        self.assertEqual(result["status"], "enrolled")

    def test_nonempty_root_without_generations_is_not_recoverable(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.mkdir(parents=True, mode=0o755)
        trust_root.chmod(0o755)
        marker = trust_root / "unexpected"
        marker.write_text("evidence", encoding="utf-8")
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "generations_untrusted",
        ):
            self.plan(trust_root)

    def test_fresh_authority_recovers_mode_0700_empty_trust_root(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.mkdir(parents=True, mode=0o700)
        trust_root.chmod(0o700)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "root_untrusted",
        ):
            MANAGER.enforce_host_ssh_trust_release_compatibility(
                {"ssh_config": "c" * 64}, trust_root=trust_root,
                expected_uid=self.uid,
            )
        plan, records, projected = self.plan(trust_root)
        result = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, plan, self.authorization(plan),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
        )
        self.assertEqual(result["status"], "enrolled")
        self.assertEqual(stat.S_IMODE(trust_root.stat().st_mode), 0o755)
        self.assertEqual(
            stat.S_IMODE((trust_root / "generations").stat().st_mode),
            0o755,
        )

    def test_fresh_authority_recovers_mode_0700_empty_generations(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        generations = trust_root / "generations"
        generations.mkdir(parents=True, mode=0o700)
        trust_root.chmod(0o755)
        generations.chmod(0o700)
        with self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "generations_untrusted",
        ):
            MANAGER.enforce_host_ssh_trust_release_compatibility(
                {"ssh_config": "c" * 64}, trust_root=trust_root,
                expected_uid=self.uid,
            )
        plan, records, projected = self.plan(trust_root)
        result = MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, plan, self.authorization(plan),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
        )
        self.assertEqual(result["status"], "enrolled")
        self.assertEqual(stat.S_IMODE(generations.stat().st_mode), 0o755)

    def test_expiry_after_generation_publication_never_selects_it(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        plan, records, projected = self.plan(trust_root)
        clock = {"now": NOW}
        original = MANAGER._host_ssh_trust_manifest

        def observe_generation(generation, trust_id, expected_uid):
            value = original(generation, trust_id, expected_uid)
            if generation.name == plan["trust_id"]:
                clock["now"] = NOW + 121
            return value

        with mock.patch.object(
            MANAGER, "_host_ssh_trust_manifest",
            side_effect=observe_generation,
        ), self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "authorization_invalid",
        ):
            MANAGER.enroll_host_ssh_trust(
                self.repo, self.uid, plan, self.authorization(plan),
                install_root=self.install_root, trust_root=trust_root,
                expected_uid=self.uid, time_reader=lambda: clock["now"],
                machine_identity_reader=lambda: "a" * 64,
                host_binding_reader=lambda _root, _uid: (
                    "b" * 64, "c" * 64,
                ),
                source_reader=lambda _repo, _uid: (records, projected),
            )
        self.assertTrue(
            (trust_root / "generations" / plan["trust_id"]).is_dir()
        )
        self.assertFalse(os.path.lexists(trust_root / "current"))

    def test_waiting_for_host_lock_rechecks_expiry_before_publication(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        plan, records, projected = self.plan(trust_root)
        held = os.open(
            self.install_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        fcntl.flock(held, fcntl.LOCK_EX)
        entering = threading.Event()
        clock = {"now": NOW}
        failures: list[BaseException] = []
        original_open = MANAGER.open_trusted_absolute_directory

        def observed_open(path, uid, *args, **kwargs):
            entering.set()
            return original_open(path, uid, *args, **kwargs)

        def worker():
            try:
                MANAGER.enroll_host_ssh_trust(
                    self.repo, self.uid, plan, self.authorization(plan),
                    install_root=self.install_root, trust_root=trust_root,
                    expected_uid=self.uid,
                    time_reader=lambda: clock["now"],
                    machine_identity_reader=lambda: "a" * 64,
                    host_binding_reader=lambda _root, _uid: (
                        "b" * 64, "c" * 64,
                    ),
                    source_reader=lambda _repo, _uid: (records, projected),
                )
            except BaseException as error:
                failures.append(error)

        try:
            with mock.patch.object(
                MANAGER, "open_trusted_absolute_directory",
                side_effect=observed_open,
            ):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertTrue(entering.wait(timeout=2))
                clock["now"] = NOW + 121
                fcntl.flock(held, fcntl.LOCK_UN)
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], MANAGER.ReleaseFailure)
        self.assertIn("authorization_invalid", str(failures[0]))
        self.assertFalse(os.path.lexists(trust_root))

    def test_concurrent_enrollments_cannot_overwrite_stale_predecessor(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        first, first_records, first_projected = self.plan(trust_root)
        self.known_hosts = b"".join(
            alias.encode("ascii") + b" " + public_key(index).strip() + b"\n"
            for index, alias in enumerate(
                MANAGER.HOST_SSH_TRUST_ALIASES, 20,
            )
        )
        (self.runs / "known_hosts").write_bytes(self.known_hosts)
        (self.runs / "known_hosts").chmod(0o600)
        second, second_records, second_projected = self.plan(trust_root)
        self.assertNotEqual(first["trust_id"], second["trust_id"])
        barrier = threading.Barrier(3)
        outcomes: list[dict] = []
        failures: list[BaseException] = []

        def worker(plan, records, projected):
            barrier.wait()
            try:
                outcomes.append(MANAGER.enroll_host_ssh_trust(
                    self.repo, self.uid, plan, self.authorization(plan),
                    install_root=self.install_root, trust_root=trust_root,
                    expected_uid=self.uid, now=NOW + 1,
                    machine_identity_reader=lambda: "a" * 64,
                    host_binding_reader=lambda _root, _uid: (
                        "b" * 64, "c" * 64,
                    ),
                    source_reader=lambda _repo, _uid: (records, projected),
                ))
            except BaseException as error:
                failures.append(error)

        threads = [
            threading.Thread(
                target=worker, args=(first, first_records, first_projected),
            ),
            threading.Thread(
                target=worker, args=(second, second_records, second_projected),
            ),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["status"], "enrolled")
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], MANAGER.ReleaseFailure)
        self.assertIn("previous_changed", str(failures[0]))

    def test_changed_source_after_authorization_fails_without_selector(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        plan, records, projected = self.plan(trust_root)
        changed = json.loads(json.dumps(records))
        changed["known_hosts"]["source_sha256"] = "8" * 64
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "sources_changed"):
            MANAGER.enroll_host_ssh_trust(
                self.repo, self.uid, plan, self.authorization(plan),
                install_root=self.install_root, trust_root=trust_root,
                expected_uid=self.uid, now=NOW + 1,
                machine_identity_reader=lambda: "a" * 64,
                host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
                source_reader=lambda _repo, _uid: (changed, projected),
            )
        self.assertFalse(os.path.lexists(trust_root / "current"))

    def test_release_compatibility_is_monotonic_after_enrollment(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        plan, records, projected = self.plan(trust_root)
        MANAGER.enroll_host_ssh_trust(
            self.repo, self.uid, plan, self.authorization(plan),
            install_root=self.install_root, trust_root=trust_root,
            expected_uid=self.uid, now=NOW + 1,
            machine_identity_reader=lambda: "a" * 64,
            host_binding_reader=lambda _root, _uid: ("b" * 64, "c" * 64),
            source_reader=lambda _repo, _uid: (records, projected),
        )
        MANAGER.enforce_host_ssh_trust_release_compatibility(
            {"ssh_config": "c" * 64}, trust_root=trust_root,
            expected_uid=self.uid,
        )
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "incompatible"):
            MANAGER.enforce_host_ssh_trust_release_compatibility(
                {"ssh_config": "7" * 64}, trust_root=trust_root,
                expected_uid=self.uid,
            )

    def test_incomplete_store_is_not_clean_absence_for_compatibility(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        (trust_root / "generations").mkdir(parents=True, mode=0o755)
        trust_root.chmod(0o755)
        with self.assertRaisesRegex(MANAGER.ReleaseFailure, "selector_missing"):
            MANAGER.enforce_host_ssh_trust_release_compatibility(
                {"ssh_config": "c" * 64}, trust_root=trust_root,
                expected_uid=self.uid,
            )

    def test_parent_acl_grant_is_rejected_even_when_store_is_absent(self):
        trust_root = self.root / "state" / "host-ssh-trust"
        trust_root.parent.mkdir(mode=0o700)
        with mock.patch.object(
            MANAGER, "reject_extended_acl",
            side_effect=MANAGER.ReleaseFailure(
                "host_ssh_trust_parent_untrusted",
            ),
        ), self.assertRaisesRegex(
            MANAGER.ReleaseFailure, "host_ssh_trust_parent_untrusted",
        ):
            MANAGER.host_ssh_trust_current(
                trust_root, self.uid, allow_absent=True,
            )


if __name__ == "__main__":
    unittest.main()
