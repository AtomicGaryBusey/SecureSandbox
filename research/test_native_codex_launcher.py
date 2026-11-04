#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import resource
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from research import native_codex_policy as policy
from research import native_codex_runtime_driver as runtime_driver


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "research/native_codex_launcher.c"


class NativeCodexLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("C compiler unavailable")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temporary.name) / "native-codex-launcher-test"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-DSECURE_SANDBOX_LAUNCHER_TEST",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-function",
                str(SOURCE),
                "-o",
                str(cls.binary),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @staticmethod
    def frame(projection_id: str, token: bytes) -> bytes:
        return b"SSCODX1\n" + projection_id.encode("ascii") + struct.pack(">I", len(token)) + token

    def run_launcher(
        self,
        *arguments: str,
        stdin: bytes = b"",
        pass_fds: tuple[int, ...] = (),
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [str(self.binary), *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            pass_fds=pass_fds,
        )

    @staticmethod
    def descriptor(model: str = "gpt-6-sol", effort: str = "high") -> dict[str, str]:
        body = {
            "runtime_authority_sha256": "1" * 64,
            "session_id": "00000000-0000-4000-8000-000000000001",
            "native_stack_binding_sha256": "2" * 64,
            "harness_binding_sha256": "3" * 64,
            "harness_generation_id": "4" * 64,
            "harness_executable_sha256": "5" * 64,
            "model_id": model,
            "reasoning_effort": effort,
            "cyber_access_program": "daybreakBlue",
        }
        return policy.validate_launch_descriptor(
            {"schema": policy.LAUNCH_SCHEMA, **body, "descriptor_sha256": policy.sha256(body)}
        )

    @contextlib.contextmanager
    def fixed_permit_fd(
        self,
        permit_bytes: bytes,
        *,
        linked: bool = False,
        mode: int = 0o400,
    ):
        saved_three: int | None = None
        try:
            saved_three = os.dup(policy.PROJECTION_PERMIT_FD)
        except OSError:
            saved_three = None
        descriptor, path_text = tempfile.mkstemp(prefix="native-codex-permit-")
        path = Path(path_text)
        try:
            os.write(descriptor, permit_bytes)
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            os.close(descriptor)
            descriptor = os.open(path, os.O_RDONLY)
            if not linked:
                path.unlink()
            if descriptor != policy.PROJECTION_PERMIT_FD:
                os.dup2(descriptor, policy.PROJECTION_PERMIT_FD)
                os.close(descriptor)
                descriptor = policy.PROJECTION_PERMIT_FD
            yield policy.PROJECTION_PERMIT_FD
        finally:
            try:
                os.close(policy.PROJECTION_PERMIT_FD)
            except OSError:
                pass
            if saved_three is not None:
                os.dup2(saved_three, policy.PROJECTION_PERMIT_FD)
                os.close(saved_three)
            if descriptor not in (-1, policy.PROJECTION_PERMIT_FD):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def permit_for(
        self,
        descriptor: dict[str, str],
        token: bytes,
        *,
        projection_id: str = "12345678-1234-4234-8234-123456789abc",
        issued_at: int | None = None,
        expires_at: int | None = None,
    ) -> dict[str, object]:
        issued = int(time.time()) if issued_at is None else issued_at
        expires = issued + 60 if expires_at is None else expires_at
        return policy.make_projection_permit(
            descriptor,
            projection_id=projection_id,
            access_token_sha256=hashlib.sha256(token).hexdigest(),
            issued_at_unix=issued,
            expires_at_unix=expires,
            launcher_uid=os.geteuid(),
            launcher_gid=os.getegid(),
        )

    def test_one_bounded_frame_is_consumed_without_disclosing_token(self) -> None:
        projection = str(uuid.UUID("12345678-1234-4234-8234-123456789abc"))
        token = b"eyJhbGciOiJSUzI1NiJ9." + b"A" * 96
        protocol_tail = b'{"id":1,"method":"initialize"}\n'
        result = self.run_launcher("--test-frame", stdin=self.frame(projection, token))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"projection_id={projection}".encode(), result.stdout)
        self.assertIn(f"token_bytes={len(token)}".encode(), result.stdout)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn(protocol_tail.strip(), result.stdout + result.stderr)
        trailing = self.run_launcher(
            "--test-frame", stdin=self.frame(projection, token) + protocol_tail)
        self.assertNotEqual(trailing.returncode, 0)
        self.assertNotIn(token + protocol_tail, trailing.stdout + trailing.stderr)

    def test_private_receipt_binds_frame_permit_session_digest_length_and_eof(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"marker-free-project-token-0123456789-ABCDEFGHIJKLMN"
        descriptor_value = self.descriptor()
        permit = self.permit_for(
            descriptor_value, token, projection_id=projection)
        with tempfile.TemporaryDirectory() as directory:
            descriptor_path = Path(directory) / "launch.authority"
            descriptor_path.write_bytes(policy.descriptor_bytes(descriptor_value))
            descriptor_path.chmod(0o640)
            with self.fixed_permit_fd(
                    policy.projection_permit_bytes(permit)) as permit_fd:
                saved_six: int | None
                try:
                    saved_six = os.dup(6)
                except OSError:
                    saved_six = None
                read_fd, write_fd = os.pipe()
                if read_fd == 6:
                    replacement = fcntl.fcntl(
                        read_fd, fcntl.F_DUPFD_CLOEXEC, 10)
                    os.close(read_fd)
                    read_fd = replacement
                if write_fd != 6:
                    os.dup2(write_fd, 6)
                    os.close(write_fd)
                try:
                    result = self.run_launcher(
                        "--test-token-receipt", str(descriptor_path),
                        stdin=self.frame(projection, token),
                        pass_fds=(permit_fd, 6))
                    os.close(6)
                    receipt = bytearray()
                    while True:
                        block = os.read(read_fd, 4096)
                        if not block:
                            break
                        receipt.extend(block)
                finally:
                    try:
                        os.close(6)
                    except OSError:
                        pass
                    if saved_six is not None:
                        os.dup2(saved_six, 6)
                        os.close(saved_six)
                    os.close(read_fd)
        self.assertEqual(result.returncode, 0, result.stderr)
        accepted = runtime_driver.validate_token_receipt(
            bytes(receipt), launch_descriptor=descriptor_value,
            expected_projection_id=projection,
            expected_permit_sha256=permit["permit_sha256"],
            expected_access_token_sha256=permit["access_token_sha256"])
        self.assertEqual(accepted.token_length, len(token))
        self.assertNotIn(token, bytes(receipt) + result.stdout + result.stderr)

    def test_bad_magic_uuid_length_control_and_truncation_fail_closed(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"A" * 32
        cases = [
            b"BADCODX1\n" + self.frame(projection, token)[8:],
            self.frame("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", token),
            b"SSCODX1\n" + projection.encode() + struct.pack(">I", 15) + b"A" * 15,
            self.frame(projection, b"A" * 16 + b"\n"),
            self.frame(projection, token)[:-1],
        ]
        for frame in cases:
            with self.subTest(frame=frame[:16]):
                result = self.run_launcher("--test-frame", stdin=frame)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(token, result.stdout + result.stderr)

    def test_projection_missing_eof_and_receipt_backpressure_time_out(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"A" * 64
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, self.frame(projection, token))
            started = time.monotonic()
            result = subprocess.run(
                [str(self.binary), "--test-frame"], stdin=read_fd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=2)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertNotEqual(result.returncode, 0)
        finally:
            os.close(write_fd)
            os.close(read_fd)

        descriptor_value = self.descriptor()
        permit = self.permit_for(
            descriptor_value, token, projection_id=projection)
        with tempfile.TemporaryDirectory() as directory:
            descriptor_path = Path(directory) / "launch.authority"
            descriptor_path.write_bytes(policy.descriptor_bytes(descriptor_value))
            descriptor_path.chmod(0o640)
            with self.fixed_permit_fd(
                    policy.projection_permit_bytes(permit)) as permit_fd:
                saved_six: int | None
                try:
                    saved_six = os.dup(6)
                except OSError:
                    saved_six = None
                receipt_read, receipt_write = os.pipe()
                flags = fcntl.fcntl(receipt_write, fcntl.F_GETFL)
                fcntl.fcntl(receipt_write, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                try:
                    while True:
                        os.write(receipt_write, b"x" * 4096)
                except BlockingIOError:
                    pass
                fcntl.fcntl(receipt_write, fcntl.F_SETFL, flags)
                if receipt_read == 6:
                    replacement = fcntl.fcntl(
                        receipt_read, fcntl.F_DUPFD_CLOEXEC, 10)
                    os.close(receipt_read)
                    receipt_read = replacement
                if receipt_write != 6:
                    os.dup2(receipt_write, 6)
                    os.close(receipt_write)
                try:
                    started = time.monotonic()
                    blocked = self.run_launcher(
                        "--test-token-receipt", str(descriptor_path),
                        stdin=self.frame(projection, token),
                        pass_fds=(permit_fd, 6))
                    self.assertLess(time.monotonic() - started, 1.5)
                    self.assertNotEqual(blocked.returncode, 0)
                finally:
                    try:
                        os.close(6)
                    except OSError:
                        pass
                    if saved_six is not None:
                        os.dup2(saved_six, 6)
                        os.close(saved_six)
                    os.close(receipt_read)

    def test_token_transport_rejects_pty_socket_and_regular_file(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"A" * 64
        frame = self.frame(projection, token)
        rejected: list[subprocess.CompletedProcess[bytes]] = []

        def run_with(descriptor: int) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [str(self.binary), "--test-frame"], stdin=descriptor,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=5)

        with tempfile.TemporaryFile() as regular:
            regular.write(frame)
            regular.seek(0)
            result = run_with(regular.fileno())
            self.assertNotEqual(result.returncode, 0)
            rejected.append(result)

        left, right = socket.socketpair()
        try:
            right.sendall(frame)
            result = run_with(left.fileno())
            self.assertNotEqual(result.returncode, 0)
            rejected.append(result)
        finally:
            left.close()
            right.close()

        master, slave = os.openpty()
        try:
            result = run_with(slave)
            self.assertNotEqual(result.returncode, 0)
            rejected.append(result)
        finally:
            os.close(master)
            os.close(slave)
        character = os.open("/dev/null", os.O_RDONLY)
        try:
            result = run_with(character)
            self.assertNotEqual(result.returncode, 0)
            rejected.append(result)
        finally:
            os.close(character)
        for result in rejected:
            self.assertNotIn(token, result.stdout + result.stderr)

    def test_root_claimed_pathless_permit_binds_frame_token_and_descriptor(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"eyJhbGciOiJSUzI1NiJ9." + b"A" * 96
        descriptor_value = self.descriptor()
        permit = self.permit_for(descriptor_value, token, projection_id=projection)
        with tempfile.TemporaryDirectory() as directory:
            descriptor_path = Path(directory) / "launch.authority"
            descriptor_path.write_bytes(policy.descriptor_bytes(descriptor_value))
            descriptor_path.chmod(0o640)
            with self.fixed_permit_fd(policy.projection_permit_bytes(permit)) as permit_fd:
                result = self.run_launcher(
                    "--test-permit", str(descriptor_path),
                    stdin=self.frame(projection, token), pass_fds=(permit_fd,),
                )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"permit_projection_id={projection}".encode(), result.stdout)
        self.assertIn(descriptor_value["session_id"].encode(), result.stdout)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_arbitrary_uuid_wrong_token_and_linked_permit_fail_closed(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        other_projection = "22222222-2222-4222-8222-222222222222"
        token = b"A" * 64
        descriptor_value = self.descriptor()
        permit = self.permit_for(descriptor_value, token, projection_id=projection)
        with tempfile.TemporaryDirectory() as directory:
            descriptor_path = Path(directory) / "launch.authority"
            descriptor_path.write_bytes(policy.descriptor_bytes(descriptor_value))
            descriptor_path.chmod(0o640)
            cases = (
                (self.frame(other_projection, token), False, 0o400),
                (self.frame(projection, b"B" * 64), False, 0o400),
                (self.frame(projection, token), True, 0o400),
                (self.frame(projection, token), False, 0o600),
            )
            for frame, linked, mode in cases:
                with self.subTest(linked=linked, mode=oct(mode), frame=frame[:48]):
                    with self.fixed_permit_fd(
                        policy.projection_permit_bytes(permit), linked=linked, mode=mode
                    ) as permit_fd:
                        result = self.run_launcher(
                            "--test-permit", str(descriptor_path), stdin=frame,
                            pass_fds=(permit_fd,),
                        )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(token, result.stdout + result.stderr)

    def test_same_root_claimed_open_description_is_consumed_once(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"A" * 64
        descriptor_value = self.descriptor()
        permit = self.permit_for(descriptor_value, token, projection_id=projection)
        with tempfile.TemporaryDirectory() as directory:
            descriptor_path = Path(directory) / "launch.authority"
            descriptor_path.write_bytes(policy.descriptor_bytes(descriptor_value))
            descriptor_path.chmod(0o640)
            with self.fixed_permit_fd(policy.projection_permit_bytes(permit)) as permit_fd:
                first = self.run_launcher(
                    "--test-permit", str(descriptor_path),
                    stdin=self.frame(projection, token), pass_fds=(permit_fd,),
                )
                second = self.run_launcher(
                    "--test-permit", str(descriptor_path),
                    stdin=self.frame(projection, token), pass_fds=(permit_fd,),
                )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertNotEqual(second.returncode, 0)

    def test_expired_permit_fails_closed(self) -> None:
        projection = "12345678-1234-4234-8234-123456789abc"
        token = b"A" * 64
        descriptor_value = self.descriptor()
        now = int(time.time())
        permit = self.permit_for(
            descriptor_value, token, projection_id=projection,
            issued_at=now - 61, expires_at=now - 1,
        )
        with tempfile.TemporaryDirectory() as directory:
            descriptor_path = Path(directory) / "launch.authority"
            descriptor_path.write_bytes(policy.descriptor_bytes(descriptor_value))
            descriptor_path.chmod(0o640)
            with self.fixed_permit_fd(policy.projection_permit_bytes(permit)) as permit_fd:
                result = self.run_launcher(
                    "--test-permit", str(descriptor_path),
                    stdin=self.frame(projection, token), pass_fds=(permit_fd,),
                )
        self.assertNotEqual(result.returncode, 0)

    def test_c_consumer_accepts_only_exact_python_descriptor_contract(self) -> None:
        descriptor = self.descriptor()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "launch.authority"
            path.write_bytes(policy.descriptor_bytes(descriptor))
            path.chmod(0o640)
            result = self.run_launcher("--test-descriptor", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(descriptor["descriptor_sha256"].encode(), result.stdout)
            self.assertIn(b"model_id=gpt-6-sol", result.stdout)
            self.assertIn(b"session_id=00000000-0000-4000-8000-000000000001", path.read_bytes())
            path.write_bytes(path.read_bytes().replace(b"model_id=gpt-6-sol", b"model_id=gpt-6-luna"))
            path.chmod(0o640)
            rejected = self.run_launcher("--test-descriptor", str(path))
            self.assertNotEqual(rejected.returncode, 0)

    def test_c_consumer_accepts_each_exact_reasoning_effort_without_coercion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "launch.authority"
            for effort in sorted(policy.REASONING_EFFORTS):
                descriptor = self.descriptor(effort=effort)
                path.write_bytes(policy.descriptor_bytes(descriptor))
                path.chmod(0o640)
                result = self.run_launcher("--test-descriptor", str(path))
                self.assertEqual(result.returncode, 0, (effort, result.stderr))

    def test_c_consumer_accepts_each_and_only_reviewed_model(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "launch.authority"
            for model in sorted(policy.MODELS):
                descriptor = self.descriptor(model=model)
                path.write_bytes(policy.descriptor_bytes(descriptor))
                path.chmod(0o640)
                result = self.run_launcher("--test-descriptor", str(path))
                self.assertEqual(result.returncode, 0, (model, result.stderr))
            self.assertNotIn("gpt-6.1-luna", policy.MODELS)

    def test_production_source_has_no_token_argv_file_or_ambient_lookup(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("getenv(", source)
        self.assertNotIn("OPENAI_API_KEY=", source)
        self.assertNotIn("--access-token", source)
        self.assertIn('"shell_environment_policy.inherit=\\"none\\""', source)
        self.assertIn('"sandbox_workspace_write.network_access=false"', source)
        self.assertIn('"approval_policy=\\"never\\""', source)
        self.assertIn('"approvals_reviewer=\\"user\\""', source)
        self.assertIn('"sandbox_mode=\\"workspace-write\\""', source)
        self.assertIn('"sandbox_workspace_write.exclude_tmpdir_env_var=true"', source)
        self.assertIn('"sandbox_workspace_write.exclude_slash_tmp=true"', source)
        self.assertIn('"suppress_unstable_features_warning=true"', source)
        self.assertIn('"daybreak=true"', source)
        self.assertIn('"skills.bundled.enabled=false"', source)
        self.assertIn('"skills.include_instructions=false"', source)
        self.assertIn('"project_doc_max_bytes=0"', source)
        self.assertIn('"features.plugins=false"', source)
        self.assertIn('"features.skill_search=false"', source)
        self.assertIn('"features.hooks=false"', source)
        self.assertIn("PROJECTION_PERMIT_FD 3", source)
        self.assertIn("PROJECTION_FRAME_FD 5", source)
        self.assertIn("TOKEN_RECEIPT_FD 6", source)
        self.assertIn("PROJECTION_IO_TIMEOUT_MILLISECONDS 15000", source)
        self.assertIn("require_exact_eof", source)
        self.assertIn("emit_token_receipt", source)
        self.assertIn("information.st_nlink != 0", source)
        self.assertNotIn("PROJECTION_DIR", source)

    def test_descriptor_closure_removes_high_inherited_fd(self) -> None:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        required = 5001
        if hard != resource.RLIM_INFINITY and hard < required:
            self.skipTest("RLIMIT_NOFILE cannot represent a descriptor above 4095")
        raised = max(soft, required)
        if hard != resource.RLIM_INFINITY:
            raised = min(raised, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (raised, hard))
        source_fd = os.open("/dev/null", os.O_RDONLY)
        high_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD, 5000)
        try:
            result = self.run_launcher(
                "--test-close-fds", str(high_fd), pass_fds=(high_fd,)
            )
        finally:
            os.close(high_fd)
            os.close(source_fd)
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"closed_probe_fd={high_fd}".encode(), result.stdout)

    def test_codex_policy_tree_requires_root_equivalent_immutable_descendants(self) -> None:
        def populate(root: Path) -> None:
            root.chmod(0o755)
            config = root / "config.toml"
            config.write_text("history.persistence = \"none\"\n", encoding="ascii")
            config.chmod(0o444)
            skills = root / "skills"
            skills.mkdir()
            skill = skills / "disabled-system-skill.toml"
            skill.write_text("enabled = false\n", encoding="ascii")
            skill.chmod(0o640)
            skills.chmod(0o555)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            accepted = self.run_launcher("--test-policy-tree", str(root))
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

        mutations = ("config_symlink", "writable_skill", "fifo", "empty_config")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                populate(root)
                if mutation == "config_symlink":
                    target = root / "real-config"
                    target.write_text("safe=true\n", encoding="ascii")
                    target.chmod(0o444)
                    (root / "config.toml").unlink()
                    (root / "config.toml").symlink_to(target)
                elif mutation == "writable_skill":
                    (root / "skills/disabled-system-skill.toml").chmod(0o666)
                elif mutation == "fifo":
                    (root / "skills").chmod(0o755)
                    os.mkfifo(root / "skills/injected", 0o444)
                    (root / "skills").chmod(0o555)
                else:
                    (root / "config.toml").chmod(0o644)
                    (root / "config.toml").write_bytes(b"")
                    (root / "config.toml").chmod(0o444)
                rejected = self.run_launcher("--test-policy-tree", str(root))
                self.assertNotEqual(rejected.returncode, 0)

    def test_session_state_is_fresh_separate_and_exact(self) -> None:
        session_id = "00000000-0000-4000-8000-000000000001"

        def populate(root: Path, policy_root: Path) -> Path:
            root.chmod(0o750)
            policy_root.chmod(0o755)
            policy_config = policy_root / "config.toml"
            policy_config.write_text('history.persistence = "none"\n', encoding="ascii")
            policy_config.chmod(0o444)
            policy_skills = policy_root / "skills"
            policy_skills.mkdir()
            policy_skills.chmod(0o555)
            session = root / session_id
            session.mkdir(mode=0o710)
            session.chmod(0o710)
            for name in ("home", "cache", "tmp"):
                child = session / name
                child.mkdir(mode=0o700)
                child.chmod(0o700)
            codex_home = session / "codex-home"
            codex_home.mkdir(mode=0o710)
            codex_home.chmod(0o710)
            config = codex_home / "config.toml"
            config.write_bytes(policy_config.read_bytes())
            config.chmod(0o640)
            skills = codex_home / "skills"
            skills.mkdir(mode=0o750)
            skills.chmod(0o750)
            for name in ("state", "logs", "tmp", ".tmp"):
                child = codex_home / name
                child.mkdir(mode=0o700)
                child.chmod(0o700)
            installation_id = codex_home / "installation_id"
            installation_id.write_text(
                "22222222-2222-4222-8222-222222222222", encoding="ascii"
            )
            installation_id.chmod(0o600)
            return session

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_root = root / "policy"
            policy_root.mkdir()
            state_root = root / "state"
            state_root.mkdir()
            populate(state_root, policy_root)
            accepted = self.run_launcher(
                "--test-session-state", str(state_root), str(policy_root), session_id
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

        mutations = (
            "extra", "nonempty", "wrong_mode", "symlink", "bundled_skill",
            "config_changed", "missing_sqlite_root",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy_root = root / "policy"
                policy_root.mkdir()
                state_root = root / "state"
                state_root.mkdir()
                session = populate(state_root, policy_root)
                if mutation == "extra":
                    (session / "plugins").mkdir(mode=0o700)
                elif mutation == "nonempty":
                    (session / "home/persisted").write_text("stale", encoding="ascii")
                elif mutation == "wrong_mode":
                    session.chmod(0o700)
                elif mutation == "symlink":
                    (session / "cache").rmdir()
                    (session / "cache").symlink_to(session / "home")
                elif mutation == "bundled_skill":
                    (session / "codex-home/skills/injected.md").write_text(
                        "unsafe", encoding="ascii"
                    )
                elif mutation == "config_changed":
                    (session / "codex-home/config.toml").write_text(
                        "features.plugins = true\n", encoding="ascii"
                    )
                    (session / "codex-home/config.toml").chmod(0o640)
                else:
                    (session / "codex-home/state").rmdir()
                rejected = self.run_launcher(
                    "--test-session-state", str(state_root), str(policy_root), session_id
                )
                self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
