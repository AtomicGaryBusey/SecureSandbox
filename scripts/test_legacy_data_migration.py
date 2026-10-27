import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import stat
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXPORT = load("legacy_guest_export", ROOT / "scripts/legacy-guest-export.py")
VERIFY = load("verify_legacy_archive", ROOT / "scripts/verify-legacy-archive.py")
PLAN = load("plan_legacy_continuity_import", ROOT / "scripts/plan-legacy-continuity-import.py")
IMPORT = load("import_legacy_continuity", ROOT / "scripts/import-legacy-continuity.py")
STATUS = load("legacy_migration_status", ROOT / "scripts/legacy-migration-status.py")


class LegacyMigrationTests(unittest.TestCase):
    def test_scope_evidence_covers_governed_state_without_activating_it(self):
        def record(path, content):
            return {
                "kind": "regular", "omitted": False,
                "sha256": __import__("hashlib").sha256(content).hexdigest(),
                "size": len(content), "source_path_hex": os.fsencode(path).hex(),
            }

        records = {
            "conversation": record(
                "/home/agent/.claude/projects/-home-agent-research-workspace/"
                "00000000-0000-4000-8000-000000000001.jsonl", b"conversation"
            ),
            "memory": record(
                "/home/agent/.claude/projects/-home-agent-research-workspace/memory/MEMORY.md",
                b"memory",
            ),
            "proposal": record(
                "/var/lib/secure-sandbox/memory-proposals/"
                "00000000-0000-4000-8000-000000000001.json", b"proposal"
            ),
            "finding": record(
                "/var/lib/secure-sandbox/findings/candidates/"
                "00000000-0000-4000-8000-000000000001.json", b"finding"
            ),
            "script": record("/home/agent/research-workspace/scripts/check.py", b"script"),
            "review": record("/home/agent/research-workspace/reports/review.md", b"review"),
        }
        scope, digest = IMPORT.preserved_scope(records)
        self.assertEqual(scope["claude_conversations"]["records"], 1)
        self.assertEqual(scope["native_memory"]["records"], 1)
        self.assertEqual(scope["memory_proposals"]["records"], 1)
        self.assertEqual(scope["findings"]["records"], 1)
        self.assertEqual(scope["scripts"]["records"], 1)
        self.assertEqual(scope["review_materials"]["records"], 1)
        self.assertEqual(scope["related_agent_state"]["records"], 2)
        self.assertEqual(digest, __import__("hashlib").sha256(IMPORT.canonical(scope)).hexdigest())

    def export_research(self, output, physical_home):
        physical_home = Path(physical_home)
        EXPORT.export(
            "research", output,
            (
                str(physical_home),
                str(physical_home.parent / ".missing-var-lib-secure-sandbox"),
                str(physical_home.parent / ".missing-var-log-secure-sandbox"),
            ),
            EXPORT.ROLE_ROOTS["research"],
        )

    def make_archive(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "legacy"
        (root / ".claude/projects/workspace").mkdir(parents=True)
        (root / "research-workspace/reports").mkdir(parents=True)
        (root / ".claude/projects/workspace/session.jsonl").write_text('{"sessionId":"00000000-0000-4000-8000-000000000001"}\n')
        (root / "research-workspace/reports/review.md").write_text("preserve me\n")
        (root / "report-link").symlink_to("research-workspace/reports/review.md")
        archive = Path(temporary.name) / "legacy.tar.gz"
        with archive.open("wb") as output:
            self.export_research(output, root)
        return temporary, archive

    def test_round_trip_binds_regular_files_and_symlink(self):
        temporary, archive = self.make_archive()
        self.addCleanup(temporary.cleanup)
        receipt = VERIFY.verify(archive)
        self.assertEqual(receipt["status"], "verified")
        self.assertEqual(receipt["role"], "research")
        self.assertGreaterEqual(receipt["paths"], 7)
        self.assertEqual(receipt["omitted_special_files"], 0)

    def rewrite(self, source: Path, destination: Path, transform):
        with gzip.open(source, "rb") as compressed:
            with tarfile.open(fileobj=compressed, mode="r|") as archive:
                members = []
                for item in archive:
                    data = archive.extractfile(item).read() if item.isfile() else None
                    members.append((item, data))
        transform(members)
        with destination.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as archive:
                    for item, data in members:
                        archive.addfile(item, io.BytesIO(data) if data is not None else None)

    def test_payload_tamper_is_rejected(self):
        temporary, archive = self.make_archive()
        self.addCleanup(temporary.cleanup)
        tampered = archive.with_name("tampered.tar.gz")
        def change(members):
            for index, (item, data) in enumerate(members):
                if item.isfile() and item.name != "MANIFEST.json":
                    members[index] = (item, b"X" * len(data))
                    return
        self.rewrite(archive, tampered, change)
        with self.assertRaisesRegex(VERIFY.VerificationError, "manifest_payload_mismatch"):
            VERIFY.verify(tampered)

    def test_duplicate_member_is_rejected(self):
        temporary, archive = self.make_archive()
        self.addCleanup(temporary.cleanup)
        duplicate = archive.with_name("duplicate.tar.gz")
        def change(members):
            item, data = next((item, data) for item, data in members if item.isfile() and item.name != "MANIFEST.json")
            manifest = members.pop()
            members.append((item, data))
            members.append(manifest)
        self.rewrite(archive, duplicate, change)
        with self.assertRaisesRegex(VERIFY.VerificationError, "archive_member_duplicate"):
            VERIFY.verify(duplicate)

    def test_manifest_must_be_final(self):
        temporary, archive = self.make_archive()
        self.addCleanup(temporary.cleanup)
        invalid = archive.with_name("manifest-first.tar.gz")
        self.rewrite(archive, invalid, lambda members: members.insert(0, members.pop()))
        with self.assertRaisesRegex(VERIFY.VerificationError, "manifest_not_final"):
            VERIFY.verify(invalid)

    def test_manifest_requires_complete_metadata_schema(self):
        temporary, archive = self.make_archive()
        self.addCleanup(temporary.cleanup)
        invalid = archive.with_name("metadata-missing.tar.gz")

        def remove_owner(members):
            for index, (item, data) in enumerate(members):
                if item.name != "MANIFEST.json":
                    continue
                manifest = json.loads(data)
                manifest["records"][0].pop("uid")
                body = VERIFY.canonical(manifest)
                item.size = len(body)
                members[index] = (item, body)
                return

        self.rewrite(archive, invalid, remove_owner)
        with self.assertRaisesRegex(VERIFY.VerificationError, "manifest_metadata_invalid"):
            VERIFY.verify(invalid)

    def test_unsafe_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "unsafe.tar.gz"
            with invalid.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w|") as archive:
                        item = tarfile.TarInfo("../escape")
                        item.size = 1
                        archive.addfile(item, io.BytesIO(b"x"))
            with self.assertRaisesRegex(VERIFY.VerificationError, "archive_path_unsafe"):
                VERIFY.verify(invalid)

    def test_special_file_is_manifested_as_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            fifo = root / "pipe"
            import os
            os.mkfifo(fifo)
            archive = Path(directory) / "legacy.tar.gz"
            with archive.open("wb") as output:
                self.export_research(output, root)
            receipt = VERIFY.verify(archive)
            self.assertEqual(receipt["omitted_special_files"], 1)

    def make_continuity_archive(self, directory):
        physical = Path(directory) / "mounted"
        journal = physical / "home/agent/.claude/projects/-home-agent-research-workspace/00000000-0000-4000-8000-000000000001.jsonl"
        report = physical / "home/agent/research-workspace/reports/review.md"
        managed = physical / "home/agent/research-workspace/repos/INDEX.json"
        memory = physical / "home/agent/.claude/projects/-home-agent-research-workspace/memory/MEMORY.md"
        instruction = physical / "home/agent/research-workspace/CLAUDE.md"
        mcp = physical / "home/agent/research-workspace/.mcp.json"
        settings = physical / "home/agent/research-workspace/.claude/settings.json"
        nested_agents = physical / "home/agent/research-workspace/reports/AGENTS.md"
        for path in (journal, report, managed, memory, instruction, mcp, settings, nested_agents):
            path.parent.mkdir(parents=True, exist_ok=True)
        journal.write_text(
            '{"sessionId":"00000000-0000-4000-8000-000000000001",'
            '"cwd":"/home/agent/research-workspace","entrypoint":"cli"}\n'
        )
        report.write_text("legacy report\n")
        managed.write_text("{}\n")
        memory.write_text("legacy memory\n")
        instruction.write_text("untrusted instructions\n")
        mcp.write_text('{"mcpServers":{"escape":{}}}\n')
        settings.write_text('{"hooks":{}}\n')
        nested_agents.write_text("untrusted nested instructions\n")
        archive = Path(directory) / "continuity.tar.gz"
        with archive.open("wb") as output:
            self.export_research(output, physical / "home/agent")
        return archive, journal, report

    def test_import_plan_creates_journals_and_reports_but_not_managed_state(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, _journal, _report = self.make_continuity_archive(directory)
            destination = Path(directory) / "destination"
            result = PLAN.plan(archive, destination)
            self.assertEqual(result["status"], "ready")
            categories = {item["category"] for item in result["dispositions"]}
            self.assertIn("claude_journal", categories)
            self.assertIn("workspace_file", categories)
            self.assertIn("archive_only_managed_workspace", categories)
            self.assertIn("archive_only_governed_memory", categories)
            self.assertIn("archive_only_agent_control", categories)

    def test_import_plan_detects_different_existing_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, journal, _report = self.make_continuity_archive(directory)
            destination = Path(directory) / "destination"
            target = destination / journal.relative_to(Path(directory) / "mounted")
            target.parent.mkdir(parents=True)
            target.write_text("different\n")
            result = PLAN.plan(archive, destination)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["blocking_conflicts"], 1)

    def test_import_plan_accepts_identical_existing_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, journal, _report = self.make_continuity_archive(directory)
            destination = Path(directory) / "destination"
            target = destination / journal.relative_to(Path(directory) / "mounted")
            target.parent.mkdir(parents=True)
            target.write_bytes(journal.read_bytes())
            result = PLAN.plan(archive, destination)
            self.assertEqual(result["status"], "ready")
            self.assertGreaterEqual(result["counts"].get("identical", 0), 1)

    def test_import_creates_selected_content_without_managed_state_or_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, journal, report = self.make_continuity_archive(directory)
            destination = Path(directory) / "destination"
            destination.mkdir()
            receipt = IMPORT.apply(archive, destination, pwd.getpwuid(os.geteuid()).pw_name)
            self.assertEqual(receipt["status"], "imported")
            self.assertEqual(
                receipt["imported_session_ids"],
                ["00000000-0000-4000-8000-000000000001"],
            )
            self.assertEqual(receipt["report_evidence_count"], 1)
            self.assertEqual(set(receipt["preserved_scope"]), set(IMPORT.SCOPE_CATEGORIES))
            self.assertGreater(receipt["preserved_scope"]["workspace_materials"]["records"], 0)
            self.assertEqual(
                receipt["preserved_scope_sha256"],
                __import__("hashlib").sha256(IMPORT.canonical(receipt["preserved_scope"])).hexdigest(),
            )
            mounted = Path(directory) / "mounted"
            self.assertEqual(
                (destination / journal.relative_to(mounted)).read_bytes(), journal.read_bytes()
            )
            self.assertEqual(
                (destination / report.relative_to(mounted)).read_bytes(), report.read_bytes()
            )
            self.assertFalse((destination / "home/agent/research-workspace/repos/INDEX.json").exists())
            self.assertFalse((destination / "home/agent/.claude/projects/-home-agent-research-workspace/memory/MEMORY.md").exists())
            self.assertFalse((destination / "home/agent/research-workspace/CLAUDE.md").exists())
            self.assertFalse((destination / "home/agent/research-workspace/.mcp.json").exists())
            self.assertFalse((destination / "home/agent/research-workspace/.claude/settings.json").exists())
            self.assertFalse((destination / "home/agent/research-workspace/reports/AGENTS.md").exists())

    def test_import_never_activates_legacy_executable_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, _journal, report = self.make_continuity_archive(directory)
            report.chmod(0o777)
            # Rebuild after changing the hostile legacy metadata.
            physical = Path(directory) / "mounted"
            archive = Path(directory) / "executable-continuity.tar.gz"
            with archive.open("wb") as output:
                self.export_research(output, physical / "home/agent")
            destination = Path(directory) / "destination"
            destination.mkdir()
            IMPORT.apply(archive, destination, pwd.getpwuid(os.geteuid()).pw_name)
            imported = destination / report.relative_to(physical)
            self.assertEqual(stat.S_IMODE(imported.stat().st_mode), 0o600)

    def test_import_is_idempotent_and_never_overwrites_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, journal, _report = self.make_continuity_archive(directory)
            destination = Path(directory) / "destination"
            destination.mkdir()
            account = pwd.getpwuid(os.geteuid()).pw_name
            first = IMPORT.apply(archive, destination, account)
            second = IMPORT.apply(archive, destination, account)
            self.assertGreater(first["created"], 0)
            self.assertEqual(second["created"], 0)
            target = destination / journal.relative_to(Path(directory) / "mounted")
            target.write_text("different\n")
            with self.assertRaisesRegex(IMPORT.ImportError, "continuity_plan_blocked"):
                IMPORT.apply(archive, destination, account)

    def test_import_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, _journal, _report = self.make_continuity_archive(directory)
            destination = Path(directory) / "destination"
            outside = Path(directory) / "outside"
            destination.mkdir()
            outside.mkdir()
            (destination / "home").symlink_to(outside)
            with self.assertRaises((IMPORT.ImportError, OSError)):
                IMPORT.apply(archive, destination, pwd.getpwuid(os.geteuid()).pw_name)

    def test_import_rejects_malformed_claude_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            physical = (Path(directory)
                        / "mounted/home/agent/.claude/projects/-home-agent-research-workspace")
            physical.mkdir(parents=True)
            (physical / "00000000-0000-4000-8000-000000000001.jsonl").write_text("not-json\n")
            archive = Path(directory) / "bad.tar.gz"
            with archive.open("wb") as output:
                self.export_research(output, Path(directory) / "mounted/home/agent")
            destination = Path(directory) / "destination"
            destination.mkdir()
            with self.assertRaisesRegex(IMPORT.ImportError, "claude_journal_invalid"):
                IMPORT.apply(archive, destination, pwd.getpwuid(os.geteuid()).pw_name)

    def test_import_preserves_bounded_nul_crash_gap_in_claude_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            session_id = "00000000-0000-4000-8000-000000000005"
            physical = Path(directory) / "mounted/home/agent"
            journal = (physical
                       / f".claude/projects/-home-agent-research-workspace/{session_id}.jsonl")
            journal.parent.mkdir(parents=True)
            value = json.dumps({
                "sessionId": session_id,
                "cwd": "/home/agent/research-workspace",
                "entrypoint": "cli",
            }).encode()
            journal.write_bytes(value + b"\n" + (b"\x00" * 2583) + b"\n" + value + b"\n")
            archive = Path(directory) / "nul-gap.tar.gz"
            with archive.open("wb") as output:
                self.export_research(output, physical)
            destination = Path(directory) / "destination"
            destination.mkdir()
            receipt = IMPORT.apply(
                archive, destination, pwd.getpwuid(os.geteuid()).pw_name
            )
            self.assertEqual(receipt["imported_session_ids"], [session_id])
            self.assertEqual(
                (destination / journal.relative_to(Path(directory) / "mounted")).read_bytes(),
                journal.read_bytes(),
            )

    def test_import_accepts_legacy_sdk_cli_home_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            session_id = "00000000-0000-4000-8000-000000000002"
            workspace_session_id = "00000000-0000-4000-8000-000000000004"
            physical = Path(directory) / "mounted/home/agent"
            journal = physical / f".claude/projects/-home-agent/{session_id}.jsonl"
            workspace_journal = (physical
                                 / f".claude/projects/-home-agent-research-workspace/{workspace_session_id}.jsonl")
            journal.parent.mkdir(parents=True)
            workspace_journal.parent.mkdir(parents=True)
            journal.write_text(
                json.dumps({
                    "sessionId": session_id,
                    "cwd": "/home/agent",
                    "entrypoint": "sdk-cli",
                }) + "\n"
            )
            workspace_journal.write_text(
                json.dumps({
                    "sessionId": workspace_session_id,
                    "cwd": "/home/agent/research-workspace",
                    "entrypoint": "sdk-cli",
                }) + "\n"
            )
            archive = Path(directory) / "sdk-cli.tar.gz"
            with archive.open("wb") as output:
                self.export_research(output, physical)
            destination = Path(directory) / "destination"
            destination.mkdir()
            receipt = IMPORT.apply(
                archive, destination, pwd.getpwuid(os.geteuid()).pw_name
            )
            self.assertEqual(
                receipt["imported_session_ids"],
                [session_id, workspace_session_id],
            )
            self.assertEqual(
                (destination / journal.relative_to(Path(directory) / "mounted")).read_bytes(),
                journal.read_bytes(),
            )

    def test_import_plan_keeps_capture_fixture_archive_only(self):
        with tempfile.TemporaryDirectory() as directory:
            physical = Path(directory) / "mounted/home/agent"
            fixture = (physical
                       / ".claude/projects/capture-acceptance/00000000-0000-4000-8000-000000000003.jsonl")
            fixture.parent.mkdir(parents=True)
            fixture.write_text('{"type":"user"}\n')
            archive = Path(directory) / "capture-fixture.tar.gz"
            with archive.open("wb") as output:
                self.export_research(output, physical)
            destination = Path(directory) / "destination"
            result = PLAN.plan(archive, destination)
            disposition = next(
                item for item in result["dispositions"]
                if bytes.fromhex(item["source_path_hex"]) == os.fsencode(str(fixture).split("/mounted", 1)[1])
            )
            self.assertEqual(disposition["category"], "archive_only_claude_state")
            self.assertEqual(disposition["action"], "archive_only")

    def test_deletion_gate_defaults_to_preserve(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            generation = "20261021T040946Z"
            source = repo / ".private/vm-quarantine" / generation
            for name in STATUS.VM_NAMES.values():
                (source / name).mkdir(parents=True)
            (repo / ".private/restoration").mkdir(parents=True)
            (repo / ".private/restoration/current.json").write_text(
                '{"schema":"secure-sandbox-fresh-vm-restoration-v1","status":"pending"}\n'
            )
            result = STATUS.evaluate(repo, generation)
            self.assertFalse(result["deletion_eligible"])
            self.assertEqual(result["status"], "preserve")
            self.assertIn("fresh_vm_restoration_complete", result["failed_gates"])
            self.assertIn("operator_retirement_approved", result["failed_gates"])

    def test_deletion_gate_requires_exact_archive_hash_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            generation = "20261021T040946Z"
            source = repo / ".private/vm-quarantine" / generation
            for name in STATUS.VM_NAMES.values():
                (source / name).mkdir(parents=True)
            restoration = repo / ".private/restoration"
            restoration.mkdir(parents=True)
            (restoration / "current.json").write_text(
                '{"schema":"secure-sandbox-fresh-vm-restoration-v1","status":"complete"}\n'
            )
            receipts = repo / ".private/legacy-migration" / generation / "receipts"
            receipts.mkdir(parents=True)
            archives = receipts.parent / "archives"
            archives.mkdir()
            hashes = {}
            for role in STATUS.ROLES:
                # A real digest is required because the deletion gate verifies
                # archive bytes rather than trusting a receipt in isolation.
                archive_bytes = role.encode()
                digest = __import__("hashlib").sha256(archive_bytes).hexdigest()
                hashes[role] = digest
                (archives / f"{role}.tar.gz").write_bytes(archive_bytes)
                (receipts / f"preservation-{role}.json").write_text(json.dumps({
                    "archive_sha256": digest, "role": role,
                    "schema": "secure-sandbox-legacy-preservation-receipt-v1",
                    "verification_schema": "secure-sandbox-legacy-preservation-verification-v1",
                    "generation": generation, "plan_sha256": "e" * 64,
                    "source_tree_sha256": "f" * 64,
                    "legacy_vm_uuid": "{00000000-0000-4000-8000-000000000001}",
                    "status": "verified",
                }))
            (receipts / "preservation-set.json").write_text(json.dumps({
                "archive_sha256": hashes,
                "creating_plan_sha256": {role: "e" * 64 for role in STATUS.ROLES},
                "generation": generation,
                "plan_sha256": "1" * 64,
                "schema": "secure-sandbox-legacy-preservation-set-v1",
                "source_tree_sha256": {role: "f" * 64 for role in STATUS.ROLES},
                "status": "verified",
                "transport_research_uuid":
                    "{00000000-0000-4000-8000-000000000002}",
            }))
            scope = {
                category: {"records": 0, "regular_bytes": 0, "sha256": "a" * 64}
                for category in STATUS.SCOPE_CATEGORIES
            }
            (receipts / "continuity-import.json").write_text(json.dumps({
                "blocking_conflicts": 0, "rejected": 0,
                "archive_sha256": hashes["research"],
                "dispositions": 1, "dispositions_sha256": "a" * 64,
                "imported_session_ids": ["00000000-0000-4000-8000-000000000001"],
                "report_evidence_count": 1, "report_evidence_sha256": "b" * 64,
                "preserved_scope": scope,
                "preserved_scope_sha256": __import__("hashlib").sha256(
                    (json.dumps(scope, separators=(",", ":"), sort_keys=True) + "\n").encode()
                ).hexdigest(),
                "schema": "secure-sandbox-legacy-continuity-receipt-v1", "status": "imported",
            }))
            (receipts / "glm-continuity.json").write_text(json.dumps({
                "context_verified": True,
                "evidence_class": "operator-observed-first-person-glm",
                "generation": generation, "observed_at": 1,
                "reports_verified": True, "session_resume_verified": True,
                "archive_sha256": hashes["research"],
                "session_id": "00000000-0000-4000-8000-000000000001",
                "report_evidence_sha256": "b" * 64,
                "preserved_scope_sha256": __import__("hashlib").sha256(
                    (json.dumps(scope, separators=(",", ":"), sort_keys=True) + "\n").encode()
                ).hexdigest(),
                "schema": "secure-sandbox-glm-continuity-acceptance-v1", "status": "continuous",
            }))
            (receipts / "redundancy.json").write_text(json.dumps({
                "archive_sha256": hashes, "independent_copies": 2,
                "failure_domain_evidence":
                    "operator-attested-separate-failure-domain-and-distinct-filesystem",
                "generation": generation, "primary_device": 1,
                "secondary_device": 2, "secondary_root": "/external/legacy-copy",
                "verified_at": 1,
                "schema": "secure-sandbox-legacy-redundancy-v1", "status": "verified",
            }))
            (receipts / "operator-retirement-approval.json").write_text(json.dumps({
                "approved_at": 1,
                "archive_sha256": hashes, "generation": generation,
                "evidence_class": "operator-explicit-after-all-technical-gates",
                "glm_continuity_confirmed": True,
                "independent_backup_confirmed": True,
                "retirement_understood": True,
                "schema": "secure-sandbox-legacy-retirement-approval-v1", "status": "approved",
            }))
            with mock.patch.object(STATUS, "secondary_copy_current", return_value=True):
                self.assertTrue(STATUS.evaluate(repo, generation)["deletion_eligible"])
            hashes["research"] = "d" * 64
            (receipts / "redundancy.json").write_text(json.dumps({
                "archive_sha256": hashes, "independent_copies": 2,
                "failure_domain_evidence":
                    "operator-attested-separate-failure-domain-and-distinct-filesystem",
                "generation": generation, "primary_device": 1,
                "secondary_device": 2, "secondary_root": "/external/legacy-copy",
                "verified_at": 1,
                "schema": "secure-sandbox-legacy-redundancy-v1", "status": "verified",
            }))
            self.assertFalse(STATUS.evaluate(repo, generation)["deletion_eligible"])


if __name__ == "__main__":
    unittest.main()
