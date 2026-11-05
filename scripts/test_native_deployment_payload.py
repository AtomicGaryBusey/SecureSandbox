#!/usr/bin/env python3

from __future__ import annotations

import ast
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import native_deployment_payload as payload
from scripts import native_research_installer
from shared import native_deployment


ROOT = Path(__file__).resolve().parents[1]


class NativeDeploymentPayloadTests(unittest.TestCase):
    def test_research_inventory_exactly_matches_installer_sources(self) -> None:
        expected = native_research_installer.source_names() - {
            "native-vendor-stacks.json"}
        self.assertEqual(
            {name for name, _source, _mode in payload.RESEARCH_SOURCES},
            expected)
        self.assertEqual(payload.DYNAMIC_SOURCES["research"], (
            "native-vendor-stacks.json",))

    def test_archives_are_deterministic_exact_and_mode_bound(self) -> None:
        for role in (
            "gateway", "research", "research-fence-acquire",
            "research-fence-release",
        ):
            first = payload.build_base_archive(ROOT, role)
            second = payload.build_base_archive(ROOT, role)
            self.assertEqual(first, second)
            files = payload.read_base_archive(first, role)
            self.assertEqual(
                set(files),
                {name for name, _source, _mode in payload.inventory(role)})
            with zipfile.ZipFile(io.BytesIO(first)) as archive:
                self.assertEqual(
                    [item.filename for item in archive.infolist()],
                    sorted(files))

    def test_dynamic_catalog_is_exactly_injected_and_package_bound(self) -> None:
        base = payload.build_base_archive(ROOT, "research")
        files, package = payload.complete_package(
            base, "research",
            dynamic={"native-vendor-stacks.json": b'{"schema":"x"}\n'})
        self.assertIn("native-vendor-stacks.json", files)
        self.assertEqual(
            native_deployment.validate_package(package, role="research"),
            package)
        self.assertEqual({item["mode"] for item in package["files"]}, {0o600})
        with self.assertRaisesRegex(
            payload.NativeDeploymentPayloadError, "dynamic_inventory"
        ):
            payload.complete_package(base, "research", dynamic={})

    def test_host_container_is_deterministic_and_revalidates_every_base(self) -> None:
        first = payload.build_payload_container(ROOT)
        self.assertEqual(first, payload.build_payload_container(ROOT))
        members = payload.read_payload_container(first)
        self.assertEqual(set(members), set(payload.CONTAINER_MEMBERS))
        for name, role in payload.CONTAINER_MEMBERS.items():
            self.assertEqual(
                set(payload.read_base_archive(members[name], role)),
                {item[0] for item in payload.inventory(role)},
            )

    def test_fence_payloads_have_exact_distinct_complete_inventories(self) -> None:
        expected_common = {
            "native_deployment_fence_bootstrap.py", "native_deployment.py",
            "native_deployment_probe.py",
            "native_deployment_lifecycle.py", "native_lifecycle_fence.py",
            "native_research_release.py", "native_guest_control.py",
            "native_vendor_stack.py", "harness_runtime_binding.py",
            "session_context_binding.py", "native_stack_runtime_binding.py",
            "model_stack_runtime_binding.py", "runtime_authority.py",
            "native_egress.py", "native-vendor-stacks.json",
        }
        for operation, request, wrapper in (
            ("acquire", "native-deployment-fence-request.json",
             "install-native-deployment-fence-bootstrap.sh"),
            ("recovery-acquire",
             "native-deployment-recovery-fence-request.json",
             "install-native-deployment-fence-recovery-bootstrap.sh"),
            ("release", "native-deployment-release-request.json",
             "install-native-deployment-fence-bootstrap-release.sh"),
        ):
            base = payload.build_base_archive(
                ROOT, f"research-fence-{operation}")
            files, package = payload.complete_fence_payload(
                base, operation, dynamic={
                    request: b'{"request":"bound"}\n',
                    "native-vendor-stacks.json": b'{"catalog":"bound"}\n',
                })
            self.assertEqual(set(files), expected_common | {request, wrapper})
            self.assertEqual(
                native_deployment.validate_package(package, role="research"),
                package,
            )
        with self.assertRaisesRegex(
            payload.NativeDeploymentPayloadError, "dynamic_inventory"
        ):
            payload.complete_fence_payload(
                payload.build_base_archive(
                    ROOT, "research-fence-acquire"),
                "acquire", dynamic={})

    def test_archive_rejects_extra_member_and_wrong_mode(self) -> None:
        original = payload.build_base_archive(ROOT, "gateway")
        values = payload.read_base_archive(original, "gateway")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
            for name, (raw, mode) in values.items():
                item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                item.create_system = 3
                item.external_attr = ((0o100000 | mode) & 0xFFFF) << 16
                archive.writestr(item, raw)
            archive.writestr("unexpected", b"bad")
        with self.assertRaises(payload.NativeDeploymentPayloadError):
            payload.read_base_archive(output.getvalue(), "gateway")

    def test_source_identity_change_during_descriptor_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.py"
            source.write_bytes(b"a" * 1024)
            original_read = payload.os.read
            changed = False

            def racing_read(descriptor: int, amount: int) -> bytes:
                nonlocal changed
                result = original_read(descriptor, amount)
                if not changed:
                    changed = True
                    source.write_bytes(b"b" * 1024)
                return result

            with mock.patch.object(payload.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(
                    payload.NativeDeploymentPayloadError,
                    "source_changed",
                ):
                    payload._read_source(source)

    def test_every_local_python_dependency_is_in_each_package(self) -> None:
        for role in (
            "gateway", "research", "research-fence-acquire",
            "research-fence-release",
        ):
            sources = payload.inventory(role)
            source_paths = {relative for _name, relative, _mode in sources}
            missing: dict[str, list[str]] = {}
            for _name, relative, _mode in sources:
                if not relative.endswith(".py"):
                    continue
                tree = ast.parse((ROOT / relative).read_bytes(), filename=relative)
                dependencies: set[str] = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module:
                        if node.module in {"research", "shared", "scripts"}:
                            dependencies.update(
                                f"{node.module}/{alias.name}.py"
                                for alias in node.names)
                        elif node.module.startswith(
                                ("research.", "shared.", "scripts.")):
                            dependencies.add(
                                node.module.replace(".", "/") + ".py")
                    elif isinstance(node, ast.Import):
                        dependencies.update(
                            alias.name.replace(".", "/") + ".py"
                            for alias in node.names if alias.name.startswith(
                                ("research.", "shared.", "scripts.")))
                dependencies = {
                    item for item in dependencies if (ROOT / item).is_file()}
                absent = sorted(dependencies - source_paths)
                if absent:
                    missing[relative] = absent
            self.assertEqual(missing, {}, role)


if __name__ == "__main__":
    unittest.main()
