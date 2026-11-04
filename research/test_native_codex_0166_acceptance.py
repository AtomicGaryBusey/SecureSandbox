#!/usr/bin/env python3
"""Live vendor-behavior acceptance for the pinned Codex 0.166 boundary."""

from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PINNED = "codex-cli 0.166.0"


class NativeCodex0166AcceptanceTests(unittest.TestCase):
    def test_initialization_and_all_capability_readbacks_are_empty_before_turn(self) -> None:
        executable = shutil.which("codex", path=str(Path.home() / ".local/bin"))
        if executable is None:
            self.skipTest("pinned Codex executable unavailable")
        version = subprocess.run(
            [executable, "--version"], check=False, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        ).stdout.strip()
        if version != PINNED:
            self.skipTest(f"requires exact {PINNED}, observed {version!r}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            config = codex_home / "config.toml"
            config.write_bytes((ROOT / "research/native-codex-config.toml").read_bytes())
            config.chmod(0o400)
            skills = codex_home / "skills"
            skills.mkdir(mode=0o500)
            for name in ("state", "logs", "tmp", ".tmp"):
                (codex_home / name).mkdir(mode=0o700)
            installation = codex_home / "installation_id"
            installation.write_text(
                "11111111-1111-4111-8111-111111111111", encoding="ascii")
            installation.chmod(0o600)
            codex_home.chmod(0o500)
            home = root / "home"
            cache = root / "cache"
            temporary = root / "tmp"
            workspace = root / "workspace"
            for path in (home, cache, temporary, workspace):
                path.mkdir(mode=0o700)
            command = [
                executable, "app-server", "--strict-config", "--listen", "stdio://",
                "-c", 'model_provider="openai_chatgpt_plan"',
                "-c", 'model_providers.openai_chatgpt_plan.name="ChatGPT plan"',
                "-c", 'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"',
                "-c", 'model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN"',
                "-c", 'model_providers.openai_chatgpt_plan.wire_api="responses"',
                "-c", "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
                "-c", "model_providers.openai_chatgpt_plan.supports_websockets=false",
                "-c", 'approval_policy="never"',
                "-c", 'approvals_reviewer="user"',
                "-c", 'sandbox_mode="workspace-write"',
                "-c", "sandbox_workspace_write.network_access=false",
                "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
                "-c", "suppress_unstable_features_warning=true",
                "-c", 'shell_environment_policy.inherit="none"',
                "-c", "mcp_servers={}", "-c", 'history.persistence="none"',
                "-c", "skills.bundled.enabled=false",
                "-c", "skills.include_instructions=false",
                "-c", "project_doc_max_bytes=0",
                "-c", "project_doc_fallback_filenames=[]",
                "-c", "features.plugins=false",
                "-c", "features.remote_plugin=false",
                "-c", "features.plugin_discovery_prefetch=false",
                "-c", "features.plugin_sharing=false",
                "-c", "features.recommended_plugins=false",
                "-c", "features.apps=false", "-c", "features.hooks=false",
                "-c", "features.multi_agent=false",
                "-c", "features.multi_agent_v2=false",
                "-c", "features.workspace_dependencies=false",
                "-c", "features.skill_search=false",
                "-c", "features.skill_catalog_deltas=false",
                "-c", "features.skill_mcp_dependency_install=false",
                "-c", "features.skip_host_skill_discovery=true",
                "-c", f'sqlite_home="{codex_home / "state"}"',
                "-c", f'log_dir="{codex_home / "logs"}"',
                "-c", "daybreak=true", "-c", 'model_reasoning_effort="high"',
                "-c", 'model="gpt-6-sol"',
            ]
            environment = {
                "ACCESS_TOKEN": "test-only-noncredential-value",
                "CODEX_HOME": str(codex_home),
                "CODEX_SQLITE_HOME": str(codex_home / "state"),
                "XDG_CONFIG_HOME": str(codex_home),
                "HOME": str(home), "XDG_CACHE_HOME": str(cache),
                "TMPDIR": str(temporary), "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8", "PATH": "/usr/local/bin:/usr/bin:/bin",
            }
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=environment,
            )
            assert process.stdin is not None and process.stdout is not None
            requests = [
                {"id": 1, "method": "initialize", "params": {
                    "clientInfo": {"name": "SecureSandbox", "title": "SecureSandbox",
                                   "version": "1.0.0"},
                    "capabilities": {"experimentalApi": True}}},
                {"id": 2, "method": "skills/list",
                 "params": {"cwds": [str(workspace)], "forceReload": True}},
                {"id": 3, "method": "plugin/list", "params": {}},
                {"id": 4, "method": "hooks/list", "params": {}},
                {"id": 5, "method": "mcpServerStatus/list", "params": {}},
            ]
            try:
                for item in requests:
                    process.stdin.write((json.dumps(
                        item, separators=(",", ":"), sort_keys=True) + "\n").encode())
                process.stdin.flush()
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                replies: dict[int, dict] = {}
                deadline = time.monotonic() + 15
                while len(replies) < 5 and time.monotonic() < deadline:
                    if not selector.select(0.25):
                        if process.poll() is not None:
                            break
                        continue
                    line = process.stdout.readline(1024 * 1024 + 1)
                    if not line or len(line) > 1024 * 1024:
                        break
                    value = json.loads(line)
                    if isinstance(value, dict) and isinstance(value.get("id"), int):
                        replies[value["id"]] = value
                self.assertEqual(set(replies), {1, 2, 3, 4, 5})
                self.assertNotIn("error", replies[1])
                skill_rows = replies[2]["result"]["data"]
                self.assertEqual(len(skill_rows), 1)
                self.assertEqual(skill_rows[0]["skills"], [])
                self.assertEqual(skill_rows[0]["errors"], [])
                plugin = replies[3]["result"]
                self.assertEqual(plugin["marketplaces"], [])
                self.assertEqual(plugin["marketplaceLoadErrors"], [])
                self.assertEqual(plugin["featuredPluginIds"], [])
                hook_rows = replies[4]["result"]["data"]
                self.assertEqual(hook_rows[0]["hooks"], [])
                self.assertEqual(hook_rows[0]["warnings"], [])
                self.assertEqual(hook_rows[0]["errors"], [])
                self.assertEqual(replies[5]["result"]["data"], [])
                self.assertEqual(list(skills.iterdir()), [])
                self.assertEqual(config.read_bytes(),
                                 (ROOT / "research/native-codex-config.toml").read_bytes())
            finally:
                process.stdin.close()
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
