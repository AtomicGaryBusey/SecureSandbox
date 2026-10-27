#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
LABCTL = SCRIPT_DIR / "labctl"


class LabctlLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        control = scripts / "privileged_control.py"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.log = self.root / "actions.log"
        labctl = LABCTL.read_text(encoding="utf-8").replace(
            'prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"',
            f'prlctl="{self.bin / "prlctl"}"',
        ).replace(
            'control_client="/usr/local/libexec/secure-sandbox-host/current/control_client"',
            f'control_client="{control}"',
        )
        self.script = scripts / "labctl"
        self.script.write_text(labctl, encoding="utf-8")
        self.script.chmod(0o755)
        control.write_text(
            """#!/bin/bash
printf 'control %s\n' "$*" >>"$MOCK_ACTION_LOG"
[[ "${MOCK_SSH_FAIL:-0}" == 1 ]] && exit 1
if [[ "${MOCK_APPLY_ACTIONS:-0}" == 1 ]]; then
  case "$*" in
    *sandbox-target-control*) printf stopped >"$MOCK_STATE_DIR/target" ;;
    *sandbox-research-control*) printf stopped >"$MOCK_STATE_DIR/research" ;;
    *sandbox-gateway-control*) printf stopped >"$MOCK_STATE_DIR/gateway" ;;
  esac
fi
exit 0
""",
            encoding="utf-8",
        )
        control.chmod(0o755)
        self._write_mock("op-agents", "#!/bin/bash\nprintf 'secret\\n'\n")
        self._write_mock(
            "ssh",
            "#!/bin/bash\nprintf 'ssh %s\\n' \"$*\" >>\"$MOCK_ACTION_LOG\"\n"
            "[[ \"${MOCK_SSH_FAIL:-0}\" == 1 ]] && exit 1\n"
            "if [[ \"${MOCK_APPLY_ACTIONS:-0}\" == 1 ]]; then\n"
            "  case \"$*\" in\n"
            "    *sandbox-target-admin*) printf stopped >\"$MOCK_STATE_DIR/target\" ;;\n"
            "    *sandbox-research-admin*) printf stopped >\"$MOCK_STATE_DIR/research\" ;;\n"
            "    *sandbox-gateway*) printf stopped >\"$MOCK_STATE_DIR/gateway\" ;;\n"
            "  esac\n"
            "fi\nexit 0\n",
        )
        self._write_mock("sleep", "#!/bin/bash\nexit 0\n")
        self._write_mock("prlctl", self._prlctl_mock())
        self.set_state(gateway="running", research="running", target="running", uplink="connected")

    def tearDown(self):
        self.temporary.cleanup()

    def _write_mock(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def _prlctl_mock(self) -> str:
        return r'''#!/bin/bash
set -u
printf 'prlctl %s\n' "$*" >>"$MOCK_ACTION_LOG"
state_file() {
  case "$1" in
    SecureSandbox-Gateway) printf '%s/gateway' "$MOCK_STATE_DIR" ;;
    SecureSandbox-Research) printf '%s/research' "$MOCK_STATE_DIR" ;;
    SecureSandbox-Target) printf '%s/target' "$MOCK_STATE_DIR" ;;
    *) exit 2 ;;
  esac
}
if [[ "$1" == list && "$2" == --all && "$3" == --json ]]; then
  name="$4"; value="$(cat "$(state_file "$name")")"
  printf '[{"name":"%s","status":"%s"}]\n' "$name" "$value"
  exit 0
fi
if [[ "$1" == list && "$2" == --info && "$3" == --json ]]; then
  enabled=true; [[ "$(cat "$MOCK_STATE_DIR/uplink")" == disconnected ]] && enabled=false
  printf '[{"Name":"SecureSandbox-Gateway","Hardware":{"net0":{"enabled":%s}}}]\n' "$enabled"
  exit 0
fi
if [[ "$1" == stop ]]; then
  name="$2"
  [[ "${MOCK_FAIL_ACTION:-}" == "stop:$name" ]] && exit 1
  [[ "${MOCK_APPLY_ACTIONS:-0}" == 1 ]] && printf stopped >"$(state_file "$name")"
  exit 0
fi
if [[ "$1" == set && "$2" == SecureSandbox-Gateway && "$3" == --device-disconnect ]]; then
  [[ "${MOCK_FAIL_ACTION:-}" == disconnect ]] && exit 1
  [[ "${MOCK_APPLY_ACTIONS:-0}" == 1 ]] && printf disconnected >"$MOCK_STATE_DIR/uplink"
  exit 0
fi
exit 2
'''

    def set_state(self, *, gateway: str, research: str, target: str, uplink: str) -> None:
        for name, value in {
            "gateway": gateway, "research": research, "target": target, "uplink": uplink,
        }.items():
            (self.state / name).write_text(value, encoding="ascii")

    def run_labctl(self, command: str, **extra: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "MOCK_ACTION_LOG": str(self.log),
            "MOCK_STATE_DIR": str(self.state),
        })
        environment.update(extra)
        return subprocess.run(
            [str(self.script), command], env=environment, text=True, capture_output=True, check=False,
        )

    def test_panic_rejects_successful_commands_without_changed_state(self):
        result = self.run_labctl("panic")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PANIC COMPLETE", result.stdout + result.stderr)
        record = json.loads(result.stderr.splitlines()[0])
        self.assertEqual(record["status"], "rejected")
        self.assertEqual(record["observed"]["gateway_net0"], "connected")

    def test_panic_attempts_every_action_and_verifies_success(self):
        result = self.run_labctl("panic", MOCK_APPLY_ACTIONS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PANIC COMPLETE", result.stdout)
        record = json.loads(result.stdout.splitlines()[0])
        self.assertEqual(record["status"], "verified")
        actions = self.log.read_text(encoding="utf-8")
        self.assertIn("stop SecureSandbox-Research --kill", actions)
        self.assertIn("stop SecureSandbox-Target --kill", actions)
        self.assertIn("set SecureSandbox-Gateway --device-disconnect net0", actions)

    def test_panic_action_failure_with_residual_vm_is_rejected(self):
        result = self.run_labctl(
            "panic", MOCK_APPLY_ACTIONS="1", MOCK_FAIL_ACTION="stop:SecureSandbox-Target",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PANIC COMPLETE", result.stdout + result.stderr)
        record = json.loads(result.stderr.splitlines()[0])
        self.assertEqual(record["observed"]["target"], "running")
        self.assertIn("target_hard_stop", record["action_failures"])

    def test_stop_fails_when_guests_remain_running(self):
        result = self.run_labctl("stop", MOCK_SSH_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        record = json.loads(result.stderr.splitlines()[0])
        self.assertEqual(record["status"], "rejected")
        self.assertEqual(record["observed"]["gateway"], "running")

    def test_stop_accepts_already_stopped_guests_after_readback(self):
        self.set_state(gateway="stopped", research="stopped", target="stopped", uplink="connected")
        result = self.run_labctl("stop", MOCK_SSH_FAIL="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record["status"], "verified")
        self.assertEqual(set(record["action_failures"]), {
            "target_guest_shutdown", "research_guest_shutdown", "gateway_guest_shutdown",
        })

    def test_stop_verifies_clean_shutdown_success(self):
        result = self.run_labctl("stop", MOCK_APPLY_ACTIONS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["action_failures"], [])
        self.assertEqual(record["observed"]["gateway"], "stopped")
        self.assertEqual(record["observed"]["research"], "stopped")
        self.assertEqual(record["observed"]["target"], "stopped")


if __name__ == "__main__":
    unittest.main()
