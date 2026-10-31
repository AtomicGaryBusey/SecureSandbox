#!/usr/bin/env python3

import json
import fcntl
import importlib.util
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
LABCTL = SCRIPT_DIR / "labctl"
LIFECYCLE = SCRIPT_DIR / "parallels-lifecycle.py"


class LabctlLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.log = self.root / "actions.log"

        lifecycle = LIFECYCLE.read_text(encoding="utf-8")
        replacements = {
            'PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")':
                f'PRLCTL = Path({str(self.bin / "prlctl")!r})',
            'CONTROL_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")':
                f'CONTROL_CLIENT = Path({str(self.bin / "control_client")!r})',
            'SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")':
                f'SSH_CONFIG = Path({str(self.root / "ssh_config")!r})',
            'PGREP = Path("/usr/bin/pgrep")': f'PGREP = Path({str(self.bin / "pgrep")!r})',
            'RUNTIME_DIR = Path(tempfile.gettempdir())':
                f'RUNTIME_DIR = Path({str(self.root)!r})',
            'time.sleep(1)': 'time.sleep(0)',
        }
        for old, new in replacements.items():
            self.assertIn(old, lifecycle)
            lifecycle = lifecycle.replace(old, new)
        helper = self.scripts / "parallels-lifecycle.py"
        helper.write_text(lifecycle, encoding="utf-8")
        helper.chmod(0o755)

        labctl = LABCTL.read_text(encoding="utf-8").replace(
            'prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"',
            f'prlctl="{self.bin / "prlctl"}"',
        )
        self.labctl = self.scripts / "labctl"
        self.labctl.write_text(labctl, encoding="utf-8")
        self.labctl.chmod(0o755)

        (self.scripts / "ensure-ssh-identities.sh").write_text(
            '#!/bin/bash\nprintf "identity-ready\\n" >>"$MOCK_ACTION_LOG"\n', encoding="utf-8",
        )
        (self.scripts / "ensure-ssh-identities.sh").chmod(0o755)

        (self.root / "ssh_config").write_text("Host test\n", encoding="ascii")
        (self.scripts / "sync-lab-time.sh").write_text(
            '#!/bin/bash\nprintf "sync %s\\n" "$*" >>"$MOCK_ACTION_LOG"\n'
            '[[ "${MOCK_SYNC_FAIL:-0}" == 1 ]] && exit 1\nexit 0\n', encoding="utf-8",
        )
        (self.scripts / "verify-boundaries.sh").write_text(
            '#!/bin/bash\nprintf "verify\\n" >>"$MOCK_ACTION_LOG"\n'
            '[[ "${MOCK_VERIFY_FAIL:-0}" == 1 ]] && exit 1\nexit 0\n', encoding="utf-8",
        )
        for path in (self.scripts / "sync-lab-time.sh", self.scripts / "verify-boundaries.sh"):
            path.chmod(0o755)
        self._write_mock("pgrep", '#!/bin/bash\n[[ "${MOCK_GUI_RUNNING:-0}" == 1 ]]\n')
        self._write_mock("prlctl", self._prlctl_mock())
        self._write_mock("control_client", self._control_mock())
        self.set_state(gateway="running", research="running", target="running",
                       uplink="connected")

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
  [[ "$value" == invalid ]] && { printf 'not-json\n'; exit 0; }
  printf '[{"name":"%s","status":"%s"}]\n' "$name" "$value"
  exit 0
fi
if [[ "$1" == list && "$2" == --info && "$3" == --json ]]; then
  state="$(cat "$MOCK_STATE_DIR/uplink")"
  gamepad="$(cat "$MOCK_STATE_DIR/gamepad")"
  if [[ "$state" == disconnected ]]; then
    printf '[{"Name":"SecureSandbox-Gateway","Hardware":{"net0":{"enabled":true,"state":"disconnected"}},"USB and Bluetooth":{"Automatic sharing gamepads":"%s"}}]\n' "$gamepad"
  else
    printf '[{"Name":"SecureSandbox-Gateway","Hardware":{"net0":{"enabled":true}},"USB and Bluetooth":{"Automatic sharing gamepads":"%s"}}]\n' "$gamepad"
  fi
  exit 0
fi
if [[ "$1" == start ]]; then
  name="$2"; action="start:$name"
  [[ "${MOCK_NO_APPLY_ACTION:-}" == "$action" ]] || printf running >"$(state_file "$name")"
  [[ "${MOCK_FAIL_RESPONSE:-}" == "$action" ]] && exit 1
  exit 0
fi
if [[ "$1" == set && "$2" == SecureSandbox-Gateway && "$3" == --device-connect ]]; then
  action=connect
  if [[ "${MOCK_NO_APPLY_ACTION:-}" != "$action" ]]; then
    printf connected >"$MOCK_STATE_DIR/uplink"
    printf on >"$MOCK_STATE_DIR/gamepad"
  fi
  [[ "${MOCK_FAIL_RESPONSE:-}" == "$action" ]] && exit 1
  exit 0
fi
if [[ "$1" == stop ]]; then
  printf stopped >"$(state_file "$2")"
  exit 0
fi
if [[ "$1" == set && "$2" == SecureSandbox-Gateway && "$3" == --device-disconnect ]]; then
  printf disconnected >"$MOCK_STATE_DIR/uplink"
  printf on >"$MOCK_STATE_DIR/gamepad"
  exit 0
fi
if [[ "$1" == set && "$2" == SecureSandbox-Gateway && "$3" == --auto-share-gamepad ]]; then
  action=gamepad
  [[ "${MOCK_NO_APPLY_ACTION:-}" == "$action" ]] || printf '%s' "$4" >"$MOCK_STATE_DIR/gamepad"
  [[ "${MOCK_FAIL_RESPONSE:-}" == "$action" ]] && exit 1
  exit 0
fi
exit 2
'''

    def _control_mock(self) -> str:
        return r'''#!/bin/bash
set -u
printf 'control %s\n' "$*" >>"$MOCK_ACTION_LOG"
timeout_seconds=""
host="$4"
operation="$8"
arguments=("$@")
for ((index=0; index<${#arguments[@]}; index++)); do
  case "${arguments[$index]}" in
    --timeout-seconds) timeout_seconds="${arguments[$((index + 1))]}" ;;
  esac
done
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] || exit 2
case "$host" in
  sandbox-gateway-control) key=gateway ;;
  sandbox-research-control) key=research ;;
  sandbox-target-control) key=target ;;
  *) exit 2 ;;
esac
if [[ "$operation" == control-status ]]; then
  [[ "${MOCK_UNREACHABLE:-}" == "$key" ]] && exit 1
  [[ "$(cat "$MOCK_STATE_DIR/$key")" == running ]]
  exit
fi
if [[ "$operation" == poweroff ]]; then
  action="poweroff:$key"
  [[ "${MOCK_NO_APPLY_ACTION:-}" == "$action" ]] || printf stopped >"$MOCK_STATE_DIR/$key"
  [[ "${MOCK_LARGE_RESPONSE:-}" == "$action" ]] && /usr/bin/python3 -c 'print("x" * 65537)'
  [[ "${MOCK_FAIL_RESPONSE:-}" == "$action" ]] && exit 255
  exit 0
fi
exit 2
'''

    def set_state(self, *, gateway: str, research: str, target: str, uplink: str) -> None:
        for name, value in {
            "gateway": gateway, "research": research, "target": target,
            "uplink": uplink, "gamepad": "off",
        }.items():
            (self.state / name).write_text(value, encoding="ascii")

    def run_labctl(self, *arguments: str, **extra: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "MOCK_ACTION_LOG": str(self.log),
            "MOCK_STATE_DIR": str(self.state),
        })
        environment.update(extra)
        return subprocess.run(
            [str(self.labctl), *arguments], env=environment, text=True,
            capture_output=True, check=False,
        )

    @staticmethod
    def record(result: subprocess.CompletedProcess[str]) -> dict:
        stream = result.stdout if result.returncode == 0 else result.stderr
        return json.loads(stream.strip().splitlines()[-1])

    def test_usage_documents_index_readback_operations(self):
        result = self.run_labctl()
        self.assertEqual(result.returncode, 2)
        self.assertIn("corpus {index|status} SOURCE_UUID", result.stderr)
        self.assertIn("codegraph {index|status} SOURCE_UUID", result.stderr)

    def test_status_is_structured_and_read_only(self):
        result = self.run_labctl("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record(result)
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["observed"]["gateway"], "running")
        self.assertEqual(record["reachability"]["target"], "reachable")
        actions = self.log.read_text(encoding="utf-8")
        self.assertNotIn("prlctl start", actions)
        self.assertNotIn("poweroff", actions)
        self.assertNotIn("identity-ready", actions)

    def test_lifecycle_progress_requires_a_live_lock(self):
        specification = importlib.util.spec_from_file_location(
            "test_progress_lifecycle", self.scripts / "parallels-lifecycle.py",
        )
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        self.assertEqual(json.loads(self.run_labctl("lifecycle-progress").stdout)["state"], "idle")
        descriptor = module.acquire_lock()
        try:
            module.publish_progress("start", "guest_readiness", "research")
            record = json.loads(self.run_labctl("lifecycle-progress").stdout)
            self.assertEqual(record["state"], "active")
            self.assertEqual(record["phase"], "guest_readiness")
            self.assertEqual(record["target"], "research")
            self.assertEqual(record["transition_id"], module.TRANSITION_ID)
        finally:
            os.close(descriptor)
        self.assertEqual(json.loads(self.run_labctl("lifecycle-progress").stdout)["state"], "idle")
        descriptor = module.acquire_lock()
        try:
            self.assertEqual(json.loads(self.run_labctl("lifecycle-progress").stdout)["state"], "starting")
        finally:
            os.close(descriptor)

    def test_start_exposes_phase_to_concurrent_reader(self):
        self.set_state(gateway="stopped", research="stopped", target="stopped",
                       uplink="connected")
        (self.scripts / "sync-lab-time.sh").write_text(
            '#!/bin/bash\nprintf "sync %s\\n" "$*" >>"$MOCK_ACTION_LOG"\nsleep 2\nexit 0\n',
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.update({"PATH": f"{self.bin}:/usr/bin:/bin",
                            "MOCK_ACTION_LOG": str(self.log),
                            "MOCK_STATE_DIR": str(self.state)})
        process = subprocess.Popen([str(self.labctl), "start"], env=environment,
                                   text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.log.exists() and "sync --apply" in self.log.read_text(encoding="utf-8"):
                    break
                time.sleep(0.05)
            else:
                self.fail("Mock transition never reached clock synchronization")
            progress = self.run_labctl("lifecycle-progress")
            self.assertEqual(progress.returncode, 0, progress.stderr)
            observed = json.loads(progress.stdout)
            self.assertEqual(observed["state"], "active")
            self.assertEqual(observed["phase"], "time_sync")
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(json.loads(stdout.strip().splitlines()[-1])["status"], "verified")
            self.assertEqual(json.loads(self.run_labctl("lifecycle-progress").stdout)["state"], "idle")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_start_checks_ephemeral_identities_before_vm_actions(self):
        self.set_state(gateway="stopped", research="stopped", target="stopped",
                       uplink="connected")
        result = self.run_labctl("start")
        self.assertEqual(result.returncode, 0, result.stderr)
        actions = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(actions[0], "identity-ready")
        self.assertGreater(next(index for index, line in enumerate(actions)
                                if line.startswith("prlctl start")), 0)

    def test_stop_checks_ephemeral_identities_before_guest_mutation(self):
        result = self.run_labctl("stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        actions = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(actions[0], "identity-ready")
        self.assertGreater(next(index for index, line in enumerate(actions)
                                if " poweroff" in line), 0)

    def test_identity_restore_failure_prevents_every_vm_action(self):
        (self.scripts / "ensure-ssh-identities.sh").write_text(
            '#!/bin/bash\nprintf "identity-failed\\n" >>"$MOCK_ACTION_LOG"\nexit 1\n',
            encoding="utf-8",
        )
        result = self.run_labctl("start")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "identity-failed\n")

    def test_command_timeout_terminates_its_process_group(self):
        specification = importlib.util.spec_from_file_location(
            "test_parallels_lifecycle", self.scripts / "parallels-lifecycle.py",
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        marker = self.root / "late-effect"
        with self.assertRaises(subprocess.TimeoutExpired):
            module.command(
                ["/bin/bash", "-c", f"sleep 0.2; printf late >{marker!s}"],
                timeout=0.05,
            )
        time.sleep(0.3)
        self.assertFalse(marker.exists())

    def test_inherited_restore_lock_remains_owned_after_stopped_readback(self):
        specification = importlib.util.spec_from_file_location(
            "test_restore_lifecycle", LIFECYCLE,
        )
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        descriptor = os.open(self.root / "restore.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            observed = {"gateway": "stopped", "research": "stopped", "target": "stopped"}
            with (patch.object(module, "observe", return_value=(observed, {})),
                  patch.object(module, "vm_state", return_value="stopped"),
                  patch.object(module, "emit"),
                  patch.object(module, "ensure_mutation_preconditions", side_effect=AssertionError("new lock"))):
                self.assertEqual(module.stop(inherited_lock=descriptor), 0)
            os.fstat(descriptor)
        finally:
            os.close(descriptor)

    def test_protected_control_calls_have_short_inner_deadlines(self):
        result = self.run_labctl("stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        control_lines = [line for line in self.log.read_text(encoding="utf-8").splitlines()
                         if line.startswith("control ")]
        self.assertTrue(control_lines)
        self.assertTrue(all("--timeout-seconds" in line for line in control_lines))

    def test_mutation_refuses_running_parallels_gui_before_actions(self):
        result = self.run_labctl("start", MOCK_GUI_RUNNING="1")
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["phase"], "preflight")
        self.assertEqual(record["action_failures"], ["parallels_gui_running"])
        actions = self.log.read_text(encoding="utf-8")
        self.assertNotIn("prlctl start", actions)

    def test_start_converges_partial_stack_and_stale_uplink(self):
        self.set_state(gateway="running", research="stopped", target="running",
                       uplink="disconnected")
        result = self.run_labctl("start")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record(result)
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["observed"]["gateway_net0"], "connected")
        self.assertEqual(record["observed"]["research"], "running")
        actions = self.log.read_text(encoding="utf-8")
        self.assertIn("--device-connect net0", actions)
        self.assertIn("--auto-share-gamepad off", actions)
        self.assertEqual((self.state / "gamepad").read_text(encoding="ascii"), "off")
        self.assertIn("start SecureSandbox-Research", actions)
        self.assertNotIn("start SecureSandbox-Target", actions)
        self.assertIn("sync --apply", actions)
        self.assertIn("verify", actions)

    def test_panic_uses_cable_state_when_adapter_remains_enabled(self):
        result = self.run_labctl("panic")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(next(line for line in result.stdout.splitlines()
                                 if line.startswith("{")))
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["observed"]["gateway_net0"], "disconnected")
        self.assertEqual(record["observed"]["research"], "stopped")
        self.assertEqual(record["observed"]["target"], "stopped")
        self.assertEqual((self.state / "gamepad").read_text(encoding="ascii"), "off")

    def test_start_rejects_unapplied_gamepad_rehardening(self):
        self.set_state(gateway="running", research="stopped", target="stopped",
                       uplink="disconnected")
        result = self.run_labctl("start", MOCK_NO_APPLY_ACTION="gamepad")
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["status"], "rejected")
        self.assertIn("gateway_gamepad_sharing_disable", record["action_failures"])
        self.assertEqual((self.state / "gamepad").read_text(encoding="ascii"), "on")

    def test_panic_rejects_unapplied_gamepad_rehardening(self):
        result = self.run_labctl("panic", MOCK_NO_APPLY_ACTION="gamepad")
        self.assertNotEqual(result.returncode, 0)
        record = json.loads(next(line for line in result.stderr.splitlines()
                                 if line.startswith("{")))
        self.assertEqual(record["status"], "rejected")
        self.assertEqual(record["observed"]["gateway_net0"], "disconnected")
        self.assertEqual((self.state / "gamepad").read_text(encoding="ascii"), "on")

    def test_start_lost_response_is_verified_by_readback(self):
        self.set_state(gateway="running", research="stopped", target="running",
                       uplink="connected")
        result = self.run_labctl(
            "start", MOCK_FAIL_RESPONSE="start:SecureSandbox-Research",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record(result)
        research = next(item for item in record["action_outcomes"]
                        if item["target"] == "research")
        self.assertEqual(research["result"], "lost_response")
        self.assertEqual(record["observed"]["research"], "running")
        self.assertEqual(
            self.log.read_text(encoding="utf-8").count("start SecureSandbox-Research"), 1,
        )

    def test_start_rejects_unapplied_action(self):
        self.set_state(gateway="running", research="stopped", target="running",
                       uplink="connected")
        result = self.run_labctl(
            "start", MOCK_NO_APPLY_ACTION="start:SecureSandbox-Research",
        )
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["status"], "rejected")
        self.assertIn("research_start", record["action_failures"])
        self.assertNotIn("verify", self.log.read_text(encoding="utf-8"))

    def test_stop_treats_ssh_disconnect_as_lost_response_after_readback(self):
        result = self.run_labctl("stop", MOCK_FAIL_RESPONSE="poweroff:research")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record(result)
        research = next(item for item in record["action_outcomes"]
                        if item["target"] == "research")
        self.assertEqual(research["result"], "lost_response")
        self.assertEqual(record["action_failures"], [])
        for key in ("gateway", "research", "target"):
            self.assertEqual(record["observed"][key], "stopped")

    def test_stop_treats_oversized_response_as_lost_after_readback(self):
        result = self.run_labctl("stop", MOCK_LARGE_RESPONSE="poweroff:target")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record(result)
        target = next(item for item in record["action_outcomes"]
                      if item["target"] == "target")
        self.assertEqual(target["result"], "lost_response")

    def test_stop_is_idempotent_when_guests_already_stopped(self):
        self.set_state(gateway="stopped", research="stopped", target="stopped",
                       uplink="connected")
        result = self.run_labctl("stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record(result)
        self.assertTrue(all(item["result"] == "already_satisfied"
                            for item in record["action_outcomes"]))
        self.assertNotIn("poweroff", self.log.read_text(encoding="utf-8"))

    def test_stop_rejects_residual_running_guest(self):
        result = self.run_labctl("stop", MOCK_NO_APPLY_ACTION="poweroff:target")
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["observed"]["target"], "running")
        self.assertIn("target_guest_shutdown", record["action_failures"])
        self.assertNotIn("poweroff:research", self.log.read_text(encoding="utf-8"))

    def test_invalid_inventory_fails_closed_without_mutation(self):
        self.set_state(gateway="invalid", research="running", target="running",
                       uplink="connected")
        result = self.run_labctl("start")
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["phase"], "preflight")
        self.assertIn("mixed_or_unknown_vm_state", record["action_failures"])
        self.assertNotIn("prlctl start", self.log.read_text(encoding="utf-8"))

    def test_concurrent_transition_is_rejected_before_mutation(self):
        lock_path = self.root / "secure-sandbox-lifecycle.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_labctl("start")
        finally:
            os.close(descriptor)
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["action_failures"], ["lifecycle_transition_active"])
        self.assertNotIn("prlctl start", self.log.read_text(encoding="utf-8"))

    def test_untrusted_runtime_directory_fails_closed(self):
        self.root.chmod(0o777)
        try:
            result = self.run_labctl("start")
        finally:
            self.root.chmod(0o700)
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["action_failures"],
                         ["lifecycle_runtime_directory_untrusted"])
        self.assertNotIn("prlctl start", self.log.read_text(encoding="utf-8"))

    def test_boundary_failure_is_not_reported_as_verified_start(self):
        result = self.run_labctl("start", MOCK_VERIFY_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        record = self.record(result)
        self.assertEqual(record["phase"], "boundary_verification")
        self.assertEqual(record["action_failures"], ["boundary_verification_failed"])


if __name__ == "__main__":
    unittest.main()
