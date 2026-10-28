#!/usr/bin/env python3
"""End-to-end P008 manager fixtures; all writes and launchd calls are isolated."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import socket
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
HELPER = Path(sys.argv[1]).resolve()
MOCK = ROOT / "tests/service/launchctl-mock.py"
STATE = (
    b"ios-unsandboxed-state\n"
    b"schema_version=1\n"
    b"service_installation=installed\n"
    b"execution_activation=disabled\n"
)
spec = importlib.util.spec_from_file_location("installer_integration", ROOT / "tests/packaging/installer-integration.py")
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
sys.argv = [str(ROOT / "tests/packaging/installer-integration.py"), str(HELPER)]
spec.loader.exec_module(fixture)


def run(suite: fixture.Suite, action: str, *, apply: bool = False, confirm: bool = False,
        ack: bool = False, mode: str = "normal", env_extra: dict[str, str] | None = None):
    data = suite.root / "var/lib/ios-unsandboxed"
    mock_rel = "var/lib/ios-unsandboxed/launchctl-mock.py"
    shutil.copy2(MOCK, data / "launchctl-mock.py")
    (data / "launchctl-mock.py").chmod(0o700)
    state = suite.root / "var/lib/ios-unsandboxed/mock-launchd.json"
    env = os.environ.copy()
    env.update({"IU_LAUNCHCTL_MOCK": "/" + mock_rel, "IU_MOCK_LAUNCHD_STATE": str(state), "IU_MOCK_LAUNCHD_MODE": mode})
    if env_extra:
        env.update(env_extra)
    args = [str(suite.root / "var/lib/ios-unsandboxed/manager.sh"), "service", action,
            "--test-root", str(suite.root)]
    if apply:
        args.append("--apply")
    if confirm:
        args.append("--confirm")
    if ack:
        args.append("--acknowledge-run-at-load")
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def ok(result, what: str):
    assert result.returncode == 0, f"{what}: rc={result.returncode}\n{result.stdout}\n{result.stderr}"


def fails(result, what: str):
    assert result.returncode != 0, f"{what} unexpectedly succeeded\n{result.stdout}"


class IpcFixture:
    def __init__(self, path: Path, state_path: Path, version: int = 1):
        self.path = path
        self.state_path = state_path
        self.version = version
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(2)
        self.server.settimeout(0.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def serve(self):
        while True:
            try:
                state = json.loads(self.state_path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                state = {"running": False}
            if not state.get("running"):
                return
            try:
                client, _ = self.server.accept()
            except TimeoutError:
                continue
            with client:
                request = client.recv(20)
                if len(request) == 20 and request[:4] == b"IUIP":
                    response = bytearray(20)
                    response[:4] = b"IUIP"
                    response[5] = self.version
                    response[6:8] = (0x8001).to_bytes(2, "big")
                    response[11] = 1
                    response[15] = 6
                    client.sendall(response)
                    client.sendall(b"\x050.1.0")

    def __exit__(self, *_):
        self.thread.join(timeout=1)
        self.server.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="iu-service-", dir="/tmp") as temp:
        base = Path(temp)
        suite = fixture.Suite(base)
        (suite.root / "Library/LaunchDaemons").mkdir(parents=True, mode=0o755)
        (suite.root / "var/run").mkdir(parents=True, mode=0o755)
        suite.ok(suite.invoke("install", suite.package_root, apply=True), "fixture install")
        active = suite.root / "Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist"
        mock_calls = suite.root / "var/lib/ios-unsandboxed/mock-launchd.calls"
        assert not active.exists(), "ordinary install activated a LaunchDaemon plist"
        assert not mock_calls.exists(), "ordinary install called launchctl"

        ok(run(suite, "plan"), "service plan")
        state_path = suite.root / "var/lib/ios-unsandboxed/mock-launchd.json"
        state_path.write_text(json.dumps({"loaded": True, "running": True}), encoding="ascii")
        fails(run(suite, "register", apply=True, confirm=True, ack=True), "foreign launchd label collision")
        assert not active.exists(), "foreign launchd label created an active project plist"
        state_path.unlink()
        outside_state = suite.base / "outside-mock-state.json"
        ok(run(suite, "status", env_extra={"IU_MOCK_LAUNCHD_STATE": str(outside_state)}), "mock path escape rejection")
        assert not outside_state.exists(), "launchctl mock wrote outside the fixture root"
        fails(run(suite, "register", apply=True), "registration without explicit confirmation")
        fails(run(suite, "register", apply=True, confirm=True), "RunAtLoad acknowledgement")
        unsupported = run(suite, "register", apply=True, confirm=True, ack=True, mode="unsupported")
        fails(unsupported, "unsupported launchctl syntax")
        assert "unsupported launchctl syntax" in unsupported.stderr
        assert not active.exists()
        ok(run(suite, "register", apply=True, confirm=True, ack=True), "registration")
        assert active.is_file() and active.stat().st_mode & 0o777 == 0o644
        assert (suite.root / "var/log/ios-unsandboxed").is_dir()
        status = run(suite, "status")
        ok(status, "service status")
        assert "job reported loaded" in status.stdout
        assert "Execution activation: disabled" in status.stdout
        assert "Startup/signing eligibility: UNKNOWN" in status.stdout
        ok(run(suite, "status"), "idempotent service status")
        fails(suite.invoke("upgrade", suite.package_new, apply=True), "upgrade while service registered")
        active_bytes = active.read_bytes()
        active.unlink()
        fails(suite.invoke("upgrade", suite.package_new, apply=True), "upgrade blocked by service record without active plist")
        fails(suite.invoke("uninstall"), "uninstall blocked by service record without active plist")
        active.write_bytes(active_bytes)
        active.chmod(0o644)

        ok(run(suite, "register", apply=True, confirm=True, ack=True), "idempotent duplicate registration")
        socket_path = suite.root / "var/run/ios-unsandboxedd.sock"
        with IpcFixture(socket_path, suite.root / "var/lib/ios-unsandboxed/mock-launchd.json"):
            ok(run(suite, "start", apply=True, confirm=True), "start and IPC readiness")
            ok(run(suite, "start", apply=True, confirm=True), "idempotent start")
            fails(run(suite, "stop", apply=True, confirm=True, mode="stop-timeout"), "stop timeout")
            assert active.exists(), "stop timeout removed the active plist"
            ok(run(suite, "recover", apply=True, confirm=True), "recovery after stop timeout")
            ok(run(suite, "stop", apply=True, confirm=True), "stop and IPC disappearance")
            ok(run(suite, "stop", apply=True, confirm=True), "idempotent stop")
            stopped_status = run(suite, "status")
            ok(stopped_status, "stopped service status")
            assert "Daemon process: not running" in stopped_status.stdout
        fails(run(suite, "start", apply=True, confirm=True, mode="start-failure"), "start rejection")
        ok(run(suite, "recover", apply=True, confirm=True), "recovery after rejected start")
        start_timeout = time.monotonic()
        fails(run(suite, "start", apply=True, confirm=True, mode="immediate-exit"), "immediate daemon exit/readiness timeout")
        assert time.monotonic() - start_timeout < 5, "IPC readiness check exceeded its test bound"
        ok(run(suite, "recover", apply=True, confirm=True), "recovery after readiness timeout")
        with IpcFixture(socket_path, suite.root / "var/lib/ios-unsandboxed/mock-launchd.json", version=2):
            mismatch_start = time.monotonic()
            fails(run(suite, "start", apply=True, confirm=True), "IPC version mismatch")
            assert time.monotonic() - mismatch_start < 5, "IPC version mismatch check exceeded its test bound"
        ok(run(suite, "recover", apply=True, confirm=True), "recovery after IPC version mismatch")
        launchctl_timeout = time.monotonic()
        timed_status = run(suite, "status", mode="hang")
        ok(timed_status, "bounded status with launchctl timeout")
        assert "Launchd query: unavailable or unsupported" in timed_status.stdout
        assert time.monotonic() - launchctl_timeout < 5, "launchctl operation exceeded its test bound"
        ok(run(suite, "recover", apply=True, confirm=True), "recovery after launchctl timeout")
        ok(run(suite, "unregister", apply=True, confirm=True), "unregister")
        assert not active.exists()
        recovered = run(suite, "recover", apply=True, confirm=True)
        ok(recovered, "idempotent recovery")
        assert mock_calls.read_text().count("/Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist") > 0

        # The mock can report that registration failed after the plist was
        # installed. Recovery observes launchd and removes only the verified file.
        fails(run(suite, "register", apply=True, confirm=True, ack=True, mode="registration-rejected"), "rejected registration")
        assert active.exists()
        fails(run(suite, "recover", apply=True, confirm=True, mode="unsupported"), "recovery with unsupported launchctl state")
        assert active.exists(), "unknown launchd state caused active plist cleanup"
        ok(run(suite, "recover", apply=True, confirm=True), "partial registration recovery")
        assert not active.exists()

        # A power loss while creating the same-directory staging file leaves a
        # prefix of the verified template; recovery removes only that owned prefix.
        staged_file = suite.root / "var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive"
        temporary = Path(str(active) + ".p008-stage")
        temporary.write_bytes(staged_file.read_bytes()[:16])
        temporary.chmod(0o600)
        journal = suite.root / "var/lib/ios-unsandboxed/service-transaction"
        journal.write_text("ios-unsandboxed-service\nschema_version=1\nlabel=com.ios-unsandboxed.daemon\nstate=registering\n", encoding="ascii")
        journal.chmod(0o600)
        ok(run(suite, "recover", apply=True, confirm=True), "partial plist staging recovery")
        assert not temporary.exists()

        # A failed unload keeps the active file and journal; recovery reconciles
        # the still-loaded project job without replaying a command.
        ok(run(suite, "register", apply=True, confirm=True, ack=True), "register before failed unload")
        fails(run(suite, "unregister", apply=True, confirm=True, mode="unregister-failure"), "unregister rejection")
        assert active.exists()
        ok(run(suite, "recover", apply=True, confirm=True), "partial removal recovery")
        assert active.exists()
        ok(run(suite, "unregister", apply=True, confirm=True), "final unregister")

        # Recovery recognizes the fixed journal format and never replays its contents.
        record = suite.root / "var/lib/ios-unsandboxed/service-registration"
        record.write_text("corrupt\n", encoding="ascii")
        fails(run(suite, "status"), "corrupt registration record")

        # A foreign active file is preserved exactly and never overwritten.
        record.unlink()
        active.write_text("foreign", encoding="ascii")
        before = active.read_bytes()
        fails(run(suite, "register", apply=True, confirm=True, ack=True), "foreign active plist")
        assert active.read_bytes() == before

        active.unlink()
        install_manifest = suite.root / "var/lib/ios-unsandboxed/install-manifest"
        original_manifest = install_manifest.read_bytes()
        install_manifest.write_bytes(original_manifest + b"corrupt\n")
        invalid_plan = run(suite, "plan")
        ok(invalid_plan, "read-only invalid installation plan")
        assert "Installation manifest: invalid" in invalid_plan.stdout
        fails(run(suite, "register", apply=True, confirm=True, ack=True), "mutation with invalid installation manifest")
        install_manifest.write_bytes(original_manifest)
        daemon = suite.root / "usr/local/bin/ios-unsandboxedd"
        original_daemon = daemon.read_bytes()
        daemon.write_bytes(original_daemon + b"modified")
        fails(run(suite, "register", apply=True, confirm=True, ack=True), "modified daemon")
        daemon.write_bytes(original_daemon)
        staged = suite.root / "var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive"
        original_plist = staged.read_bytes()
        staged.write_bytes(original_plist + b"modified")
        fails(run(suite, "register", apply=True, confirm=True, ack=True), "modified staged plist")
        staged.write_bytes(original_plist)

        # The installer lock serializes concurrent service mutations.
        state = suite.root / "var/lib/ios-unsandboxed/mock-launchd.json"
        if state.exists():
            state.unlink()
        lock_env = {"IU_MOCK_LAUNCHD_DELAY": "0.3"}
        lock_args = [str(suite.root / "var/lib/ios-unsandboxed/manager.sh"), "service", "register",
                     "--test-root", str(suite.root), "--apply", "--confirm", "--acknowledge-run-at-load"]
        env = os.environ.copy()
        env.update({"IU_LAUNCHCTL_MOCK": "/var/lib/ios-unsandboxed/launchctl-mock.py",
                    "IU_MOCK_LAUNCHD_STATE": str(state), **lock_env})
        first = subprocess.Popen(lock_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        time.sleep(0.03)
        second = subprocess.run(lock_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        first_out, first_err = first.communicate(timeout=5)
        assert first.returncode == 0 or second.returncode == 0, (first_out, first_err, second.stdout, second.stderr)
        assert first.returncode != 0 or second.returncode != 0, "concurrent mutations both passed the exclusive lock"

        # Package upgrades remain passive.
        ok(run(suite, "unregister", apply=True, confirm=True), "cleanup concurrent registration")
        suite.ok(suite.invoke("upgrade", suite.package_new, apply=True), "fixture upgrade")
        assert not active.exists(), "package upgrade activated a LaunchDaemon plist"
        assert (suite.root / "var/lib/ios-unsandboxed/install-state").read_bytes() == STATE
        print("service lifecycle fixtures: PASS (isolated launchctl mock; no physical-device evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
