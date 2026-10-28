#!/usr/bin/env python3
"""Isolated P011 manager and persistence fixtures; never touch production paths."""
import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installer_fixture", ROOT / "tests/packaging/installer-integration.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
spec2 = importlib.util.spec_from_file_location("planner_fixture", ROOT / "tests/planner/planner-fixtures.py")
planner = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(planner)

with tempfile.TemporaryDirectory(prefix="iu-policy-") as td:
    base = Path(td)
    suite = fixture.Suite(base)
    suite.ok(suite.invoke("install", suite.package_root, apply=True), "install")
    root = suite.root
    scopes = root / "opt/ios-unsandboxed-scopes"
    scopes.mkdir(parents=True)
    for name in ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]:
        (scopes / name).mkdir()
    manager = suite.bundle / "manager.sh"
    policy = root / "var/lib/ios-unsandboxed/execution-policy"
    def run(*args, ok=True):
        result = subprocess.run([str(manager), "policy", *args, "--test-root", str(root)], capture_output=True, text=True)
        assert (result.returncode == 0) == ok, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout + result.stderr
    def add(path, *flags, ok=True):
        return run("add-directory", "/opt/ios-unsandboxed-scopes/" + path, *flags, ok=ok)
    assert "missing" in run("status")
    add("one")
    assert not policy.exists()
    add("one", "--apply", ok=False)
    assert not policy.exists()
    add("one", "--apply", "--confirm")
    first = policy.read_bytes()
    assert first.startswith(b"ios-unsandboxed-execution-policy\nschema_version=1\nmode=preview-only\nscope_count=1\n")
    add("one", "--apply", "--confirm")
    assert policy.read_bytes() == first
    (scopes / "one/nested").mkdir()
    add("one/nested", "--apply", "--confirm", ok=False)
    run("add-directory", "/System", "--apply", "--confirm", ok=False)
    (scopes / "two").chmod(0o777)
    add("two", "--apply", "--confirm", ok=False)
    (scopes / "two").chmod(0o755)
    (scopes / "link").symlink_to("two", target_is_directory=True)
    add("link", "--apply", "--confirm", ok=False)
    (scopes / "two/linked-parent").symlink_to(scopes / "one", target_is_directory=True)
    run("add-directory", "/opt/ios-unsandboxed-scopes/two/linked-parent/nested", "--apply", "--confirm", ok=False)
    (scopes / "two/linked-parent").unlink()
    one_dir = scopes / "one"
    moved = scopes / "moved"
    one_dir.rename(moved)
    one_dir.mkdir()
    assert "UNSAFE_DIRECTORY" in run("preview", "/opt/ios-unsandboxed-scopes/one/tool")
    one_dir.rmdir()
    moved.rename(one_dir)
    binary = scopes / "one/tool"
    binary.write_bytes(planner.macho())
    binary.chmod(0o755)
    result = run("preview", "/opt/ios-unsandboxed-scopes/one/tool")
    assert "ARTIFACT_PROVENANCE_UNVERIFIED" in result and "Operational authorization: false" in result and "DENY_DISABLED" in result and "P009 capability" in result, result
    assert "P003 simulated directory scope result (NOT artifact eligibility): ALLOW_ELIGIBLE" in result
    assert "HYPOTHETICALLY_ELIGIBLE" not in result, result
    # A structurally valid Mach-O copied after scope enrollment has no trusted
    # evidence of origin. This simulates the protected Apple-service copy risk
    # without using or claiming to identify a real Apple binary.
    fake_system_source = base / "fixture-system-service"
    fake_system_source.write_bytes(planner.macho())
    copied_system_tool = scopes / "one/copied-system-service"
    copied_system_tool.write_bytes(fake_system_source.read_bytes())
    copied_system_tool.chmod(0o755)
    copied_result = run("preview", "/opt/ios-unsandboxed-scopes/one/copied-system-service")
    assert "ARTIFACT_PROVENANCE_UNVERIFIED" in copied_result, copied_result
    assert "Operational authorization: false" in copied_result, copied_result
    assert "HYPOTHETICALLY_ELIGIBLE" not in copied_result, copied_result
    assert copied_system_tool.read_bytes() == fake_system_source.read_bytes()
    copied_system_tool.unlink()
    assert "OUTSIDE_ALLOWED_SCOPE" in run("preview", "/opt/ios-unsandboxed-scopes/two/tool")
    binary.write_bytes(planner.macho(signature="none"))
    assert "MISSING_SIGNATURE_COMMAND" in run("preview", "/opt/ios-unsandboxed-scopes/one/tool")
    binary.write_bytes(planner.macho(cpu=0x01000007))
    assert "UNSUPPORTED_MACHO" in run("preview", "/opt/ios-unsandboxed-scopes/one/tool")
    (scopes / "two/system-service").write_bytes(b"service")
    add("two", "--apply", "--confirm", ok=False)
    (scopes / "two/system-service").unlink()
    for name in ["two", "three", "four", "five", "six", "seven", "eight"]:
        add(name, "--apply", "--confirm")
    add("nine", "--apply", "--confirm", ok=False)
    assert "Scopes: 8" in run("list")
    run("remove-directory", "/opt/ios-unsandboxed-scopes/two", "--apply", "--confirm")
    assert "Scopes: 7" in run("status")
    previous = policy.read_bytes()
    interrupted = subprocess.run([str(manager), "policy", "reset", "--test-root", str(root), "--apply", "--confirm", "--test-interrupt-at", "policy-before-rename"], capture_output=True)
    assert interrupted.returncode == 86 and policy.read_bytes() == previous
    orphans = list(policy.parent.glob(".policy-tmp-*"))
    assert len(orphans) == 1
    lock = root / "var/lib/.ios-unsandboxed-installer.lock"
    with lock.open("r+") as fd:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run("reset", "--apply", "--confirm", ok=False)
    assert policy.read_bytes() == previous
    suite.ok(suite.invoke("upgrade", suite.package_new, apply=True), "upgrade with policy")
    assert policy.read_bytes() == previous
    suite.ok(suite.invoke("rollback", apply=True), "rollback with policy")
    assert policy.read_bytes() == previous
    encoded_one = ("/opt/ios-unsandboxed-scopes/one".encode().hex() + "|1|1\n").encode()
    policy_header = b"ios-unsandboxed-execution-policy\nschema_version=1\nmode=preview-only\n"
    for value, expected in [
        (b"ios-unsandboxed-execution-policy\nschema_version=2\n", "unsupported"),
        (b"ios-unsandboxed-execution-policy\nschema_version=1\nmode=enabled\nscope_count=0\n", "corrupt"),
        (b"ios-unsandboxed-execution-policy\nschema_version=1\nmode=preview-only\nscope_count=0\nunknown=x\n", "corrupt"),
        (b"ios-unsandboxed-execution-policy\nschema_version=1\nmode=preview-only\nscope_count=0", "corrupt"),
        (b"ios-unsandboxed-execution-policy\nschema_version=1\nmode=preview-only\nscope_count=1\nscope_0=00\n", "corrupt"),
        (policy_header + b"scope_count=9\n", "corrupt"),
        (policy_header + b"scope_count=2\nscope_0=" + encoded_one + b"scope_1=" + encoded_one, "corrupt"),
        (policy_header + b"scope_count=1\nscope_0=zz|1|1\n", "corrupt"),
        (policy_header + b"scope_count=1\nscope_1=" + encoded_one, "corrupt"),
        (b"\0", "corrupt"),
    ]:
        policy.write_bytes(value)
        assert expected in run("status", ok=False)
        run("reset", "--apply", "--confirm", ok=False)
        assert policy.read_bytes() == value
        if expected == "unsupported":
            suite.fails(suite.invoke("upgrade", suite.package_new, apply=True), "unsupported policy blocks upgrade")
    policy.write_bytes(previous)
    policy.chmod(0o666)
    assert "unsafe" in run("status", ok=False)
    policy.chmod(0o600)
    link = policy.parent / "foreign-link"
    os.link(policy, link)
    assert "unsafe" in run("status", ok=False)
    link.unlink()
    policy.unlink()
    policy.symlink_to("install-state")
    assert "unsafe" in run("status", ok=False)
    policy.unlink()
    policy.write_bytes(previous)
    policy.chmod(0o600)
    run("reset", "--apply", "--confirm")
    assert b"scope_count=0\n" in policy.read_bytes()
    suite.ok(suite.invoke("uninstall", apply=True), "uninstall preserving policy")
    assert policy.exists() and orphans[0].exists()
    if os.geteuid() != 0:
        nonroot = subprocess.run([str(manager), "policy", "reset", "--apply", "--confirm"], capture_output=True)
        assert nonroot.returncode != 0
print("policy manager fixtures passed")
