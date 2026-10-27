#!/usr/bin/env python3
"""Deterministic host fixtures for the rootful package manager."""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HELPER = Path(sys.argv[1]).resolve()
MANAGER_SOURCE = ROOT / "packaging/rootful/manager.sh"
PLIST = ROOT / "packaging/rootful/com.ios-unsandboxed.daemon.plist"
STATE = (
    b"ios-unsandboxed-state\n"
    b"schema_version=1\n"
    b"service_installation=installed\n"
    b"execution_activation=disabled\n"
)
FILES = (
    ("payload/bin/ios-unsandboxed", 0o755),
    ("payload/bin/ios-unsandboxedd", 0o755),
    ("payload/share/manager.sh", 0o700),
    ("payload/share/installer-helper", 0o700),
    ("payload/share/paths.env", 0o600),
    ("payload/share/install-state.example", 0o600),
    ("payload/share/com.ios-unsandboxed.daemon.plist", 0o600),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mach_o(label: bytes, cpu: int = 0x0100000C) -> bytes:
    # A bounded thin ARM64 executable header with one iOS 12.0 build command.
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, 0, 2, 1, 24, 0, 0)
    load = struct.pack("<IIIIII", 0x32, 24, 2, 0x000C0000, 0x000C0000, 0)
    return header + load + label


def fixture_manager_script(host_manager: Path) -> bytes:
    return ("#!/bin/sh\nexec " + str(host_manager) + ' "$@"\n').encode()


def make_package(directory: Path, version: str, host_manager: Path, marker: bytes = b"base") -> Path:
    directory.mkdir(mode=0o755)
    for name in ("payload", "payload/bin", "payload/share"):
        (directory / name).mkdir(mode=0o755)
    contents = {
        FILES[0][0]: mach_o(b"cli-" + marker),
        FILES[1][0]: mach_o(b"daemon-" + marker),
        FILES[2][0]: fixture_manager_script(host_manager),
        FILES[3][0]: mach_o(b"helper-fixture"),
        FILES[4][0]: (ROOT / "packaging/rootful/paths.env").read_bytes(),
        FILES[5][0]: STATE,
        FILES[6][0]: PLIST.read_bytes(),
    }
    for relative, mode in FILES:
        target = directory / relative
        target.write_bytes(contents[relative])
        target.chmod(mode)
    records = [
        "ios-unsandboxed-package",
        "schema_version=1",
        f"project_version={version}",
        "platform=ios",
        "architecture=arm64",
        "minimum_ios=12.0",
        "signing_status=unsigned",
        "signature_verification=not_applicable",
        "artifact_signing=payload/bin/ios-unsandboxed|unsigned|not_applicable",
        "artifact_signing=payload/bin/ios-unsandboxedd|unsigned|not_applicable",
        "artifact_signing=payload/share/installer-helper|unsigned|not_applicable",
    ]
    records.extend(
        f"file={relative}|regular|{mode:04o}|{digest(contents[relative])}"
        for relative, mode in FILES
    )
    manifest = ("\n".join(records) + "\n").encode("ascii")
    (directory / "package-manifest").write_bytes(manifest)
    (directory / "package-manifest").chmod(0o644)
    sums = [("package-manifest", digest(manifest))]
    sums.extend((relative, digest(contents[relative])) for relative, _ in FILES)
    (directory / "SHA256SUMS").write_text(
        "".join(f"{sha}  {name}\n" for name, sha in sums), encoding="ascii"
    )
    (directory / "SHA256SUMS").chmod(0o644)
    return directory


def tree_snapshot(path: Path) -> dict[str, tuple[str, int, int, int]]:
    result: dict[str, tuple[str, int, int, int]] = {}
    if not path.exists():
        return result
    for entry in sorted(path.rglob("*")):
        rel = entry.relative_to(path).as_posix()
        st = entry.lstat()
        if stat.S_ISLNK(st.st_mode):
            result[rel] = ("link:" + os.readlink(entry), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
        elif stat.S_ISREG(st.st_mode):
            result[rel] = (digest(entry.read_bytes()), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
        else:
            result[rel] = ("dir", stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
    return result


class Suite:
    def __init__(self, base: Path):
        self.base = base
        self.bundle = base / "manager-bundle"
        self.bundle.mkdir(mode=0o700)
        shutil.copy2(MANAGER_SOURCE, self.bundle / "manager.sh")
        shutil.copy2(HELPER, self.bundle / "installer-helper")
        (self.bundle / "manager.sh").chmod(0o700)
        (self.bundle / "installer-helper").chmod(0o700)
        self.package_root = make_package(base / "package-0.1.0", "0.1.0", self.bundle / "manager.sh")
        self.package_new = make_package(base / "package-0.2.0", "0.2.0", self.bundle / "manager.sh", b"upgrade")
        self.root = base / "fixture"
        self.make_root(self.root)

    @staticmethod
    def make_root(root: Path) -> None:
        root.mkdir(mode=0o700)
        for path in ("usr", "usr/local", "usr/local/bin", "var", "var/lib", "var/log"):
            (root / path).mkdir(mode=0o755)

    def invoke(self, command: str, package: Path | None = None, apply: bool = False,
               root: Path | None = None, interrupt: str | None = None,
               manager: Path | None = None) -> subprocess.CompletedProcess[str]:
        root = root or self.root
        manager = manager or (root / "var/lib/ios-unsandboxed/manager.sh")
        if not manager.exists():
            manager = self.bundle / "manager.sh"
        args = [str(manager), command]
        if package is not None:
            args += ["--package", str(package)]
        args += ["--test-root", str(root)]
        if apply:
            args.append("--apply")
        if interrupt:
            args += ["--test-interrupt-at", interrupt]
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def ok(self, result: subprocess.CompletedProcess[str], label: str) -> None:
        assert result.returncode == 0, f"{label} failed ({result.returncode})\n{result.stdout}\n{result.stderr}"

    def fails(self, result: subprocess.CompletedProcess[str], label: str) -> None:
        assert result.returncode != 0, f"{label} unexpectedly succeeded\n{result.stdout}"

    def installed_path(self, root: Path, relative: str) -> Path:
        return root / relative.lstrip("/")


def refresh_package_metadata(package: Path, architecture: str | None = None,
                             first_path: str | None = None) -> None:
    manifest_path = package / "package-manifest"
    lines = manifest_path.read_text().splitlines()
    if architecture is not None:
        lines[4] = f"architecture={architecture}"
    if first_path is not None:
        for i, line in enumerate(lines):
            if line.startswith("file="):
                fields = line[5:].split("|")
                fields[0] = first_path
                lines[i] = "file=" + "|".join(fields)
                break
    text = "\n".join(lines) + "\n"
    manifest_path.write_text(text)
    sums = package / "SHA256SUMS"
    sum_lines = sums.read_text().splitlines()
    sum_lines[0] = f"{digest(text.encode())}  package-manifest"
    sums.write_text("\n".join(sum_lines) + "\n")


def test_package_rejections(suite: Suite) -> None:
    root = suite.base / "invalid-root"
    Suite.make_root(root)
    # Missing payload and an ordinary payload checksum mismatch both fail closed.
    missing = shutil.copytree(suite.package_root, suite.base / "missing-payload")
    (missing / FILES[0][0]).unlink()
    suite.fails(suite.invoke("install", missing, apply=True, root=root), "missing package payload")
    bad_hash = shutil.copytree(suite.package_root, suite.base / "bad-hash")
    (bad_hash / FILES[0][0]).write_bytes((bad_hash / FILES[0][0]).read_bytes() + b"changed")
    suite.fails(suite.invoke("install", bad_hash, apply=True, root=root), "invalid package checksum")
    wrong_meta = shutil.copytree(suite.package_root, suite.base / "wrong-metadata")
    refresh_package_metadata(wrong_meta, architecture="x86_64")
    suite.fails(suite.invoke("install", wrong_meta, apply=True, root=root), "wrong architecture metadata")
    oversized_version = shutil.copytree(suite.package_root, suite.base / "oversized-version")
    version_lines = (oversized_version / "package-manifest").read_text().splitlines()
    version_lines[2] = "project_version=4294967296.0.0"
    version_text = "\n".join(version_lines) + "\n"
    (oversized_version / "package-manifest").write_text(version_text)
    (oversized_version / "SHA256SUMS").write_text(
        f"{digest(version_text.encode())}  package-manifest\n" +
        "".join(f"{digest((oversized_version / name).read_bytes())}  {name}\n" for name, _ in FILES)
    )
    suite.fails(suite.invoke("install", oversized_version, apply=True, root=root), "out-of-range version component")
    blank_record = shutil.copytree(suite.package_root, suite.base / "blank-record")
    blank_manifest = (blank_record / "package-manifest").read_text().replace(
        "schema_version=1\n", "schema_version=1\n\n", 1
    )
    (blank_record / "package-manifest").write_text(blank_manifest)
    blank_sums = (blank_record / "SHA256SUMS").read_text().splitlines()
    blank_sums[0] = f"{digest(blank_manifest.encode())}  package-manifest"
    (blank_record / "SHA256SUMS").write_text("\n".join(blank_sums) + "\n")
    suite.fails(suite.invoke("install", blank_record, apply=True, root=root), "blank package manifest record")
    traversal = shutil.copytree(suite.package_root, suite.base / "traversal")
    refresh_package_metadata(traversal, first_path="payload/../outside")
    suite.fails(suite.invoke("install", traversal, apply=True, root=root), "traversal package entry")
    wrong_binary = shutil.copytree(suite.package_root, suite.base / "wrong-binary")
    (wrong_binary / FILES[0][0]).write_bytes(mach_o(b"x86", cpu=0x01000007))
    refresh_package_metadata(wrong_binary)
    # Recompute the affected payload record and SHA256SUMS to prove architecture
    # inspection is independent of the self-consistent package metadata.
    lines = (wrong_binary / "package-manifest").read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"file={FILES[0][0]}|"):
            fields = line[5:].split("|")
            fields[-1] = digest((wrong_binary / FILES[0][0]).read_bytes())
            lines[i] = "file=" + "|".join(fields)
    manifest_text = "\n".join(lines) + "\n"
    (wrong_binary / "package-manifest").write_text(manifest_text)
    sums = [("package-manifest", digest(manifest_text.encode()))]
    sums += [(relative, digest((wrong_binary / relative).read_bytes())) for relative, _ in FILES]
    (wrong_binary / "SHA256SUMS").write_text("".join(f"{sha}  {name}\n" for name, sha in sums))
    suite.fails(suite.invoke("install", wrong_binary, apply=True, root=root), "wrong Mach-O CPU type")
    assert not (root / "var/lib/ios-unsandboxed").exists()


def test_bounded_install_metadata(suite: Suite) -> None:
    manifest_root = suite.base / "oversized-install-manifest-root"
    Suite.make_root(manifest_root)
    suite.ok(suite.invoke("install", suite.package_root, apply=True, root=manifest_root), "setup oversized install manifest")
    manifest = manifest_root / "var/lib/ios-unsandboxed/install-manifest"
    manifest.write_text(manifest.read_text().replace("signing_status=unsigned", "signing_status=" + "x" * 256, 1))
    before = tree_snapshot(manifest_root)
    result = suite.invoke("status", root=manifest_root)
    suite.fails(result, "oversized install manifest field")
    assert "installation manifest, owned files, or disabled state failed verification" in result.stderr
    assert tree_snapshot(manifest_root) == before

    journal_root = suite.base / "oversized-journal-root"
    Suite.make_root(journal_root)
    suite.ok(suite.invoke("install", suite.package_root, apply=True, root=journal_root), "setup oversized journal")
    interrupted = suite.invoke("upgrade", suite.package_new, apply=True, root=journal_root, interrupt="prepared")
    assert interrupted.returncode == 86
    journal = journal_root / "var/lib/ios-unsandboxed/transaction"
    journal.write_text(journal.read_text().replace("action=upgrade", "action=" + "x" * 256, 1))
    before = tree_snapshot(journal_root)
    result = suite.invoke("status", root=journal_root)
    suite.fails(result, "oversized transaction journal field")
    assert "transaction journal is corrupt or unsafe" in result.stderr
    assert tree_snapshot(journal_root) == before


def test_foreign_and_symlink_conflicts(suite: Suite) -> None:
    foreign_root = suite.base / "foreign-root"
    Suite.make_root(foreign_root)
    (foreign_root / "var/lib/.ios-unsandboxed-installer.lock").touch(mode=0o600)
    (foreign_root / "var/lib/.ios-unsandboxed-installer.lock").chmod(0o600)
    foreign = foreign_root / "usr/local/bin/ios-unsandboxedd"
    foreign.write_bytes(b"foreign-owned")
    before = tree_snapshot(foreign_root)
    suite.fails(suite.invoke("install", suite.package_root, apply=True, root=foreign_root), "foreign destination")
    assert tree_snapshot(foreign_root) == before
    link_root = suite.base / "symlink-root"
    Suite.make_root(link_root)
    (link_root / "var/lib/.ios-unsandboxed-installer.lock").touch(mode=0o600)
    (link_root / "var/lib/.ios-unsandboxed-installer.lock").chmod(0o600)
    target = suite.base / "outside-target"
    target.write_bytes(b"outside")
    os.symlink(target, link_root / "usr/local/bin/ios-unsandboxed")
    before = tree_snapshot(link_root)
    suite.fails(suite.invoke("install", suite.package_root, apply=True, root=link_root), "symlink destination")
    assert tree_snapshot(link_root) == before
    assert target.read_bytes() == b"outside", "a rejected symlink destination changed data outside the fixture root"


def test_main_lifecycle(suite: Suite) -> None:
    help_result = subprocess.run([str(suite.bundle / "manager.sh"), "help"], text=True, capture_output=True)
    suite.ok(help_result, "manager help")
    version_result = subprocess.run([str(suite.bundle / "manager.sh"), "version"], text=True, capture_output=True)
    suite.ok(version_result, "manager version")

    before = tree_snapshot(suite.root)
    suite.ok(suite.invoke("plan", suite.package_root), "empty-root plan")
    suite.ok(suite.invoke("install", suite.package_root), "install dry run")
    assert tree_snapshot(suite.root) == before, "dry-run modified fixture files"
    package_before = tree_snapshot(suite.package_root)
    assert tree_snapshot(suite.package_root) == package_before, "dry-run modified package inputs"

    suite.ok(suite.invoke("install", suite.package_root, apply=True), "first install")
    suite.ok(suite.invoke("status"), "status after first install")
    cli = suite.installed_path(suite.root, "/usr/local/bin/ios-unsandboxed")
    daemon = suite.installed_path(suite.root, "/usr/local/bin/ios-unsandboxedd")
    alias = suite.installed_path(suite.root, "/usr/local/bin/iu")
    state = suite.installed_path(suite.root, "/var/lib/ios-unsandboxed/install-state")
    inactive_plist = suite.installed_path(suite.root, "/var/lib/ios-unsandboxed/com.ios-unsandboxed.daemon.plist.inactive")
    assert cli.read_bytes() == mach_o(b"cli-base")
    assert daemon.read_bytes() == mach_o(b"daemon-base")
    assert alias.is_symlink() and os.readlink(alias) == "/usr/local/bin/ios-unsandboxed"
    assert state.read_bytes() == STATE and stat.S_IMODE(state.stat().st_mode) == 0o600
    assert inactive_plist.is_file()
    assert not (suite.root / "Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist").exists()
    assert not (suite.root / "var/run/ios-unsandboxedd.sock").exists()
    assert not list(suite.root.rglob("*.launchd-called"))

    snapshot = tree_snapshot(suite.root)
    suite.fails(suite.invoke("install", suite.package_root, apply=True), "repeated install")
    assert tree_snapshot(suite.root) == snapshot
    suite.ok(suite.invoke("plan", suite.package_new), "upgrade plan")
    suite.ok(suite.invoke("upgrade", suite.package_new), "upgrade dry run")
    assert tree_snapshot(suite.root) == snapshot
    suite.ok(suite.invoke("upgrade", suite.package_new, apply=True), "successful upgrade")
    assert cli.read_bytes() == mach_o(b"cli-upgrade")
    assert daemon.read_bytes() == mach_o(b"daemon-upgrade")
    suite.ok(suite.invoke("status"), "status after upgrade")
    suite.ok(suite.invoke("rollback", apply=True), "rollback after upgrade")
    assert cli.read_bytes() == mach_o(b"cli-base")
    assert daemon.read_bytes() == mach_o(b"daemon-base")
    suite.ok(suite.invoke("status"), "status after rollback")

    # An unexpected hard-link alias invalidates ownership; status and uninstall
    # refuse to adopt or delete it.
    hardlink_root = suite.base / "hardlink-root"
    shutil.copytree(suite.root, hardlink_root, symlinks=True)
    hard_cli = hardlink_root / "usr/local/bin/ios-unsandboxed"
    os.link(hard_cli, hardlink_root / "usr/local/bin/foreign-hardlink")
    suite.fails(suite.invoke("status", root=hardlink_root), "hard-link validation")
    suite.fails(suite.invoke("uninstall", apply=True, root=hardlink_root), "hard-link uninstall guard")
    assert hard_cli.exists()

    active_root = suite.base / "active-launchd-root"
    shutil.copytree(suite.root, active_root, symlinks=True)
    active_job = active_root / "Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist"
    active_job.parent.mkdir(parents=True)
    active_job.write_bytes(PLIST.read_bytes())
    suite.fails(suite.invoke("uninstall", apply=True, root=active_root), "active plist uninstall guard")
    assert active_job.read_bytes() == PLIST.read_bytes()

    # Corrupt/missing backup generations are refused before any deployment file
    # is changed. Use isolated copies so the main rollback chain remains usable.
    corrupt_root = suite.base / "corrupt-backup-root"
    shutil.copytree(suite.root, corrupt_root, symlinks=True)
    corrupt_manifest = (corrupt_root / "var/lib/ios-unsandboxed/install-manifest").read_text().splitlines()
    backup_generation = next(line.split("=", 1)[1] for line in corrupt_manifest if line.startswith("backup_generation="))
    corrupt_file = corrupt_root / f"var/lib/ios-unsandboxed/backups/{backup_generation}/files/f0"
    corrupt_file.write_bytes(corrupt_file.read_bytes() + b"corrupt")
    before = tree_snapshot(corrupt_root)
    suite.fails(suite.invoke("rollback", apply=True, root=corrupt_root), "corrupt backup")
    assert tree_snapshot(corrupt_root) == before
    missing_root = suite.base / "missing-backup-root"
    shutil.copytree(suite.root, missing_root, symlinks=True)
    missing_generation = next(line.split("=", 1)[1] for line in (missing_root / "var/lib/ios-unsandboxed/install-manifest").read_text().splitlines() if line.startswith("backup_generation="))
    shutil.rmtree(missing_root / f"var/lib/ios-unsandboxed/backups/{missing_generation}")
    before = tree_snapshot(missing_root)
    suite.fails(suite.invoke("rollback", apply=True, root=missing_root), "missing backup")
    assert tree_snapshot(missing_root) == before

    # A user modification, unsafe mode, and unknown manifest version all fail
    # closed and remain untouched.
    modified_root = suite.base / "modified-root"
    shutil.copytree(suite.root, modified_root, symlinks=True)
    modified_cli = modified_root / "usr/local/bin/ios-unsandboxed"
    modified_cli.write_bytes(modified_cli.read_bytes() + b"user edit")
    suite.fails(suite.invoke("status", root=modified_root), "modified installed file")
    suite.fails(suite.invoke("uninstall", apply=True, root=modified_root), "modified uninstall guard")
    unsafe_root = suite.base / "unsafe-root"
    shutil.copytree(suite.root, unsafe_root, symlinks=True)
    (unsafe_root / "usr/local/bin/ios-unsandboxed").chmod(0o777)
    suite.fails(suite.invoke("status", root=unsafe_root), "unsafe installed mode")
    unknown_root = suite.base / "unknown-manifest-root"
    shutil.copytree(suite.root, unknown_root, symlinks=True)
    manifest = unknown_root / "var/lib/ios-unsandboxed/install-manifest"
    manifest.write_text(manifest.read_text().replace("schema_version=1", "schema_version=2", 1))
    suite.fails(suite.invoke("status", root=unknown_root), "unknown install manifest schema")
    state_root = suite.base / "enabled-state-root"
    shutil.copytree(suite.root, state_root, symlinks=True)
    state_path = state_root / "var/lib/ios-unsandboxed/install-state"
    state_path.write_bytes(STATE.replace(b"execution_activation=disabled", b"execution_activation=enabled"))
    suite.fails(suite.invoke("status", root=state_root), "enabled state rejection")
    suite.fails(suite.invoke("uninstall", apply=True, root=state_root), "enabled state uninstall guard")
    unsupported_state_root = suite.base / "unsupported-state-root"
    shutil.copytree(suite.root, unsupported_state_root, symlinks=True)
    unsupported_state = unsupported_state_root / "var/lib/ios-unsandboxed/install-state"
    unsupported_state.write_bytes(STATE.replace(b"schema_version=1", b"schema_version=2"))
    suite.fails(suite.invoke("status", root=unsupported_state_root), "unsupported persistent state schema")
    owner_root = suite.base / "wrong-owner-manifest-root"
    shutil.copytree(suite.root, owner_root, symlinks=True)
    owner_manifest = owner_root / "var/lib/ios-unsandboxed/install-manifest"
    owner_lines = owner_manifest.read_text().splitlines()
    for index, line in enumerate(owner_lines):
        if line.startswith("file=/usr/local/bin/ios-unsandboxed|"):
            fields = line[5:].split("|")
            fields[3] = str(os.geteuid() + 1)
            owner_lines[index] = "file=" + "|".join(fields)
            break
    owner_manifest.write_text("\n".join(owner_lines) + "\n")
    suite.fails(suite.invoke("status", root=owner_root), "wrong recorded owner")

    foreign_upgrade_root = suite.base / "foreign-upgrade-root"
    shutil.copytree(suite.root, foreign_upgrade_root, symlinks=True)
    foreign_upgrade_cli = foreign_upgrade_root / "usr/local/bin/ios-unsandboxed"
    foreign_upgrade_cli.write_bytes(b"foreign replacement")
    suite.fails(suite.invoke("upgrade", suite.package_new, apply=True, root=foreign_upgrade_root), "foreign upgrade conflict")
    assert foreign_upgrade_cli.read_bytes() == b"foreign replacement"

    # Lock contention is exercised with a process-owned POSIX advisory lock.
    lock_path = suite.root / "var/lib/.ios-unsandboxed-installer.lock"
    with lock_path.open("a+") as lock_file:
        fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        blocked = suite.invoke("upgrade", suite.package_new, apply=True)
        assert blocked.returncode == 4, f"lock contention returned {blocked.returncode}: {blocked.stderr}"
        fcntl.lockf(lock_file, fcntl.LOCK_UN)

    # Successful and repeated uninstall only remove verified project files.
    suite.ok(suite.invoke("uninstall"), "uninstall dry run")
    before = tree_snapshot(suite.root)
    suite.ok(suite.invoke("uninstall", apply=True), "safe uninstall")
    suite.ok(suite.invoke("uninstall", apply=True), "repeated uninstall")
    assert not cli.exists() and not daemon.exists() and not alias.exists() and not state.exists()
    assert tree_snapshot(suite.root) == {key: value for key, value in before.items()
                                       if key in {"usr", "usr/local", "usr/local/bin", "var", "var/lib", "var/log",
                                                  "var/lib/.ios-unsandboxed-installer.lock"}}


def test_interrupted_recovery(suite: Suite) -> None:
    # Crash before a journal: recovery removes only private, fixed-name staging.
    staging_root = suite.base / "staging-interrupt-root"
    Suite.make_root(staging_root)
    result = suite.invoke("install", suite.package_root, apply=True, root=staging_root, interrupt="staging")
    assert result.returncode == 86
    stage_dir = next((staging_root / "var/lib/ios-unsandboxed/staging").iterdir())
    orphan_stage_temp = stage_dir / ".tmp-123-1"
    orphan_stage_temp.write_bytes(b"partial atomic staging file")
    orphan_stage_temp.chmod(0o600)
    suite.ok(suite.invoke("recover", apply=True, root=staging_root), "interrupted staging recovery")
    assert not (staging_root / "var/lib/ios-unsandboxed").exists()
    assert not (staging_root / "usr/local/bin/ios-unsandboxed").exists()

    # Crash after two first-install destination replacements: journal recovery
    # removes only files matching the staged package generation.
    commit_root = suite.base / "commit-interrupt-root"
    Suite.make_root(commit_root)
    result = suite.invoke("install", suite.package_root, apply=True, root=commit_root, interrupt="commit:2")
    assert result.returncode == 86
    orphan_destination_temp = commit_root / "usr/local/bin/.iu-tmp-123-1-1"
    orphan_destination_temp.write_bytes(b"partial destination temp")
    orphan_destination_temp.chmod(0o600)
    orphan_metadata_temp = commit_root / "var/lib/ios-unsandboxed/.tmp-123-2"
    orphan_metadata_temp.write_bytes(b"partial manifest temp")
    orphan_metadata_temp.chmod(0o600)
    suite.fails(suite.invoke("status", root=commit_root), "interrupted transaction status")
    suite.ok(suite.invoke("recover", apply=True, root=commit_root), "interrupted first-install recovery")
    assert not orphan_destination_temp.exists() and not orphan_metadata_temp.exists()
    assert not (commit_root / "var/lib/ios-unsandboxed").exists()
    assert not (commit_root / "usr/local/bin/ios-unsandboxed").exists()

    # Upgrade interruption is rolled back to the known-good old generation.
    upgrade_root = suite.base / "upgrade-interrupt-root"
    Suite.make_root(upgrade_root)
    suite.ok(suite.invoke("install", suite.package_root, apply=True, root=upgrade_root), "setup interrupted-upgrade fixture")
    result = suite.invoke("upgrade", suite.package_new, apply=True, root=upgrade_root, interrupt="commit:2")
    assert result.returncode == 86
    suite.ok(suite.invoke("recover", apply=True, root=upgrade_root), "interrupted upgrade recovery")
    assert (upgrade_root / "usr/local/bin/ios-unsandboxed").read_bytes() == mach_o(b"cli-base")
    suite.ok(suite.invoke("status", root=upgrade_root), "status after interrupted upgrade recovery")

    # Rollback interruption restores the pre-rollback release from the dedicated
    # recovery snapshot, even when some destinations already contain old files.
    rollback_root = suite.base / "rollback-interrupt-root"
    Suite.make_root(rollback_root)
    suite.ok(suite.invoke("install", suite.package_root, apply=True, root=rollback_root), "setup interrupted-rollback fixture")
    suite.ok(suite.invoke("upgrade", suite.package_new, apply=True, root=rollback_root), "setup rollback generation")
    result = suite.invoke("rollback", apply=True, root=rollback_root, interrupt="rollback:2")
    assert result.returncode == 86
    suite.ok(suite.invoke("recover", apply=True, root=rollback_root), "interrupted rollback recovery")
    assert (rollback_root / "usr/local/bin/ios-unsandboxed").read_bytes() == mach_o(b"cli-upgrade")
    suite.ok(suite.invoke("status", root=rollback_root), "status after interrupted rollback recovery")

    # An interrupted uninstall is recoverable through its preserved generation.
    uninstall_root = suite.base / "uninstall-interrupt-root"
    Suite.make_root(uninstall_root)
    suite.ok(suite.invoke("install", suite.package_root, apply=True, root=uninstall_root), "setup interrupted-uninstall fixture")
    result = suite.invoke("uninstall", apply=True, root=uninstall_root, interrupt="prepared")
    assert result.returncode == 86
    suite.ok(suite.invoke("recover", apply=True, root=uninstall_root), "interrupted uninstall recovery")
    suite.ok(suite.invoke("status", root=uninstall_root), "status after interrupted uninstall recovery")


def test_fixture_root_guards(suite: Suite) -> None:
    result = subprocess.run([str(suite.bundle / "manager.sh"), "status", "--test-root", "/"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode != 0, "test-root / must be rejected"
    symlink_root = suite.base / "fixture-root-link"
    os.symlink(suite.root, symlink_root)
    result = subprocess.run([str(suite.bundle / "manager.sh"), "status", "--test-root", str(symlink_root)],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode != 0, "symlinked test root must be rejected"
    unsafe_root = suite.base / "unsafe-fixture-root"
    Suite.make_root(unsafe_root)
    unsafe_root.chmod(0o777)
    result = subprocess.run([str(suite.bundle / "manager.sh"), "status", "--test-root", str(unsafe_root)],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode != 0, "group/world-writable test root must be rejected"


def main() -> None:
    assert HELPER.is_file()
    with tempfile.TemporaryDirectory(prefix="iu-installer-fixtures-") as temporary:
        suite = Suite(Path(temporary))
        test_package_rejections(suite)
        test_bounded_install_metadata(suite)
        test_foreign_and_symlink_conflicts(suite)
        test_main_lifecycle(suite)
        test_interrupted_recovery(suite)
        test_fixture_root_guards(suite)
    print("Rootful installer fixtures passed. Ownership values were simulated with the host user's UID/GID; no device paths or launchd operations were used.")


if __name__ == "__main__":
    main()
