#!/usr/bin/env python3
"""Validate a built distribution package and its reproducible archive."""

from __future__ import annotations

import hashlib
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = Path(sys.argv[1]).resolve()
ARCHIVE = PACKAGE.parent / f"{PACKAGE.name}.tar.gz"
REQUIRED = {
    "payload/bin/ios-unsandboxed": 0o755,
    "payload/bin/ios-unsandboxedd": 0o755,
    "payload/share/manager.sh": 0o700,
    "payload/share/installer-helper": 0o700,
    "payload/share/paths.env": 0o600,
    "payload/share/install-state.example": 0o600,
    "payload/share/com.ios-unsandboxed.daemon.plist": 0o600,
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    assert PACKAGE.is_dir(), f"package directory is absent: {PACKAGE}"
    assert ARCHIVE.is_file(), f"distribution archive is absent: {ARCHIVE}"
    assert (PACKAGE / "package-manifest").is_file()
    assert (PACKAGE / "SHA256SUMS").is_file()
    lines = (PACKAGE / "package-manifest").read_text(encoding="ascii").splitlines()
    assert lines[:6] == [
        "ios-unsandboxed-package", "schema_version=1", "project_version=0.1.0",
        "platform=ios", "architecture=arm64", "minimum_ios=12.0",
    ]
    signing = lines[6].split("=", 1)[1]
    verification = lines[7].split("=", 1)[1]
    assert signing in {"unsigned", "adhoc_signed", "signed_unverified", "signature_verification_passed", "unknown"}
    assert verification in {"passed", "failed", "not_applicable", "unknown", "mixed"}
    assert len(lines) == 11 + len(REQUIRED)
    assert lines[8:11] == [
        f"artifact_signing=payload/bin/ios-unsandboxed|{lines[8].split('|')[1]}|{lines[8].split('|')[2]}",
        f"artifact_signing=payload/bin/ios-unsandboxedd|{lines[9].split('|')[1]}|{lines[9].split('|')[2]}",
        f"artifact_signing=payload/share/installer-helper|{lines[10].split('|')[1]}|{lines[10].split('|')[2]}",
    ]
    for line in lines[8:11]:
        _, status, result = line.split("|")
        assert status in {"unsigned", "adhoc_signed", "signed_unverified", "signature_verification_passed", "unknown"}
        assert result in {"passed", "failed", "not_applicable", "unknown"}
    for relative, mode in REQUIRED.items():
        path = PACKAGE / relative
        assert path.is_file() and not path.is_symlink(), f"missing regular payload: {relative}"
        assert path.stat().st_mode & 0o7777 == mode, f"unexpected mode for {relative}"
        record = next(line for line in lines if line.startswith(f"file={relative}|"))
        fields = record[5:].split("|")
        assert fields == [relative, "regular", f"{mode:04o}", sha(path)]
    sums = (PACKAGE / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    expected = [("package-manifest", sha(PACKAGE / "package-manifest"))]
    expected.extend((name, sha(PACKAGE / name)) for name in REQUIRED)
    assert sums == [f"{digest}  {name}" for name, digest in expected]
    for relative in ("payload/bin/ios-unsandboxed", "payload/bin/ios-unsandboxedd", "payload/share/installer-helper"):
        assert (PACKAGE / relative).read_bytes()[:8] == bytes.fromhex("cffaedfe0c000001"), f"not a thin Apple ARM64 Mach-O: {relative}"
    with (PACKAGE / "payload/share/com.ios-unsandboxed.daemon.plist").open("rb") as stream:
        plist = plistlib.load(stream)
    assert plist["ProgramArguments"] == ["/usr/local/bin/ios-unsandboxedd", "--serve"]
    assert plist["UserName"] == "root" and plist["GroupName"] == "wheel"
    assert plist["RunAtLoad"] is True and plist["KeepAlive"] is False
    assert "/Library/LaunchDaemons/" not in str(PACKAGE / "payload/share/com.ios-unsandboxed.daemon.plist")
    with ARCHIVE.open("rb") as stream:
        header = stream.read(10)
    assert header[:2] == b"\x1f\x8b" and header[4:8] == b"\0\0\0\0", "gzip timestamp is not normalized"
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        assert members
        names = [member.name for member in members]
        assert names[0] == PACKAGE.name
        assert names[1:] == sorted(names[1:]), "archive entries are not sorted deterministically"
        for member in members:
            member_path = Path(member.name)
            assert not member_path.is_absolute() and ".." not in member_path.parts
            assert member.uid == 0 and member.gid == 0 and member.mtime == 0
            assert member.isfile() or member.isdir()
        assert f"{PACKAGE.name}/package-manifest" in names
    with tempfile.TemporaryDirectory(prefix="iu-package-repro-") as temp:
        one = Path(temp) / "one"
        two = Path(temp) / "two"
        command = [sys.executable, str(ROOT / "scripts/build-rootful-package.sh")]
        artifacts = [
            "--cli", str(ROOT / "target/aarch64-apple-ios/release/ios-unsandboxed"),
            "--daemon", str(ROOT / "build/ios/ios-unsandboxedd"),
            "--installer-helper", str(ROOT / "build/ios/installer-helper"),
        ]
        subprocess.run(command + artifacts + ["--output-root", str(one)], check=True)
        subprocess.run(command + artifacts + ["--output-root", str(two)], check=True)
        archive_one = one / f"{PACKAGE.name}.tar.gz"
        archive_two = two / f"{PACKAGE.name}.tar.gz"
        assert sha(archive_one) == sha(archive_two) == sha(ARCHIVE), "package output is not reproducible"
    print(f"Rootful package integrity and deterministic archive validated: {ARCHIVE}")
    print(f"Signing status recorded as {signing}; runtime startup remains unverified.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: rootful-package-test.py PACKAGE_DIRECTORY")
    main()
