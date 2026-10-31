#!/usr/bin/env python3
"""Assemble a deterministic, checksummed rootful iOS package from Apple builds."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = (
    ("payload/bin/ios-unsandboxed", 0o755),
    ("payload/bin/ios-unsandboxedd", 0o755),
    ("payload/share/manager.sh", 0o700),
    ("payload/share/installer-helper", 0o700),
    ("payload/share/paths.env", 0o600),
    ("payload/share/install-state.example", 0o600),
    ("payload/share/com.ios-unsandboxed.daemon.plist", 0o600),
)
MACH_O_PAYLOADS = {
    "payload/bin/ios-unsandboxed",
    "payload/bin/ios-unsandboxedd",
    "payload/share/installer-helper",
}
MACH_O_ORDER = (
    "payload/bin/ios-unsandboxed",
    "payload/bin/ios-unsandboxedd",
    "payload/share/installer-helper",
)
IOS_SYSTEM_LIBRARIES = {
    "/usr/lib/libSystem.B.dylib",
    # Rust's Apple target links this public iOS SDK system library for std.
    "/usr/lib/libiconv.2.dylib",
}


class BuildError(RuntimeError):
    pass


def run(*args: str, required: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
    except OSError as exc:
        raise BuildError(f"required tool {args[0]!r} is unavailable: {exc}") from exc
    if required and result.returncode:
        raise BuildError(f"{args[0]} failed ({result.returncode}):\n{result.stdout.strip()}")
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def declares_ios_12(load_commands: str) -> bool:
    commands = list(re.finditer(r"(?m)^\s*Load command \d+\s*$", load_commands))
    for index, marker in enumerate(commands):
        end = commands[index + 1].start() if index + 1 < len(commands) else len(load_commands)
        block = load_commands[marker.start():end]
        if re.search(r"(?m)^\s*cmd LC_BUILD_VERSION\s*$", block):
            platform_is_ios = re.search(r"(?m)^\s*platform\s+(?:IOS|2)\s*$", block)
            minimum_is_12 = re.search(r"(?m)^\s*minos\s+12\.0(?:\s|$)", block)
            if platform_is_ios and minimum_is_12:
                return True
        if re.search(r"(?m)^\s*cmd LC_VERSION_MIN_IPHONEOS\s*$", block):
            if re.search(r"(?m)^\s*version\s+12\.0(?:\s|$)", block):
                return True
    return False


def inspect_macho(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise BuildError(f"required Apple build artifact is missing or not a regular file: {path}")
    result = run("file", str(path))
    if "Mach-O" not in result.stdout or "arm64" not in result.stdout.lower():
        raise BuildError(f"refusing non-Apple-ARM64 input: {path}: {result.stdout.strip()}")
    header = run("otool", "-hv", str(path)).stdout
    if "ARM64" not in header and "ARM64" not in header.upper():
        raise BuildError(f"otool did not identify ARM64 CPU type for {path}")
    loads = run("otool", "-l", str(path)).stdout
    if not declares_ios_12(loads):
        raise BuildError(f"{path} does not declare the required iOS platform and 12.0 minimum target")
    dependencies = run("otool", "-L", str(path)).stdout.splitlines()[1:]
    unexpected = [line.strip() for line in dependencies
                  if line.strip() and line.strip().split(" ", 1)[0] not in IOS_SYSTEM_LIBRARIES]
    if unexpected:
        raise BuildError(f"unexpected iOS runtime dependencies in {path}: {', '.join(unexpected)}")


def signing_status(path: Path) -> tuple[str, str]:
    display = run("codesign", "-dv", "--verbose=4", str(path), required=False)
    output = display.stdout
    if "code object is not signed at all" in output.lower():
        return "unsigned", "not_applicable"
    if display.returncode != 0 and "Signature=" not in output and "Authority=" not in output:
        return "unknown", "unknown"
    verify = run("codesign", "--verify", "--strict", "--verbose=2", str(path), required=False)
    if "signature=adhoc" in output.lower():
        return "adhoc_signed", "passed" if verify.returncode == 0 else "failed"
    if verify.returncode == 0:
        return "signature_verification_passed", "passed"
    return "signed_unverified", "failed"


def validate_plist(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            value = plistlib.load(stream)
    except Exception as exc:  # plistlib reports several parse exception types.
        raise BuildError(f"LaunchDaemon template is not a valid property list: {exc}") from exc
    if not isinstance(value, dict):
        raise BuildError("LaunchDaemon template must have a dictionary root")
    expected = {
        "Label": "com.ios-unsandboxed.daemon",
        "ProgramArguments": ["/usr/local/bin/ios-unsandboxedd", "--serve"],
        "UserName": "root",
        "GroupName": "wheel",
        "RunAtLoad": True,
        "KeepAlive": False,
    }
    for key, wanted in expected.items():
        if value.get(key) != wanted:
            raise BuildError(f"LaunchDaemon template has an unexpected {key!r} value")
    if "/Library/LaunchDaemons/" in str(path):
        raise BuildError("the package must keep the plist inactive under the project data directory")


def write_tarball(package_dir: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                paths = [package_dir, *sorted(package_dir.rglob("*"), key=lambda p: p.relative_to(package_dir).as_posix())]
                for path in paths:
                    relative = Path(package_dir.name) / path.relative_to(package_dir)
                    info = tarfile.TarInfo(relative.as_posix())
                    st = path.lstat()
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "wheel"
                    info.mtime = 0
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        info.size = 0
                        tar.addfile(info)
                    elif path.is_file() and not path.is_symlink():
                        info.type = tarfile.REGTYPE
                        info.mode = stat.S_IMODE(st.st_mode)
                        info.size = st.st_size
                        with path.open("rb") as stream:
                            tar.addfile(info, stream)
                    else:
                        raise BuildError(f"unexpected package entry type: {path}")


def assemble(args: argparse.Namespace) -> tuple[Path, Path]:
    if os.uname().sysname != "Darwin":
        raise BuildError("rootful iOS package assembly requires macOS file, otool, codesign, and Apple ARM64 artifacts; no host binaries are substituted")
    for tool in ("file", "otool", "codesign"):
        if shutil.which(tool) is None:
            raise BuildError(f"required packaging tool {tool!r} is unavailable; install/use the configured macOS Xcode runner")

    sources = {
        "payload/bin/ios-unsandboxed": args.cli,
        "payload/bin/ios-unsandboxedd": args.daemon,
        "payload/share/installer-helper": args.installer_helper,
        "payload/share/manager.sh": ROOT / "packaging/rootful/manager.sh",
        "payload/share/paths.env": ROOT / "packaging/rootful/paths.env",
        "payload/share/install-state.example": ROOT / "packaging/rootful/install-state.example",
        "payload/share/com.ios-unsandboxed.daemon.plist": ROOT / "packaging/rootful/com.ios-unsandboxed.daemon.plist",
    }
    for target in sorted(MACH_O_PAYLOADS):
        inspect_macho(Path(sources[target]))
    signing_records = {target: signing_status(Path(sources[target])) for target in MACH_O_ORDER}
    statuses = [signing_records[target][0] for target in MACH_O_ORDER]
    signing_status_value = statuses[0] if len(set(statuses)) == 1 else "unknown"
    verification_results = [signing_records[target][1] for target in MACH_O_ORDER]
    verification = verification_results[0] if len(set(verification_results)) == 1 else "mixed"
    plist_source = Path(sources["payload/share/com.ios-unsandboxed.daemon.plist"])
    validate_plist(plist_source)

    out_root = Path(args.output_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    package_name = f"ios-unsandboxed-{args.version}-rootful-arm64"
    package_dir = out_root / package_name
    if package_dir.exists():
        raise BuildError(f"output already exists; choose a fresh output root: {package_dir}")
    with tempfile.TemporaryDirectory(prefix="iu-package-", dir=out_root) as temp_name:
        temp_root = Path(temp_name)
        package_temp = temp_root / package_name
        (package_temp / "payload/bin").mkdir(parents=True)
        (package_temp / "payload/share").mkdir(parents=True)
        for relative, mode in PAYLOADS:
            source = Path(sources[relative])
            if not source.is_file() or source.is_symlink():
                raise BuildError(f"required package input is absent or not a regular file: {source}")
            target = package_temp / relative
            shutil.copyfile(source, target)
            os.chmod(target, mode)

        records = [
            "ios-unsandboxed-package",
            "schema_version=1",
            f"project_version={args.version}",
            "platform=ios",
            "architecture=arm64",
            "minimum_ios=12.0",
            f"signing_status={signing_status_value}",
            f"signature_verification={verification}",
        ]
        records.extend(
            f"artifact_signing={target}|{signing_records[target][0]}|{signing_records[target][1]}"
            for target in MACH_O_ORDER
        )
        hashes: list[tuple[str, str]] = []
        for relative, mode in PAYLOADS:
            digest = sha256(package_temp / relative)
            hashes.append((relative, digest))
            records.append(f"file={relative}|regular|{mode:04o}|{digest}")
        (package_temp / "package-manifest").write_text("\n".join(records) + "\n", encoding="ascii", newline="\n")
        sums = [("package-manifest", sha256(package_temp / "package-manifest")), *hashes]
        (package_temp / "SHA256SUMS").write_text(
            "".join(f"{digest}  {relative}\n" for relative, digest in sums), encoding="ascii", newline="\n")
        os.chmod(package_temp / "package-manifest", 0o644)
        os.chmod(package_temp / "SHA256SUMS", 0o644)
        shutil.copytree(package_temp, package_dir)
    archive = out_root / f"{package_name}.tar.gz"
    write_tarball(package_dir, archive)
    return package_dir, archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, default=ROOT / "target/aarch64-apple-ios/release/ios-unsandboxed")
    parser.add_argument("--daemon", type=Path, default=ROOT / "build/ios/ios-unsandboxedd")
    parser.add_argument("--installer-helper", type=Path, default=ROOT / "build/ios/installer-helper")
    parser.add_argument("--output-root", type=Path, default=ROOT / "dist")
    parser.add_argument("--version", default="0.1.0")
    args = parser.parse_args()
    if not args.version or any(ch not in "0123456789." for ch in args.version) or len(args.version.split(".")) != 3:
        parser.error("--version must be a numeric major.minor.patch value")
    try:
        package_dir, archive = assemble(args)
    except BuildError as exc:
        print(f"package-rootful: error: {exc}", file=sys.stderr)
        return 2
    print(f"Rootful package directory: {package_dir}")
    print(f"Deterministic distribution archive: {archive}")
    print("Signing status is metadata only; package creation does not establish device startup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
