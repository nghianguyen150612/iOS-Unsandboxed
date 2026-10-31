#!/usr/bin/env python3
"""Read-only production builder-trust CLI smoke and no-mutation fixture."""

import os
import pathlib
import stat
import subprocess
import sys


def tree_state(path: pathlib.Path):
    try:
        root = path.lstat()
    except FileNotFoundError:
        return None

    def metadata(item: pathlib.Path):
        value = item.lstat()
        return (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
        )

    entries = []
    if stat.S_ISDIR(root.st_mode):
        for item in sorted(path.iterdir(), key=lambda child: child.name):
            entries.append((item.name, metadata(item)))
            if item.is_file() and not item.is_symlink():
                entries.append((item.name + ":sha256", __import__("hashlib").sha256(item.read_bytes()).hexdigest()))
    return metadata(path), tuple(entries)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: cli-test.py <ios-unsandboxed-binary>")
    binary = pathlib.Path(sys.argv[1]).resolve()
    root = pathlib.Path("/private/var/lib/ios-unsandboxed/builder-trust" if sys.platform == "darwin" else "/var/lib/ios-unsandboxed/builder-trust")
    before = tree_state(root)
    commands = [
        (["provenance", "builder-trust", "status"], "Independent trust establishment: UNVERIFIED"),
        (["provenance", "builder-trust", "list"], "Rollback protection: UNVERIFIED"),
        (["provenance", "builder-trust", "inspect", "unknown-fixture-signer"], "Independent trust establishment: UNVERIFIED"),
    ]
    for arguments, expected in commands:
        result = subprocess.run([os.fspath(binary), *arguments], check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(f"{arguments} exited {result.returncode}: {result.stderr}")
        if expected not in result.stdout:
            raise AssertionError(f"{arguments} omitted {expected!r}: {result.stdout}")
        if "publicKey" in result.stdout or "private key" in result.stdout.lower():
            raise AssertionError("diagnostics exposed key material")
    after = tree_state(root)
    if before != after:
        raise AssertionError("read-only diagnostics modified the production trust path")
    print("builder trust CLI diagnostics are read-only and report trust limitations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
