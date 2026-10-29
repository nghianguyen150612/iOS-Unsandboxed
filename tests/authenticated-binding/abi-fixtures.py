#!/usr/bin/env python3
"""Isolated C17 v2 descriptor ABI fixtures; never touch system trust or policy."""
import os
import pathlib
import runpy
import subprocess
import sys
import tempfile


macho = runpy.run_path("tests/planner/planner-fixtures.py")["macho"]
test_binary = pathlib.Path(sys.argv[1]).resolve()

with tempfile.TemporaryDirectory(prefix="iu-p013c-abi-") as temporary:
    root = pathlib.Path(temporary)
    artifact = root / "artifact"
    replacement = root / "replacement"
    artifact.write_bytes(macho())
    replacement.write_bytes(macho())
    artifact.chmod(0o700)
    replacement.chmod(0o700)
    subprocess.run([str(test_binary), str(artifact), str(replacement)], check=True)
