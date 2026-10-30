#!/usr/bin/env python3
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1]).resolve()
fixture = pathlib.Path(__file__).with_name("valid-transaction.v1").read_bytes()
valid = subprocess.run([binary], input=fixture, capture_output=True, check=True)
assert valid.stdout == fixture
for invalid in (
    fixture.replace(b"schema_version=1", b"schema_version=2"),
    fixture.replace(b"operation=combined", b"operation=unknown"),
    fixture.replace(b"new_root_generation=1", b"new_root_generation=01"),
    fixture.replace(b"new_root_generation=1", b"new_root_generation=18446744073709551616"),
    fixture.replace(b"roots.stage.v1", b"../roots"),
    fixture.replace(b"phase=prepared", b"phase=committed"),
    fixture.replace(b"a" * 64, b"A" * 64),
    fixture.replace(b"schema_version=1\n", b"schema_version=1\nschema_version=1\n"),
):
    assert subprocess.run([binary], input=invalid, capture_output=True).returncode != 0
print("builder transaction C17 canonical fixtures passed")
