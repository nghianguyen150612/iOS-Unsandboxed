#!/usr/bin/env python3
"""Cross-language transaction and read-only CLI mutation fixtures."""
import json
import pathlib
import subprocess
import sys
import tempfile


transaction_codec = pathlib.Path(sys.argv[1]).resolve()
cli = pathlib.Path(sys.argv[2]).resolve()
vectors = json.loads(
    pathlib.Path(__file__).with_name("mutation-vectors.json").read_text(encoding="utf-8")
)
assert vectors["schemaVersion"] == 1
vector = vectors["firstSignerPlan"]
document = vector["transaction"].encode("ascii")
completed = subprocess.run([transaction_codec], input=document, capture_output=True)
assert completed.returncode == 0, completed.stderr
assert completed.stdout == document, "C17 transaction codec changed Rust plan bytes"

with tempfile.TemporaryDirectory(prefix="iu-builder-mutation-cli-") as root:
    directory = pathlib.Path(root)
    regular = directory / "public-key.txt"
    regular.write_text("00" * 32 + "\n", encoding="ascii")
    link = directory / "key-link.txt"
    link.symlink_to(regular)
    before = sorted(path.name for path in directory.iterdir())
    rejected = subprocess.run(
        [
            cli,
            "provenance",
            "builder-trust",
            "plan",
            "add-signer",
            str(link),
            "--identity",
            "fixture-ci",
        ],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "without following symlinks" in rejected.stderr
    assert sorted(path.name for path in directory.iterdir()) == before
    apply = subprocess.run(
        [
            cli,
            "provenance",
            "builder-trust",
            "plan",
            "add-signer",
            str(regular),
            "--apply",
            "fixture-ci",
        ],
        capture_output=True,
        text=True,
    )
    assert apply.returncode == 2
    assert sorted(path.name for path in directory.iterdir()) == before

print("builder mutation plan vector and read-only CLI fixtures passed")
