#!/usr/bin/env python3
import pathlib
import json
import subprocess
import sys

binary = pathlib.Path(sys.argv[1]).resolve()
corpus_path = pathlib.Path(__file__).with_name("transaction-vectors.json")
corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
assert corpus["schemaVersion"] == 1
for case in corpus["cases"]:
    document = corpus["bases"][case["base"]]
    for old, new in case["mutations"]:
        assert document.count(old) == 1, (case["name"], old)
        document = document.replace(old, new, 1)
    completed = subprocess.run([binary], input=document.encode("ascii"), capture_output=True)
    if case["valid"]:
        assert completed.returncode == 0, (case["name"], completed.stderr)
        assert completed.stdout.decode("ascii") == document, case["name"]
    else:
        assert completed.returncode != 0, case["name"]
oversized = corpus["bases"]["first_enrollment"].encode("ascii") + b" " * 1024
assert len(oversized) > 1024
assert subprocess.run([binary], input=oversized, capture_output=True).returncode != 0
print(f"builder transaction C17 canonical/adversarial vectors passed: {len(corpus['cases'])}")
