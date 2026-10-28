#!/usr/bin/env python3
import os
import pathlib
import runpy
import subprocess
import sys
import tempfile
macho = runpy.run_path('tests/planner/planner-fixtures.py')['macho']
with tempfile.TemporaryDirectory(prefix='iu-p012-') as tmp:
    root = pathlib.Path(tmp)
    for name, data in {'parseable': macho(), 'adhoc': macho(adhoc=True), 'unsigned': macho(signature='none'), 'malformed': macho(signature='malformed'), 'wrong-architecture': macho(cpu=0x01000007)}.items():
        p = root / name
        p.write_bytes(data)
        p.chmod(0o700)
    os.mkfifo(root / 'fifo')
    (root / 'opt/ios-unsandboxed-scopes/enrolled').mkdir(parents=True)
    (root / 'data').mkdir(mode=0o700)
    for binary in sys.argv[1:]:
        subprocess.run([str(pathlib.Path(binary).resolve()), tmp], check=True)
