#!/usr/bin/env python3
"""Local CLI preview requires neither a daemon nor a privileged write."""
import pathlib
import runpy
import subprocess
import tempfile
macho = runpy.run_path('tests/planner/planner-fixtures.py')['macho']
with tempfile.TemporaryDirectory(prefix='iu-p012-cli-') as temporary:
    path = pathlib.Path(temporary) / 'fixture'
    path.write_bytes(macho())
    path.chmod(0o700)
    result = subprocess.run(['target/debug/ios-unsandboxed', 'plan', str(path)], text=True, capture_output=True, check=True)
    for expected in ('Architecture: ARM64', 'SHA-256:', 'Identity: RECORDED', 'Scope match:', 'Artifact provenance: EVIDENCE ABSENT', 'Launch binding: PREVIEW ONLY', 'Operational authorization: FALSE', 'Execution activation: DISABLED'):
        assert expected in result.stdout, (expected, result.stdout)
    assert set(p.name for p in pathlib.Path(temporary).iterdir()) == {'fixture'}
print('local CLI preview: PASS')
