#!/usr/bin/env python3
"""Exercise both production Rust parser and C17 codec with the same bytes."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = sys.argv[1]
subprocess.run([binary, '--self-test'], check=True)

def key(i):
    public = hashlib.sha256(f'fixture-public-key-{i}'.encode()).hexdigest()
    kid = hashlib.sha256(bytes.fromhex(public)).hexdigest()[:32]
    return kid, public

def store(records, generation='1'):
    lines = ['ios-unsandboxed-trust-store', 'schema_version=1', f'generation={generation}', f'key_count={len(records)}']
    for i, (kid, public, publisher, state) in enumerate(records):
        lines.append(f'key_{i}={kid}|ed25519|{public}|publisher|{publisher}|{state}')
    return ('\n'.join(lines) + '\n').encode()

records = sorted((kid, public, f'publisher-{i}', 'revoked' if i % 2 else 'active') for i, (kid, public) in enumerate(key(i) for i in range(64)))
valid = {'empty': store([]), 'one': store(records[:1]), 'many': store(records[:4]), 'all_active': store([r for r in records if r[3] == 'active'][:4]), 'max': store(records, '18446744073709551615'), 'revoked': store([next(r for r in records if r[3] == 'revoked')])}
base = valid['many']
invalid = {
 'too_many': store(records).replace(b'key_count=64', b'key_count=65'),
 'duplicate': store([records[0], records[0]]),
 'bad_id': base.replace(records[0][0].encode(), b'0' * 32, 1),
 'bad_key': base.replace(records[0][1].encode(), b'g' * 64, 1),
 'truncated_key': base.replace(records[0][1].encode(), b'a' * 62, 1),
 'algorithm': base.replace(b'|ed25519|', b'|other|', 1),
 'scope': base.replace(b'|publisher|', b'|other|', 1),
 'publisher': base.replace(records[0][2].encode(), b'bad!name', 1),
 'schema': base.replace(b'schema_version=1', b'schema_version=2'),
 'zero': base.replace(b'generation=1', b'generation=0'),
 'overflow': base.replace(b'generation=1', b'generation=18446744073709551616'),
 'leading_zero': base.replace(b'generation=1', b'generation=01'),
 'out_of_order': store([records[1], records[0]]),
 'truncated': base[:-2],
 'nul': base.replace(b'publisher-', b'publisher\x00', 1),
 'cr': base.replace(b'\n', b'\r\n', 1),
 'oversize': base + b'x' * 16385,
 'extra': base + b'extra=value\n',
}
with tempfile.TemporaryDirectory(prefix='iu-trust-format-') as tmp:
    root = Path(tmp)
    for label, data in valid.items(): (root / f'{label}.valid').write_bytes(data)
    for label, data in invalid.items(): (root / f'{label}.invalid').write_bytes(data)
    for label, data in valid.items():
        result = subprocess.run([binary], input=data, capture_output=True)
        assert result.returncode == 0 and result.stdout == data, (label, result.returncode, result.stderr)
        (root / f'{label}.valid').write_bytes(result.stdout)
    for label, data in invalid.items():
        result = subprocess.run([binary], input=data, capture_output=True)
        assert result.returncode == 1, (label, result.returncode, result.stderr)
    env = dict(os.environ, IU_TRUST_FORMAT_FIXTURES=tmp)
    subprocess.run(['cargo', 'test', '--locked', '--workspace', 'provenance::tests::trust_format_parity_fixtures'], env=env, check=True)
    for label, expected in valid.items():
        rust = (root / f'{label}.rust').read_bytes()
        result = subprocess.run([binary], input=rust, capture_output=True)
        assert rust == expected and result.returncode == 0 and result.stdout == rust, label
print('C17/Rust trust format round trips and malformed fixtures: PASS')
