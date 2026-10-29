#!/usr/bin/env python3
import fcntl
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path
root_repo = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fixture', root_repo/'tests/packaging/installer-integration.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
with tempfile.TemporaryDirectory(prefix='iu-trust-mutation-') as td:
    base=Path(td); suite=f.Suite(base)
    suite.ok(suite.invoke('install',suite.package_root,apply=True),'install')
    manager=suite.bundle/'manager.sh'; data=suite.root/'var/lib/ios-unsandboxed'; store=data/'trusted-publishers/store.v1'
    def run(*args, ok=True):
        p=subprocess.run([str(manager),'trust',*args,'--test-root',str(suite.root)],capture_output=True,text=True)
        assert (p.returncode==0)==ok,(args,p.returncode,p.stdout,p.stderr)
        return p
    def key(i):
        p=base/f'key{i}'; raw=hashlib.sha256(str(i).encode()).digest();p.write_text(raw.hex()+'\n');return str(p),hashlib.sha256(raw).hexdigest()[:32]
    a,aid=key(1); b,bid=key(2); c,cid=key(3)
    run('status'); run('add-key',a,'--publisher','fixture');assert not store.parent.exists()
    run('add-key',a,'--publisher','fixture','--apply');assert not store.parent.exists()
    flags=['--apply','--confirm']
    run('add-key',a,'--publisher','fixture',*flags);assert b'generation=1\n' in store.read_bytes()
    run('add-key',a,'--publisher','fixture',*flags,ok=False)
    run('add-key',b,'--publisher','bad!',*flags,ok=False)
    run('add-key',b,'--publisher','fixture',*flags);assert b'generation=2\n' in store.read_bytes()
    run('rotate-key',aid,c,'--publisher','other',*flags,ok=False)
    run('rotate-key',aid,b,'--publisher','fixture',*flags,ok=False)
    run('rotate-key',aid,c,'--publisher','fixture',*flags);assert b'generation=3\n' in store.read_bytes()
    assert any(aid in line and line.endswith('revoked') for line in store.read_text().splitlines())
    run('revoke-key',bid,*flags);before=store.read_bytes();run('revoke-key',bid,*flags);assert before==store.read_bytes()
    run('revoke-key','0'*32,*flags,ok=False)
    run('add-key',b,'--publisher','fixture','--force',ok=False)
    lock=suite.root/'var/lib/.ios-unsandboxed-installer.lock'
    with lock.open('r+b') as fd:
        fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        d,_=key(4);run('add-key',d,'--publisher','fixture',*flags,ok=False)
    store.chmod(0o644);run('revoke-key',cid,*flags,ok=False);store.chmod(0o600)
    saved=store.read_bytes();store.write_text('bad\n');run('revoke-key',cid,*flags,ok=False);store.write_bytes(saved)
    d,_=key(4)
    run('add-key',d,'--publisher','fixture',*flags,'--test-interrupt-at','trust-before-rename',ok=False)
    assert saved==store.read_bytes() and list(store.parent.glob('.trust-tmp-*'))
    run('add-key',d,'--publisher','fixture',*flags)
    assert 'Operational authorization: false' in run('list').stdout
    # Persisted bytes are parsed and reserialized by the production Rust parser.
    parity=base/'parity';parity.mkdir();(parity/'mutation.valid').write_bytes(store.read_bytes())
    import os
    subprocess.run(['cargo','test','--locked','--workspace','provenance::tests::trust_format_parity_fixtures'],env=dict(os.environ,IU_TRUST_FORMAT_FIXTURES=str(parity)),check=True)
    # Nonblocking shared locking allows successful commits and explicit contention failures.
    paths=[key(i)[0] for i in range(10,14)]
    procs=[subprocess.Popen([str(manager),'trust','add-key',p,'--publisher','fixture',*flags,'--test-root',str(suite.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for p in paths]
    success=0
    for p in procs:
        p.communicate();assert p.returncode in (0,3);success+=p.returncode==0
    assert success>0
    assert f'key_count={4+success}\n' in store.read_text()
    assert f'generation={5+success}\n' in store.read_text()
    run('status')
    # Symlinked/hard-linked stores are never replaced.
    store.rename(store.with_name('saved'))
    store.symlink_to('saved');run('revoke-key',cid,*flags,ok=False);store.unlink()
    os.link(store.with_name('saved'),store);run('revoke-key',cid,*flags,ok=False);store.unlink()
    store.with_name('saved').rename(store)
    parent=store.parent; moved=parent.with_name('held-trust')
    parent.rename(moved);parent.symlink_to(moved);run('status',ok=False);parent.unlink();moved.rename(parent)
    bad=base/'invalid-key';bad.write_text('A'*64+'\n');run('add-key',str(bad),'--publisher','fixture',*flags,ok=False)
    items=[]
    for i in range(64):
        raw=hashlib.sha256(f'full-{i}'.encode()).digest();items.append((hashlib.sha256(raw).hexdigest()[:32],raw.hex()))
    lines=['ios-unsandboxed-trust-store','schema_version=1','generation=8','key_count=64']
    lines += [f'key_{i}={kid}|ed25519|{pub}|publisher|fixture|active' for i,(kid,pub) in enumerate(sorted(items))]
    store.write_text('\n'.join(lines)+'\n')
    run('status');run('add-key',a,'--publisher','fixture',*flags,ok=False)
    store.write_bytes(saved.replace(b'generation=4',b'generation=18446744073709551615'))
    e,_=key(5);run('add-key',e,'--publisher','fixture',*flags,ok=False)
print('trust manager mutations, planning, lock contention and interrupted rename: PASS')
