#!/usr/bin/env python3
"""Shared P007 lock, conflict gates and package history preservation."""
from admin_fixture import *
import tempfile

with tempfile.TemporaryDirectory(prefix="iu-builder-lifecycle-") as tmp:
    s=Suite(Path(tmp));r=s.install();s.enroll(r);s.add_policy(r)
    policy_id=json.loads(saved(r)["policies.v1"])["policies"][0]["policyId"]
    s.run(r,"revoke-policy",policy_id,apply=True)
    s.run(r,"revoke-signer",kid(),apply=True)
    history=saved(r)
    installer=s.installer
    for action, package in [("upgrade",installer.package_new),("rollback",None)]:
        result=installer.invoke(action,package,apply=True,root=r)
        installer.ok(result,action)
        assert saved(r)==history
    result=installer.invoke("uninstall",apply=True,root=r)
    installer.ok(result,"uninstall")
    assert "Builder-trust signer/policy history" in result.stdout
    assert saved(r)==history
    s.run(r,"status")  # history remains inspectable after uninstall
    r=s.install("locking");s.enroll(r)
    # Advisory fcntl lock is common to package, builder and publisher operations.
    lock=r/"var/lib/.ios-unsandboxed-installer.lock"
    with lock.open("r+b") as f:
        fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        s.run(r,"add-signer",s.keys[1],"--identity","b",apply=True,code=4)
        assert installer.invoke("upgrade",installer.package_new,apply=True,root=r).returncode==4
        cmd=[str(HELPER),"trust","add-key",s.keys[1],"--publisher","p","--apply","--confirm","--test-root",str(r)]
        assert subprocess.run(cmd,capture_output=True).returncode==4
    # Concurrent requests serialize; at most one can enroll the same key/identity.
    cmd=[str(HELPER),"builder-trust","add-signer",s.keys[1],"--identity","b","--apply","--confirm","--test-root",str(r)]
    p1=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p2=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p1.communicate();p2.communicate()
    assert sorted([p1.returncode,p2.returncode]) in [[0,3],[0,4]]
    assert sum(k["keyId"]==kid(1) for k in json.loads(saved(r)["roots.v1"])["keys"])==1
    # Pending builder transactions block package and publisher operations including recovery.
    s.run(r,"revoke-signer",kid(1),apply=True,fault="builder-after-journal-fsync",code=86)
    before=saved(r)
    for action,package in [("upgrade",installer.package_new),("rollback",None),("uninstall",None),("recover",None)]:
        assert installer.invoke(action,package,apply=True,root=r).returncode==3
        assert saved(r)==before
    for action in ["add-key","recover"]:
        cmd=[str(HELPER),"trust",action]
        if action=="add-key":cmd += [s.keys[2],"--publisher","p"]
        cmd += ["--apply","--confirm","--test-root",str(r)]
        assert subprocess.run(cmd,capture_output=True).returncode==3
        assert saved(r)==before
    s.run(r,"recover",apply=True)
    # Publisher pending journals block both builder writes and builder recovery.
    cmd=[str(HELPER),"trust","add-key",s.keys[2],"--publisher","p","--apply","--confirm","--test-root",str(r),"--test-interrupt-at","trust-after-journal-fsync"]
    assert subprocess.run(cmd,capture_output=True).returncode==86
    s.run(r,"add-signer",s.keys[2],"--identity","c",apply=True,code=3)
    s.run(r,"recover",apply=True,code=3)
    # Package pending transaction blocks builder/publisher writes and recovery.
    r=s.install("package-pending")
    assert installer.invoke("upgrade",installer.package_new,apply=True,root=r,interrupt="prepared").returncode==86
    s.run(r,"add-signer",s.keys[0],"--identity","a",apply=True,code=3)
    s.run(r,"recover",apply=True,code=3)
    # Read-only help/status work without persistence flags; production rejects host hooks.
    assert subprocess.run([str(HELPER),"builder-trust","help"],capture_output=True).returncode==0
print("Builder lifecycle: shared package/publisher lock, conflict gates, upgrade/rollback/uninstall preservation PASS")
