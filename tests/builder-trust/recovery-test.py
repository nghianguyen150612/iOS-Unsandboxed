#!/usr/bin/env python3
"""Process termination, forward recovery, exact bytes, and corrupt evidence."""
from admin_fixture import *
import tempfile

PHASES = ["builder-before-stage","builder-after-first-stage-fsync","builder-after-second-stage-fsync","builder-before-journal","builder-after-journal-fsync","builder-before-first-rename","builder-after-first-rename","builder-after-first-dir-fsync","builder-before-second-rename","builder-after-second-rename","builder-after-second-dir-fsync","builder-before-marker","builder-after-marker-fsync","builder-after-marker-rename","builder-before-cleanup","builder-during-cleanup","builder-after-cleanup"]
with tempfile.TemporaryDirectory(prefix="iu-builder-recovery-") as tmp:
    s=Suite(Path(tmp)); cases=0
    for operation in ["initial", "roots", "policies", "policy-revoke", "rotate"]:
        for phase in PHASES:
            # Checkpoints refer to the fixed roots-first, policies-second store order.
            if operation in ["roots","rotate"] and ("second" in phase):continue
            if operation in ["policies","policy-revoke"] and ("first" in phase):continue
            r=s.install(operation)
            if operation!="initial":s.enroll(r)
            if operation=="initial":args=("add-signer",s.keys[0],"--identity","signer-a")
            elif operation=="roots":args=("revoke-signer",kid())
            elif operation=="rotate":args=("rotate-signer",kid(),s.keys[1],"--new-identity","signer-b")
            elif operation=="policies":args=("add-policy",s.policy)
            else:
                s.add_policy(r);args=("revoke-policy",json.loads(saved(r)["policies.v1"])["policies"][0]["policyId"])
            old=saved(r);expected=s.expected(r,*args)
            s.run(r,*args,apply=True,fault=phase,code=86)
            before=saved(r)
            s.run(r,"recover")  # always read-only
            assert saved(r)==before
            if "transaction.v1" in before:
                # Every pending state blocks additional mutations and package work.
                s.run(r,"add-signer",s.keys[2],"--identity","other",apply=True,code=3)
            s.run(r,"recover",apply=True)
            if phase in ["builder-before-stage","builder-after-first-stage-fsync","builder-after-second-stage-fsync","builder-before-journal"]:
                # No durable journal: stages are cleaned, never promoted.
                assert saved(r)==old,(operation,phase,saved(r),old)
                s.run(r,*args,apply=True)
            s.assert_settled(r,expected)
            final=saved(r);s.run(r,"recover",apply=True);assert saved(r)==final
            if operation=="roots":assert json.loads(final["roots.v1"])["keys"][0]["state"]=="revoked"
            if operation=="policy-revoke":assert json.loads(final["policies.v1"])["policies"][0]["state"]=="revoked"
            cases+=1
    # Recovery itself can be interrupted and resumed by another process.
    for phase in PHASES[5:]:
        r=s.install("recovery-interruption")
        args=("add-signer",s.keys[0],"--identity","signer-a")
        expected=s.expected(r,*args)
        s.run(r,*args,apply=True,fault="builder-after-journal-fsync",code=86)
        s.run(r,"recover",apply=True,fault=phase,code=86)
        s.run(r,"recover",apply=True)
        s.assert_settled(r,expected)
        cases+=1
    # Independent error returns, not just process interruption.
    for fault in ["builder-fail-write","builder-disk-full","builder-fail-fsync","builder-fail-dir-fsync","builder-fail-rename","builder-fail-post-rename-fsync","builder-fail-journal-fsync","builder-fail-marker-fsync","builder-short-write"]:
        r=s.install(fault);args=("add-signer",s.keys[0],"--identity","signer-a");expected=s.expected(r,*args)
        result=s.run(r,*args,apply=True,fault=fault,code=0 if fault=="builder-short-write" else 3)
        if fault in ["builder-fail-rename","builder-fail-post-rename-fsync","builder-fail-journal-fsync","builder-fail-marker-fsync"]:
            assert "Persistence: RECOVERY_REQUIRED" in result.stdout
            assert (trustdir(r)/"transaction.v1").exists()
            s.run(r,"recover",apply=True);s.assert_settled(r,expected)
        elif fault=="builder-short-write":s.assert_settled(r,expected)
        else:
            before=fixture.tree_snapshot(r)
            result=s.run(r,"recover",apply=True,code=None)
            if fault in ["builder-fail-write","builder-disk-full"]:
                assert result.returncode==3 and fixture.tree_snapshot(r)==before
            else:
                assert result.returncode==0  # valid orphan stage can be safely discarded
    # A recovery journal flush failure must leave every live byte unchanged.
    r=s.install("recovery-journal-flush");s.enroll(r)
    s.run(r,"revoke-signer",kid(),apply=True,fault="builder-after-journal-fsync",code=86)
    before=saved(r)
    s.run(r,"recover",apply=True,fault="builder-fail-recovery-journal-fsync",code=3)
    assert saved(r)==before
    s.run(r,"recover",apply=True)
    assert json.loads(saved(r)["roots.v1"])["keys"][0]["state"]=="revoked"
    # Stage/journal/marker corruption, changed live store and unrecognized evidence.
    for fault in ["stage-corrupt","stage-missing","journal-truncated","journal-digest","journal-generation","journal-deleted","marker-mismatch","stage-symlink","journal-symlink","journal-hardlink","foreign","unsafe-mode"]:
        r=s.install(fault);s.enroll(r)
        s.run(r,"revoke-signer",kid(),apply=True,fault="builder-after-journal-fsync",code=86)
        d=trustdir(r);stage=d/"roots.stage.v1";journal=d/"transaction.v1"
        if fault=="stage-corrupt":write(stage,stage.read_bytes()+b" ")
        elif fault=="stage-missing":stage.unlink()
        elif fault=="journal-truncated":write(journal,journal.read_bytes()[:75])
        elif fault=="journal-digest":write(journal,journal.read_bytes().replace(hashlib.sha256(stage.read_bytes()).hexdigest().encode(),b"0"*64))
        elif fault=="journal-generation":write(journal,journal.read_bytes().replace(b"old_root_generation=1",b"old_root_generation=2").replace(b"new_root_generation=2",b"new_root_generation=3"))
        elif fault=="journal-deleted":
            # A journal deleted after a live rename must never cause old-store restoration.
            os.replace(stage,d/"roots.v1");journal.unlink()
        elif fault=="marker-mismatch":write(d/"state.v1",marker(r).replace(b"root_generation=1",b"root_generation=99"))
        elif fault in ["stage-symlink","journal-symlink"]:
            p=stage if fault=="stage-symlink" else journal;out=s.base/f"outside-{fault}";p.rename(out);p.symlink_to(out)
        elif fault=="journal-hardlink":os.link(journal,s.base/"journal-link")
        elif fault=="foreign":write(d/"foreign",b"preserve")
        elif fault=="unsafe-mode":journal.chmod(0o666)
        before=fixture.tree_snapshot(r)
        s.run(r,"recover",apply=True,code=3)
        assert fixture.tree_snapshot(r)==before,(fault,"evidence changed")
    # Missing stage after successful replacement is expected, including policy-only.
    for args, phase in [(("revoke-signer",kid()),"builder-after-first-rename"),(("add-policy",s.policy),"builder-after-second-rename")]:
        r=s.install("stage-consumed");s.enroll(r);expected=s.expected(r,*args)
        s.run(r,*args,apply=True,fault=phase,code=86);s.run(r,"recover",apply=True);s.assert_settled(r,expected)
    # A valid two-store revocation from an existing pair; policies-first
    # simulates the classifier's SECOND_STORE_REPLACED observation too.
    for replaced in ["none", "policy", "roots", "both"]:
        r=s.install("combined");s.enroll(r);s.add_policy(r);d=trustdir(r);old=saved(r)
        roots=json.loads(old["roots.v1"]);policies=json.loads(old["policies.v1"])
        roots["generation"]+=1;roots["keys"][0]["state"]="revoked"
        policies["generation"]+=1;p=policies["policies"][0];p["state"]="revoked";p["policyId"]=pid(p)
        rb,pb=canonical(roots),canonical(policies)
        write(d/"roots.stage.v1",rb);write(d/"policies.stage.v1",pb)
        def pair_lines(kind, oldbytes, newbytes):
            return (f"old_{kind}_generation={json.loads(oldbytes)['generation']}\nnew_{kind}_generation={json.loads(newbytes)['generation']}\n"
                    f"old_{kind}_sha256={hashlib.sha256(oldbytes).hexdigest()}\nnew_{kind}_sha256={hashlib.sha256(newbytes).hexdigest()}\n")
        journal=("ios-unsandboxed-builder-transaction\nschema_version=1\noperation=combined\n"+pair_lines("root",old["roots.v1"],rb)+pair_lines("policy",old["policies.v1"],pb)+"stage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n").encode()
        write(d/"transaction.v1",journal)
        if replaced in ["roots","both"]:os.replace(d/"roots.stage.v1",d/"roots.v1")
        if replaced in ["policy","both"]:os.replace(d/"policies.stage.v1",d/"policies.v1")
        states={"none":"PREPARED_OLD_PAIR","policy":"SECOND_STORE_REPLACED","roots":"FIRST_STORE_REPLACED","both":"BOTH_STORES_REPLACED"}
        assert "Transaction state: "+states[replaced] in s.run(r,"recover").stdout
        s.run(r,"recover",apply=True)
        expected={"roots.v1":rb,"policies.v1":pb,"state.v1":marker(r)}
        s.assert_settled(r,expected)
        s.run(r,"recover",apply=True);assert saved(r)==expected
    # A canonical, internally hashed journal must not reactivate a live tombstone.
    r=s.install("reactivation");s.enroll(r);s.run(r,"revoke-signer",kid(),apply=True)
    d=trustdir(r);old=saved(r);roots=json.loads(old["roots.v1"]);roots["generation"]+=1;roots["keys"][0]["state"]="active";rb=canonical(roots)
    pb=old["policies.v1"]
    # roots-only transaction with otherwise valid generation/digest evidence.
    journal=("ios-unsandboxed-builder-transaction\nschema_version=1\noperation=roots\n"+pair_lines("root",old["roots.v1"],rb)+pair_lines("policy",pb,pb)+"stage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n").encode()
    write(d/"roots.stage.v1",rb);write(d/"transaction.v1",journal)
    before=saved(r);s.run(r,"recover",apply=True,code=3);assert saved(r)==before
    # Store changed after journal preparation: fail closed without any replacement.
    r=s.install("stale-live");s.enroll(r);s.run(r,"revoke-signer",kid(),apply=True,fault="builder-after-journal-fsync",code=86)
    d=trustdir(r);roots=json.loads((d/"roots.v1").read_bytes());roots["generation"]+=7;write(d/"roots.v1",canonical(roots))
    before=saved(r);s.run(r,"recover",apply=True,code=3);assert saved(r)==before
    # All five operations and every meaningful crash checkpoint exercised above.
print(f"Builder recovery: {cases} process interruptions, IO faults, corrupt/unsafe evidence, idempotence and tombstones PASS")
