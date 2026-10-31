#!/usr/bin/env python3
"""Independent canonical bytes, validation and filesystem corruption fixtures."""
from admin_fixture import *
import tempfile

with tempfile.TemporaryDirectory(prefix="iu-builder-persistence-") as tmp:
    s = Suite(Path(tmp))
    root = s.install()
    add = ("add-signer", s.keys[0], "--identity", "signer-a")
    expected = s.expected(root, *add)
    r = json.loads(expected["roots.v1"])
    assert r == {"generation":1,"keyCount":1,"keys":[{"algorithm":"Ed25519","keyId":kid(),"publicKey":KEYS[0],"signerIdentity":"signer-a","state":"active"}],"schemaVersion":1}
    assert json.loads(expected["policies.v1"]) == {"generation":1,"policies":[],"schemaVersion":1}
    assert not trustdir(root).exists()
    for flags in [("--apply",), ("--confirm",), ("--apply","--confirm","--apply")]:
        s.run(root, *add, raw_flags=flags, code=2)
    s.run(root, "unknown", code=2)
    s.run(root, *add, apply=True)
    s.assert_settled(root, expected)
    for args in [add, ("add-signer", s.keys[1], "--identity", "signer-a"), ("rotate-signer",kid(),s.keys[1],"--new-identity","signer-a")]:
        before = saved(root)
        s.run(root, *args, apply=True, code=3)
        assert saved(root) == before
    # Policy-only change: independent policy ID and unchanged root generation/bytes.
    expected = s.expected(root, "add-policy", s.policy)
    record = json.loads(expected["policies.v1"])["policies"][0]
    assert record["policyId"] == pid(record)
    assert json.loads(expected["policies.v1"])["generation"] == 2
    assert expected["roots.v1"] == saved(root)["roots.v1"]
    s.add_policy(root)
    s.assert_settled(root, expected)
    policy_id = record["policyId"]
    # Full revision, exact fields, duplicate JSON and unknown/revoked signer checks.
    for field, value in [("signerIdentity","unknown"),("allowedGitRevisions",["0123456"]),("externalParameters",{}),("verified",True)]:
        policy = json.loads(s.policy.read_bytes());policy[field] = value
        bad = s.base / "bad-policy.json";bad.write_bytes(canonical(policy))
        s.run(root,"add-policy",bad,apply=True,code=3)
    bad.write_text('{"version":1,"version":1}')
    s.run(root,"add-policy",bad,apply=True,code=3)
    # Policy tombstones have independently derived IDs; old-ID revocation is a no-op.
    expected = s.expected(root,"revoke-policy",policy_id)
    s.run(root,"revoke-policy",policy_id,apply=True)
    s.assert_settled(root,expected)
    record = json.loads(expected["policies.v1"])["policies"][0]
    assert record["state"] == "revoked" and record["policyId"] == pid(record) != policy_id
    before = saved(root)
    s.run(root,"revoke-policy",policy_id,apply=True)
    s.run(root,"revoke-policy",record["policyId"],apply=True)
    s.run(root,"add-policy",s.policy,apply=True,code=3)
    assert saved(root) == before
    # Rotation retains public key history and does not transfer policies.
    expected = s.expected(root,"rotate-signer",kid(),s.keys[1],"--new-identity","signer-b")
    s.run(root,"rotate-signer",kid(),s.keys[1],"--new-identity","signer-b",apply=True)
    s.assert_settled(root,expected)
    roots = json.loads(expected["roots.v1"])
    assert next(k for k in roots["keys"] if k["keyId"] == kid())["state"] == "revoked"
    assert next(k for k in roots["keys"] if k["keyId"] == kid(1))["state"] == "active"
    s.run(root,"revoke-signer",kid(),apply=True)
    assert saved(root) == expected
    s.run(root,"add-signer",s.keys[0],"--identity","other",apply=True,code=3)
    # Generation overflow is checked before any IO, both store types.
    for name, args in [("roots.v1",("revoke-signer",kid(1))), ("policies.v1",("add-policy",s.policy))]:
        root2=s.install("overflow");s.enroll(root2)
        if name=="policies.v1":
            args=("add-policy",s.policy)
        else: args=("revoke-signer",kid())
        path=trustdir(root2)/name;value=json.loads(path.read_bytes());value["generation"]=(1<<64)-1
        write(path,canonical(value));write(trustdir(root2)/"state.v1",marker(root2))
        before=saved(root2);s.run(root2,*args,apply=True,code=3);assert saved(root2)==before
    # Unsafe entries and incomplete marker refuse every write and preserve evidence.
    for kind in ["store-symlink","store-hardlink","mode","directory-mode","foreign","marker-mismatch","marker-missing","directory-symlink"]:
        r=s.install(kind);s.enroll(r);d=trustdir(r);target=d/"roots.v1";outside=s.base/f"outside-{kind}"
        if kind=="store-symlink": target.rename(outside);target.symlink_to(outside)
        elif kind=="store-hardlink": os.link(target,outside)
        elif kind=="mode":target.chmod(0o640)
        elif kind=="directory-mode":d.chmod(0o750)
        elif kind=="foreign":write(d/"foreign",b"evidence")
        elif kind=="marker-mismatch":write(d/"state.v1",marker(r).replace(b"root_generation=1",b"root_generation=2"))
        elif kind=="marker-missing":(d/"state.v1").unlink()
        elif kind=="directory-symlink":d.rename(outside);d.symlink_to(outside)
        before=fixture.tree_snapshot(r)
        s.run(r,"revoke-signer",kid(),apply=True,code=3)
        assert fixture.tree_snapshot(r)==before
    subprocess.run([str(REPO/"build/host/builder-admin-abi-test"), str(root/"var/lib/ios-unsandboxed")], check=True, capture_output=True)
    # Canonical key input: uppercase/private formats/invalid points are rejected.
    for text in [KEYS[0].upper()+"\n", KEYS[0], "-----BEGIN PRIVATE KEY-----\n", "ff"*32+"\n"]:
        key=s.base/"bad-key";key.write_text(text)
        r=s.install("bad-key");s.run(r,"add-signer",key,"--identity","a",apply=True,code=3)
        assert not trustdir(r).exists()
print("Builder persistence: canonical bytes/generations, five operations, validation, filesystem safety PASS")
