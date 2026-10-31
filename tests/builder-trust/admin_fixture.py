"""Shared isolated installer fixtures; no production directory is selected."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
HELPER = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("installer_fixture", REPO / "tests/packaging/installer-integration.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
KEYS = [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
]
REV = "0123456789abcdef0123456789abcdef01234567"
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def kid(index=0):
    return hashlib.sha256(bytes.fromhex(KEYS[index])).hexdigest()[:32]
def pid(record):
    value = dict(record)
    value.pop("policyId", None)
    return hashlib.sha256(canonical(value)).hexdigest()
def trustdir(root):
    return root / "var/lib/ios-unsandboxed/builder-trust"
def saved(root):
    directory = trustdir(root)
    return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file() and not p.is_symlink()} if directory.exists() else {}
def write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
def marker(root):
    d = trustdir(root)
    r, p = (d / "roots.v1").read_bytes(), (d / "policies.v1").read_bytes()
    return ("ios-unsandboxed-builder-state\nschema_version=1\n"
            f"root_generation={json.loads(r)['generation']}\nroot_sha256={hashlib.sha256(r).hexdigest()}\n"
            f"policy_generation={json.loads(p)['generation']}\npolicy_sha256={hashlib.sha256(p).hexdigest()}\n").encode()
class Suite:
    def __init__(self, base):
        self.base = base
        self.installer = fixture.Suite(base)
        self.keys = []
        for index, key in enumerate(KEYS):
            path = base / f"public-{index}.hex"
            path.write_text(key + "\n")
            self.keys.append(str(path))
        self.policy = base / "policy.json"
        self.policy.write_bytes(canonical({"version":1,"signerIdentity":"signer-a","builderId":"builder-a","buildType":"https://example.invalid/build-v1","externalParameters":{"revision":REV,"repository":"repo-a"},"sourceUri":"git+https://example.invalid/repo","allowedGitRevisions":[REV]}))
        self.counter = 0
    def install(self, label="fixture"):
        self.counter += 1
        root = self.base / f"{label}-{self.counter}"
        self.installer.make_root(root)
        self.installer.ok(self.installer.invoke("install", self.installer.package_root, apply=True, root=root), "install")
        assert not trustdir(root).exists(), "install must not enroll"
        return root
    def run(self, root, *args, apply=False, fault=None, code=0, raw_flags=()):
        cmd = [str(HELPER), "builder-trust", *map(str,args), "--test-root", str(root), *raw_flags]
        if apply:
            cmd += ["--apply", "--confirm"]
        if fault:
            cmd += ["--test-interrupt-at", fault]
        result = subprocess.run(cmd, text=True, capture_output=True)
        if code is not None:
            assert result.returncode == code, (cmd, result.returncode, result.stdout, result.stderr)
        return result
    def enroll(self, root):
        return self.run(root, "add-signer", self.keys[0], "--identity", "signer-a", apply=True)
    def add_policy(self, root):
        return self.run(root, "add-policy", self.policy, apply=True)
    def expected(self, root, *args):
        before = saved(root)
        result = self.run(root, *args)
        assert saved(root) == before
        expected = {}
        for name, label in [("roots.v1", "Proposed roots.v1 (canonical JSON):"), ("policies.v1", "Proposed policies.v1 (canonical JSON):")]:
            expected[name] = result.stdout.split(label + "\n",1)[1].splitlines()[0].encode()
            assert canonical(json.loads(expected[name])) == expected[name]
        r, p = expected["roots.v1"], expected["policies.v1"]
        expected["state.v1"] = ("ios-unsandboxed-builder-state\nschema_version=1\n"
            f"root_generation={json.loads(r)['generation']}\nroot_sha256={hashlib.sha256(r).hexdigest()}\n"
            f"policy_generation={json.loads(p)['generation']}\npolicy_sha256={hashlib.sha256(p).hexdigest()}\n").encode()
        return expected
    def assert_settled(self, root, expected):
        assert saved(root) == expected, (saved(root), expected)
        assert (trustdir(root) / "state.v1").read_bytes() == marker(root)
        for path in trustdir(root).iterdir():
            st = path.stat()
            assert st.st_mode & 0o7777 == 0o600 and st.st_nlink == 1 and st.st_uid == os.geteuid()
        assert trustdir(root).stat().st_mode & 0o7777 == 0o700
        out = self.run(root, "status").stdout
        assert "Transaction state: NO_TRANSACTION" in out
        for line in ["Independent trust establishment: UNVERIFIED", "Rollback protection: UNVERIFIED", "Build origin: BUILD_ORIGIN_UNVERIFIED", "Operational authorization: FALSE", "Execution activation: DISABLED"]:
            assert line in out
