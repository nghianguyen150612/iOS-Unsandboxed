#!/usr/bin/env python3
"""Crash/recovery fixtures run only under isolated --test-root trees."""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
HELPER = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("installer_fixture", ROOT / "tests/packaging/installer-integration.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

with tempfile.TemporaryDirectory(prefix="iu-trust-recovery-") as tmp:
    base = Path(tmp)
    suite = fixture.Suite(base)

    def install(name: str) -> Path:
        root = base / name
        suite.make_root(root)
        suite.ok(suite.invoke("install", suite.package_root, apply=True, root=root), f"install {name}")
        return root

    def trust(root: Path, *args: str, apply: bool = False, confirm: bool = False,
              interrupt: str | None = None, ok: bool = True) -> subprocess.CompletedProcess[str]:
        manager = root / "var/lib/ios-unsandboxed/manager.sh"
        command = [str(manager), "trust", *args, "--test-root", str(root)]
        if apply:
            command.append("--apply")
        if confirm:
            command.append("--confirm")
        if interrupt:
            command += ["--test-interrupt-at", interrupt]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert (result.returncode == 0) == ok, (command, result.returncode, result.stdout, result.stderr)
        return result

    def key(index: int) -> tuple[str, str]:
        secret = hashlib.sha256(f"trust-recovery-{index}".encode()).digest()
        path = base / f"key-{index}.hex"
        path.write_text(secret.hex() + "\n", encoding="ascii")
        return str(path), hashlib.sha256(secret).hexdigest()[:32]

    def store_path(root: Path) -> Path:
        return root / "var/lib/ios-unsandboxed/trusted-publishers/store.v1"

    def crash_add(name: str, phase: str) -> tuple[Path, str, str]:
        root = install(name)
        pub, kid = key(abs(hash((name, phase))) % 100000)
        result = trust(root, "add-key", pub, "--publisher", "fixture", apply=True, confirm=True,
                       interrupt=phase, ok=False)
        assert result.returncode == 86, (phase, result.returncode, result.stdout, result.stderr)
        return root, pub, kid

    # Interruption before any staged bytes leaves no unresolved transaction.
    root, pub, _ = crash_add("before-stage-write", "trust-before-stage-write")
    trust(root, "recover", apply=True, confirm=True)
    trust(root, "add-key", pub, "--publisher", "fixture", apply=True, confirm=True)

    # A durable but unjournaled temporary stage is ambiguous and must be preserved.
    root, _, _ = crash_add("after-stage-fsync", "trust-after-stage-fsync")
    trust(root, "recover", ok=False)
    trust(root, "recover", apply=True, confirm=True, ok=False)
    assert (store_path(root).parent / ".stage.tmp").exists()

    # Pre-rename recovery completes the intended first enrollment from verified bytes.
    for index, phase in enumerate(("trust-after-journal-fsync", "trust-before-rename")):
        root, _, _ = crash_add(f"pre-rename-{index}", phase)
        trust(root, "recover", apply=True, confirm=True)
        saved = store_path(root).read_bytes()
        assert b"generation=1\n" in saved and b"key_count=1\n" in saved
        trust(root, "recover", apply=True, confirm=True)  # repeated recovery is idempotent

    # Post-rename states are verified from the actual canonical store, never from phase text.
    for index, phase in enumerate(("trust-after-rename", "trust-after-dir-fsync", "trust-after-verify", "trust-after-generation-fsync", "trust-after-generation-anchor", "trust-during-cleanup")):
        root, _, _ = crash_add(f"post-rename-{index}", phase)
        trust(root, "recover", apply=True, confirm=True)
        assert b"generation=1\n" in store_path(root).read_bytes()
        assert (store_path(root).parent / "generation.v1").exists()
        assert not (store_path(root).parent / "transaction.v1").exists()
        trust(root, "recover", apply=True, confirm=True)

    # Successful recovery of an interrupted revocation preserves the revocation.
    root = install("revoke-recovery")
    old_file, old_id = key(301)
    trust(root, "add-key", old_file, "--publisher", "fixture", apply=True, confirm=True)
    result = trust(root, "revoke-key", old_id, apply=True, confirm=True,
                   interrupt="trust-after-journal-fsync", ok=False)
    assert result.returncode == 86
    trust(root, "recover", apply=True, confirm=True)
    revoked = store_path(root).read_text()
    assert f"{old_id}|ed25519|" in revoked and revoked.rstrip().endswith("revoked")

    # Rotation recovery commits both key outcomes as one store generation.
    root = install("rotate-recovery")
    old_file, old_id = key(302)
    new_file, new_id = key(303)
    trust(root, "add-key", old_file, "--publisher", "fixture", apply=True, confirm=True)
    trust(root, "rotate-key", old_id, new_file, "--publisher", "fixture", apply=True, confirm=True,
          interrupt="trust-after-journal-fsync", ok=False)
    trust(root, "recover", apply=True, confirm=True)
    rotated = store_path(root).read_text()
    records = [line.split("=", 1)[1] for line in rotated.splitlines() if line.startswith("key_")]
    assert any(record.startswith(f"{old_id}|ed25519|") and record.endswith("|revoked") for record in records)
    assert any(record.startswith(f"{new_id}|ed25519|") and record.endswith("|active") for record in records)
    assert b"generation=2\n" in rotated.encode()

    # Missing/modified stage, digest mismatch, invalid generations, and foreign files fail closed.
    root, _, _ = crash_add("missing-stage", "trust-after-journal-fsync")
    stage = store_path(root).parent / "stage.v1"
    stage.unlink()
    trust(root, "recover", apply=True, confirm=True, ok=False)
    assert (stage.parent / "transaction.v1").exists()

    root, _, _ = crash_add("modified-stage", "trust-after-journal-fsync")
    stage = store_path(root).parent / "stage.v1"
    stage.write_bytes(stage.read_bytes() + b"corrupt\n")
    trust(root, "recover", apply=True, confirm=True, ok=False)

    root, _, _ = crash_add("bad-generation", "trust-after-journal-fsync")
    journal = store_path(root).parent / "transaction.v1"
    journal.write_text(journal.read_text().replace("new_generation=1", "new_generation=0"))
    trust(root, "recover", apply=True, confirm=True, ok=False)

    root, _, _ = crash_add("foreign-temp", "trust-after-journal-fsync")
    foreign = store_path(root).parent / "foreign.tmp"
    foreign.write_text("administrator data\n")
    trust(root, "recover", apply=True, confirm=True, ok=False)
    assert foreign.read_text() == "administrator data\n"

    root, _, _ = crash_add("conflicting-store", "trust-after-journal-fsync")
    store = store_path(root)
    store.write_bytes(b"ios-unsandboxed-trust-store\nschema_version=1\ngeneration=9\nkey_count=0\n")
    trust(root, "recover", apply=True, confirm=True, ok=False)

    root = install("same-generation-conflict")
    subject_file, subject_id = key(405)
    trust(root, "add-key", subject_file, "--publisher", "fixture", apply=True, confirm=True)
    trust(root, "revoke-key", subject_id, apply=True, confirm=True,
          interrupt="trust-after-journal-fsync", ok=False)
    store = store_path(root)
    changed = store.read_bytes().replace(b"|active\n", b"|revoked\n")
    assert changed != store.read_bytes()
    store.write_bytes(changed)  # Same generation, different bytes than journal old digest.
    trust(root, "recover", apply=True, confirm=True, ok=False)

    # Corrupt, symlinked, hard-linked, and unsafe-mode journals are never treated as absent.
    root, _, _ = crash_add("corrupt-journal", "trust-after-journal-fsync")
    journal = store_path(root).parent / "transaction.v1"
    journal.write_text("corrupt\n")
    trust(root, "recover", apply=True, confirm=True, ok=False)
    assert journal.exists()

    root, _, _ = crash_add("symlink-journal", "trust-after-journal-fsync")
    journal = store_path(root).parent / "transaction.v1"
    saved = journal.with_name("journal.saved")
    journal.rename(saved)
    journal.symlink_to(saved.name)
    trust(root, "recover", apply=True, confirm=True, ok=False)
    journal.unlink(); saved.rename(journal)

    root, _, _ = crash_add("hardlink-journal", "trust-after-journal-fsync")
    journal = store_path(root).parent / "transaction.v1"
    alias = journal.with_name("journal.alias")
    os.link(journal, alias)
    trust(root, "recover", apply=True, confirm=True, ok=False)

    root, _, _ = crash_add("mode-journal", "trust-after-journal-fsync")
    journal = store_path(root).parent / "transaction.v1"
    journal.chmod(0o644)
    trust(root, "recover", apply=True, confirm=True, ok=False)

    root, _, _ = crash_add("owner-journal", "trust-after-journal-fsync")
    journal = store_path(root).parent / "transaction.v1"
    try:
        os.chown(journal, os.geteuid() + 1, os.getegid())
    except PermissionError:
        pass
    else:
        trust(root, "recover", apply=True, confirm=True, ok=False)

    # Pending trust state blocks package upgrade and all trust mutations.
    root, pub, _ = crash_add("package-block", "trust-after-journal-fsync")
    suite.fails(suite.invoke("upgrade", suite.package_new, apply=True, root=root), "upgrade with pending trust transaction")
    trust(root, "add-key", pub, "--publisher", "fixture", apply=True, confirm=True, ok=False)

    # Shared installer lock serializes trust recovery, add-key, and package upgrade.
    root, _, _ = crash_add("lock-contention", "trust-after-journal-fsync")
    lock_path = root / "var/lib/.ios-unsandboxed-installer.lock"
    with lock_path.open("r+b") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        trust(root, "recover", apply=True, confirm=True, ok=False)
        next_key, _ = key(404)
        trust(root, "add-key", next_key, "--publisher", "fixture", apply=True, confirm=True, ok=False)
        suite.fails(suite.invoke("upgrade", suite.package_new, apply=True, root=root), "upgrade lock contention")

    # Concurrent recovery attempts may contend, but leave one verified settled generation.
    root, _, _ = crash_add("concurrent-recovery", "trust-after-journal-fsync")
    results: list[subprocess.CompletedProcess[str]] = []
    barrier = threading.Barrier(3)
    def recover_worker() -> None:
        barrier.wait()
        manager = root / "var/lib/ios-unsandboxed/manager.sh"
        results.append(subprocess.run([str(manager), "trust", "recover", "--apply", "--confirm", "--test-root", str(root)],
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
    workers = [threading.Thread(target=recover_worker) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join()
    assert all(result.returncode in (0, 4) for result in results), [(r.returncode, r.stdout, r.stderr) for r in results]
    assert b"generation=1\n" in store_path(root).read_bytes()
    assert not (store_path(root).parent / "transaction.v1").exists()

    # A local generation anchor detects a store rollback or conflicting bytes.
    root = install("local-generation-anchor")
    first_file, _ = key(601)
    second_file, _ = key(602)
    trust(root, "add-key", first_file, "--publisher", "fixture", apply=True, confirm=True)
    previous = store_path(root).read_bytes()
    trust(root, "add-key", second_file, "--publisher", "fixture", apply=True, confirm=True)
    anchor = store_path(root).parent / "generation.v1"
    assert b"generation=2\n" in anchor.read_bytes()
    store_path(root).write_bytes(previous)
    trust(root, "status", ok=False)
    assert store_path(root).read_bytes() == previous

    # Package upgrade and rollback never restore older trust records.
    root = install("rollback-revocation")
    old_file, old_id = key(501)
    trust(root, "add-key", old_file, "--publisher", "fixture", apply=True, confirm=True)
    active_bytes = store_path(root).read_bytes()
    active_generation = store_path(root).parent.joinpath("generation.v1").read_bytes()
    suite.ok(suite.invoke("upgrade", suite.package_new, apply=True, root=root), "upgrade preserving trust")
    assert store_path(root).read_bytes() == active_bytes
    assert store_path(root).parent.joinpath("generation.v1").read_bytes() == active_generation
    trust(root, "revoke-key", old_id, apply=True, confirm=True)
    revoked_bytes = store_path(root).read_bytes()
    revoked_generation = store_path(root).parent.joinpath("generation.v1").read_bytes()
    suite.ok(suite.invoke("rollback", apply=True, root=root), "package rollback preserving trust")
    assert store_path(root).read_bytes() == revoked_bytes
    assert store_path(root).parent.joinpath("generation.v1").read_bytes() == revoked_generation
    result = trust(root, "list")
    assert "Operational authorization: false" in result.stdout

    # Uninstall removes only package-owned files and leaves trust records for review.
    root = install("uninstall-preserves-trust")
    old_file, _ = key(502)
    trust(root, "add-key", old_file, "--publisher", "fixture", apply=True, confirm=True)
    preserved = store_path(root).read_bytes()
    preserved_generation = store_path(root).parent.joinpath("generation.v1").read_bytes()
    result = suite.invoke("uninstall", apply=True, root=root)
    suite.ok(result, "uninstall preserving trust metadata")
    assert store_path(root).read_bytes() == preserved
    assert store_path(root).parent.joinpath("generation.v1").read_bytes() == preserved_generation
    assert "Trust metadata" in result.stdout

print("trust transaction interruption, recovery, corruption, lifecycle, and lock fixtures: PASS")
