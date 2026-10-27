#!/usr/bin/env python3
"""Host-only fixture check for the P006 read-only path inventory."""

import pathlib
import subprocess
import tempfile


def main():
    repo = pathlib.Path(__file__).resolve().parents[2]
    harness = repo / "tests/device/ios-runtime-qualification.sh"
    inspector = repo / "tests/device/inspect-ios-build.sh"
    with tempfile.TemporaryDirectory(prefix="iu-p006-fixture-") as temp:
        fixture = pathlib.Path(temp) / "root"
        launchd = fixture / "amethyst/launchd_hook.dylib"
        base_hook_target = fixture / "usr/lib/base_hook.fixture"
        base_hook = fixture / "usr/lib/base_hook.dylib"
        cli = fixture / "usr/local/bin/ios-unsandboxed"

        launchd.parent.mkdir(parents=True)
        base_hook.parent.mkdir(parents=True)
        cli.parent.mkdir(parents=True)
        launchd.write_bytes(b"fixture only; not Mach-O\n")
        base_hook_target.write_bytes(b"fixture target\n")
        base_hook.symlink_to("base_hook.fixture")
        cli.write_bytes(b"fixture executable; must not be run\n")
        cli.chmod(0o755)

        syntax = subprocess.run(["sh", "-n", str(harness)], text=True, capture_output=True)
        if syntax.returncode != 0:
            raise AssertionError(f"shell syntax check failed:\n{syntax.stderr}")
        syntax = subprocess.run(["sh", "-n", str(inspector)], text=True, capture_output=True)
        if syntax.returncode != 0:
            raise AssertionError(f"build inspector shell syntax check failed:\n{syntax.stderr}")

        result = subprocess.run(
            ["sh", str(harness), "--root", str(fixture)],
            text=True,
            capture_output=True,
            timeout=20,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"fixture inventory failed ({result.returncode}):\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

        expected = (
            "MODE: HOST FIXTURE ONLY",
            "OBSERVED_FILE_TYPE: regular-file",
            "OBSERVED_FILE_TYPE: symlink",
            "PATH_VALUE: " + str(fixture / "var/run/ios-unsandboxedd.sock"),
            "RESULT: host fixture inventory completed; this is not iOS, Amethyst, IPC, or launchd device evidence.",
            "TEMPORARY_IPC_TEST: NOT RUN in fixture mode.",
        )
        for item in expected:
            if item not in result.stdout:
                raise AssertionError(f"fixture output missing {item!r}:\n{result.stdout}")

        forbidden = ("fixture executable; must not be run",)
        for item in forbidden:
            if item in result.stdout:
                raise AssertionError(f"inventory unexpectedly read/executed fixture content: {item!r}")

    print("P006 harness host fixtures passed (filesystem inventory only; no device simulation).")


if __name__ == "__main__":
    main()
