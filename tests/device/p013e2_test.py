#!/usr/bin/env python3
"""Deterministic host fixtures for P013E-2 qualification helpers."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

import p013e2_qualification as qual


def fake_macho(helper: bool = False) -> bytes:
    build = struct.pack("<IIIIII", 0x32, 24, 2, 0x000C0000, 0, 0)
    name = b"/usr/lib/libSystem.B.dylib\0"
    dylib_size = (24 + len(name) + 7) & ~7
    dylib = struct.pack("<IIIIII", 0xC, dylib_size, 24, 0, 0, 0) + name
    dylib += b"\0" * (dylib_size - len(dylib))
    commands = build + dylib
    suffix = b""
    ncmds = 2
    if helper:
        ncmds += 1
        symoff = 32 + len(commands) + 24
        stroff = symoff + 16
        strings = b"\0_iu_builder_admin_v1\0"
        symtab = struct.pack("<IIIIII", 0x2, 24, symoff, 1, stroff, len(strings))
        commands += symtab
        suffix = struct.pack("<IBBHQ", 1, 0x0F, 0, 0, 0) + strings
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, ncmds, len(commands), 0, 0
    )
    return header + commands + suffix


def artifact_zip(path: Path) -> None:
    package_name = "ios-unsandboxed-0.1.0-rootful-arm64"
    binaries = {
        "payload/bin/ios-unsandboxed": fake_macho(),
        "payload/bin/ios-unsandboxedd": fake_macho(),
        "payload/share/installer-helper": fake_macho(helper=True),
    }
    payloads = {
        **binaries,
        "payload/share/manager.sh": b"#!/bin/sh\nexit 0\n",
        "payload/share/paths.env": b"IOS_UNSANDBOXED_CLI=/usr/local/bin/ios-unsandboxed\n",
        "payload/share/install-state.example": b"disabled\n",
        "payload/share/com.ios-unsandboxed.daemon.plist": plistlib.dumps(
            {
                "ProgramArguments": ["/usr/local/bin/ios-unsandboxedd", "--serve"],
                "UserName": "root", "GroupName": "wheel", "RunAtLoad": True, "KeepAlive": False,
            }
        ),
    }
    payloads = {key: payloads[key] for key in qual.PACKAGE_FILES}
    lines = [
        "ios-unsandboxed-package", "schema_version=1", "project_version=0.1.0",
        "platform=ios", "architecture=arm64", "minimum_ios=12.0",
        "signing_status=unsigned", "signature_verification=not_applicable",
        "artifact_signing=payload/bin/ios-unsandboxed|unsigned|not_applicable",
        "artifact_signing=payload/bin/ios-unsandboxedd|unsigned|not_applicable",
        "artifact_signing=payload/share/installer-helper|unsigned|not_applicable",
    ]
    for relative, mode in qual.PACKAGE_FILES.items():
        lines.append(f"file={relative}|regular|{mode:04o}|{hashlib.sha256(payloads[relative]).hexdigest()}")
    manifest = ("\n".join(lines) + "\n").encode("ascii")
    sums = [f"{hashlib.sha256(manifest).hexdigest()}  package-manifest"]
    sums.extend(f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}" for name in payloads)
    checksums = ("\n".join(sums) + "\n").encode("ascii")
    entries = {
        "package-manifest": manifest,
        "SHA256SUMS": checksums,
        **payloads,
    }
    root = package_name
    tar_bytes = io.BytesIO()
    with gzip.GzipFile(fileobj=tar_bytes, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            root_info = tarfile.TarInfo(root)
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o755
            root_info.uid = root_info.gid = root_info.mtime = 0
            archive.addfile(root_info)
            tar_entries = [
                ("payload", None), ("payload/bin", None), ("payload/share", None),
                *[(relative, value) for relative, value in entries.items()],
            ]
            for relative, value in sorted(tar_entries, key=lambda item: item[0]):
                info = tarfile.TarInfo(f"{root}/{relative}")
                info.uid = info.gid = info.mtime = 0
                if value is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    archive.addfile(info)
                else:
                    info.mode = qual.PACKAGE_FILES.get(relative, 0o644)
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as artifact:
        artifact.writestr(f"{package_name}.tar.gz", tar_bytes.getvalue())
        for relative, value in entries.items():
            artifact.writestr(f"{package_name}/{relative}", value)


def inspected_report(cli_sha: str, daemon_sha: str, head_sha: str = "1" * 40) -> dict[str, object]:
    metadata = {
        "architecture": "arm64",
        "file_type": "MH_EXECUTE",
        "minimum_ios": "12.0.0",
        "minimum_ios_check": "PASS",
        "production_test_hook_check": "PASS",
        "manifest_signature_consistency": "PASS",
    }
    workflow = {
        "result": "PASS", "status": "completed", "conclusion": "success",
        "observed_head_sha": head_sha, "expected_head_sha": head_sha,
    }
    return {
        "schema_version": "p013e2.artifact-inspection.v1",
        "integrity": "PASS",
        "artifact_sha256": "a" * 64,
        "package_archive_sha256": "b" * 64,
        "workflow_run": workflow,
        "package_target": {"platform": "ios", "architecture": "arm64", "minimum_ios": "12.0"},
        "binaries": {
            "payload/bin/ios-unsandboxed": {**metadata, "sha256": cli_sha},
            "payload/bin/ios-unsandboxedd": {**metadata, "sha256": daemon_sha},
        },
    }


def device_report(session_id: str = "fixture-session", model: str = "iPad4,4") -> dict[str, object]:
    return {
        "schema_version": "p013e2.device-evidence.v1",
        "evidence_origin": "local_read_only_inventory",
        "device": {
            "session_identifier": session_id,
            "profile_match": "PASS" if model == "iPad4,4" else "FAIL",
            "observed": {"model": model, "architecture": "arm64", "ios_version": "12.5.7", "os_build": "16H81"},
        },
        "observations": [
            {"command": ["sysctl", "-n", "hw.model"], "exit_code": 0},
            {"command": ["uname", "-m"], "exit_code": 0},
            {"command": ["sw_vers", "-productVersion"], "exit_code": 0},
        ],
    }


class QualificationTests(unittest.TestCase):
    def test_malformed_inventory_is_blocked_without_inventing_device_values(self) -> None:
        evidence = qual.parse_inventory("garbage", 0, "provided_transcript_unverified")
        self.assertEqual(evidence["device"]["profile_match"], "BLOCKED")
        self.assertEqual(evidence["device"]["observed"]["model"], None)
        self.assertEqual(evidence["observations"][0]["result"], "BLOCKED")

    def test_unavailable_device_report_has_no_fabricated_observations(self) -> None:
        evidence = qual.unavailable_evidence("No authorized SSH session was supplied.")
        self.assertEqual(evidence["evidence_origin"], "no_device_session")
        self.assertEqual(evidence["observations"], [])
        self.assertEqual(evidence["device"]["profile_match"], "NOT RUN")
        self.assertIsNone(evidence["device"]["observed"]["model"])
        self.assertIn("NOT RUN", evidence["qualification_status"])

    def test_expected_device_profile_requires_observed_values(self) -> None:
        fixture = (
            "P006 iOS device runtime qualification\n"
            "OBSERVED hardware model identifier: iPad4,4\n"
            "OBSERVED kernel architecture: arm64\n"
            "OBSERVED OS product version: 12.5.7\n"
            "OBSERVED OS build identifier: 16H81\n"
        )
        imported = qual.parse_inventory(fixture, 0, "provided_transcript_unverified", "fixture-session")
        self.assertEqual(imported["device"]["profile_match"], "UNVERIFIED")
        self.assertEqual(imported["device"]["transcript_profile_match"], "PASS")
        good = qual.parse_inventory(fixture, 0, "local_read_only_inventory", "fixture-session")
        self.assertEqual(good["device"]["profile_match"], "PASS")
        self.assertEqual(good["device"]["session_identifier"], "fixture-session")
        mismatch = qual.parse_inventory(
            fixture.replace("iPad4,4", "iPad4,1"), 0, "local_read_only_inventory", "fixture-session"
        )
        self.assertEqual(mismatch["device"]["profile_match"], "FAIL")
        missing = qual.parse_inventory(
            fixture.replace("12.5.7", "unknown"), 0, "local_read_only_inventory", "fixture-session"
        )
        self.assertEqual(missing["device"]["profile_match"], "FAIL")

    def test_host_fixture_is_never_promoted_to_device_evidence(self) -> None:
        output = "P006 iOS device runtime qualification\nMODE: HOST FIXTURE ONLY\n"
        evidence = qual.parse_inventory(output, 0, "host_fixture")
        self.assertEqual(evidence["device"]["profile_match"], "NOT RUN")
        self.assertEqual(evidence["evidence_origin"], "host_fixture")

    def test_p006_inventory_events_keep_exact_command_status_and_missing_tool(self) -> None:
        transcript = (
            "P006 iOS device runtime qualification\n"
            "OBSERVED qualification timestamp UTC (system clock): 2026-10-31T00:00:00Z\n"
            "COMMAND: <uname> <-m>\nEXIT_STATUS: 0\nOBSERVED kernel architecture: arm64\n"
            "MISSING_COMMAND: otool (Mach-O headers and dependencies)\n"
        )
        evidence = qual.parse_inventory(transcript, 0, "provided_transcript_unverified", "ssh-session-1")
        command = next(item for item in evidence["observations"] if item.get("command") == ["uname", "-m"])
        missing = next(item for item in evidence["observations"] if item.get("command") == ["otool"])
        self.assertEqual(command["exit_code"], 0)
        self.assertEqual(command["timestamp_utc"], "2026-10-31T00:00:00Z")
        self.assertEqual(command["device_session_identifier"], "ssh-session-1")
        self.assertEqual(missing["result"], "BLOCKED")

    def test_secret_redaction(self) -> None:
        clean = qual.redact("token=abc123 Bearer qwerty /home/alice/private")
        self.assertNotIn("abc123", clean)
        self.assertNotIn("qwerty", clean)
        self.assertNotIn("/home/alice", clean)

    def test_evidence_writer_refuses_production_paths(self) -> None:
        with self.assertRaises(ValueError):
            qual._write_json({}, "/var/lib/p013e2-evidence.json")

    def staged_pair(self, stage: Path) -> tuple[Path, Path, str, str]:
        os.chmod(stage, 0o700)
        cli = stage / "ios-unsandboxed"
        daemon = stage / "ios-unsandboxedd"
        cli.write_bytes(b"CLI fixture; never executed by this test\n")
        daemon.write_bytes(b"daemon fixture; never executed by this test\n")
        cli.chmod(0o700)
        daemon.chmod(0o700)
        return cli, daemon, qual.sha256_file(cli), qual.sha256_file(daemon)

    def test_missing_binary_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            stage = Path(temp)
            os.chmod(stage, 0o700)
            cli = stage / "missing-cli"
            daemon = stage / "missing-daemon"
            report = inspected_report("0" * 64, "0" * 64)
            evidence = qual.run_runtime(cli, daemon, report, device_report(), "1" * 40, True, session_id="fixture-session")
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")
            self.assertEqual(evidence["observations"], [])

    def test_hash_mismatch_blocks_all_binary_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, _, _ = self.staged_pair(Path(temp))
            runner = mock.Mock()
            report = inspected_report("0" * 64, "1" * 64)
            evidence = qual.run_runtime(cli, daemon, report, device_report(), "1" * 40, True, runner=runner, session_id="fixture-session")
            runner.assert_not_called()
            self.assertEqual(evidence["observations"][0]["result"], "FAIL")
            self.assertIn("neither binary was launched", evidence["observations"][0]["interpretation"])

    def test_unsafe_path_and_symlink_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))
            runner = mock.Mock()
            outside_fd, outside_name = tempfile.mkstemp(prefix="p013e2-outside-", dir="/tmp")
            os.close(outside_fd)
            moved_cli = Path(outside_name)
            moved_cli.write_bytes(cli.read_bytes())
            moved_cli.chmod(0o700)
            report = inspected_report(cli_hash, daemon_hash)
            evidence = qual.run_runtime(moved_cli, daemon, report, device_report(), "1" * 40, True, runner=runner, session_id="fixture-session")
            moved_cli.unlink()
            runner.assert_not_called()
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")
            link = cli.parent / "linked-cli"
            link.symlink_to(cli)
            evidence = qual.run_runtime(link, daemon, report, device_report(), "1" * 40, True, runner=runner, session_id="fixture-session")
            runner.assert_not_called()
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")

    def test_runtime_requires_explicit_authorization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))
            runner = mock.Mock()
            report = inspected_report(cli_hash, daemon_hash)
            evidence = qual.run_runtime(cli, daemon, report, device_report(), "1" * 40, False, runner=runner, session_id="fixture-session")
            runner.assert_not_called()
            self.assertEqual(evidence["observations"], [])

    def test_runtime_requires_a_nonsecret_session_label(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))
            runner = mock.Mock()
            report = inspected_report(cli_hash, daemon_hash)
            evidence = qual.run_runtime(cli, daemon, report, device_report(), "1" * 40, True, runner=runner)
            runner.assert_not_called()
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")

    def test_runtime_refuses_mismatched_or_imported_device_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))
            report = inspected_report(cli_hash, daemon_hash)
            runner = mock.Mock()
            mismatch = device_report(model="iPad4,1")
            evidence = qual.run_runtime(
                cli, daemon, report, mismatch, "1" * 40, True,
                runner=runner, session_id="fixture-session",
            )
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")
            imported = device_report()
            imported["evidence_origin"] = "provided_transcript_unverified"
            evidence = qual.run_runtime(
                cli, daemon, report, imported, "1" * 40, True,
                runner=runner, session_id="fixture-session",
            )
            runner.assert_not_called()
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")

    def test_runtime_refuses_unassociated_or_uninspected_artifact_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))
            report = inspected_report(cli_hash, daemon_hash)
            report["workflow_run"]["result"] = "UNVERIFIED"  # type: ignore[index]
            runner = mock.Mock()
            evidence = qual.run_runtime(cli, daemon, report, device_report(), "1" * 40, True, runner=runner, session_id="fixture-session")
            runner.assert_not_called()
            self.assertEqual(evidence["runtime_matrix"]["cli_version_startup"], "BLOCKED")

    def test_failed_startup_and_signal_are_recorded_exactly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))
            calls = 0

            def failed_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                nonlocal calls
                calls += 1
                if command[1] == "--version":
                    return subprocess.CompletedProcess(command, -9, "", "")
                return subprocess.CompletedProcess(command, 0, "diagnostic output\n", "")

            report = inspected_report(cli_hash, daemon_hash)
            evidence = qual.run_runtime(cli, daemon, report, device_report(), "1" * 40, True, runner=failed_runner, session_id="fixture-session")
            self.assertEqual(calls, len(qual.DIAGNOSTIC_COMMANDS))
            version = evidence["observations"][0]
            self.assertEqual(version["termination_signal"], 9)
            self.assertIsNone(version["exit_code"])
            self.assertEqual(version["result"], "FAIL")

            def failed_exit_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                code = 23 if command[1] == "--version" else 0
                output = "" if code else "read-only diagnostic\n"
                return subprocess.CompletedProcess(command, code, output, "")

            failed_exit = qual.run_runtime(
                cli, daemon, report, device_report(), "1" * 40, True,
                runner=failed_exit_runner, session_id="fixture-session",
            )["observations"][0]
            self.assertEqual(failed_exit["exit_code"], 23)
            self.assertIsNone(failed_exit["termination_signal"])
            self.assertEqual(failed_exit["result"], "FAIL")

    def test_unavailable_tool_is_blocked_not_failed(self) -> None:
        def missing_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("not found")

        result = qual._run_process(["missing-tool"], 1, missing_runner)
        self.assertEqual(result["result"], "BLOCKED")
        self.assertIsNone(result["exit_code"])

    def test_timeout_is_blocked_with_output_preserved_and_redacted(self) -> None:
        def timeout_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(command, 1, output=b"token=hidden")

        result = qual._run_process(["diagnostic"], 1, timeout_runner)
        self.assertEqual(result["result"], "BLOCKED")
        self.assertIn("<redacted>", result["sanitized_output"])
        self.assertNotIn("hidden", result["sanitized_output"])

    def test_private_ipc_requires_confirmed_recovery_session(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ios-unsandboxed-p013e2.", dir="/tmp") as temp:
            cli, daemon, cli_hash, daemon_hash = self.staged_pair(Path(temp))

            def startup_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                if command[1] == "--version":
                    output = "ios-unsandboxed 0.1.0\n"
                elif command[1] == "--probe":
                    output = "iOS-Unsandboxed read-only preflight\n"
                else:
                    output = "read-only diagnostic\n"
                return subprocess.CompletedProcess(command, 0, output, "")

            report = inspected_report(cli_hash, daemon_hash)
            evidence = qual.run_runtime(
                cli, daemon, report, device_report(), "1" * 40, True, allow_ipc=True,
                recovery_session_confirmed=False, runner=startup_runner,
                session_id="fixture-session",
            )
            self.assertEqual(evidence["runtime_matrix"]["temporary_ipc_peer_credentials"], "BLOCKED")
            self.assertFalse(any(item["label"] == "P006 private-socket read-only IPC" for item in evidence["observations"]))

    def test_process_group_timeout_requests_cleanup_signal(self) -> None:
        class FakeProcess:
            pid = 12345
            returncode = 0

            def __init__(self) -> None:
                self.calls = 0

            def communicate(self, timeout: float | None = None) -> tuple[str, None]:
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(["p006"], timeout, output="partial")
                return "partial", None

        process = FakeProcess()
        with mock.patch.object(qual.subprocess, "Popen", return_value=process), mock.patch.object(
            qual.os, "killpg"
        ) as killpg:
            result = qual.run_process_group(["sh", "p006"], 0.01)
        killpg.assert_called_once_with(process.pid, qual.signal.SIGTERM)
        self.assertEqual(result["result"], "BLOCKED")
        self.assertIn("partial", result["sanitized_output"])

    def test_macho_metadata_parsing(self) -> None:
        cli = qual.inspect_macho(fake_macho())
        helper = qual.inspect_macho(fake_macho(helper=True))
        self.assertEqual(cli["architecture"], "arm64")
        self.assertEqual(cli["minimum_ios"], "12.0.0")
        self.assertEqual(cli["dynamic_dependencies"], ["/usr/lib/libSystem.B.dylib"])
        self.assertEqual(cli["code_signature_metadata"], "unsigned")
        self.assertEqual(helper["builder_admin_linkage"], "PASS")
        with self.assertRaises(ValueError):
            qual.inspect_macho(b"not a Mach-O")

    def test_artifact_inspection_reads_zip_without_extracting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "fixture.zip"
            artifact_zip(artifact)
            report = qual.inspect_artifact(artifact)
            self.assertEqual(report["integrity"], "PASS")
            self.assertEqual(report["package_target"]["minimum_ios"], "12.0")
            self.assertEqual(report["amethyst_trust"], "UNVERIFIED")
            self.assertEqual(
                report["binaries"]["payload/bin/ios-unsandboxed"]["manifest_signature_consistency"],
                "PASS",
            )
            self.assertEqual(
                report["binaries"]["payload/share/installer-helper"]["builder_admin_linkage"], "PASS"
            )
            self.assertEqual(
                report["binaries"]["payload/share/installer-helper"]["production_test_hook_check"], "PASS"
            )

    def test_artifact_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "fixture.zip"
            artifact_zip(artifact)
            broken = Path(temp) / "broken.zip"
            with zipfile.ZipFile(artifact, "r") as source, zipfile.ZipFile(
                broken, "w", compression=zipfile.ZIP_DEFLATED
            ) as destination:
                for info in source.infolist():
                    content = source.read(info)
                    if info.filename.endswith("/payload/bin/ios-unsandboxed"):
                        content = b"changed"
                    destination.writestr(info.filename, content)
            with self.assertRaises(ValueError):
                qual.inspect_artifact(broken)

    def test_workflow_artifact_association_requires_successful_exact_head(self) -> None:
        expected = "1" * 40

        def matching(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command, 0,
                json.dumps({"headSha": expected, "status": "completed", "conclusion": "success"}),
                "",
            )

        self.assertEqual(qual.verify_workflow_run("41201769177", expected, matching)["result"], "PASS")

        def wrong_sha(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command, 0,
                json.dumps({"headSha": "2" * 40, "status": "completed", "conclusion": "success"}),
                "",
            )

        self.assertEqual(qual.verify_workflow_run("41201769177", expected, wrong_sha)["result"], "FAIL")

        def missing_gh(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("gh is unavailable")

        self.assertEqual(qual.verify_workflow_run("41201769177", expected, missing_gh)["result"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
