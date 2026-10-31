#!/usr/bin/env python3
"""P013E-2 read-only artifact/device qualification helpers.

This tool delegates filesystem/device inventory to the existing P006 shell
harness. Runtime commands are a separate, hash-pinned opt-in and are never
run by the default inventory command.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import zipfile
from typing import Any, Callable


SCHEMA_VERSION = "p013e2.device-evidence.v1"
EXPECTED_DEVICE = {
    "model": "iPad4,4",
    "architecture": "arm64",
    "ios_version": "12.5.7",
}
PACKAGE_FILES = {
    "payload/bin/ios-unsandboxed": 0o755,
    "payload/bin/ios-unsandboxedd": 0o755,
    "payload/share/manager.sh": 0o700,
    "payload/share/installer-helper": 0o700,
    "payload/share/paths.env": 0o600,
    "payload/share/install-state.example": 0o600,
    "payload/share/com.ios-unsandboxed.daemon.plist": 0o600,
}
TEST_HOOK_MARKERS = (
    b"iu_builder_admin_test_v1",
    b"iu_provenance_test_verify",
    b"iu_execution_plan_test_evaluate_v1",
    b"iu_launch_binding_test_scope_v1",
    b"IU_AME_TESTING",
    b"IU_PROVENANCE_TESTING",
    b"IU_EXECUTION_PLANNER_TESTING",
    b"IU_LAUNCH_BINDING_TESTING",
    b"builder-disk-full",
    b"builder-fail-post-rename-fsync",
    b"IU_INSTALLER_TESTING",
)
DIAGNOSTIC_COMMANDS = (
    ("CLI version", "cli", ("--version",)),
    ("CLI help", "cli", ("--help",)),
    ("CLI doctor", "cli", ("doctor",)),
    ("CLI Amethyst doctor", "cli", ("doctor", "--amethyst")),
    ("CLI status", "cli", ("status",)),
    ("Builder trust status", "cli", ("provenance", "builder-trust", "status")),
    ("Builder trust list", "cli", ("provenance", "builder-trust", "list")),
    ("Daemon read-only probe", "daemon", ("--probe",)),
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def redact(text: str) -> str:
    """Remove common secret forms while preserving useful diagnostic output."""
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1<redacted>", text)
    text = re.sub(
        r"(?i)(authorization|password|passwd|token|secret|private[_ -]?key)(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2<redacted>",
        text,
    )
    text = re.sub(r"(?i)([?&](?:sig|se|sp|skoid|skt|sktid|sv)=)[^&\s]+", r"\1<redacted>", text)
    text = re.sub(r"/(?:Users|home)/[^/\s]+", "/<redacted-home>", text)
    return text


def base_evidence(origin: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "evidence_origin": origin,
        "device": {
            "session_identifier": None,
            "observed": {"model": None, "architecture": None, "ios_version": None, "os_build": None},
            "expected_profile": dict(EXPECTED_DEVICE),
            "profile_match": "NOT RUN",
        },
        "observations": [],
        "runtime_matrix": {
            "arm64_macho_loader_acceptance": "NOT RUN",
            "cli_version_startup": "NOT RUN",
            "rust_runtime_startup": "NOT RUN",
            "native_c17_preflight": "NOT RUN",
            "daemon_temporary_diagnostic_startup": "NOT RUN",
            "temporary_ipc_peer_credentials": "NOT RUN",
            "rootful_filesystem_metadata": "NOT RUN",
            "builder_trust_read_only_diagnostics": "NOT RUN",
            "builder_signer_detail_inspect": "NOT RUN",
            "dsse_offline_fixture_verification": "NOT RUN",
            "amethyst_component_detection": "NOT RUN",
            "amethyst_installed_build_identity": "NOT RUN",
            "actual_amethyst_hook_activity": "NOT RUN",
            "kernel_filesystem_durability": "NOT RUN",
            "execution_activation_remains_disabled": "NOT RUN",
        },
        "limitations": [],
    }


def unavailable_evidence(reason: str) -> dict[str, Any]:
    evidence = base_evidence("no_device_session")
    evidence["qualification_status"] = (
        "P013E-2: PARTIAL (offline harness complete; physical-device validation NOT RUN)"
    )
    evidence["blockers"] = [redact(reason)]
    evidence["limitations"].append(
        "No physical-device command was run; expected values remain separate from observed values."
    )
    return evidence


def classify_profile(observed: dict[str, str | None]) -> str:
    values = (observed.get("model"), observed.get("architecture"), observed.get("ios_version"))
    if not all(values):
        return "BLOCKED"
    expected = (EXPECTED_DEVICE["model"], EXPECTED_DEVICE["architecture"], EXPECTED_DEVICE["ios_version"])
    return "PASS" if values == expected else "FAIL"


def inventory_values(output: str) -> dict[str, str | None]:
    labels = {
        "hardware model identifier": "model",
        "kernel architecture": "architecture",
        "OS product version": "ios_version",
        "OS build identifier": "os_build",
    }
    found: dict[str, str | None] = {key: None for key in (*labels.values(),)}
    for line in output.splitlines():
        match = re.match(r"OBSERVED ([^:]+):\s*(.*)$", line)
        if match and match.group(1) in labels:
            value = match.group(2).strip()
            found[labels[match.group(1)]] = value or None
    return found


def p006_command_events(output: str, origin: str, session_id: str | None) -> list[dict[str, Any]]:
    lines = output.splitlines()
    starts = {
        "COMMAND:": ("EXIT_STATUS:", "COMMAND_EXIT_STATUS:"),
        "HASH_COMMAND:": ("HASH_EXIT_STATUS:",),
        "STAT_COMMAND:": ("STAT_EXIT_STATUS:",),
        "LS_COMMAND:": ("LS_EXIT_STATUS:",),
    }
    markers = tuple(starts)
    clock_match = re.search(r"OBSERVED qualification timestamp UTC \(system clock\):\s*(\S+)", output)
    timestamp = clock_match.group(1) if clock_match else utc_now()
    events: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        marker = next((item for item in markers if line.startswith(item)), None)
        if marker is None:
            continue
        args = re.findall(r"<([^>]*)>", line[len(marker) :])
        if not args:
            continue
        status = None
        end_index = len(lines)
        for cursor in range(index + 1, len(lines)):
            if any(lines[cursor].startswith(item) for item in markers):
                end_index = cursor
                break
            for candidate in starts[marker]:
                match = re.fullmatch(re.escape(candidate) + r"\s*(\d+)", lines[cursor])
                if match:
                    status = int(match.group(1))
                    end_index = cursor
                    break
            if status is not None:
                break
        if status is None:
            continue
        output_lines = lines[index + 1 : end_index]
        if output_lines and output_lines[0].startswith("COMMAND:"):
            output_lines = output_lines[1:]
        events.append(
            {
                "timestamp_utc": timestamp,
                "timestamp_source": "P006 device clock" if clock_match else "evidence capture clock",
                "device_session_identifier": session_id,
                "command": args,
                "exit_code": status,
                "termination_signal": None,
                "sanitized_output": redact("\n".join(output_lines)),
                "binary_sha256": None,
                "evidence_origin": origin,
                "result": "PASS" if status == 0 else "FAIL",
                "interpretation": "Exact command exit status recorded by P006; signal cause is not inferred.",
            }
        )
    for line in lines:
        missing = re.match(r"MISSING_COMMAND: ([^ (]+)(?: \((.*)\))?", line)
        if missing:
            events.append(
                {
                    "timestamp_utc": timestamp,
                    "timestamp_source": "P006 device clock" if clock_match else "evidence capture clock",
                    "device_session_identifier": session_id,
                    "command": [missing.group(1)],
                    "exit_code": None,
                    "termination_signal": None,
                    "sanitized_output": redact(missing.group(2) or line),
                    "binary_sha256": None,
                    "evidence_origin": origin,
                    "result": "BLOCKED",
                    "interpretation": "Required inspection utility was unavailable; no command was run.",
                }
            )
    return events


def parse_inventory(output: str, exit_code: int, origin: str, session_id: str | None = None) -> dict[str, Any]:
    evidence = base_evidence(origin)
    if session_id and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", session_id):
        evidence["limitations"].append(
            "Session identifier omitted because it is not a safe non-secret label."
        )
        session_id = None
    clean_output = redact(output)
    if "P006 iOS device runtime qualification" not in output:
        result = "BLOCKED"
        interpretation = "P006 transcript is malformed or missing its qualification header."
    elif "MODE: HOST FIXTURE ONLY" in output or "HOST FIXTURE ONLY" in output:
        result = "PASS" if exit_code == 0 else "FAIL"
        interpretation = "P006 host fixture output is not physical-device evidence."
        evidence["evidence_origin"] = "host_fixture"
    elif exit_code == 0:
        result = "PASS"
        interpretation = "P006 inventory command completed; this does not establish runtime compatibility."
    else:
        result = "FAIL"
        interpretation = "P006 inventory command exited nonzero; see sanitized output."
    observed = inventory_values(output)
    evidence["device"]["observed"] = observed
    if "P006 iOS device runtime qualification" not in output:
        evidence["device"]["profile_match"] = "BLOCKED"
    elif evidence["evidence_origin"] == "host_fixture":
        evidence["device"]["profile_match"] = "NOT RUN"
    elif evidence["evidence_origin"] == "provided_transcript_unverified":
        evidence["device"]["transcript_profile_match"] = classify_profile(observed)
        evidence["device"]["profile_match"] = "UNVERIFIED"
        evidence["limitations"].append("Imported transcript origin is not independently verified.")
    elif evidence["evidence_origin"] == "local_read_only_inventory" and not session_id:
        evidence["device"]["profile_match"] = "UNVERIFIED"
        evidence["limitations"].append("No non-secret device/session label was supplied for the local inventory.")
    else:
        evidence["device"]["profile_match"] = classify_profile(observed)
    evidence["device"]["session_identifier"] = session_id
    evidence["observations"].append(
        {
            "timestamp_utc": utc_now(),
            "device_session_identifier": session_id,
            "command": ["sh", "tests/device/ios-runtime-qualification.sh"],
            "exit_code": exit_code,
            "termination_signal": None,
            "sanitized_output": clean_output,
            "binary_sha256": None,
            "evidence_origin": evidence["evidence_origin"],
            "result": result,
            "interpretation": interpretation,
        }
    )
    evidence["observations"].extend(
        p006_command_events(output, evidence["evidence_origin"], session_id)
    )
    if evidence["evidence_origin"] == "host_fixture":
        evidence["limitations"].append("Host fixture output is separate from physical-device observations.")
    return evidence


def _run_process(
    command: list[str],
    timeout: float,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    started = utc_now()
    try:
        result = runner(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as error:
        return {
            "timestamp_utc": started,
            "command": command,
            "exit_code": None,
            "termination_signal": None,
            "sanitized_output": redact(str(error)),
            "result": "BLOCKED",
            "interpretation": "Required executable or diagnostic binary is unavailable.",
        }
    except subprocess.TimeoutExpired as error:
        raw = error.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        err = error.stderr or ""
        if isinstance(err, bytes):
            err = err.decode("utf-8", errors="replace")
        output = (str(raw) + str(err)).strip()
        return {
            "timestamp_utc": started,
            "command": command,
            "exit_code": None,
            "termination_signal": None,
            "sanitized_output": redact(output),
            "result": "BLOCKED",
            "interpretation": f"Diagnostic exceeded its {timeout:g}-second timeout; cause is unclassified.",
        }
    except OSError as error:
        return {
            "timestamp_utc": started,
            "command": command,
            "exit_code": None,
            "termination_signal": None,
            "sanitized_output": redact(str(error)),
            "result": "BLOCKED",
            "interpretation": "The operating system could not start the diagnostic command.",
        }
    code = result.returncode
    output = redact((result.stdout or "") + (result.stderr or ""))
    termination_signal = -code if code < 0 else None
    return {
        "timestamp_utc": started,
        "command": command,
        "exit_code": code if code >= 0 else None,
        "termination_signal": termination_signal,
        "sanitized_output": output,
        "result": "PASS" if code == 0 else "FAIL",
        "interpretation": "Command completed with exit status zero." if code == 0 else "Command failed; no cause is inferred.",
    }


def _is_private_staged_binary(path: Path, prefix: str, euid: int | None = None) -> tuple[bool, str]:
    euid = os.geteuid() if euid is None else euid
    try:
        absolute = Path(os.path.abspath(path))
        parent = absolute.parent
        root = Path("/tmp")
        if not path.is_absolute() or ".." in path.parts:
            return False, "binary path must be absolute and contain no parent traversal"
        if parent.parent != root or not parent.name.startswith(prefix):
            return False, f"binary must be staged directly under a unique /tmp/{prefix}* directory"
        if parent.is_symlink() or not parent.is_dir():
            return False, "staging directory is missing or a symlink"
        directory_stat = parent.stat(follow_symlinks=False)
        if stat.S_IMODE(directory_stat.st_mode) != 0o700 or directory_stat.st_uid != euid:
            return False, "staging directory must be owned by the current uid with mode 0700"
        if absolute.is_symlink() or not absolute.is_file():
            return False, "binary must be a regular non-symlink file"
        binary_stat = absolute.stat(follow_symlinks=False)
        if binary_stat.st_uid != euid or binary_stat.st_nlink != 1 or not os.access(absolute, os.X_OK):
            return False, "binary ownership, link count, or executable mode is unsafe"
        return True, "safe private staging path"
    except OSError as error:
        return False, redact(str(error))


def device_report_matches(report: Any, session_id: str) -> bool:
    if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
        return False
    if report.get("evidence_origin") != "local_read_only_inventory":
        return False
    device = report.get("device", {})
    if not isinstance(device, dict) or device.get("profile_match") != "PASS":
        return False
    if device.get("session_identifier") != session_id:
        return False
    observed = device.get("observed", {})
    if not isinstance(observed, dict):
        return False
    if any(observed.get(key) != expected for key, expected in EXPECTED_DEVICE.items()):
        return False
    observations = report.get("observations", [])
    if not isinstance(observations, list):
        return False
    successful_commands: set[tuple[str, ...]] = set()
    for item in observations:
        if not isinstance(item, dict) or item.get("exit_code") != 0:
            continue
        command = item.get("command")
        if isinstance(command, list) and all(isinstance(argument, str) for argument in command):
            successful_commands.add(tuple(command))
    required = {
        ("sysctl", "-n", "hw.model"),
        ("uname", "-m"),
        ("sw_vers", "-productVersion"),
    }
    return required.issubset(successful_commands)


def run_runtime(
    cli: Path,
    daemon: Path,
    artifact_report: dict[str, Any],
    device_report: dict[str, Any],
    expected_head_sha: str,
    authorized: bool,
    allow_ipc: bool = False,
    recovery_session_confirmed: bool = False,
    timeout: float = 15.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    session_id: str | None = None,
    signer_id: str | None = None,
) -> dict[str, Any]:
    evidence = base_evidence("explicit_temporary_runtime")
    if not session_id:
        evidence["limitations"].append("A non-secret device/session label is required before temporary runtime checks.")
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", session_id):
        evidence["limitations"].append("Session identifier must be a non-secret label using letters, digits, dot, underscore, or hyphen.")
        return evidence
    evidence["device"]["session_identifier"] = session_id
    if timeout <= 0:
        evidence["limitations"].append("Diagnostic timeout must be a positive number of seconds.")
        return evidence
    if signer_id and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", signer_id):
        evidence["limitations"].append("Signer identifier contains unsupported characters.")
        evidence["runtime_matrix"]["builder_signer_detail_inspect"] = "BLOCKED"
        return evidence
    if not authorized:
        evidence["limitations"].append("Temporary execution was not authorized; no diagnostic binary was run.")
        return evidence
    if not device_report_matches(device_report, session_id):
        evidence["limitations"].append(
            "A successful P006 inventory for the expected iPad and same session label is required; no binary was launched."
        )
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    evidence["device"] = device_report["device"]
    if not isinstance(artifact_report, dict):
        evidence["limitations"].append("Inspected artifact evidence is malformed; no binary was launched.")
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    workflow = artifact_report.get("workflow_run", {})
    artifact_binaries = artifact_report.get("binaries", {})
    if not isinstance(workflow, dict) or not isinstance(artifact_binaries, dict):
        evidence["limitations"].append("Inspected artifact evidence is malformed; no binary was launched.")
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    cli_metadata = artifact_binaries.get("payload/bin/ios-unsandboxed", {})
    daemon_metadata = artifact_binaries.get("payload/bin/ios-unsandboxedd", {})
    if not isinstance(cli_metadata, dict) or not isinstance(daemon_metadata, dict):
        evidence["limitations"].append("Inspected artifact binary records are malformed; no binary was launched.")
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    cli_digest = cli_metadata.get("sha256")
    daemon_digest = daemon_metadata.get("sha256")
    package_target = artifact_report.get("package_target", {})
    artifact_hash = artifact_report.get("artifact_sha256")
    package_archive_hash = artifact_report.get("package_archive_sha256")
    if (
        artifact_report.get("schema_version") != "p013e2.artifact-inspection.v1"
        or artifact_report.get("integrity") != "PASS"
        or not re.fullmatch(r"[0-9a-f]{64}", str(artifact_hash or ""))
        or not re.fullmatch(r"[0-9a-f]{64}", str(package_archive_hash or ""))
        or workflow.get("result") != "PASS"
        or workflow.get("status") != "completed"
        or workflow.get("conclusion") != "success"
        or workflow.get("observed_head_sha") != expected_head_sha
        or workflow.get("expected_head_sha") != expected_head_sha
        or package_target != {"platform": "ios", "architecture": "arm64", "minimum_ios": "12.0"}
        or not re.fullmatch(r"[0-9a-fA-F]{40}", expected_head_sha or "")
        or not re.fullmatch(r"[0-9a-f]{64}", str(cli_digest or ""))
        or not re.fullmatch(r"[0-9a-f]{64}", str(daemon_digest or ""))
        or any(
            metadata.get(key) != expected
            for metadata in (cli_metadata, daemon_metadata)
            for key, expected in (
                ("architecture", "arm64"), ("file_type", "MH_EXECUTE"),
                ("minimum_ios_check", "PASS"), ("production_test_hook_check", "PASS"),
                ("manifest_signature_consistency", "PASS"),
            )
        )
    ):
        evidence["limitations"].append(
            "A valid inspected artifact associated with the expected successful workflow HEAD is required; no binary was launched."
        )
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    cli_ok, cli_reason = _is_private_staged_binary(cli, "ios-unsandboxed-p013e2.")
    daemon_ok, daemon_reason = _is_private_staged_binary(daemon, "ios-unsandboxed-p013e2.")
    if not cli_ok or not daemon_ok or cli.parent != daemon.parent:
        evidence["limitations"].append("Unsafe staged binary path: " + "; ".join((cli_reason, daemon_reason)))
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence

    try:
        actual_cli = sha256_file(cli)
        actual_daemon = sha256_file(daemon)
    except (OSError, ValueError) as error:
        evidence["limitations"].append("Binary hash could not be checked: " + redact(str(error)))
        evidence["runtime_matrix"]["cli_version_startup"] = "BLOCKED"
        return evidence
    evidence["artifact_sha256"] = {"cli": actual_cli, "daemon": actual_daemon}
    if actual_cli.lower() != str(cli_digest).lower() or actual_daemon.lower() != str(daemon_digest).lower():
        evidence["runtime_matrix"]["cli_version_startup"] = "FAIL"
        evidence["observations"].append(
            {
                "timestamp_utc": utc_now(),
                "device_session_identifier": session_id,
                "command": ["sha256", str(cli), str(daemon)],
                "exit_code": 1,
                "termination_signal": None,
                "sanitized_output": f"cli={actual_cli}; daemon={actual_daemon}; expected hashes did not match",
                "binary_sha256": {"cli": actual_cli, "daemon": actual_daemon},
                "evidence_origin": "explicit_temporary_runtime",
                "result": "FAIL",
                "interpretation": "Hash mismatch blocked execution; neither binary was launched.",
            }
        )
        return evidence

    binaries = {"cli": cli, "daemon": daemon}
    diagnostic_commands = list(DIAGNOSTIC_COMMANDS)
    if signer_id:
        diagnostic_commands.append(
            ("Builder trust signer inspect", "cli", ("provenance", "builder-trust", "inspect", signer_id))
        )
    for label, binary_name, args in diagnostic_commands:
        binary = binaries[binary_name]
        command = [str(binary), *args]
        observation = _run_process(command, timeout, runner)
        observation.update(
            {
                "device_session_identifier": session_id,
                "binary_sha256": actual_cli if binary_name == "cli" else actual_daemon,
                "evidence_origin": "explicit_temporary_runtime",
                "label": label,
            }
        )
        if binary_name == "cli" and args == ("--version",):
            normal_banner = "ios-unsandboxed 0.1.0" in observation["sanitized_output"]
            observation["result"] = (
                "PASS" if observation["exit_code"] == 0 and normal_banner else "FAIL"
            ) if observation["exit_code"] is not None else observation["result"]
            evidence["runtime_matrix"]["cli_version_startup"] = observation["result"]
            evidence["runtime_matrix"]["rust_runtime_startup"] = observation["result"]
        if binary_name == "daemon" and args == ("--probe",):
            banner = "iOS-Unsandboxed read-only preflight" in observation["sanitized_output"]
            preflight = "PASS" if banner else ("BLOCKED" if observation["result"] == "BLOCKED" else "FAIL")
            evidence["runtime_matrix"]["native_c17_preflight"] = preflight
            evidence["runtime_matrix"]["daemon_temporary_diagnostic_startup"] = preflight
        if label.startswith("Builder trust"):
            current = evidence["runtime_matrix"]["builder_trust_read_only_diagnostics"]
            evidence["runtime_matrix"]["builder_trust_read_only_diagnostics"] = (
                "FAIL" if observation["result"] == "FAIL" or current == "FAIL" else "PASS"
            )
        if label == "Builder trust signer inspect":
            evidence["runtime_matrix"]["builder_signer_detail_inspect"] = observation["result"]
        evidence["observations"].append(observation)

    if allow_ipc:
        if not recovery_session_confirmed:
            evidence["runtime_matrix"]["temporary_ipc_peer_credentials"] = "BLOCKED"
            evidence["limitations"].append(
                "Private IPC was not run: an independent SSH recovery session was not confirmed."
            )
        elif evidence["runtime_matrix"]["cli_version_startup"] != "PASS" or evidence["runtime_matrix"]["daemon_temporary_diagnostic_startup"] != "PASS":
            evidence["runtime_matrix"]["temporary_ipc_peer_credentials"] = "BLOCKED"
            evidence["limitations"].append("Private IPC was gated because temporary startup did not pass.")
        else:
            p006 = Path(__file__).with_name("ios-runtime-qualification.sh")
            command = ["sh", str(p006), "--runtime-test", "--cli", str(cli), "--daemon", str(daemon)]
            observation = run_process_group(command, timeout=max(timeout, 30.0))
            observation.update(
                {
                    "device_session_identifier": session_id,
                    "binary_sha256": {"cli": actual_cli, "daemon": actual_daemon},
                    "evidence_origin": "explicit_temporary_runtime",
                    "label": "P006 private-socket read-only IPC",
                }
            )
            evidence["runtime_matrix"]["temporary_ipc_peer_credentials"] = (
                "PASS" if "TEMPORARY_IPC_RESULT: PASS" in observation["sanitized_output"] else
                "FAIL" if observation["result"] == "FAIL" else "BLOCKED"
            )
            evidence["observations"].append(observation)
    return evidence


def run_process_group(command: list[str], timeout: float) -> dict[str, Any]:
    """Run P006 as a process group so a timeout can signal its cleanup trap."""
    started = utc_now()
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True
        )
    except FileNotFoundError as error:
        return {
            "timestamp_utc": started, "command": command, "exit_code": None,
            "termination_signal": None, "sanitized_output": redact(str(error)),
            "result": "BLOCKED", "interpretation": "Required command is unavailable.",
        }
    except OSError as error:
        return {
            "timestamp_utc": started, "command": command, "exit_code": None,
            "termination_signal": None, "sanitized_output": redact(str(error)),
            "result": "BLOCKED", "interpretation": "The operating system could not start P006.",
        }
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = process.communicate()
        return {
            "timestamp_utc": started, "command": command, "exit_code": None,
            "termination_signal": signal.SIGTERM, "sanitized_output": redact(output or ""),
            "result": "BLOCKED", "interpretation": f"P006 exceeded {timeout:g} seconds; SIGTERM cleanup was requested.",
        }
    code = process.returncode
    return {
        "timestamp_utc": started, "command": command,
        "exit_code": code if code >= 0 else None,
        "termination_signal": -code if code < 0 else None,
        "sanitized_output": redact(output or ""),
        "result": "PASS" if code == 0 else "FAIL",
        "interpretation": "P006 completed." if code == 0 else "P006 failed; no cause is inferred.",
    }


def _version(value: int) -> str:
    return f"{(value >> 16) & 0xffff}.{(value >> 8) & 0xff}.{value & 0xff}"


def inspect_macho(data: bytes) -> dict[str, Any]:
    if len(data) < 32 or data[:4] != bytes.fromhex("cffaedfe"):
        raise ValueError("expected a thin little-endian 64-bit Mach-O image")
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<IiiIIIII", data)
    if magic != 0xFEEDFACF or cpu & 0xFFFFFFFF != 0x0100000C:
        raise ValueError("Mach-O is not ARM64")
    if ncmds > 4096 or sizeofcmds > len(data) - 32:
        raise ValueError("Mach-O load-command bounds are invalid")
    offset = 32
    end = offset + sizeofcmds
    dependencies: list[str] = []
    min_ios: str | None = None
    platform: int | None = None
    code_signature: tuple[int, int] | None = None
    symbols: set[str] = set()
    string_table: tuple[int, int] | None = None
    symbol_table: tuple[int, int] | None = None
    for _ in range(ncmds):
        if offset + 8 > end:
            raise ValueError("truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > end:
            raise ValueError("invalid Mach-O load-command size")
        if cmd == 0x32 and cmdsize >= 24:  # LC_BUILD_VERSION
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", data, offset + 8)
            min_ios = _version(minos)
        elif cmd == 0x25 and cmdsize >= 16:  # LC_VERSION_MIN_IPHONEOS
            minos, sdk = struct.unpack_from("<II", data, offset + 8)
            min_ios = _version(minos)
            platform = 2
        elif cmd in {0xC, 0x80000018, 0x8000001F, 0x80000023, 0x20} and cmdsize >= 24:
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset < cmdsize:
                raw = data[offset + name_offset : offset + cmdsize].split(b"\0", 1)[0]
                dependencies.append(raw.decode("utf-8", errors="replace"))
        elif cmd == 0x1D and cmdsize >= 16:  # LC_CODE_SIGNATURE
            code_signature = struct.unpack_from("<II", data, offset + 8)
        elif cmd == 0x2 and cmdsize >= 24:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, offset + 8)
            symbol_table, string_table = (symoff, nsyms), (stroff, strsize)
        offset += cmdsize
    if offset != end:
        raise ValueError("Mach-O load-command size does not match header")
    if symbol_table and string_table:
        symoff, nsyms = symbol_table
        stroff, strsize = string_table
        if nsyms > 2_000_000 or symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
            raise ValueError("Mach-O symbol table bounds are invalid")
        string_bytes = data[stroff : stroff + strsize]
        for index in range(nsyms):
            string_index = struct.unpack_from("<I", data, symoff + index * 16)[0]
            if string_index < strsize:
                name = string_bytes[string_index:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
                if name:
                    symbols.add(name)
    signature_status = "unsigned"
    if code_signature:
        dataoff, datasize = code_signature
        if datasize and dataoff + datasize <= len(data):
            signature = data[dataoff : dataoff + datasize]
            if signature[:4] == bytes.fromhex("fade0cc0") and len(signature) >= 12:
                count = struct.unpack_from(">I", signature, 8)[0]
                code_directory = None
                for index in range(min(count, 64)):
                    if 12 + index * 8 + 8 > len(signature):
                        break
                    slot, blob_offset = struct.unpack_from(">II", signature, 12 + index * 8)
                    if blob_offset + 16 <= len(signature) and signature[blob_offset : blob_offset + 4] == bytes.fromhex("fade0c02"):
                        code_directory = signature[blob_offset:]
                        break
                if code_directory and len(code_directory) >= 12:
                    code_flags = struct.unpack_from(">I", code_directory, 8)[0]
                    signature_status = "adhoc_signed" if code_flags & 0x2 else "signed_unverified"
                else:
                    signature_status = "signature_metadata_unrecognized"
            else:
                signature_status = "signature_metadata_unrecognized"
        else:
            signature_status = "signature_metadata_invalid"
    test_hook_symbols = sorted(
        symbol for symbol in symbols
        if "test_v1" in symbol or "test_scope" in symbol or "test_evaluate" in symbol
    )
    return {
        "architecture": "arm64",
        "file_type": "MH_EXECUTE" if filetype == 2 else f"Mach-O filetype {filetype}",
        "minimum_ios": min_ios,
        "platform_id": platform,
        "dynamic_dependencies": sorted(set(dependencies)),
        "code_signature_metadata": signature_status,
        "code_signature_trusted_by_amethyst": "UNVERIFIED",
        "builder_admin_linkage": "PASS" if "_iu_builder_admin_v1" in symbols else "FAIL",
        "builder_admin_test_hook_absent": "PASS" if "_iu_builder_admin_test_v1" not in symbols else "FAIL",
        "test_hook_symbols": test_hook_symbols,
        "test_hook_markers": [marker.decode("ascii") for marker in TEST_HOOK_MARKERS if marker in data],
    }


def _safe_zip_names(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    entries: dict[str, zipfile.ZipInfo] = {}
    for info in archive.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or not info.filename:
            raise ValueError("artifact ZIP contains an unsafe path")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("artifact ZIP contains a symbolic link")
        if info.flag_bits & 0x1:
            raise ValueError("artifact ZIP contains an encrypted entry")
        if info.file_size > 64 * 1024 * 1024:
            raise ValueError("artifact ZIP contains an oversized entry")
        name = info.filename.rstrip("/")
        if name in entries:
            raise ValueError("artifact ZIP contains duplicate paths")
        entries[name] = info
    return entries


def verify_workflow_run(
    run_id: str,
    expected_head_sha: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if not run_id.isdigit() or not re.fullmatch(r"[0-9a-fA-F]{40}", expected_head_sha):
        return {"run_id": run_id, "expected_head_sha": expected_head_sha, "result": "BLOCKED"}
    command = [
        "gh", "run", "view", run_id, "--repo", "nghianguyen150612/iOS-Unsandboxed",
        "--json", "headSha,status,conclusion",
    ]
    result = _run_process(command, 15.0, runner)
    if result["result"] == "BLOCKED":
        return {
            "run_id": run_id, "expected_head_sha": expected_head_sha,
            "result": "BLOCKED", "limitation": result["interpretation"],
        }
    if result["exit_code"] != 0:
        return {
            "run_id": run_id, "expected_head_sha": expected_head_sha,
            "result": "BLOCKED", "limitation": "GitHub Actions run metadata could not be retrieved.",
        }
    try:
        metadata = json.loads(result["sanitized_output"])
    except json.JSONDecodeError:
        return {
            "run_id": run_id, "expected_head_sha": expected_head_sha,
            "result": "BLOCKED", "limitation": "GitHub Actions run metadata was malformed.",
        }
    observed_head = metadata.get("headSha")
    success = (
        observed_head == expected_head_sha
        and metadata.get("status") == "completed"
        and metadata.get("conclusion") == "success"
    )
    return {
        "run_id": run_id,
        "observed_head_sha": observed_head,
        "expected_head_sha": expected_head_sha,
        "status": metadata.get("status"),
        "conclusion": metadata.get("conclusion"),
        "result": "PASS" if success else "FAIL",
    }


def inspect_artifact(
    path: Path,
    workflow_run_id: str | None = None,
    expected_head_sha: str | None = None,
    run_lookup: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Read and validate an uploaded GitHub artifact ZIP without extracting it."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("artifact must be a regular non-symlink file")
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("artifact ZIP exceeds the 64 MiB inspection limit")
    artifact_sha = sha256_file(path)
    with zipfile.ZipFile(path, "r") as archive:
        entries = _safe_zip_names(archive)
        if sum(info.file_size for info in entries.values()) > 128 * 1024 * 1024:
            raise ValueError("artifact ZIP expands beyond the 128 MiB inspection limit")
        manifests = [name for name in entries if name.endswith("package-manifest")]
        if len(manifests) != 1:
            raise ValueError("artifact must contain exactly one package-manifest")
        manifest_name = manifests[0]
        package_root = PurePosixPath(manifest_name).parent.as_posix()

        def read_member(relative: str) -> bytes:
            name = f"{package_root}/{relative}" if package_root != "." else relative
            if name not in entries:
                raise ValueError(f"artifact is missing {relative}")
            return archive.read(entries[name])

        manifest_bytes = read_member("package-manifest")
        lines = manifest_bytes.decode("ascii").splitlines()
        if lines[:6] != [
            "ios-unsandboxed-package", "schema_version=1", "project_version=0.1.0",
            "platform=ios", "architecture=arm64", "minimum_ios=12.0",
        ]:
            raise ValueError("package manifest header or target metadata is invalid")
        if len(lines) != 11 + len(PACKAGE_FILES):
            raise ValueError("package manifest has an unexpected record count")
        allowed_signing = {"unsigned", "adhoc_signed", "signed_unverified", "signature_verification_passed", "unknown"}
        allowed_verification = {"passed", "failed", "not_applicable", "unknown", "mixed"}
        signing_fields = lines[6].split("=", 1)
        verification_fields = lines[7].split("=", 1)
        if len(signing_fields) != 2 or signing_fields[0] != "signing_status" or signing_fields[1] not in allowed_signing:
            raise ValueError("package signing classification is malformed")
        if len(verification_fields) != 2 or verification_fields[0] != "signature_verification" or verification_fields[1] not in allowed_verification:
            raise ValueError("package signature-verification classification is malformed")
        artifact_signing: dict[str, dict[str, str]] = {}
        expected_macho_paths = (
            "payload/bin/ios-unsandboxed",
            "payload/bin/ios-unsandboxedd",
            "payload/share/installer-helper",
        )
        for line, expected_path in zip(lines[8:11], expected_macho_paths):
            fields = line.removeprefix("artifact_signing=").split("|")
            if len(fields) != 3 or fields[0] != expected_path or fields[1] not in allowed_signing or fields[2] not in {"passed", "failed", "not_applicable", "unknown"}:
                raise ValueError("per-binary signing metadata is malformed")
            artifact_signing[expected_path] = {"classification": fields[1], "verification": fields[2]}
        signing_values = {record["classification"] for record in artifact_signing.values()}
        verification_values = {record["verification"] for record in artifact_signing.values()}
        aggregate_signing = next(iter(signing_values)) if len(signing_values) == 1 else "unknown"
        aggregate_verification = next(iter(verification_values)) if len(verification_values) == 1 else "mixed"
        if signing_fields[1] != aggregate_signing or verification_fields[1] != aggregate_verification:
            raise ValueError("package signing summary disagrees with per-binary records")
        files: dict[str, dict[str, Any]] = {}
        for line in lines[11:]:
            if not line.startswith("file="):
                raise ValueError("package manifest has a malformed payload record")
            fields = line[5:].split("|")
            if len(fields) != 4 or fields[0] not in PACKAGE_FILES:
                raise ValueError("package manifest contains an unexpected payload entry")
            relative, kind, mode, digest = fields
            if kind != "regular" or mode != f"{PACKAGE_FILES[relative]:04o}" or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"invalid manifest metadata for {relative}")
            if relative in files:
                raise ValueError(f"duplicate manifest entry: {relative}")
            data = read_member(relative)
            actual = sha256_bytes(data)
            if actual != digest:
                raise ValueError(f"payload hash mismatch: {relative}")
            files[relative] = {"mode": mode, "sha256": actual, "size_bytes": len(data)}
        if set(files) != set(PACKAGE_FILES):
            raise ValueError("package manifest is missing a required payload")
        checksum_lines = read_member("SHA256SUMS").decode("ascii").splitlines()
        expected_sums = [f"{sha256_bytes(manifest_bytes)}  package-manifest"]
        expected_sums.extend(f"{files[name]['sha256']}  {name}" for name in PACKAGE_FILES)
        if checksum_lines != expected_sums:
            raise ValueError("SHA256SUMS does not match package-manifest and payloads")
        try:
            plist = plistlib.loads(read_member("payload/share/com.ios-unsandboxed.daemon.plist"))
        except Exception as error:
            raise ValueError("package LaunchDaemon plist is malformed") from error
        if plist.get("ProgramArguments") != ["/usr/local/bin/ios-unsandboxedd", "--serve"]:
            raise ValueError("package LaunchDaemon arguments do not match the passive template")
        if plist.get("UserName") != "root" or plist.get("GroupName") != "wheel":
            raise ValueError("package LaunchDaemon owner is unexpected")
        if plist.get("RunAtLoad") is not True or plist.get("KeepAlive") is not False:
            raise ValueError("package LaunchDaemon activation policy is unexpected")

        archive_name = f"{PurePosixPath(package_root).name}.tar.gz"
        candidates = [name for name in entries if PurePosixPath(name).name == archive_name]
        if len(candidates) != 1:
            raise ValueError("artifact must contain exactly one matching deterministic tar.gz")
        archive_bytes = archive.read(entries[candidates[0]])
        expected_zip_files = {
            candidates[0],
            f"{package_root}/package-manifest" if package_root != "." else "package-manifest",
            f"{package_root}/SHA256SUMS" if package_root != "." else "SHA256SUMS",
        }
        expected_zip_files.update(
            f"{package_root}/{relative}" if package_root != "." else relative
            for relative in PACKAGE_FILES
        )
        actual_zip_files = {name for name, info in entries.items() if not info.is_dir()}
        if actual_zip_files != expected_zip_files:
            raise ValueError("artifact ZIP contains unexpected or missing files")
        if len(archive_bytes) < 10 or archive_bytes[:2] != b"\x1f\x8b" or archive_bytes[4:8] != b"\0\0\0\0":
            raise ValueError("package archive is invalid or has a non-normalized gzip timestamp")
        tar_members: list[str] = []
        with tarfile.open(fileobj=__import__("io").BytesIO(archive_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise ValueError("package tar contains an unsafe path")
                if not (member.isfile() or member.isdir()) or member.issym() or member.islnk():
                    raise ValueError("package tar contains an unsupported entry type")
                if member.uid != 0 or member.gid != 0 or member.mtime != 0:
                    raise ValueError("package tar ownership or timestamp is not normalized")
                tar_members.append(member.name)
            if not tar_members or tar_members[0] != PurePosixPath(package_root).name:
                raise ValueError("package tar root directory is unexpected")
            if len(tar_members) != len(set(tar_members)):
                raise ValueError("package tar contains duplicate paths")
            if tar_members[1:] != sorted(tar_members[1:]):
                raise ValueError("package tar members are not sorted deterministically")
            root_name = PurePosixPath(package_root).name
            expected_tar_files = {
                "package-manifest": manifest_bytes,
                "SHA256SUMS": read_member("SHA256SUMS"),
                **{relative: read_member(relative) for relative in PACKAGE_FILES},
            }
            expected_tar_members = [root_name, *sorted(
                [f"{root_name}/payload", f"{root_name}/payload/bin", f"{root_name}/payload/share"]
                + [f"{root_name}/{relative}" for relative in expected_tar_files]
            )]
            if tar_members != expected_tar_members:
                raise ValueError("package tar members do not match the package directory")
            for relative, expected_data in expected_tar_files.items():
                tar_path = f"{root_name}/{relative}"
                member_info = tar.getmember(tar_path) if tar_path in tar_members else None
                member = tar.extractfile(tar_path) if member_info else None
                if member is None or member.read() != expected_data:
                    raise ValueError(f"package archive payload mismatch: {relative}")
                expected_mode = PACKAGE_FILES.get(relative, 0o644)
                if stat.S_IMODE(member_info.mode) != expected_mode:
                    raise ValueError(f"package archive mode mismatch: {relative}")

        binaries: dict[str, Any] = {}
        for relative in (
            "payload/bin/ios-unsandboxed",
            "payload/bin/ios-unsandboxedd",
            "payload/share/installer-helper",
        ):
            data = read_member(relative)
            metadata = inspect_macho(data)
            metadata["sha256"] = sha256_bytes(data)
            metadata["size_bytes"] = len(data)
            recorded_signature = artifact_signing[relative]["classification"]
            normalized_signature = {
                "signature_verification_passed": "signed_unverified",
                "unknown": "signature_metadata_unrecognized",
            }.get(recorded_signature, recorded_signature)
            metadata["manifest_signature_consistency"] = (
                "PASS" if metadata["code_signature_metadata"] == normalized_signature else "FAIL"
            )
            metadata["minimum_ios_check"] = (
                "PASS"
                if metadata["minimum_ios"] == "12.0.0" and metadata["platform_id"] == 2
                and metadata["file_type"] == "MH_EXECUTE"
                else "FAIL"
            )
            metadata["production_test_hook_check"] = "PASS" if not metadata["test_hook_markers"] else "FAIL"
            binaries[relative] = metadata
        signing = signing_fields[1]
        if workflow_run_id or expected_head_sha:
            workflow_run = (
                verify_workflow_run(workflow_run_id or "", expected_head_sha or "", run_lookup)
            )
        else:
            workflow_run = {"result": "UNVERIFIED", "limitation": "No GitHub workflow run was supplied."}
        return {
            "schema_version": "p013e2.artifact-inspection.v1",
            "artifact_sha256": artifact_sha,
            "artifact_zip": path.name,
            "workflow_run": workflow_run,
            "package_directory": package_root,
            "package_archive": candidates[0],
            "package_archive_sha256": sha256_bytes(archive_bytes),
            "package_manifest_sha256": sha256_bytes(manifest_bytes),
            "package_target": {"platform": "ios", "architecture": "arm64", "minimum_ios": "12.0"},
            "package_signing_classification": signing,
            "manifest_binary_signing": artifact_signing,
            "amethyst_trust": "UNVERIFIED",
            "binaries": binaries,
            "integrity": "PASS",
            "limitations": [
                "Code-signature metadata does not establish Amethyst trust or device loader acceptance.",
                "Artifact inspection does not establish runtime behavior or physical-device compatibility.",
            ],
        }


def _write_json(value: dict[str, Any], output: str | None) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if output:
        target = Path(output)
        if target.is_symlink():
            raise ValueError("refusing to write evidence through a symlink")
        absolute = Path(os.path.abspath(target))
        protected = (
            Path("/usr/local"), Path("/var/lib"), Path("/Library/LaunchDaemons"),
            Path("/var/run"), Path("/var/log"), Path("/System"),
        )
        if any(absolute == root or root in absolute.parents for root in protected):
            raise ValueError("refusing to write evidence under a production system path")
        target.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action")
    artifact_parser = subparsers.add_parser("inspect-artifact", help="inspect a downloaded GitHub Actions artifact ZIP")
    artifact_parser.add_argument("artifact", type=Path)
    artifact_parser.add_argument("--workflow-run-id")
    artifact_parser.add_argument("--expected-head-sha")
    artifact_parser.add_argument("--output")
    inventory_parser = subparsers.add_parser("inventory", help="run or convert the read-only P006 inventory")
    inventory_parser.add_argument("--root", type=Path, help="isolated host fixture root only")
    inventory_parser.add_argument("--transcript", type=Path, help="convert a saved P006 transcript instead of executing it")
    inventory_parser.add_argument("--exit-code", type=int, default=0, help="exit status of the saved transcript command")
    inventory_parser.add_argument("--session-id", help="non-secret operator-selected SSH session label")
    inventory_parser.add_argument("--output")
    runtime_parser = subparsers.add_parser("runtime", help="explicit hash-pinned temporary diagnostic execution")
    runtime_parser.add_argument("--cli", required=True, type=Path)
    runtime_parser.add_argument("--daemon", required=True, type=Path)
    runtime_parser.add_argument("--artifact-evidence", required=True, type=Path)
    runtime_parser.add_argument("--device-evidence", required=True, type=Path)
    runtime_parser.add_argument("--expected-head-sha", required=True)
    runtime_parser.add_argument("--authorize-temporary-runtime", action="store_true")
    runtime_parser.add_argument("--private-ipc", action="store_true")
    runtime_parser.add_argument("--recovery-session-confirmed", action="store_true")
    runtime_parser.add_argument("--session-id", required=True, help="non-secret operator-selected SSH session label")
    runtime_parser.add_argument("--inspect-signer-id", help="optional read-only builder signer identifier")
    runtime_parser.add_argument("--timeout", type=float, default=15.0)
    runtime_parser.add_argument("--output")
    unavailable_parser = subparsers.add_parser(
        "unavailable", help="record that physical-device qualification could not be run"
    )
    unavailable_parser.add_argument(
        "--reason", required=True, help="non-secret reason no authorized device observation was collected"
    )
    unavailable_parser.add_argument("--output")
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv.insert(0, "inventory")
    args = parser.parse_args(argv)
    action = args.action
    try:
        if action == "inspect-artifact":
            _write_json(
                inspect_artifact(args.artifact, args.workflow_run_id, args.expected_head_sha), args.output
            )
            return 0
        if action == "runtime":
            if args.artifact_evidence.is_symlink() or not args.artifact_evidence.is_file():
                raise ValueError("artifact evidence must be a regular non-symlink JSON file")
            if args.device_evidence.is_symlink() or not args.device_evidence.is_file():
                raise ValueError("device evidence must be a regular non-symlink JSON file")
            if args.artifact_evidence.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("artifact evidence exceeds the 4 MiB inspection limit")
            if args.device_evidence.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("device evidence exceeds the 4 MiB inspection limit")
            artifact_report = json.loads(args.artifact_evidence.read_text(encoding="utf-8"))
            device_report = json.loads(args.device_evidence.read_text(encoding="utf-8"))
            evidence = run_runtime(
                args.cli, args.daemon, artifact_report, device_report, args.expected_head_sha,
                args.authorize_temporary_runtime, args.private_ipc,
                args.recovery_session_confirmed, args.timeout,
                session_id=args.session_id, signer_id=args.inspect_signer_id,
            )
            _write_json(evidence, args.output)
            return 0
        if action == "unavailable":
            _write_json(unavailable_evidence(args.reason), args.output)
            return 0
        if args.transcript:
            transcript = args.transcript.read_text(encoding="utf-8", errors="replace")
            evidence = parse_inventory(transcript, args.exit_code, "provided_transcript_unverified", args.session_id)
        else:
            script = Path(__file__).with_name("ios-runtime-qualification.sh")
            command = ["sh", str(script)]
            if args.root:
                command += ["--root", str(args.root)]
            result = _run_process(command, 45.0)
            evidence = parse_inventory(
                result["sanitized_output"],
                result["exit_code"] if result["exit_code"] is not None else 1,
                "host_fixture" if args.root else "local_read_only_inventory",
                args.session_id,
            )
            evidence["observations"][0]["termination_signal"] = result["termination_signal"]
            evidence["observations"][0]["result"] = result["result"]
            evidence["observations"][0]["interpretation"] = result["interpretation"]
        _write_json(evidence, args.output)
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        failure = base_evidence("inspection_tool")
        failure["limitations"].append(redact(str(error)))
        failure["observations"].append(
            {
                "timestamp_utc": utc_now(), "device_session_identifier": None,
                "command": sys.argv, "exit_code": None, "termination_signal": None,
                "sanitized_output": redact(str(error)), "binary_sha256": None,
                "evidence_origin": "inspection_tool", "result": "BLOCKED",
                "interpretation": "Evidence could not be produced; this is not a device result.",
            }
        )
        _write_json(failure, getattr(args, "output", None))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
