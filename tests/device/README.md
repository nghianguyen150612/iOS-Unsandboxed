# Device qualification tools

`ios-runtime-qualification.sh` is a POSIX `sh` inventory for the supported rootful iPad profile. It runs read-only by default and reports missing utilities instead of assuming Procursus includes them. It records selected machine, OS, kernel, effective identity, environment-presence, filesystem, Amethyst component, package, plist, and launchd facts. It omits environment values and unrelated package/process data.

Run the inventory on the device with:

```sh
sh tests/device/ios-runtime-qualification.sh
```

`--root DIR` redirects filesystem probes below an isolated fixture root. It is for the host fixture test only; it does not query host package/launchd state and does not provide device evidence.

The opt-in runtime mode requires both explicit staged binary paths:

```sh
sh tests/device/ios-runtime-qualification.sh \
  --runtime-test \
  --cli /tmp/ios-unsandboxed-p006-run/ios-unsandboxed \
  --daemon /tmp/ios-unsandboxed-p006-run/ios-unsandboxedd
```

It uses a new `/tmp/ios-unsandboxed-p006.*` directory, a private `--test-socket`, read-only status requests, and SIGTERM. It never starts production `--serve`, writes install-state, changes socket permissions, or calls management operations. It removes only its own test directory; an unexpected leftover prevents directory removal and is reported. SSH continuity and root/non-root coverage must be verified manually from existing sessions.

`inspect-ios-build.sh IOS_CLI IOS_DAEMON` runs on the macOS CI runner after `make build-ios`. It records hashes, Mach-O architecture/type, iOS 12 deployment commands, dynamic dependencies, and code-signing display/validation. It does not sign or deploy. Host signature validity, an ad-hoc signature, Amethyst trust, sandbox state, and successful device startup remain distinct.

`host-fixture-test.py` checks shell syntax and read-only path reporting against a temporary fixture tree. It does not emulate Darwin sockets or device behavior and ordinary CI does not require an iPad.

`p013e2_qualification.py` extends this P006 harness. Its default mode is read-only inventory and it delegates path/platform probes to `ios-runtime-qualification.sh`; host fixture mode remains explicitly labeled and is never reported as device evidence. It emits versioned JSON, sanitizes captured output, preserves command exit codes and signals, distinguishes unavailable tools from failed commands, and records the observed identifiers separately from the expected iPad profile.

On the device, run inventory from the existing authorized SSH session and keep the session label non-secret:

```sh
python3 tests/device/p013e2_qualification.py inventory --session-id ipad-reference-session
```

The JSON is written to stdout by default. To convert a saved P006 transcript on the host when Python is unavailable on the device, pass `inventory --transcript FILE --exit-code STATUS --session-id LABEL`. A host capture remains `provided_transcript_unverified`; retain the original session and source alongside it. Expected iPad identifiers never fill missing observations.

For a later approved runtime phase, use the `inventory` JSON from the same SSH session. Keep Phase B read-only by collecting it to the host; only copy it into the private temporary directory after Phase C staging/runtime approval is available.

Inspect a downloaded GitHub Actions artifact without extracting or rebuilding it:

```sh
python3 tests/device/p013e2_qualification.py inspect-artifact /tmp/ios-unsandboxed-artifact.zip \
  --workflow-run-id 41201769177 \
  --expected-head-sha 3371d714876cba5c5ad7d8a5724942e46375df5f
```

The inspector validates the GitHub run association, package manifest and hashes, normalized tar archive, ARM64/iOS deployment commands, dependencies, helper linkage, signature metadata, and test-hook markers. It does not execute a package script, extract archive paths, sign files, or establish Amethyst trust.

Temporary diagnostic startup is a separate, opt-in mode. Run it only after receiving explicit approval for temporary staging/execution and confirming an independent SSH recovery session. Stage the exact inspected CLI and daemon directly inside a new mode-0700 `/tmp/ios-unsandboxed-p013e2.*` directory. The tool checks owner, type, link count, executable mode, and SHA-256 against the expected artifact before invoking only the fixed read-only commands shown below. A mismatch or unsafe path blocks execution.

```sh
python3 tests/device/p013e2_qualification.py runtime \
  --cli /tmp/ios-unsandboxed-p013e2.unique/ios-unsandboxed \
  --daemon /tmp/ios-unsandboxed-p013e2.unique/ios-unsandboxedd \
  --artifact-evidence /path/to/P013E2_ARTIFACT_EVIDENCE.json \
  --device-evidence /tmp/ios-unsandboxed-p013e2.unique/device-evidence.json \
  --expected-head-sha FINAL_ARTIFACT_HEAD_SHA \
  --authorize-temporary-runtime \
  --session-id ipad-reference-session
```

The device-evidence file must be a preceding P006 inventory from the same session label, with observed `iPad4,4`, `arm64`, and iOS `12.5.7`. Imported or mismatched device evidence blocks execution. Keep this report inside the approved private temporary directory during Phase C; no production path is used. The artifact-evidence file must come from `inspect-artifact`, match the successful workflow run and expected HEAD, and pass archive/Mach-O checks. Runtime hashes come from that report; arbitrary hash values are not accepted. This runs `--version`, `--help`, `doctor`, `doctor --amethyst`, `status`, and builder-trust `status`/`list` on the CLI, plus daemon `--probe`. It does not run a management command or trust mutation. To opt into the existing P006 private-socket checks, add `--private-ipc --recovery-session-confirmed`; both temporary startup checks must pass first. The second flag records the operator's assertion and cannot verify another SSH session itself. Do not add `--private-ipc` if SSH continuity or server stability is uncertain.

If a signer identifier was observed in the read-only list and is safe to inspect, `--inspect-signer-id SIGNER_ID` adds the read-only detail query. It is omitted when no signer identifier is known.

Machine evidence uses `p013e2.device-evidence.v1`; artifact inspection uses `p013e2.artifact-inspection.v1`. Host fixtures test malformed transcripts, missing binaries/tools, failed startup, signals, hash mismatch, unsafe paths, timeouts, package integrity, and Mach-O metadata. They do not simulate an iPad.
