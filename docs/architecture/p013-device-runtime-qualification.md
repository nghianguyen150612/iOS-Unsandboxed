# P013 Device Runtime Qualification Architecture

## Components

P013E-2 extends the P006 workflow rather than adding a competing device inventory:

- `tests/device/ios-runtime-qualification.sh` remains the read-only source for platform, identity, path, package, launchd, file, and ownership probes. It now emits the exact command arguments and exit statuses for its observation, metadata, hash, and tool calls.
- `tests/device/p013e2_qualification.py` wraps that P006 output in versioned JSON, redacts common secret forms, classifies expected-versus-observed identifiers, inspects the downloaded artifact ZIP without extraction, and implements the hash-pinned temporary-runtime guard.
- `tests/device/p013e2_test.py` exercises malformed output, missing tools/files, startup failures, signals, hashes, paths, timeout cleanup, archive contents, and Mach-O metadata using host-only fixtures.

`make device-harness-test` runs both the preserved P006 host fixture and the new P013E-2 fixtures. `make test` includes that target. No test requires a live iPad.

## Evidence schemas

Device observations use `p013e2.device-evidence.v1`. Each observation carries a timestamp, optional non-secret operator-selected session label, exact argument vector, exit code or termination signal, sanitized output, optional binary SHA-256, evidence origin, result classification, and interpretation. The document records the expected model profile separately from values parsed from P006. Host fixtures are labeled `host_fixture`; transcript imports are labeled `provided_transcript_unverified` and cannot establish device provenance.

The offline artifact report uses `p013e2.artifact-inspection.v1`. It records the uploaded ZIP, exact GitHub Actions run association, archive and manifest SHA-256 values, payload hashes, Mach-O metadata, dependencies, signature metadata, installer-helper linkage, and test-hook checks. The inspector rejects unsafe/duplicate ZIP and tar paths and validates package bytes without unpacking or rebuilding the artifact.

When a device session is unavailable, `unavailable --reason ...` emits an empty observation set, null observed identifiers, `NOT RUN` device gates, and a sanitized blocker. It does not synthesize command results.

## Runtime guard

The default command is read-only inventory. Runtime mode requires all of the following before starting any project binary:

1. The operator passes `--authorize-temporary-runtime`, which records explicit approval for temporary staging/runtime checks.
2. A preceding local P006 inventory is supplied from the same session label. Its observed product identifier, architecture and OS version must match the declared reference iPad profile, and its three identity commands must have exit status zero. Imported transcripts and host fixtures cannot authorize runtime checks.
3. CLI and daemon are regular executable files in the same direct child directory of `/tmp` named `ios-unsandboxed-p013e2.*`.
4. The staging directory is owned by the current identity, mode `0700`, and not a symlink. Binaries are owned by that identity, single-linked, non-symlink regular files.
5. The supplied artifact evidence is schema-valid, has `integrity=PASS`, matches a successful completed GitHub run on the requested HEAD, and records ARM64/iOS 12.0 production binaries without test-hook markers.
6. Both staged binary SHA-256 values match the CLI/daemon records in that inspected artifact evidence.

On mismatched device identity/session, unassociated or malformed artifact evidence, hash mismatch, unsafe path, missing binary, or missing executable, runtime commands do not run and the evidence result is `FAIL` or `BLOCKED` as appropriate. The device and artifact reports are stored separately and both are required. Successful hash validation invokes only fixed diagnostic argument vectors: CLI `--version`, `--help`, `doctor`, `doctor --amethyst`, `status`, builder-trust `status` and `list`, optional signer `inspect`, and daemon `--probe`. No command-line field accepts an arbitrary executable or management operation. The authorization flag is an operator acknowledgement; this tool cannot grant approval on a user's behalf.

Private IPC is a further opt-in. `--private-ipc` requires both temporary startup gates to pass and `--recovery-session-confirmed`; it then delegates to the P006 private-socket harness. That flag is an operator assertion, not proof that another SSH route works. The harness uses a unique private test socket and never starts production `--serve` or touches the production socket. If the process group times out, the wrapper sends SIGTERM so P006 can run its cleanup trap, then SIGKILL only after a grace period.

The runtime wrapper requires Python 3.10 or newer and the existing P006 `sh` harness. If unavailable, report the missing utility and use P006's human-readable read-only inventory only; do not install a runtime dependency on the iPad for qualification.

## Trust and interpretation boundaries

Mach-O architecture, minimum OS, dependency, and signature load-command metadata do not establish device loader acceptance, cryptographic trust, Amethyst trust, or successful startup. An unsigned/ad-hoc signature is not treated as trusted. Package name/version and component filenames do not establish Amethyst installed-build identity or active hook behavior. Host `SO_PEERCRED` and fixture results do not establish iOS `getpeereid` behavior. Successful signatures never authorize execution. Execution remains disabled and operational authorization remains false.

Physical-device gates remain `NOT RUN` when no authorized SSH session and required temporary-runtime approval are available. A host fixture is never promoted to a physical observation.
