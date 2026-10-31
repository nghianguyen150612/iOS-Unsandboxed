# P013E-2 Device Qualification Gates

P013E-2 adds evidence collection for the reference iPad while preserving the P006 read-only inventory and private-socket harness. The default workflow inspects; temporary binary execution and private IPC require separate explicit options and are never enabled by default.

Use only `PASS`, `FAIL`, `BLOCKED`, `NOT RUN`, or `UNVERIFIED` for result fields. Record an exit code only when a command ran. A missing executable or inspection utility is `BLOCKED`, while a command that ran and returned nonzero is `FAIL`. A signal is recorded separately from an exit code. An expected profile value is never copied into the observed field.

| Gate | Required evidence | Qualification boundary |
|---|---|---|
| Final artifact association | GitHub Actions run ID, observed HEAD SHA, expected HEAD SHA, run status and conclusion | GitHub workflow metadata only |
| Package integrity | ZIP and package archive hashes, package manifest and `SHA256SUMS`, path/type/mode/hash checks, normalized tar metadata | Offline package bytes; do not run packaging scripts for inspection |
| Mach-O compatibility metadata | ARM64 architecture, `MH_EXECUTE`, iOS 12.0 load command, dynamic dependencies, helper linkage, signature metadata, test-hook scan | Metadata does not prove device loader acceptance or Amethyst trust |
| Device inventory | Observed model/product identifier, iOS version/build, kernel/architecture, rootful paths, ownership, Amethyst/project metadata and utility availability | Existing authorized SSH session; no configuration changes |
| CLI/Rust startup | Exact hash-pinned `--version`, `--help`, `doctor`, `doctor --amethyst`, and `status` results | Explicit temporary-runtime approval and unique private staging directory |
| Native preflight and daemon startup | Daemon `--probe` exact status/output and binary hash | Temporary diagnostic invocation only; no production `--serve` |
| Private IPC | P006 private test socket, read-only requests, peer credentials, shutdown and cleanup | Startup passes first; a separate recovery SSH session is confirmed |
| Builder trust | Read-only `status`/`list`, optional `inspect SIGNER_ID` | No trust mutation; signer ID must be observed and explicitly supplied |
| DSSE and publisher trust | Safe offline fixture verification, with each trust result recorded independently | Never infer physical-device trust from host fixtures |
| Amethyst compatibility | Installed component presence, hashes, Mach-O/signature metadata, installed-build identity, live hook evidence | Filenames/package version are not installed-build identity or hook activity |
| Persistence and activation | Rootful ownership/mode, filesystem durability assumptions, execution activation state | Read-only observation only; never reboot or alter the device |

The machine-readable device report uses schema `p013e2.device-evidence.v1`; the offline artifact report uses `p013e2.artifact-inspection.v1`. Both keep host fixtures separate from physical-device observations. Detailed implementation and operator commands are in [the qualification architecture](../architecture/p013-device-runtime-qualification.md). Current evidence is in [P013E2_DEVICE_RESULTS.md](P013E2_DEVICE_RESULTS.md).
