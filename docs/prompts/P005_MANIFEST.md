# P005 manifest — device IPC qualification and safe service lifecycle

## Outcome

**P005: PARTIAL — host lifecycle/state implementation is ready for review; physical-device qualification remains NOT RUN.** The LaunchDaemon plist is passive packaging only. No service was deployed or activated, and no execution capability was implemented. Local Apple ARM64 cross-compilation is blocked by this Linux host; the PR's macOS CI cross-build passed.

## Baseline and repository review

- Repository: https://github.com/nghianguyen150612/iOS-Unsandboxed
- Verified live `origin/main` before edits: `8331b30ca7055fedf1fdaab59190058883b48e64`.
- Verified P004 implementation commit `619cb9b38e85ba2c662476970ca753516ca3cd0c` and P004 merge ancestry; P004 merge is current main HEAD.
- Feature branch: `feat/p005-service-lifecycle`, created from that verified main.
- Working tree was clean before edits.
- Read P002, P003, and P004 manifests and the requested P004 IPC/security, preflight, policy, rootful layout, Makefile, CI, and README files.
- `docs/prompts/P001_MANIFEST.md` is absent from current main and the available P001 feature branch; no P001 manifest content was available to read. P001 path-contract docs remain present.

## Security review and corrections

- Production `--serve` requires effective UID 0 and a root:wheel `/var/run` parent without group/world write access. The socket remains `0600`; authenticated read-only semantics do not weaken pathname access. A future dedicated read-only group model is documented with authorization tests and the limitation that `getpeereid` does not report supplementary-group membership.
- Existing peer authentication is retained: Darwin/iOS `getpeereid`, Linux `SO_PEERCRED`; request payloads cannot claim identity. P005 reports the server-authenticated peer UID/GID only to that same read-only requester for qualification evidence.
- P004 `GET_STATUS` remains an unchanged 8-byte response. P005 adds request ID 4 with a separate lifecycle payload; the CLI has a tested fallback for P004 daemons.
- Review found fatal listener `poll`/`accept` errors returned success and signal handlers were installed after socket creation. Both are corrected: handlers are installed before setup, signals perform owned-socket cleanup, and fatal listener errors return failure.
- Lock/socket metadata checks now validate root:wheel or test-process ownership, modes, and inode identity. Stale-socket replacement and unlink still rely on a root-owned, non-writable parent to constrain portable pathname races. The best-effort immediate trailing-byte check is documented as unsuitable authorization for any future mutating operation.
- No Amethyst runtime integration exists. State errors and missing Amethyst components leave the diagnostic service available where the runtime socket can start and cannot enable execution.

## State and lifecycle implementation

- Added a read-only native C17 state loader for `/var/lib/ios-unsandboxed/install-state`.
- Schema 1 is exactly four LF-terminated lines: `ios-unsandboxed-state`, `schema_version=1`, `service_installation=installed`, and `execution_activation=disabled`.
- Production data directory is UID/GID 0 mode `0700`; state file is UID/GID 0 mode `0600`, regular, bounded, and opened without following its final component. Multiple hard links, wrong ownership/mode/type, malformed/truncated contents, and unknown schema fail closed. A descriptor opened before atomic replacement may report zero links and remains a complete snapshot. There is no migration or production writer.
- A state record is not execution authorization. The loader initializes activation to disabled and rejects any value other than the literal disabled field. No command or IPC operation can mutate it.
- `status` distinguishes daemon response/IPC, local daemon/plist file presence, launchd state (explicitly unknown), installation record, state/schema, Amethyst compatibility, activation, and device acceptance. When IPC is unavailable, state and activation remain unknown.
- Added a foreground, SIGTERM-aware service lifecycle and a dormant LaunchDaemon template at `packaging/rootful/com.ios-unsandboxed.daemon.plist`: root:wheel, `RunAtLoad=true`, `KeepAlive=false`, no socket activation. P005 does not install, load, bootstrap, kickstart, or activate it.
- Recovery, rollback limits, future manager ownership, and P006 gates are documented. No Apple/Amethyst job or file was changed.

## Device qualification

No physical iPad session is available in this workspace. There is no device output to report. The full bounded procedure is in `docs/validation/ios-device-ipc-qualification.md`; it starts with temporary read-only IPC, records peer credentials, covers root/non-root access, production socket ownership/mode, SIGTERM cleanup, and SSH preservation, and does not load launchd.

All device gates remain **NOT RUN**: A1489/A7/iOS build identification; ARM64 Mach-O execution and dynamic linker; installed Amethyst provenance; Procursus/rootful layout; native `getpeereid`; root/non-root SSH access; `/var/run`; device daemon restart and shutdown; launchd; reboot/jailbreak restart; and unrelated SSH preservation. Linux peer credential tests are not native iOS evidence.

## Validation

Results below must reflect the final commit. Host and Apple cross-compilation are reported separately from physical-device evidence.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --locked --workspace` | PASS — 11 unit tests |
| `make build` | PASS — Rust host CLI and strict C17 daemon build |
| `make test` | PASS — Rust, native/state, IPC, plist, and smoke checks |
| `make native-test` / state fixtures | PASS — preflight/policy, peer-auth, and state fixtures |
| `make ipc-test` | PASS — Linux `SO_PEERCRED`, protocol, lifecycle, restart, and same-UID integration |
| `make packaging-test` / Python `plistlib` parse | PASS — syntax/contract only |
| `make smoke-test` | PASS |
| `make build-ios` on local Linux host | BLOCKED: requires macOS, Xcode, and iPhoneOS SDK |
| Apple ARM64 iOS cross-compilation in PR CI | PASS — [PR workflow run](https://github.com/nghianguyen150612/iOS-Unsandboxed/actions/runs/40500328908), source commit `183cf48d430fa8f19c50351da7ab124bf551a533` |
| Physical reference iPad qualification | NOT RUN |

The Rust toolchain was already available under the user-local rustup directory but not on the initial shell `PATH`; the requested commands were run after exposing that existing toolchain. No repository toolchain files were changed.

## Changed files

- `.github/workflows/ci.yml`, `Makefile`, `README.md`
- `cli/src/ipc/client.rs`, `cli/src/ipc/mod.rs`, `cli/src/ipc/protocol.rs`, `cli/src/main.rs`
- `daemon/include/iu_ipc_server.h`, `daemon/src/ipc_server.c`, `daemon/src/main.c`
- `native/include/iu_ipc_protocol.h`, `native/include/iu_service_state.h`, `native/src/iu_service_state.c`, `native/README.md`
- `packaging/rootful/com.ios-unsandboxed.daemon.plist`, `packaging/rootful/install-state.example`
- `tests/ipc-integration.py`, `tests/packaging-plist-test.py`, `tests/service-state-test.c`
- `docs/architecture/daemon-security.md`, `docs/architecture/ipc-lifecycle.md`, `docs/architecture/ipc-protocol.md`, `docs/architecture/overview.md`, `docs/architecture/persistent-state.md`, `docs/architecture/recovery-rollback.md`, `docs/architecture/rootful-layout.md`, `docs/architecture/service-lifecycle.md`
- `docs/validation/ios-device-ipc-qualification.md`, `docs/prompts/P005_MANIFEST.md`

## Git follow-through

- Commit: one logical reviewable commit on `feat/p005-service-lifecycle`; exact amended branch HEAD is in the task final report.
- Pull request targeting `main`: [PR #5](https://github.com/nghianguyen150612/iOS-Unsandboxed/pull/5).
- No merge and no P006 work are included.

## P006 prerequisites

1. Complete the physical device matrix and preserve evidence for each result.
2. Verify installed Amethyst revision/provenance, native `getpeereid`, root/non-root SSH behavior, `/var/run`, Procursus paths, launchd behavior, reboot recovery, and SSH preservation.
3. Review any state writer and its root authorization independently; never expose it as unauthenticated management IPC.
4. Do not plan execution activation until compatibility, authenticated policy, and reviewed launch integration have device evidence and a separate safety review.
