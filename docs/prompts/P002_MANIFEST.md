# P002 manifest — Amethyst source and ABI compatibility audit

## Outcome

**Research status: COMPLETE. Runtime feasibility: EXPERIMENTAL BLOCKER.** The requested Amethyst source was available and all seven prioritized files exist at the inspected commit. The audit does not prove runtime compatibility or fully unsigned execution. No P003 implementation, Amethyst component modification, or physical-device operation was performed.

## Baseline and source identity

- Repository: https://github.com/nghianguyen150612/iOS-Unsandboxed
- Verified remote baseline: origin/main at fd7b920b7368165bbe8bf99ea6adc455068ad328, the P001 merge commit.
- P001 source commit: 94307f705acaabed266b6b45a7b41dc56c88aa8a.
- Initial checkout: clean working tree on main after fetch; no unrelated changes were present.
- Work branch: docs/p002-amethyst-abi-audit, created from verified origin/main.
- Upstream: https://github.com/staturnzz/amethyst
- Inspected Amethyst revision: 61ce86d7d3f00e5395f4d42bebda0e5dce04946a, branch main, tag v1.1.
- Upstream license: MIT. P002 copied no Amethyst implementation and did not vendor the repository.

## Source inventory

The seven prioritized paths exist at the pinned revision:

- basebins/base_hook/src/loader.c
- basebins/base_hook/src/main.c
- basebins/common/src/basebin_jbserver.c
- basebins/common/src/basebin_macho.c
- basebins/launchd_hook/src/loader.c
- basebins/launchd_hook/src/codesign.c
- basebins/launchd_hook/src/trustcache.c

Related inspected call sites include base_hook/src/hooks.c; common/include/basebin_jbserver.h, common/include/basebin_macho.h, common/src/basebin_util.c, and common/src/basebin_hook.c; launchd_hook/src/main.c, jbserver.c, memory.c, util.c, and ppl.c; launchd_hook/include/jbserver.h, codesign.h, trustcache.h, and info.h; Amethyst/Amethyst/jailbreak/handoff.c and install.c; jbutil main/injector sources; and the basebin build/package Makefiles.

## Findings

- Amethyst injects launchd_hook into PID 1 through its jailbreak handoff and jbutil --kickstart. launchd_hook intercepts launchd posix_spawn; its injected base_hook intercepts execve and posix_spawn only in processes that loaded it.
- For an SSH command that directly executes ./binary, the needed existing extension point is the base hook's execve_hook/spawn_handler. The SSH daemon and shell injection path is source-plausible but device-unverified; a user-space daemon cannot observe every launch.
- Normal Amethyst preparation only signs or adds trust for an executable slice after it obtains a parseable signature from LC_CODE_SIGNATURE. Missing or unusable command structures are skipped.
- The lower-level builder can generate a CodeDirectory without an old signature and submit it through F_ADDSIGS. The shipped launch path does not call it for a missing command. Whether iOS 12.5.7 accepts that vnode-attached signature and completes ARM64 startup is unknown.
- Trust-cache insertion, code-signing flags, sandbox state, entitlement policy, dynamic linking, and successful runtime startup are separate conditions. Amethyst's current hooks ignore preparation errors in key launch callers and do not provide a stable external ABI.
- Amethyst applies its AUTO sandbox policy to each injected process in the base-hook constructor. That policy is not product opt-in and must not be reused as iOS-Unsandboxed's eligibility decision.
- The proposed C17 adapter is project-owned and versioned. A reviewed Amethyst-owned base-hook extension is required to call it before direct SSH-launched execution. A project dylib under /usr/local/lib/ios-unsandboxed is not automatically loaded.
- Recommended P003 work is limited to a disabled-by-default, device-validated experiment of explicit no-LC F_ADDSIGS preparation. No shipping architecture is recommended until kernel acceptance, rollback, and launch behavior pass on the reference device.

## Deliverables

- docs/research/amethyst-source-audit.md
- docs/research/launch-path-matrix.md
- docs/research/signing-trustcache-audit.md
- docs/architecture/amethyst-abi-contract.md
- docs/architecture/unsigned-macho-feasibility.md
- docs/prompts/P002_MANIFEST.md
- README status note and links to the audit

## Acceptance checklist

- [x] Current main baseline and P001 ancestry verified before editing.
- [x] Amethyst revision pinned; named files and call graphs inspected.
- [x] Launch interception paths, direct SSH execution, filters, and injection boundaries documented.
- [x] Signing, trust-cache, private RPC, errors, synchronization, and unsandbox mechanisms documented.
- [x] Native ABI points classified as internal, private IPC, hooks, or proposed project-owned adapter.
- [x] Ad-hoc, invalid, empty/unusable, and no-load-command states assessed separately.
- [x] Candidate architectures classified with SSH, filesystem, failure, rollback, upstream-change, and device constraints.
- [x] Security requirements and P003 prerequisites documented; not represented as implemented.
- [x] Existing P001 validation gates attempted; environment limitations and available partial checks recorded below.

The single-commit, branch-push, and PR requirements are recorded in the P002 task outcome after the Git workflow completes.

## Validation and Git follow-through

| Gate | Result |
| --- | --- |
| cargo fmt --all -- --check | BLOCKED: `cargo` is not installed in the Linux execution environment (exit 127). |
| cargo clippy --locked --workspace --all-targets -- -D warnings | BLOCKED: `cargo` is not installed (exit 127). |
| make build | BLOCKED before compilation: Make could not find `cargo` (exit 2 / child exit 127). |
| make test | BLOCKED in its `host-build` prerequisite because `cargo` is unavailable; Rust tests and repository smoke script did not run. |
| C17 daemon compile and focused help/version/fail-safe checks | PASS using `cc -std=c17 -Wall -Wextra -Wpedantic -Werror -O2`; binary was written under `/tmp`, not the repository. |
| Markdown local-link and pinned-source line-range validation; `git diff --check` | PASS. |
| make build-ios / Apple ARM64 cross-compilation | BLOCKED: `make build-ios` requires macOS, Xcode command-line tools, and the iPhoneOS SDK; this host is Linux (exit 2). |
| Physical-device testing | **NOT RUN** |

The exact commit, branch, and PR identifiers are reported in the P002 task outcome.

## Physical-device gates

All remain **NOT RUN**: Amethyst ABI interoperability; launchd hook initialization on iOS 12.5.7; SSH-launched executable interception; signing/trust-cache operation; unsandbox policy behavior; fully unsigned ARM64 Mach-O execution; enable/disable; device restart and jailbreak restart; SSH stability.

## Blockers

No requested source file or license was inaccessible. The blockers are runtime facts that source cannot establish: the exact Amethyst build installed on the iPad; iOS 12.5.7 kernel acceptance of F_ADDSIGS state without LC_CODE_SIGNATURE; SSH shell hook inheritance/injection; dynamic-link/startup results; exact rollback behavior for vnode and trust-cache state; and lifecycle behavior across jailbreak/device restart. P003 prerequisites are listed in docs/architecture/unsigned-macho-feasibility.md.
