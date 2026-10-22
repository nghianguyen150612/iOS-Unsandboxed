# Fully unsigned Mach-O feasibility

## Decision summary

P002 does not establish that an ARM64 Mach-O without LC_CODE_SIGNATURE can launch on the reference iPad. Amethyst's ordinary pre-launch path does nothing for a missing or unusable signature structure. Its lower-level builder can create a CodeDirectory for a slice without an old signature, and sign_binary submits the generated blob through F_ADDSIGS without a userspace on-disk rewrite. No current normal caller reaches that case, and iOS 12.5.7 kernel acceptance and dynamic-loader startup have not been tested.

**Verdict: EXPERIMENTAL BLOCKER.** Do not claim that trust-cache insertion, signing, sandbox exemption, or successful runtime startup is solved. A future, separately authorized device experiment may test the in-memory F_ADDSIGS path after the integration and security prerequisites below are met. This document does not authorize an Amethyst patch or a device modification.

## Four distinct input states

| State | Source handling at pinned Amethyst revision | Feasibility conclusion |
| --- | --- | --- |
| A. Ad-hoc signature | Requires LC_CODE_SIGNATURE and a parseable CodeDirectory. The parser marks it ad-hoc only when no substantive CMS signature blob is present and the CodeDirectory ad-hoc flag is set. On a modern signature outside /var/containers, normal policy leaves it alone and trusts its cdhash. | Existing Amethyst path can add trust for this signature state. It is not a fully unsigned file, and this does not establish page-hash correctness or launch success. |
| B. Invalid signature | A malformed/unparseable structure yields no macho_signature_t and is skipped. A structurally parseable CodeDirectory is hashed, but this parser does not validate CMS authenticity or recompute/check the signature's stored per-page hashes before trust-cache handling. | “Invalid” must be split into malformed structure and parseable-but-cryptographically-invalid content. Source does not show a general repair path; kernel acceptance is unverified. |
| C. Empty or unusable signature structure | LC_CODE_SIGNATURE can exist while its referenced blob contains no recognized CodeDirectory. macho_get_signature then returns NULL, so the ordinary callers skip both sign and trust operations. The parser has no dedicated empty-signature recovery routine. | Current path does not prepare it. The direct builder may produce a blob if explicitly called, but that does not prove the kernel accepts it for this state. |
| D. No LC_CODE_SIGNATURE | The parser scans the commands, finds no LC_CODE_SIGNATURE, and returns NULL. process_binary and jbserver_process_binary only invoke signing/trust operations inside a non-NULL signature branch. | Current ordinary launch flow does nothing. No command insertion or file reconstruction occurs. Lower-level preparation is technically possible in source but unverified at runtime. |

The parser and selection policy are in [basebin_macho.c](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/common/src/basebin_macho.c#L195-L265) and [macho_should_sign](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/common/src/basebin_macho.c#L411-L419). The normal launch callers are [launchd_hook/loader.c](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/src/loader.c#L42-L68) and [basebin_jbserver.c](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/common/src/basebin_jbserver.c#L229-L253).

## What the no-load-command lower-level path proves

macho_sign_binary handles a NULL old signature by using the slice size as codeLimit, creating page hashes, and constructing a SuperBlob with a CodeDirectory and no copied entitlements. The builder zero-initializes that CodeDirectory and does not set its flags field or CS_ADHOC bit; it also creates no CMS signature slot. sign_binary can then call fcntl(F_ADDSIGS) with the slice offset and generated blob. That userspace routine opens the original file O_RDONLY and contains no write/pwrite/rename or LC_CODE_SIGNATURE insertion. The code later sets CS_VALID/CS_SIGNED on the kernel cs_blob, which is a separate state transition and does not establish that the generated structure is accepted by iOS 12.5.7. See [macho_sign_binary](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/common/src/basebin_macho.c#L330-L409) and [create_cs_blob/sign_binary](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/src/codesign.c#L8-L130).

That is a source-confirmed code path only if a caller explicitly reaches it. The current base-hook preparation function does not: it sees no signature and returns success without sending a request. The private JBSERVER_CMD_SIGN_BINARY handler can call sign_binary from a request, but the shipped client rejects a zero le_size even though sign_binary itself ignores le_offset/le_size/file_type. Calling that private command for case D would be a version-coupled shim behavior, not an existing supported API. See [client request](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/common/src/basebin_jbserver.c#L74-L90), [server handler](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/src/jbserver.c#L149-L160), and [builder](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/common/src/basebin_macho.c#L330-L409).

The source path does not prove:

- F_ADDSIGS accepts an ARM64 vnode without an LC_CODE_SIGNATURE command on iOS 12.5.7.
- A7/iOS 12 AMFI and exec code will use the attached cs_blob for that vnode.
- Kernel page validation and trust-cache lookup succeed for the generated CodeDirectory.
- The dynamic loader can load the image and its dependencies after that signature state is attached.
- A file replacement, vnode cache, or concurrent launch will observe the intended identity.

Trust-cache registration alone is insufficient on source evidence: it adds a cdhash from an existing CodeDirectory and never creates a CodeDirectory or LC_CODE_SIGNATURE. A code-signature acceptance result is separate from sandbox state and process policy. Both are separate again from dynamic linking and application startup.

## iOS 12.5.7 / A7 constraints in the inspected source

The launchd hook recognizes SOC_A7 and A8, uses a 4 KiB page size for those chips, selects a generic iOS 12 kernel-offset set (with a special case only for iOS 12.0), and selects dynamic trust-cache V0 for versions before iOS 13. The source marks PPL only for A12 and later SoCs. These code paths are relevant to the A7 target but do not identify or validate the exact 12.5.7 build's kernel layout at runtime. See [SoC/version/offset selection](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/src/main.c#L13-L138) and [trust-cache format selection](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/src/trustcache.c#L14-L40).

Preparation must happen before the original executable launch because launchd/base_hook call preparation before their original spawn/exec calls. Per-process sandbox changes happen only after the process exists: the injected target's base-hook constructor calls the Amethyst client with getpid() before normal application entry. An arbitrary daemon cannot retrofit this timing by observing a PID after it has started.

## Candidate architecture assessment

### 1. Transparent in-place on-disk preparation

**Classification: UNSUPPORTED by inspected Amethyst source.**

- **Prerequisites:** a complete ARM64 Mach-O rewriter that can add LC_CODE_SIGNATURE, update ncmds/sizeofcmds, place an aligned signature blob, update __LINKEDIT metadata, and preserve all unrelated command/data offsets. If the existing file has no room in its load-command area, the image must be reconstructed or layout-adjusted.
- **Advantages:** if validly implemented and accepted by iOS, the file itself carries the signature structure expected by conventional loaders.
- **Limitations:** Amethyst has no load-command insertion/reconstruction function. Adding a command can require shifting or rebuilding segments and fat-slice offsets. The exact iOS 12 requirements are not established here.
- **Filesystem:** changes the user's original executable. Writes must use a same-filesystem temporary file, complete-write checks, fsync, preserved mode/owner/group/flags/xattrs, atomic rename, and post-write Mach-O/hash verification. Directory permissions, hard links, open file descriptors, and symlink resolution complicate replacement.
- **Atomicity and rollback:** an in-place partial write can corrupt the executable. Atomic replacement avoids partial visibility but changes inode identity and requires a verified backup plus restore plan. Concurrent launches must lock and recheck file identity.
- **SSH compatibility:** direct ./binary can be preserved only if the existing base-hook exec path performs the preparation synchronously and then executes the replaced canonical path. The wrapper cannot be part of the user workflow.
- **Failure handling:** every validation/write/rename/readback failure must abort only that opted-in launch, report the stage, and leave a verified original/backup available.
- **Upstream change:** the base-hook launch path still needs a reviewed Amethyst-owned integration; an independent daemon cannot see all SSH launches.
- **Device uncertainty:** Mach-O rewrite acceptance, dyld startup, permissions, and rollback on the reference device remain untested.

### 2. Private staged-copy preparation and transparent redirection

**Classification: PLAUSIBLE / UNVERIFIED as a project design; not present upstream.**

- **Prerequisites:** a secure staging policy and storage area; copy and verify source bytes; prepare or reconstruct the staged Mach-O; atomically publish the complete staged artifact; retain mapping from original path/inode/hash to stage; redirect the intercepted launch to the stage.
- **Advantages:** can preserve the user's original bytes and provide a disposable prepared artifact. A complete temp file can be verified before it becomes eligible for launch.
- **Limitations:** Amethyst has no staging or redirection facility. A new staged path can change @executable_path/@loader_path behavior and dynamic-library resolution. Hard-coded paths, resource lookup, argv[0], executable identity, entitlements, and script handling need review.
- **Filesystem:** stage files need root-owned, non-user-writable directories and safe cleanup. If dependencies expect the original executable directory, staging must preserve those path semantics or fail closed.
- **Atomicity and rollback:** atomically publish a verified stage and never replace the original. Rollback removes only the product-owned stage, after confirming it is not in use. Stale stages need crash/reboot cleanup.
- **SSH compatibility:** possible only through synchronous interception of direct ./binary and redirection before original exec; it cannot require an explicit wrapper.
- **Failure handling:** missing stage storage, low disk space, mismatch, race, or failed dynamic-link preflight must return an explicit launch error.
- **Upstream change:** base_hook's execve/posix_spawn path must invoke policy and redirect; Amethyst's private calls still need a versioned shim.
- **Device uncertainty:** stage path semantics and startup behavior are unverified; no source establishes compatibility with the target's SSH environment.

### 3. Extend the existing base-hook launch path to request vnode-attached F_ADDSIGS state

**Classification: PLAUSIBLE / UNVERIFIED; a possible future bounded experiment, not a release architecture.**

- **Prerequisites:** modify or compatibly extend Amethyst's base_hook execve_hook/spawn_handler so it checks an explicit product opt-in and performs preparation synchronously before the original launch. Add a version handshake and precise error propagation. The request must identify the canonical path plus a revalidated file identity. Extend the private Amethyst adapter/server path so it explicitly calls the already-present CodeDirectory builder for no-LC slices and F_ADDSIGS operation.
- **Advantages:** preserves the original file and direct ./binary workflow if the kernel honors the vnode-attached blob. The source builder already handles a missing old signature; sign_binary already submits an in-memory blob through F_ADDSIGS.
- **Limitations:** no current launch caller invokes this case. F_ADDSIGS acceptance without LC_CODE_SIGNATURE, signature cache behavior, and dyld startup are unknown. The generated CodeDirectory has no CMS slot and its flags field remains zero, while Amethyst later changes kernel cs_blob flags; this is not source evidence of a conventional valid or ad-hoc file signature. The private XPC protocol is unstable. The generated blob does not install arbitrary entitlements. The ordinary trust-cache helper ignores insertion failures.
- **Filesystem:** no userspace write to the original file appears in the inspected signing path. The operation can still modify kernel vnode/code-signing/trust state.
- **Atomicity and rollback:** no on-disk rollback is needed if the file remains untouched, but the source exposes no reliable per-vnode cs_blob removal API. The launchd-hook trust-cache source has no per-hash removal operation. Disabling prevents new work; it does not undo existing kernel state. A full reboot clears volatile kernel state, but relying on reboot is not an acceptable per-executable rollback.
- **SSH compatibility:** uses the existing source-confirmed hook point for direct exec only when the SSH shell has base_hook injected and the hook can synchronously reach the Amethyst server.
- **Failure handling:** no fallthrough to the original launch after an opted-in preparation failure. Distinguish “policy skip” from error; verify server response, trust result, target file identity, and spawned image. Do not modify unrelated launch state.
- **Upstream change:** required. A sidecar at /usr/local/lib is not automatically loaded; Amethyst's launchd hook injects its own base_hook path. Any Amethyst-owned source or binary modification needs separate review.
- **Device uncertainty:** mandatory test on the exact A1489/iOS 12.5.7/Amethyst/Procursus target before any enablement claim.

### 4. Daemon-only process observation or CLI wrapper

**Classification: UNSUPPORTED for the requested workflow.**

A normal user-space daemon has no source-confirmed way to see every exec before it begins. Polling a process table is too late for signature preparation and creates a race. An execution wrapper violates the direct ./binary requirement. Neither is a substitute for a validated hook in the existing launch path.

## Rootful filesystem integration and lifecycle

The P001 contract reserves /usr/local/bin/ios-unsandboxed, /usr/local/bin/iu (filesystem symlink), /usr/local/bin/ios-unsandboxedd, /var/lib/ios-unsandboxed/, manager.sh, install-state, /usr/local/lib/ios-unsandboxed/, /Library/LaunchDaemons/com.ios-unsandboxed.daemon.plist, /var/run/ios-unsandboxedd.sock, and /var/log/ios-unsandboxed/. These are project-owned locations; they are not Amethyst hooks.

Amethyst's launchd_hook intercepts reads of launchd configuration: it adds plist files found in /Library/LaunchDaemons to the LaunchDaemons dictionary and adds /Library/LaunchDaemons to the path array. This is the source-confirmed Amethyst registration path that could expose a project-owned LaunchDaemon plist. It does not load a dylib merely because it exists under /usr/local/lib. See [jbserver.c LaunchDaemons/Paths hook](https://github.com/staturnzz/amethyst/blob/61ce86d7d3f00e5395f4d42bebda0e5dce04946a/basebins/launchd_hook/src/jbserver.c#L392-L429).

The project daemon would need root:wheel ownership, restricted socket permissions, and a default-disabled policy. The actual launchd hook is Amethyst-owned and must already be active when launchd enumerates the project plist; source gives no ordering guarantee between Amethyst initialization and the project daemon. Future service work must make the daemon wait for an authenticated compatibility handshake and refuse launch work while the hook/server is unavailable. The feature's enabled state may persist in the project install-state file across reboot, but the live Amethyst/kernel capability must be revalidated after every jailbreak start. Disable must atomically stop new work and record disabled state. On Amethyst component restart, lost IPC or a failed heartbeat must make the hook fail closed and report unavailable; it must not silently continue targeted binaries. On system reboot, trust-cache/vnode state is volatile and Amethyst must be active again before the feature can operate.

The SSH server is expected to remain a normal Amethyst-injected process. No product launchd job should replace, wrap, or modify SSH. If a hook/daemon failure could disrupt SSH, the project integration must be independently disableable and must leave unrelated SSH launches on the original path. The base-hook modification itself is Amethyst-owned and requires separate review.

## Security and reliability requirements

None of these execution controls is implemented by P002 or P003. P003 adds only read-only preflight diagnostics and a testable eligibility policy; these controls remain prerequisites for future execution work.

| Failure mode | Required control |
| --- | --- |
| Executable corruption or malformed Mach-O | Read-only preflight, strict bounds and slice checks, validate final artifact/hash, reject unsupported/malformed files without mutation. |
| Incomplete writes or interrupted upgrade | Same-filesystem temp, complete-write/fsync checks, atomic replacement, verified backup, transactional installer state, rollback. |
| Trust-cache inconsistency or partial insertion | Check and propagate every operation result; record exact cdhash and Amethyst session; do not report prepared on RPC success alone. Define recovery when entries cannot be removed. |
| Hook initialization failure | Verify hook/server status and compatibility before enabling. Constructor failures must be reported, not silently ignored. |
| IPC failure, daemon crash, Amethyst restart, or missing jailbreak service | Fail closed for opted-in launches, bounded timeout, authenticated peer identity, health recheck, safe disabled state, recoverable logs. |
| System reboot | Revalidate Amethyst after reboot; never infer live trust from the persistent enabled flag. |
| Concurrent launch of one executable | Serialize by stable file identity or use immutable staged artifacts; recheck identity immediately before exec. |
| Path substitution, symlink race, or hard-link alias | Resolve and open safely, inspect fstat identity on the held descriptor, constrain owner/mode/filesystem, revalidate before operation, define hard-link policy. |
| Privilege escalation through untrusted IPC | Permit only configured caller UIDs to submit narrowly scoped launch requests; verify peer credentials, path/file identity, and policy server-side. Keep enable/disable and management verbs root-only; reject arbitrary PID/path operations. |
| Accidental Apple-system executable modification | Deny system and Amethyst-owned paths; narrow allowlist for user-owned writable roots; check canonical path and inode before any operation. |
| SSH loss | Keep integration disableable without SSH, avoid changing SSH binaries/jobs, preserve SSH on unrelated requests, maintain recovery path and device-only SSH stability gate. |

Policy invariants: operation is default-disabled; enable is explicit; only narrowly eligible targets are handled; unrelated processes keep their existing policy; signature/trust failures are never silent; file replacement, if ever required, is atomic with verified backups and reversible restoration; no independent kernel exploit or kernel patch is introduced. These are requirements, not claims about existing P001 or Amethyst protections.

## Physical-device gates

All remain **NOT RUN** because the reference device was not available:

- Amethyst ABI interoperability.
- launchd hook initialization on iOS 12.5.7.
- SSH-launched executable interception.
- Signing and trust-cache runtime operation.
- Unsandbox policy behavior.
- Fully unsigned ARM64 Mach-O execution.
- Enable/disable.
- Device restart and jailbreak restart.
- SSH stability.

## P004 and later prerequisites

1. Obtain and record the exact Amethyst build and source revision installed on the reference iPad; verify it corresponds to the audited ABI or perform a new audit.
2. Review and approve any necessary Amethyst-owned base_hook change separately. It must add an explicit policy gate and invoke a product-owned C17 adapter before execve/spawn for eligible targets.
3. Define a versioned adapter and authenticated daemon IPC, with error-stage propagation, a server/version handshake, and no public exposure of the private Amethyst request protocol.
4. Implement the no-LC F_ADDSIGS experimental path only behind a disabled-by-default feature flag. Verify file identity and propagate failures; never fall through silently after an opted-in preparation error.
5. Set a narrow eligible path/ownership/mode policy; reject Apple system and Amethyst-owned executables, malformed or unsupported Mach-O, setuid/setgid files, unsafe symlinks, and path races.
6. Specify enable/disable persistence, launchd job ordering, Amethyst restart behavior, reboot recovery, logs, and rollback before implementation.
7. Run host and iOS cross-compilation gates, then each physical-device gate above on the exact reference configuration. Source inspection and CI cannot substitute for device evidence.

P002 was research-only. P003 subsequently added read-only compatibility diagnostics and an in-memory C17 eligibility policy. No Amethyst component was modified, no device operation was performed, and no P004 work has started.
