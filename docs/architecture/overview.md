# Architecture and implementation boundary

## Intended component flow

```text
Rust CLI (ios-unsandboxed)
        |
        | versioned AF_UNIX/SOCK_STREAM IPC, peer credentials
        v
C17 daemon (ios-unsandboxedd)
        |
        | Versioned project-owned interface; read-only in P009
        v
P003 preflight and execution policy
        |
        | Read-only contract (P009)
        v
Amethyst compatibility adapter
        |
        +-- source/build provenance and component evidence
        +-- capability classifications
        +-- bounded Mach-O inspection
        +-- hypothetical P003 preview
```

The Rust CLI owns user-facing command parsing, diagnostics, configuration, and error reporting. `iu doctor` performs read-only diagnostics directly and does not call a companion through `PATH`; `doctor --amethyst` can also request the daemon's additive read-only adapter status. The C17 daemon is the long-running service boundary for native Darwin integration. `ios-unsandboxedd --probe` calls the P003 C17 preflight module. The reusable native policy evaluator remains authoritative for hypothetical eligibility.

P003 implements a versioned C17 compatibility result and a deterministic fail-closed eligibility policy. P004 adds authenticated IPC; P005 adds a read-only persistent-state loader, an additive lifecycle diagnostic, and a passive LaunchDaemon template. P007/P008 add a separate rootful package manager and controlled LaunchDaemon lifecycle. P009 adds a project-owned read-only adapter ABI, evidence collector, capability contract, and safe Mach-O inspector. There is still no Amethyst runtime backend, launch hook, signing implementation, or trust-cache integration. The daemon runs only after an explicit start request. Execution activation remains disabled. Production compatibility cannot be promoted to verified without trusted installed-build identity and independent device hook evidence.

## Launch integration constraints

A daemon cannot universally intercept process launches merely by running. A future system-wide workflow depends on a compatible integration point in the jailbreak's existing launch path. No kernel exploit or kernel patch is planned. Any launch integration must be isolated behind a project-owned platform interface, with Amethyst-specific details confined to its adapter.

The relevant upstream project is [Amethyst](https://github.com/staturnzz/amethyst). Later source and ABI research should inspect, at minimum:

- `basebins/base_hook/src/loader.c`
- `basebins/base_hook/src/main.c`
- `basebins/common/src/basebin_jbserver.c`
- `basebins/common/src/basebin_macho.c`
- `basebins/launchd_hook/src/loader.c`
- `basebins/launchd_hook/src/codesign.c`
- `basebins/launchd_hook/src/trustcache.c`

These paths and their interfaces may change. P003 does not import or call Amethyst internal interfaces. Before integration, inspect the exact upstream revision used by the target Amethyst release and validate its ABI and behavior on the reference device.

## Build and runtime gates

Host compilation checks source quality and basic command behavior. Apple ARM64 iOS cross-compilation checks the target toolchain and linker. Physical iPad execution checks the actual iOS 12.5.7, rootful Amethyst, and Procursus environment. These are independent gates; host or cross-compilation success is not device evidence.

P009 leaves device validation **NOT RUN**: the workspace does not provide the reference iPad. The pinned source revision, host fixture tests, and iOS cross-compilation cannot establish installed Amethyst provenance, hook initialization, SSH inheritance, signing/trust behavior, or runtime launch success. Fully unsigned Mach-O support remains blocked/unverified.
