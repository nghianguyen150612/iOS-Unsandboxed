# Architecture and implementation boundary

## Intended component flow

```text
Rust CLI (ios-unsandboxed)
        |
        | Future authenticated native IPC; absent in P003
        v
C17 daemon (ios-unsandboxedd)
        |
        | Future product-owned platform interface; absent in P003
        v
Native execution layer
        |
        | Isolated, version-validated adapter
        v
Amethyst integration backend
        |
        v
Existing jailbreak launch/signing/trust mechanisms
```

The Rust CLI owns user-facing command parsing, diagnostics, configuration, and error reporting. `iu doctor` performs read-only diagnostics directly and does not call a companion through `PATH`. The C17 daemon is the future long-running service boundary for native Darwin integration. `ios-unsandboxedd --probe` calls the P003 C17 preflight module. The reusable native policy evaluator is separate from Amethyst and currently has no execution caller.

P003 implements a versioned C17 compatibility result and a deterministic fail-closed eligibility policy. There is still no IPC protocol, native Amethyst backend, launch hook, signing implementation, or trust-cache integration. The daemon does not run in the background and has no privileged behavior. Compatibility remains unverified unless the exact installed Amethyst build and required device evidence can be established; P003's probes do not establish that proof.

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

P003 leaves device validation **NOT RUN**: the workspace does not provide the reference iPad. The audited source revision, host fixture tests, and iOS cross-compilation cannot establish installed Amethyst provenance, hook initialization, SSH inheritance, signing/trust behavior, or runtime launch success.
