# Architecture and implementation boundary

## Intended component flow

```text
Rust CLI (ios-unsandboxed)
        |
        | Future native IPC; absent in P001
        v
C17 daemon (ios-unsandboxedd)
        |
        | Future product-owned platform interface; absent in P001
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

The Rust CLI owns user-facing command parsing, diagnostics, configuration, and error reporting. The C17 daemon is the future long-running service boundary for native Darwin integration. The native execution layer and Amethyst adapter belong outside both the Rust CLI and generic daemon entry point, so platform-specific behavior can be reviewed and validated separately.

In P001, only CLI argument handling and diagnostic daemon flags exist. There is no IPC protocol, native execution layer, Amethyst backend, launch hook, signing implementation, or trust-cache integration. The daemon does not run in the background and has no privileged behavior.

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

These paths and their interfaces may change. P001 does not import or call Amethyst internal interfaces. Before integration, inspect the exact upstream revision used by the target Amethyst release and validate its ABI and behavior on the reference device.

## Build and runtime gates

Host compilation checks source quality and basic command behavior. Apple ARM64 iOS cross-compilation checks the target toolchain and linker. Physical iPad execution checks the actual iOS 12.5.7, rootful Amethyst, and Procursus environment. These are independent gates; host or cross-compilation success is not device evidence.

P001 intentionally leaves device validation NOT RUN: no device deployment was authorized or performed, and the workspace does not provide the reference iPad.
