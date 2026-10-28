# Native C17 boundaries

P003 adds two reusable project-owned C17 modules:

- `include/iu_preflight.h` and `src/iu_preflight.c` define the versioned, read-only compatibility probe.
- `include/iu_policy.h` and `src/iu_policy.c` define bounded target inspection and a deterministic execution-eligibility evaluator.

Both modules build into the host diagnostic daemon and the Apple ARM64 iOS diagnostic daemon. The host test target compiles them with C17, `-Wall -Wextra -Wpedantic -Werror`.

P009 adds `include/iu_amethyst_adapter.h`, `include/iu_amethyst_capabilities.h`, and their C17 implementations. They pin the audited Amethyst source revision as provenance, perform read-only bounded component evidence collection, expose fixed capability records, and inspect bounded ARM64 Mach-O signature structures. The adapter is part of both host and Apple ARM64 daemon builds. `make adapter-test` runs the mock-backed integration and production fail-closed fixtures. The test-only backend is not linked into production targets.

P005 adds `include/iu_service_state.h` and `src/iu_service_state.c`, a bounded read-only loader for `/var/lib/ios-unsandboxed/install-state`. Production expects a root:wheel `0700` data directory and root:wheel `0600` regular file. It accepts only schema 1 with `execution_activation=disabled`; it has no writer or migration path. State tests use isolated temporary directories and never touch an iOS installation path.

This code does not link to Amethyst, load untrusted dylibs, invoke private jailbreak-server commands, read or write kernel memory, change files, generate signatures, activate services, or intercept launches. Production P009 does not emit adapter `SUPPORTED_AND_VERIFIED` because no independent trusted build/runtime evidence collector is implemented. P003's separate compatibility enum remains unchanged. The policy's test configuration is not authenticated production authorization. Its hypothetical `ALLOW_ELIGIBLE` result is not an execution decision, and P009 preview keeps `operational_authorization=0`.

Keep future Amethyst-specific code behind the versioned project-owned P009 boundary. Do not treat the private Amethyst ABI or protocol as a stable product API. The P005 lifecycle status reads state without mutating it. Any future writer requires an independently reviewed root authorization boundary and atomic replacement; it must not add launch-hook behavior or unrestricted access to Amethyst's private protocol.
