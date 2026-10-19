# Native C17 boundaries

P003 adds two reusable project-owned C17 modules:

- `include/iu_preflight.h` and `src/iu_preflight.c` define the versioned, read-only compatibility probe.
- `include/iu_policy.h` and `src/iu_policy.c` define bounded target inspection and a deterministic execution-eligibility evaluator.

Both modules build into the host diagnostic daemon and the Apple ARM64 iOS diagnostic daemon. The host test target compiles them with C17, `-Wall -Wextra -Wpedantic -Werror`.

This code does not link to Amethyst, load untrusted dylibs, invoke private jailbreak-server commands, read or write kernel memory, change files, activate services, or intercept launches. `SUPPORTED_AND_VERIFIED` is not emitted because P003 cannot verify the exact installed Amethyst build or live hook state. The policy's test configuration is not authenticated production authorization. Its hypothetical `ALLOW_ELIGIBLE` result is not an execution decision, and the final launch gate remains blocked until a future integration can preserve and revalidate file identity.

Keep future Amethyst-specific code behind a separately reviewed project-owned boundary. Do not treat the private Amethyst ABI or protocol as a stable product API. P004 may add authenticated CLI-to-daemon IPC and root-owned policy state; it must not add launch-hook behavior or unrestricted access to Amethyst's private protocol.
