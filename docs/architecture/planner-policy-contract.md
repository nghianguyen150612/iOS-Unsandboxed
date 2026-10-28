# Planner and P003/P009 policy contract

P003 remains the eligibility authority. `iu_execution_plan_create_v1` constructs a `iu_policy_target_v1` from the opened descriptor metadata and canonical path and calls `iu_policy_evaluate_v1`; it does not implement a second classifier. P003's public numeric enums and policy order are unchanged. Its protected-path, safe-file, ownership, descriptor-identity, backend-compatibility, disabled-state, and configured-target outcomes remain authoritative whenever the corresponding configured facts reach those checks.

The production planner constructs a valid disabled configuration with unverified Amethyst compatibility. Therefore its ordinary result is denied (`DENY_DISABLED`, before later policy checks), even when a file can be inspected. P009's read-only adapter probe contributes platform/component classification and its capability table; filenames and filesystem hashes do not verify the running hooks or installed trusted build. The test-only `IU_EXECUTION_PLANNER_TESTING` entry point injects explicit in-memory policy and adapter facts for deterministic simulated cases. It is compiled only into the planner fixture executable. Neither the CLI nor daemon exposes it, and no IPC payload can supply verified backend facts.

The planner calls P009's capability classifier and classifies Amethyst compatibility with no trusted device or runtime facts. Capability requirements and missing-prerequisite bits are descriptive. Source evidence is not runtime evidence. Capability state cannot override P003, and neither a hypothetical P003 `ALLOW_ELIGIBLE` nor P009 compatibility can change the always-false operational authorization field.

## Result meaning

The fixed-layout ABI v1 result contains:

- artifact identity and full SHA-256 digest;
- P009 parser state, architecture, and Mach-O file type;
- descriptive signature preparation state;
- P003 outcome and reason;
- P009 adapter compatibility plus required and missing capability masks;
- preview status and blocking reason;
- runtime-verification and operational-authorization flags, both zero.

`required_capabilities` is an ID bitset (bit `1 << capability_id`) consumed from P009's fixed capability table. `missing_prerequisites` is a separate flag set: trusted installed-build identity, runtime hook evidence, SSH coverage, signature preparation, execution adapter, trust-cache integration, kernel acceptance, sandbox result, dynamic-loader startup, and launch-boundary identity. P009 `SOURCE_CONFIRMED` does not clear a runtime prerequisite; only an applicable `RUNTIME_VERIFIED` capability can clear the corresponding bit. Trust-cache/kernel/sandbox/loader/launch-boundary flags remain set because P009 has no authoritative runtime records for them.

Result records contain no pointers. Revalidation requires ABI v1, exact structure size, bounded canonical path termination, safe enum values, recorded single-link regular-file identity, zero reserved fields, and zero authorization/runtime flags. It reopens and rechecks the current path and bytes. It is not a launch-boundary guarantee.

The planner does not change reserved-operation behavior or expose signing, trust-cache, unsandbox, interception, or launch APIs. `iu enable` and `iu disable` remain unavailable.
